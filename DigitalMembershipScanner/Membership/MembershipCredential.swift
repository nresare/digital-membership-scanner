import CBlst
import Foundation

struct ParsedMembershipCredential: Equatable, Sendable {
    let version: UInt8
    let keyID: UInt8
    let flags: Set<Int>
    let unsignedCredential: Data
    let nameBytes: Data
    let signature: Data
}

struct VerifiedMembership: Equatable, Identifiable, Sendable {
    let name: String
    let flags: Set<Int>
    let keyID: UInt8

    var id: String { "\(keyID):\(name):\(flags.sorted())" }
}

enum MembershipCredentialError: LocalizedError, Equatable, Sendable {
    case tooShort
    case unsupportedVersion(UInt8)
    case invalidExtendedFlagLength
    case flagDataOutOfBounds
    case nonMinimalFlags
    case invalidNameLength
    case invalidNameEncoding
    case controlCharacterInName

    var errorDescription: String? {
        switch self {
        case .tooShort: "The credential is shorter than the 50-byte minimum."
        case let .unsupportedVersion(version): "Credential version \(version) is not supported."
        case .invalidExtendedFlagLength: "The extended flag length is not minimally encoded."
        case .flagDataOutOfBounds: "The flag data extends beyond the credential."
        case .nonMinimalFlags: "The flag bitset contains an unnecessary trailing zero byte."
        case .invalidNameLength: "The display name must contain between 1 and 255 bytes."
        case .invalidNameEncoding: "The display name is not valid UTF-8."
        case .controlCharacterInName: "The display name contains a control character."
        }
    }
}

struct MembershipCredentialParser: Sendable {
    static let signatureLength = 48
    static let domainPrefix = Data("digital-membership/v1\0".utf8)

    func parse(_ data: Data) throws -> ParsedMembershipCredential {
        guard data.count >= 50 else { throw MembershipCredentialError.tooShort }

        let signatureStart = data.count - Self.signatureLength
        let header = data[data.startIndex]
        let version = header >> 5
        guard version == 1 else { throw MembershipCredentialError.unsupportedVersion(version) }

        let keyID = (header >> 2) & 0b111
        let flagSizeCode = header & 0b11
        var flagStart = data.startIndex + 1
        let flagLength: Int

        if flagSizeCode == 0b11 {
            guard flagStart < signatureStart else { throw MembershipCredentialError.flagDataOutOfBounds }
            flagLength = Int(data[flagStart])
            flagStart += 1
            guard flagLength >= 3 else { throw MembershipCredentialError.invalidExtendedFlagLength }
        } else {
            flagLength = Int(flagSizeCode)
        }

        guard flagLength <= signatureStart - flagStart else {
            throw MembershipCredentialError.flagDataOutOfBounds
        }

        let flagEnd = flagStart + flagLength
        let flagBytes = data[flagStart..<flagEnd]
        if let finalFlagByte = flagBytes.last, finalFlagByte == 0 {
            throw MembershipCredentialError.nonMinimalFlags
        }

        let nameLength = signatureStart - flagEnd
        guard (1...255).contains(nameLength) else { throw MembershipCredentialError.invalidNameLength }

        let nameBytes = Data(data[flagEnd..<signatureStart])

        var flags = Set<Int>()
        for (byteIndex, byte) in flagBytes.enumerated() {
            for bitIndex in 0..<8 where byte & (1 << bitIndex) != 0 {
                flags.insert(byteIndex * 8 + bitIndex)
            }
        }

        return ParsedMembershipCredential(
            version: version,
            keyID: keyID,
            flags: flags,
            unsignedCredential: Data(data[..<signatureStart]),
            nameBytes: nameBytes,
            signature: Data(data[signatureStart...])
        )
    }
}

protocol MembershipSignatureVerifying: Sendable {
    func verify(_ credential: ParsedMembershipCredential) throws -> Bool
}

protocol MembershipNameDecoding: Sendable {
    func decompressName(_ bytes: Data, keyID: UInt8) throws -> String
}

struct UnavailableMembershipNameDecoder: MembershipNameDecoding {
    func decompressName(_ bytes: Data, keyID: UInt8) throws -> String {
        throw MembershipSignatureVerificationError.trustedKeyUnavailable(keyID: keyID)
    }
}

struct NameCompressionMembershipNameDecoder: MembershipNameDecoding {
    let models: [UInt8: NameCompressionTable]

    func decompressName(_ bytes: Data, keyID: UInt8) throws -> String {
        guard let model = models[keyID] else {
            throw MembershipSignatureVerificationError.trustedKeyUnavailable(keyID: keyID)
        }
        return try model.decompress(bytes)
    }
}

struct UTF8MembershipNameDecoder: MembershipNameDecoding {
    func decompressName(_ bytes: Data, keyID: UInt8) throws -> String {
        guard let name = String(data: bytes, encoding: .utf8) else {
            throw MembershipCredentialError.invalidNameEncoding
        }
        return name
    }
}

enum MembershipSignatureVerificationError: LocalizedError, Equatable, Sendable {
    case trustedKeyUnavailable(keyID: UInt8)
    case invalidTrustedPublicKey(keyID: UInt8)
    case invalidSignatureEncoding

    var errorDescription: String? {
        switch self {
        case let .trustedKeyUnavailable(keyID):
            "No trusted BLS public key is configured for key ID \(keyID)."
        case let .invalidTrustedPublicKey(keyID):
            "The trusted BLS public key for key ID \(keyID) is invalid."
        case .invalidSignatureEncoding:
            "The credential signature is not a canonical BLS12-381 G1 point."
        }
    }
}

struct UnavailableMembershipSignatureVerifier: MembershipSignatureVerifying {
    func verify(_ credential: ParsedMembershipCredential) throws -> Bool {
        throw MembershipSignatureVerificationError.trustedKeyUnavailable(keyID: credential.keyID)
    }
}

struct BLSTMembershipSignatureVerifier: MembershipSignatureVerifying {
    static let publicKeyLength = 96
    static let ciphersuite = Data("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".utf8)

    let trustedPublicKeys: [UInt8: Data]

    func verify(_ credential: ParsedMembershipCredential) throws -> Bool {
        guard let publicKeyBytes = trustedPublicKeys[credential.keyID] else {
            throw MembershipSignatureVerificationError.trustedKeyUnavailable(keyID: credential.keyID)
        }
        guard var publicKey = Self.validatedPublicKey(publicKeyBytes) else {
            throw MembershipSignatureVerificationError.invalidTrustedPublicKey(keyID: credential.keyID)
        }

        var signature = blst_p1_affine()
        let signatureDecodeResult = credential.signature.withUnsafeBytes { bytes in
            blst_p1_uncompress(&signature, bytes.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard signatureDecodeResult == BLST_SUCCESS,
              blst_p1_affine_in_g1(&signature),
              !blst_p1_affine_is_inf(&signature),
              Self.isCanonical(signature, encodedAs: credential.signature)
        else {
            throw MembershipSignatureVerificationError.invalidSignatureEncoding
        }

        var message = MembershipCredentialParser.domainPrefix
        message.append(credential.unsignedCredential)

        let verificationResult = message.withUnsafeBytes { messageBytes in
            Self.ciphersuite.withUnsafeBytes { ciphersuiteBytes in
                blst_core_verify_pk_in_g2(
                    &publicKey,
                    &signature,
                    true,
                    messageBytes.bindMemory(to: UInt8.self).baseAddress!,
                    messageBytes.count,
                    ciphersuiteBytes.bindMemory(to: UInt8.self).baseAddress!,
                    ciphersuiteBytes.count,
                    nil,
                    0
                )
            }
        }
        return verificationResult == BLST_SUCCESS
    }

    static func isValidTrustedPublicKey(_ bytes: Data) -> Bool {
        validatedPublicKey(bytes) != nil
    }

    private static func validatedPublicKey(_ bytes: Data) -> blst_p2_affine? {
        guard bytes.count == publicKeyLength else { return nil }

        var publicKey = blst_p2_affine()
        let decodeResult = bytes.withUnsafeBytes { rawBytes in
            blst_p2_uncompress(&publicKey, rawBytes.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard decodeResult == BLST_SUCCESS,
              blst_p2_affine_in_g2(&publicKey),
              !blst_p2_affine_is_inf(&publicKey),
              isCanonical(publicKey, encodedAs: bytes)
        else { return nil }
        return publicKey
    }

    private static func isCanonical(_ publicKey: blst_p2_affine, encodedAs bytes: Data) -> Bool {
        var publicKey = publicKey
        var canonical = Data(repeating: 0, count: publicKeyLength)
        canonical.withUnsafeMutableBytes { output in
            blst_p2_affine_compress(output.bindMemory(to: UInt8.self).baseAddress!, &publicKey)
        }
        return canonical == bytes
    }

    private static func isCanonical(_ signature: blst_p1_affine, encodedAs bytes: Data) -> Bool {
        var signature = signature
        var canonical = Data(repeating: 0, count: MembershipCredentialParser.signatureLength)
        canonical.withUnsafeMutableBytes { output in
            blst_p1_affine_compress(output.bindMemory(to: UInt8.self).baseAddress!, &signature)
        }
        return canonical == bytes
    }
}

enum MembershipVerificationResult: Identifiable, Sendable {
    case verified(VerifiedMembership)
    case rejected(String)
    case trustedKeyUnavailable(keyID: UInt8)

    var id: String {
        switch self {
        case let .verified(membership): "verified:\(membership.id)"
        case let .rejected(reason): "rejected:\(reason)"
        case let .trustedKeyUnavailable(keyID): "missing-key:\(keyID)"
        }
    }
}

struct MembershipCredentialValidator: Sendable {
    let parser: MembershipCredentialParser
    let verifier: any MembershipSignatureVerifying
    let nameDecoder: any MembershipNameDecoding

    init(
        parser: MembershipCredentialParser = MembershipCredentialParser(),
        verifier: any MembershipSignatureVerifying = UnavailableMembershipSignatureVerifier(),
        nameDecoder: any MembershipNameDecoding = UnavailableMembershipNameDecoder()
    ) {
        self.parser = parser
        self.verifier = verifier
        self.nameDecoder = nameDecoder
    }

    func validate(_ data: Data) -> MembershipVerificationResult {
        do {
            let parsed = try parser.parse(data)
            guard try verifier.verify(parsed) else { return .rejected("The credential signature is invalid.") }
            let name = try nameDecoder.decompressName(parsed.nameBytes, keyID: parsed.keyID)
            guard (1...255).contains(name.utf8.count) else { throw MembershipCredentialError.invalidNameLength }
            guard name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw MembershipCredentialError.controlCharacterInName
            }
            return .verified(VerifiedMembership(name: name, flags: parsed.flags, keyID: parsed.keyID))
        } catch let MembershipSignatureVerificationError.trustedKeyUnavailable(keyID) {
            return .trustedKeyUnavailable(keyID: keyID)
        } catch {
            return .rejected(error.localizedDescription)
        }
    }
}
