import CBlst
import Foundation

struct ParsedMembershipCredential: Equatable, Sendable {
    let version: UInt8
    let issueDay: UInt16
    let memberIdentifier: MembershipIdentifier
    let flags: Set<Int>
    let unsignedCredential: Data
    let nameBytes: Data
    let signature: Data
}

struct VerifiedMembership: Equatable, Identifiable, Sendable {
    let name: String
    let flags: Set<Int>
    let issueDay: UInt16
    let memberIdentifier: MembershipIdentifier

    var id: String { "\(name):\(issueDay):\(memberIdentifier):\(flags.sorted())" }
}

enum MembershipIdentifier: Equatable, Sendable {
    case none
    case number(UInt64)
    case text(String)
}

enum MembershipCredentialError: LocalizedError, Equatable, Sendable {
    case tooShort
    case unsupportedVersion(UInt8)
    case invalidExtendedFlagLength
    case issuanceWordOutOfBounds
    case identifierOutOfBounds
    case nonMinimalIdentifier
    case invalidIdentifierLength
    case invalidIdentifierEncoding
    case controlCharacterInIdentifier
    case flagDataOutOfBounds
    case nonMinimalFlags
    case invalidNameLength
    case invalidNameEncoding
    case controlCharacterInName

    var errorDescription: String? {
        switch self {
        case .tooShort: "The credential is shorter than the 52-byte minimum."
        case let .unsupportedVersion(version): "Credential version \(version) is not supported."
        case .invalidExtendedFlagLength: "The extended flag length is not minimally encoded."
        case .issuanceWordOutOfBounds: "The credential does not contain a complete issuance word."
        case .identifierOutOfBounds: "The member identifier extends beyond the credential."
        case .nonMinimalIdentifier: "The numeric member identifier is not minimally encoded."
        case .invalidIdentifierLength: "The text member identifier must contain between 1 and 255 bytes."
        case .invalidIdentifierEncoding: "The member identifier is not valid UTF-8."
        case .controlCharacterInIdentifier: "The member identifier contains a control character."
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
        guard data.count >= 52 else { throw MembershipCredentialError.tooShort }

        let signatureStart = data.count - Self.signatureLength
        let header = data[data.startIndex]
        let version = header >> 5
        guard version == 1 else { throw MembershipCredentialError.unsupportedVersion(version) }

        let headerFlags = header & 0b111
        let flagSizeCode = (header >> 3) & 0b11
        var cursor = data.startIndex + 1
        let flagLength: Int

        if flagSizeCode == 0b11 {
            guard cursor < signatureStart else { throw MembershipCredentialError.flagDataOutOfBounds }
            flagLength = Int(data[cursor])
            cursor += 1
            guard flagLength >= 3 else { throw MembershipCredentialError.invalidExtendedFlagLength }
        } else {
            flagLength = Int(flagSizeCode)
        }

        guard cursor + 2 <= signatureStart else { throw MembershipCredentialError.issuanceWordOutOfBounds }
        let issuanceWord = UInt16(data[cursor]) << 8 | UInt16(data[cursor + 1])
        let issueDay = issuanceWord >> 3
        let identifierCode = Int(issuanceWord & 0b111)
        cursor += 2

        let memberIdentifier: MembershipIdentifier
        switch identifierCode {
        case 0:
            memberIdentifier = .none
        case 1...6:
            guard cursor + identifierCode <= signatureStart else {
                throw MembershipCredentialError.identifierOutOfBounds
            }
            let identifierBytes = data[cursor..<(cursor + identifierCode)]
            if identifierCode > 1, identifierBytes.first == 0 {
                throw MembershipCredentialError.nonMinimalIdentifier
            }
            let value = identifierBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            memberIdentifier = .number(value)
            cursor += identifierCode
        case 7:
            guard cursor < signatureStart else { throw MembershipCredentialError.identifierOutOfBounds }
            let length = Int(data[cursor])
            cursor += 1
            guard length > 0 else { throw MembershipCredentialError.invalidIdentifierLength }
            guard cursor + length <= signatureStart else { throw MembershipCredentialError.identifierOutOfBounds }
            let identifierData = Data(data[cursor..<(cursor + length)])
            guard let identifier = String(data: identifierData, encoding: .utf8) else {
                throw MembershipCredentialError.invalidIdentifierEncoding
            }
            guard identifier.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw MembershipCredentialError.controlCharacterInIdentifier
            }
            memberIdentifier = .text(identifier)
            cursor += length
        default:
            preconditionFailure("The three-bit identifier code is always between zero and seven")
        }

        let flagStart = cursor
        guard flagLength <= signatureStart - flagStart else {
            throw MembershipCredentialError.flagDataOutOfBounds
        }

        let flagEnd = flagStart + flagLength
        let flagBytes = data[flagStart..<flagEnd]
        if let finalFlagByte = flagBytes.last, finalFlagByte == 0 {
            throw MembershipCredentialError.nonMinimalFlags
        }

        let nameLength = signatureStart - flagEnd
        guard nameLength > 0 else { throw MembershipCredentialError.invalidNameLength }

        let nameBytes = Data(data[flagEnd..<signatureStart])

        var flags = Set((0..<3).filter { headerFlags & (1 << $0) != 0 })
        for (byteIndex, byte) in flagBytes.enumerated() {
            for bitIndex in 0..<8 where byte & (1 << bitIndex) != 0 {
                flags.insert(3 + byteIndex * 8 + bitIndex)
            }
        }

        return ParsedMembershipCredential(
            version: version,
            issueDay: issueDay,
            memberIdentifier: memberIdentifier,
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
    func decompressName(_ bytes: Data) throws -> String
}

struct UnavailableMembershipNameDecoder: MembershipNameDecoding {
    func decompressName(_ bytes: Data) throws -> String {
        throw MembershipSignatureVerificationError.trustedIssuerUnavailable
    }
}

struct NameCompressionMembershipNameDecoder: MembershipNameDecoding {
    let model: NameCompressionTable

    func decompressName(_ bytes: Data) throws -> String {
        return try model.decompress(bytes)
    }
}

struct UTF8MembershipNameDecoder: MembershipNameDecoding {
    func decompressName(_ bytes: Data) throws -> String {
        guard let name = String(data: bytes, encoding: .utf8) else {
            throw MembershipCredentialError.invalidNameEncoding
        }
        return name
    }
}

enum MembershipSignatureVerificationError: LocalizedError, Equatable, Sendable {
    case trustedIssuerUnavailable
    case invalidTrustedPublicKey
    case invalidSignatureEncoding

    var errorDescription: String? {
        switch self {
        case .trustedIssuerUnavailable:
            "No trusted issuer is configured."
        case .invalidTrustedPublicKey:
            "The trusted issuer's BLS public key is invalid."
        case .invalidSignatureEncoding:
            "The credential signature is not a canonical BLS12-381 G1 point."
        }
    }
}

struct UnavailableMembershipSignatureVerifier: MembershipSignatureVerifying {
    func verify(_ credential: ParsedMembershipCredential) throws -> Bool {
        throw MembershipSignatureVerificationError.trustedIssuerUnavailable
    }
}

struct BLSTMembershipSignatureVerifier: MembershipSignatureVerifying {
    static let publicKeyLength = 96
    static let ciphersuite = Data("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".utf8)

    let trustedPublicKey: Data

    func verify(_ credential: ParsedMembershipCredential) throws -> Bool {
        guard var publicKey = Self.validatedPublicKey(trustedPublicKey) else {
            throw MembershipSignatureVerificationError.invalidTrustedPublicKey
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
    case trustedIssuerUnavailable

    var id: String {
        switch self {
        case let .verified(membership): "verified:\(membership.id)"
        case let .rejected(reason): "rejected:\(reason)"
        case .trustedIssuerUnavailable: "missing-issuer"
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
            let name = try nameDecoder.decompressName(parsed.nameBytes)
            guard (1...255).contains(name.utf8.count) else { throw MembershipCredentialError.invalidNameLength }
            guard name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw MembershipCredentialError.controlCharacterInName
            }
            return .verified(
                VerifiedMembership(
                    name: name,
                    flags: parsed.flags,
                    issueDay: parsed.issueDay,
                    memberIdentifier: parsed.memberIdentifier
                )
            )
        } catch MembershipSignatureVerificationError.trustedIssuerUnavailable {
            return .trustedIssuerUnavailable
        } catch {
            return .rejected(error.localizedDescription)
        }
    }
}
