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
        guard let name = String(data: nameBytes, encoding: .utf8) else {
            throw MembershipCredentialError.invalidNameEncoding
        }
        guard name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw MembershipCredentialError.controlCharacterInName
        }

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
    let verifier: (any MembershipSignatureVerifying)?

    init(
        parser: MembershipCredentialParser = MembershipCredentialParser(),
        verifier: (any MembershipSignatureVerifying)? = nil
    ) {
        self.parser = parser
        self.verifier = verifier
    }

    func validate(_ data: Data) -> MembershipVerificationResult {
        do {
            let parsed = try parser.parse(data)
            guard let verifier else { return .trustedKeyUnavailable(keyID: parsed.keyID) }
            guard try verifier.verify(parsed) else { return .rejected("The credential signature is invalid.") }
            guard let name = String(data: parsed.nameBytes, encoding: .utf8) else {
                return .rejected("The verified name could not be decoded.")
            }
            return .verified(VerifiedMembership(name: name, flags: parsed.flags, keyID: parsed.keyID))
        } catch {
            return .rejected(error.localizedDescription)
        }
    }
}
