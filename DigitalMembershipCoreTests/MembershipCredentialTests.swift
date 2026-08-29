import Foundation
import Testing
@testable import DigitalMembershipCore

@Suite("Digital Membership credential parser")
struct MembershipCredentialTests {
    private let parser = MembershipCredentialParser()

    @Test func parsesSpecificationExampleLayout() throws {
        let parsed = try parser.parse(makeCredential(header: 0x29, flags: [0x21], name: "Alice"))
        #expect(parsed.version == 1)
        #expect(parsed.keyID == 2)
        #expect(parsed.flags == [0, 5])
        #expect(parsed.nameBytes == Data("Alice".utf8))
        #expect(parsed.signature.count == 48)
    }

    @Test func parsesExtendedFlagLength() throws {
        let parsed = try parser.parse(makeCredential(header: 0x23, flags: [0x01, 0x00, 0x80], name: "A"))
        #expect(parsed.flags == [0, 23])
    }

    @Test func rejectsShortCredential() {
        #expect(throws: MembershipCredentialError.tooShort) {
            try parser.parse(Data(repeating: 0, count: 49))
        }
    }

    @Test func rejectsUnsupportedVersion() {
        #expect(throws: MembershipCredentialError.unsupportedVersion(2)) {
            try parser.parse(makeCredential(header: 0x40, flags: [], name: "A"))
        }
    }

    @Test func rejectsNonMinimalExtendedFlagLength() {
        #expect(throws: MembershipCredentialError.invalidExtendedFlagLength) {
            try parser.parse(makeCredential(header: 0x23, flags: [0x01, 0x01], name: "A"))
        }
    }

    @Test func rejectsTrailingZeroFlagByte() {
        #expect(throws: MembershipCredentialError.nonMinimalFlags) {
            try parser.parse(makeCredential(header: 0x22, flags: [0x01, 0x00], name: "A"))
        }
    }

    @Test func rejectsControlCharacterInName() {
        #expect(throws: MembershipCredentialError.controlCharacterInName) {
            try parser.parse(makeCredential(header: 0x20, flags: [], nameBytes: Data([0x41, 0x0A])))
        }
    }

    @Test func validatorDoesNotRevealNameWithoutTrustedKey() {
        let result = MembershipCredentialValidator().validate(
            makeCredential(header: 0x20, flags: [], name: "Private Name")
        )
        guard case .trustedKeyUnavailable(keyID: 0) = result else {
            Issue.record("Expected a missing-key result")
            return
        }
    }

    @Test func verifiesReferenceRustFixture() {
        let result = validator().validate(Self.referenceCredential)
        guard case let .verified(membership) = result else {
            Issue.record("Expected the Rust fixture to verify")
            return
        }
        #expect(membership.name == "Alice")
        #expect(membership.flags == [0, 5])
        #expect(membership.keyID == 2)
    }

    @Test func rejectsAlteredSignedPayload() {
        var credential = Self.referenceCredential
        credential[credential.startIndex + 2] = Character("B").asciiValue!

        guard case .rejected = validator().validate(credential) else {
            Issue.record("Expected the altered credential to be rejected")
            return
        }
    }

    @Test func rejectsKeyIDTamperingEvenWhenKeyBytesAreReused() {
        var credential = Self.referenceCredential
        credential[credential.startIndex] = 0x2D
        let verifier = BLSTMembershipSignatureVerifier(
            trustedPublicKeys: [2: Self.referencePublicKey, 3: Self.referencePublicKey]
        )

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(credential) else {
            Issue.record("Expected the altered key ID to invalidate the signature")
            return
        }
    }

    @Test func rejectsIdentitySignature() {
        var credential = Data(Self.referenceCredential.dropLast(MembershipCredentialParser.signatureLength))
        credential.append(0xC0)
        credential.append(Data(repeating: 0, count: MembershipCredentialParser.signatureLength - 1))

        guard case .rejected = validator().validate(credential) else {
            Issue.record("Expected the identity signature to be rejected")
            return
        }
    }

    @Test func rejectsMalformedSignaturePoint() {
        var credential = Data(Self.referenceCredential.dropLast(MembershipCredentialParser.signatureLength))
        credential.append(Data(repeating: 0xFF, count: MembershipCredentialParser.signatureLength))

        guard case .rejected = validator().validate(credential) else {
            Issue.record("Expected the malformed signature point to be rejected")
            return
        }
    }

    @Test func rejectsIdentityTrustedPublicKey() {
        var identity = Data([0xC0])
        identity.append(Data(repeating: 0, count: BLSTMembershipSignatureVerifier.publicKeyLength - 1))
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKeys: [2: identity])

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            Issue.record("Expected the identity public key to be rejected")
            return
        }
    }

    @Test func rejectsWrongLengthTrustedPublicKey() {
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKeys: [2: Data(repeating: 0, count: 95)])

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            Issue.record("Expected the wrong-length public key to be rejected")
            return
        }
    }

    private func validator() -> MembershipCredentialValidator {
        MembershipCredentialValidator(
            verifier: BLSTMembershipSignatureVerifier(trustedPublicKeys: [2: Self.referencePublicKey])
        )
    }

    // Generated by digital-membership's Rust encoder path using blst 0.3.17 and fixed IKM 0x42 × 32.
    private static let referencePublicKey = hexData(
        "af36910e3a5b90ad6de8807b56001898196afb6da4d51380249039384450b67d" +
            "b79d58d01ec95b4b8a53b8a3991822e91055cc8480f78958cd7e5a079f13eda7" +
            "a53eb36830b8b9dfbe93c56c390e4d7717e86740fb70d1ae1a41067275f84db4"
    )

    private static let referenceCredential = hexData(
        "2921416c696365" +
            "97e0ff4ce838ddfe96c92f7e4f84bc84475bbe718c856f9a248f29a6fe8a82fd" +
            "eec852b4b7f7aee8b0f36d65ba1ecb86"
    )

    private static func hexData(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        })
    }

    private func makeCredential(header: UInt8, flags: [UInt8], name: String) -> Data {
        makeCredential(header: header, flags: flags, nameBytes: Data(name.utf8))
    }

    private func makeCredential(header: UInt8, flags: [UInt8], nameBytes: Data) -> Data {
        var data = Data([header])
        if header & 0b11 == 0b11 { data.append(UInt8(flags.count)) }
        data.append(contentsOf: flags)
        data.append(nameBytes)
        data.append(Data(repeating: 0x80, count: 48))
        return data
    }
}
