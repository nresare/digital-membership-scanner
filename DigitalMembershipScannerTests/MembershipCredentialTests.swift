import XCTest
@testable import DigitalMembershipScanner

final class MembershipCredentialTests: XCTestCase {
    private let parser = MembershipCredentialParser()

    func testParsesSpecificationExampleLayout() throws {
        let payload = makeCredential(header: 0x29, flags: [0x21], name: "Alice")
        let parsed = try parser.parse(payload)
        XCTAssertEqual(parsed.version, 1)
        XCTAssertEqual(parsed.keyID, 2)
        XCTAssertEqual(parsed.flags, [0, 5])
        XCTAssertEqual(parsed.nameBytes, Data("Alice".utf8))
        XCTAssertEqual(parsed.signature.count, 48)
    }

    func testParsesExtendedFlagLength() throws {
        let payload = makeCredential(header: 0x23, flags: [0x01, 0x00, 0x80], name: "A")
        XCTAssertEqual(try parser.parse(payload).flags, [0, 23])
    }

    func testRejectsShortCredential() {
        XCTAssertThrowsError(try parser.parse(Data(repeating: 0, count: 49))) {
            XCTAssertEqual($0 as? MembershipCredentialError, .tooShort)
        }
    }

    func testRejectsUnsupportedVersion() {
        let payload = makeCredential(header: 0x40, flags: [], name: "A")
        XCTAssertThrowsError(try parser.parse(payload)) {
            XCTAssertEqual($0 as? MembershipCredentialError, .unsupportedVersion(2))
        }
    }

    func testRejectsNonMinimalExtendedFlagLength() {
        let payload = makeCredential(header: 0x23, flags: [0x01, 0x01], name: "A")
        XCTAssertThrowsError(try parser.parse(payload)) {
            XCTAssertEqual($0 as? MembershipCredentialError, .invalidExtendedFlagLength)
        }
    }

    func testRejectsTrailingZeroFlagByte() {
        let payload = makeCredential(header: 0x22, flags: [0x01, 0x00], name: "A")
        XCTAssertThrowsError(try parser.parse(payload)) {
            XCTAssertEqual($0 as? MembershipCredentialError, .nonMinimalFlags)
        }
    }

    func testRejectsControlCharacterInDecodedName() {
        let validator = MembershipCredentialValidator(
            verifier: AlwaysValidSignatureVerifier(),
            nameDecoder: FixedNameDecoder(name: "A\n")
        )
        guard case .rejected = validator.validate(makeCredential(header: 0x20, flags: [], name: "encoded")) else {
            return XCTFail("Expected the decoded control character to be rejected")
        }
    }

    func testValidatorDoesNotRevealNameWithoutTrustedKey() {
        let result = MembershipCredentialValidator().validate(
            makeCredential(header: 0x20, flags: [], name: "Private Name")
        )
        guard case .trustedKeyUnavailable(keyID: 0) = result else {
            return XCTFail("Expected a missing-key result")
        }
    }

    func testVerifiesReferenceRustFixture() {
        let result = validator().validate(Self.referenceCredential)
        guard case let .verified(membership) = result else {
            return XCTFail("Expected the Rust fixture to verify")
        }
        XCTAssertEqual(membership.name, "Alice")
        XCTAssertEqual(membership.flags, [0, 5])
        XCTAssertEqual(membership.keyID, 2)
    }

    func testRejectsAlteredSignedPayload() {
        var credential = Self.referenceCredential
        credential[credential.startIndex + 2] = Character("B").asciiValue!

        guard case .rejected = validator().validate(credential) else {
            return XCTFail("Expected the altered credential to be rejected")
        }
    }

    func testRejectsKeyIDTamperingEvenWhenKeyBytesAreReused() {
        var credential = Self.referenceCredential
        credential[credential.startIndex] = 0x2D
        let verifier = BLSTMembershipSignatureVerifier(
            trustedPublicKeys: [2: Self.referencePublicKey, 3: Self.referencePublicKey]
        )

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(credential) else {
            return XCTFail("Expected the altered key ID to invalidate the signature")
        }
    }

    func testRejectsIdentitySignature() {
        var credential = Data(Self.referenceCredential.dropLast(MembershipCredentialParser.signatureLength))
        credential.append(0xC0)
        credential.append(Data(repeating: 0, count: MembershipCredentialParser.signatureLength - 1))

        guard case .rejected = validator().validate(credential) else {
            return XCTFail("Expected the identity signature to be rejected")
        }
    }

    func testRejectsMalformedSignaturePoint() {
        var credential = Data(Self.referenceCredential.dropLast(MembershipCredentialParser.signatureLength))
        credential.append(Data(repeating: 0xFF, count: MembershipCredentialParser.signatureLength))

        guard case .rejected = validator().validate(credential) else {
            return XCTFail("Expected the malformed signature point to be rejected")
        }
    }

    func testRejectsIdentityTrustedPublicKey() {
        var identity = Data([0xC0])
        identity.append(Data(repeating: 0, count: BLSTMembershipSignatureVerifier.publicKeyLength - 1))
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKeys: [2: identity])

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            return XCTFail("Expected the identity public key to be rejected")
        }
    }

    func testRejectsWrongLengthTrustedPublicKey() {
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKeys: [2: Data(repeating: 0, count: 95)])

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            return XCTFail("Expected the wrong-length public key to be rejected")
        }
    }

    private func validator() -> MembershipCredentialValidator {
        MembershipCredentialValidator(
            verifier: BLSTMembershipSignatureVerifier(trustedPublicKeys: [2: Self.referencePublicKey]),
            nameDecoder: UTF8MembershipNameDecoder()
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

    private struct AlwaysValidSignatureVerifier: MembershipSignatureVerifying {
        func verify(_ credential: ParsedMembershipCredential) throws -> Bool { true }
    }

    private struct FixedNameDecoder: MembershipNameDecoding {
        let name: String
        func decompressName(_ bytes: Data, keyID: UInt8) throws -> String { name }
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
