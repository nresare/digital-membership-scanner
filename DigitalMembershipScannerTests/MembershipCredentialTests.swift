import XCTest
@testable import DigitalMembershipScanner

final class MembershipCredentialTests: XCTestCase {
    private let parser = MembershipCredentialParser()

    func testParsesSpecificationExampleLayout() throws {
        let payload = makeCredential(
            header: 0x29,
            issuanceWord: [0x07, 0x8A],
            identifier: [0x10, 0x92],
            flags: [0x04],
            name: "Alice"
        )
        let parsed = try parser.parse(payload)
        XCTAssertEqual(parsed.version, 1)
        XCTAssertEqual(parsed.issueDay, 241)
        XCTAssertEqual(parsed.memberIdentifier, .number(4242))
        XCTAssertEqual(parsed.flags, [0, 5])
        XCTAssertEqual(parsed.nameBytes, Data("Alice".utf8))
        XCTAssertEqual(parsed.signature.count, 48)
    }

    func testParsesExtendedFlagLength() throws {
        let payload = makeCredential(header: 0x38, flags: [0x00, 0x00, 0x01], name: "A")
        XCTAssertEqual(try parser.parse(payload).flags, [19])
    }

    func testParsesLiveChoirQRNameAtTheDraftPointFiveOffset() throws {
        let parsed = try parser.parse(Self.liveChoirCredential)

        XCTAssertEqual(parsed.issueDay, 241)
        XCTAssertEqual(parsed.memberIdentifier, .none)
        XCTAssertTrue(parsed.flags.isEmpty)
        XCTAssertEqual(parsed.nameBytes, Self.hexData("1a1ad80298"))
    }

    func testParsesTextMemberIdentifier() throws {
        let parsed = try parser.parse(
            makeCredential(
                header: 0x20,
                issuanceWord: [0x00, 0x0F],
                identifier: [0x05] + Array("AB-99".utf8),
                flags: [],
                name: "A"
            )
        )
        XCTAssertEqual(parsed.issueDay, 1)
        XCTAssertEqual(parsed.memberIdentifier, .text("AB-99"))
    }

    func testRejectsNonMinimalNumericIdentifier() {
        XCTAssertThrowsError(
            try parser.parse(
                makeCredential(
                    header: 0x20,
                    issuanceWord: [0x00, 0x0A],
                    identifier: [0x00, 0x01],
                    flags: [],
                    name: "A"
                )
            )
        ) {
            XCTAssertEqual($0 as? MembershipCredentialError, .nonMinimalIdentifier)
        }
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
        let payload = makeCredential(header: 0x38, flags: [0x01], name: "A", extendedFlagLength: 1)
        XCTAssertThrowsError(try parser.parse(payload)) {
            XCTAssertEqual($0 as? MembershipCredentialError, .invalidExtendedFlagLength)
        }
    }

    func testRejectsTrailingZeroFlagByte() {
        let payload = makeCredential(header: 0x30, flags: [0x01, 0x00], name: "A")
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

    func testValidatorDoesNotRevealNameWithoutTrustedIssuer() {
        let result = MembershipCredentialValidator().validate(
            makeCredential(header: 0x20, flags: [], name: "Private Name")
        )
        guard case .trustedIssuerUnavailable = result else {
            return XCTFail("Expected a missing-issuer result")
        }
    }

    func testVerifiesReferenceRustFixture() {
        let result = validator().validate(Self.referenceCredential)
        guard case let .verified(membership) = result else {
            return XCTFail("Expected the Rust fixture to verify")
        }
        XCTAssertEqual(membership.name, "Alice")
        XCTAssertEqual(membership.flags, [0, 5])
        XCTAssertEqual(membership.issueDay, 241)
        XCTAssertEqual(membership.memberIdentifier, .none)
    }

    func testRejectsAlteredSignedPayload() {
        var credential = Self.referenceCredential
        credential[credential.startIndex + 4] = Character("B").asciiValue!

        guard case .rejected = validator().validate(credential) else {
            return XCTFail("Expected the altered credential to be rejected")
        }
    }

    func testRejectsHeaderTampering() {
        var credential = Self.referenceCredential
        credential[credential.startIndex] = 0x2A
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKey: Self.referencePublicKey)

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
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKey: identity)

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            return XCTFail("Expected the identity public key to be rejected")
        }
    }

    func testRejectsWrongLengthTrustedPublicKey() {
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKey: Data(repeating: 0, count: 95))

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            return XCTFail("Expected the wrong-length public key to be rejected")
        }
    }

    private func validator() -> MembershipCredentialValidator {
        MembershipCredentialValidator(
            verifier: BLSTMembershipSignatureVerifier(trustedPublicKey: Self.referencePublicKey),
            nameDecoder: UTF8MembershipNameDecoder()
        )
    }

    // Draft-0.5 signature fixture generated with blst 0.3.17 and fixed IKM 0x42 × 32.
    private static let referencePublicKey = hexData(
        "af36910e3a5b90ad6de8807b56001898196afb6da4d51380249039384450b67d" +
            "b79d58d01ec95b4b8a53b8a3991822e91055cc8480f78958cd7e5a079f13eda7" +
            "a53eb36830b8b9dfbe93c56c390e4d7717e86740fb70d1ae1a41067275f84db4"
    )

    private static let referenceCredential = hexData(
        "29078804416c696365" +
            "987d733c2093ee12d124ea2d9371a2fe8f2394b4a498b96124554b15c21164ce" +
            "46ba3250670f7b7dcbbad3212f9666e2"
    )

    // Downloaded from /api/choir/qr?name=Bo+Smith and decoded with the same ZXing release as the app.
    private static let liveChoirCredential = hexData(
        "2007881a1ad80298b267f76efbf8" +
            "96161bbd6b07e2e5564c807812b9bee252fd723211773233e35149db88712de6" +
            "7cc1389a27ef2f5cf6e0"
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
        func decompressName(_ bytes: Data) throws -> String { name }
    }

    private func makeCredential(
        header: UInt8,
        issuanceWord: [UInt8] = [0x00, 0x00],
        identifier: [UInt8] = [],
        flags: [UInt8],
        name: String,
        extendedFlagLength: UInt8? = nil
    ) -> Data {
        makeCredential(
            header: header,
            issuanceWord: issuanceWord,
            identifier: identifier,
            flags: flags,
            nameBytes: Data(name.utf8),
            extendedFlagLength: extendedFlagLength
        )
    }

    private func makeCredential(
        header: UInt8,
        issuanceWord: [UInt8] = [0x00, 0x00],
        identifier: [UInt8] = [],
        flags: [UInt8],
        nameBytes: Data,
        extendedFlagLength: UInt8? = nil
    ) -> Data {
        var data = Data([header])
        if (header >> 3) & 0b11 == 0b11 { data.append(extendedFlagLength ?? UInt8(flags.count)) }
        data.append(contentsOf: issuanceWord)
        data.append(contentsOf: identifier)
        data.append(contentsOf: flags)
        data.append(nameBytes)
        data.append(Data(repeating: 0x80, count: 48))
        return data
    }
}
