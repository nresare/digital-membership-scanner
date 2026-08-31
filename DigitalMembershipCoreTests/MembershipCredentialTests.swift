import Foundation
import Testing
@testable import DigitalMembershipCore

@Suite("Digital Membership credential parser")
struct MembershipCredentialTests {
    private let parser = MembershipCredentialParser()

    @Test func parsesSpecificationExampleLayout() throws {
        let parsed = try parser.parse(
            makeCredential(
                header: 0x29,
                issuanceWord: [0x07, 0x8A],
                identifier: [0x10, 0x92],
                flags: [0x04],
                name: "Alice"
            )
        )
        #expect(parsed.version == 1)
        #expect(parsed.issueDay == 241)
        #expect(parsed.memberIdentifier == .number(4242))
        #expect(parsed.flags == [0, 5])
        #expect(parsed.nameBytes == Data("Alice".utf8))
        #expect(parsed.signature.count == 48)
    }

    @Test func parsesExtendedFlagLength() throws {
        let parsed = try parser.parse(makeCredential(header: 0x38, flags: [0x00, 0x00, 0x01], name: "A"))
        #expect(parsed.flags == [19])
    }

    @Test func parsesLiveChoirQRNameAtTheDraftPointFiveOffset() throws {
        let parsed = try parser.parse(Self.liveChoirCredential)

        #expect(parsed.issueDay == 241)
        #expect(parsed.memberIdentifier == .none)
        #expect(parsed.flags.isEmpty)
        #expect(parsed.nameBytes == Self.hexData("1a1ad80298"))
    }

    @Test func parsesTextMemberIdentifier() throws {
        let parsed = try parser.parse(
            makeCredential(
                header: 0x20,
                issuanceWord: [0x00, 0x0F],
                identifier: [0x05] + Array("AB-99".utf8),
                flags: [],
                name: "A"
            )
        )
        #expect(parsed.issueDay == 1)
        #expect(parsed.memberIdentifier == .text("AB-99"))
    }

    @Test func rejectsNonMinimalNumericIdentifier() {
        #expect(throws: MembershipCredentialError.nonMinimalIdentifier) {
            try parser.parse(
                makeCredential(
                    header: 0x20,
                    issuanceWord: [0x00, 0x0A],
                    identifier: [0x00, 0x01],
                    flags: [],
                    name: "A"
                )
            )
        }
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
            try parser.parse(makeCredential(header: 0x38, flags: [0x01], name: "A", extendedFlagLength: 1))
        }
    }

    @Test func rejectsTrailingZeroFlagByte() {
        #expect(throws: MembershipCredentialError.nonMinimalFlags) {
            try parser.parse(makeCredential(header: 0x30, flags: [0x01, 0x00], name: "A"))
        }
    }

    @Test func rejectsControlCharacterInDecodedName() {
        let validator = MembershipCredentialValidator(
            verifier: AlwaysValidSignatureVerifier(),
            nameDecoder: FixedNameDecoder(name: "A\n")
        )
        guard case .rejected = validator.validate(makeCredential(header: 0x20, flags: [], name: "encoded")) else {
            Issue.record("Expected the decoded control character to be rejected")
            return
        }
    }

    @Test func validatorDoesNotRevealNameWithoutTrustedIssuer() {
        let result = MembershipCredentialValidator().validate(
            makeCredential(header: 0x20, flags: [], name: "Private Name")
        )
        guard case .trustedIssuerUnavailable = result else {
            Issue.record("Expected a missing-issuer result")
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
        #expect(membership.issueDay == 241)
        #expect(membership.memberIdentifier == .none)
    }

    @Test func rejectsAlteredSignedPayload() {
        var credential = Self.referenceCredential
        credential[credential.startIndex + 4] = Character("B").asciiValue!

        guard case .rejected = validator().validate(credential) else {
            Issue.record("Expected the altered credential to be rejected")
            return
        }
    }

    @Test func rejectsHeaderTampering() {
        var credential = Self.referenceCredential
        credential[credential.startIndex] = 0x2A
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKey: Self.referencePublicKey)

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
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKey: identity)

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            Issue.record("Expected the identity public key to be rejected")
            return
        }
    }

    @Test func rejectsWrongLengthTrustedPublicKey() {
        let verifier = BLSTMembershipSignatureVerifier(trustedPublicKey: Data(repeating: 0, count: 95))

        guard case .rejected = MembershipCredentialValidator(verifier: verifier).validate(Self.referenceCredential)
        else {
            Issue.record("Expected the wrong-length public key to be rejected")
            return
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

@Suite("Issuer setup discovery")
struct IssuerSetupTests {
    @Test func decodesSetupAndResolvesProvisioningURL() throws {
        let response = try JSONDecoder().decode(
            IssuerSetupResponse.self,
            from: Data(
                #"{"issuers":[{"id":"choir","name":"Example Choir Society","provision_url":"/api/choir/provision"},{"id":"fairer","name":"Make Southwark fairer","description":"We change local politics","provision_url":"/api/fairer/provision"}]}"#.utf8
            )
        )

        #expect(response.issuers.count == 2)
        #expect(response.issuers[0].id == "choir")
        #expect(response.issuers[0].name == "Example Choir Society")
        #expect(response.issuers[0].description == nil)
        #expect(response.issuers[1].description == "We change local politics")
        #expect(
            try response.issuers[0].provisioningEndpoint(relativeTo: #require(URL(string: "https://dm.noa.re/setup")))
                == URL(string: "https://dm.noa.re/api/choir/provision")
        )
    }

    @Test func rejectsNonHTTPProvisioningURL() throws {
        let issuer = SetupIssuer(
            id: "choir",
            name: "Example Choir",
            description: "A friendly community choir.",
            provisionURL: "file:///tmp/key"
        )
        let setupURL = try #require(URL(string: "https://dm.noa.re/setup"))

        #expect(throws: IssuerProvisioningError.invalidProvisioningURL) {
            try issuer.provisioningEndpoint(relativeTo: setupURL)
        }
    }

    @Test func rejectsProvisioningURLOnAnotherOrigin() throws {
        let issuer = SetupIssuer(
            id: "choir",
            name: "Example Choir",
            description: "A friendly community choir.",
            provisionURL: "https://example.com/api/choir/provision"
        )
        let setupURL = try #require(URL(string: "https://dm.noa.re/setup"))

        #expect(throws: IssuerProvisioningError.invalidProvisioningURL) {
            try issuer.provisioningEndpoint(relativeTo: setupURL)
        }
    }

    @Test func decodesLiveIssuerPresentationMetadataAndFlagLabels() throws {
        let response = try JSONDecoder().decode(
            IssuerProvisioningResponse.self,
            from: Data(
                #"{"algorithm":"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_","id":"choir","name":"Example Choir Society","name_model_id":3638818724,"name_model_url":"/api/choir/model/model.ncmp.xz","public_key":"abc","flags":["Sheet music group","Party planners"]}"#.utf8
            )
        )

        #expect(response.id == "choir")
        #expect(response.name == "Example Choir Society")
        #expect(response.description == nil)
        #expect(response.flags == ["Sheet music group", "Party planners"])
    }

    @Test func reportsThePathOfAMissingRequiredField() {
        #expect(
            throws: IssuerProvisioningError.invalidResponse(
                "The setup service response is missing required field “issuers[0].name”."
            )
        ) {
            try IssuerResponseDecoder.decode(
                IssuerSetupResponse.self,
                from: Data(
                    #"{"issuers":[{"id":"choir","provision_url":"/api/choir/provision"}]}"#.utf8
                ),
                responseName: "setup service"
            )
        }
    }

    @Test func resolvesOnlyNonEmptyFlagLabels() {
        let profile = IssuerProfile(
            id: "choir",
            name: "Example Choir",
            description: "A friendly community choir.",
            flagLabels: ["member", "", "party planners"]
        )

        #expect(profile.label(for: 0) == "member")
        #expect(profile.label(for: 1) == nil)
        #expect(profile.label(for: 2) == "party planners")
        #expect(profile.label(for: 3) == nil)
    }
}
