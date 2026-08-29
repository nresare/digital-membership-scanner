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
