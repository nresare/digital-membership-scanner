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

    func testRejectsControlCharacterInName() {
        let payload = makeCredential(header: 0x20, flags: [], nameBytes: Data([0x41, 0x0A]))
        XCTAssertThrowsError(try parser.parse(payload)) {
            XCTAssertEqual($0 as? MembershipCredentialError, .controlCharacterInName)
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
