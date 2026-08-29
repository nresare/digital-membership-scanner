import Combine
import Foundation

enum IssuerProvisioningError: LocalizedError, Equatable {
    case invalidURL
    case unsupportedAlgorithm(String)
    case invalidKeyID(Int)
    case invalidPublicKey
    case invalidModelURL
    case unexpectedResponse
    case invalidModelID

    var errorDescription: String? {
        switch self {
        case .invalidURL: "Enter a valid HTTP or HTTPS provisioning URL."
        case let .unsupportedAlgorithm(algorithm): "Unsupported signature algorithm: \(algorithm)."
        case let .invalidKeyID(keyID): "The issuer supplied an invalid key ID (\(keyID))."
        case .invalidPublicKey: "The issuer supplied an invalid BLS public key."
        case .invalidModelURL: "The issuer supplied an invalid name-model URL."
        case .unexpectedResponse: "The issuer server returned an unexpected response."
        case .invalidModelID: "The downloaded name model does not match the issuer response."
        }
    }
}

struct IssuerProvisioningResponse: Decodable, Sendable {
    let algorithm: String
    let keyID: Int
    let nameModelID: UInt32
    let nameModelURL: String
    let publicKey: String

    enum CodingKeys: String, CodingKey {
        case algorithm
        case keyID = "key_id"
        case nameModelID = "name_model_id"
        case nameModelURL = "name_model_url"
        case publicKey = "public_key"
    }

    func validatedConfiguration(modelData: Data) throws -> IssuerConfiguration {
        guard algorithm == String(decoding: BLSTMembershipSignatureVerifier.ciphersuite, as: UTF8.self) else {
            throw IssuerProvisioningError.unsupportedAlgorithm(algorithm)
        }
        guard let keyID = UInt8(exactly: keyID), keyID <= 7 else {
            throw IssuerProvisioningError.invalidKeyID(keyID)
        }
        guard let publicKey = Data(base64URLEncoded: publicKey),
              BLSTMembershipSignatureVerifier.isValidTrustedPublicKey(publicKey)
        else { throw IssuerProvisioningError.invalidPublicKey }

        let table = try NameCompressionTable(encoded: modelData)
        guard table.id == nameModelID else { throw IssuerProvisioningError.invalidModelID }
        return IssuerConfiguration(keyID: keyID, publicKey: publicKey, model: table)
    }
}

struct IssuerConfiguration: Sendable {
    let keyID: UInt8
    let publicKey: Data
    let model: NameCompressionTable
}

@MainActor
final class IssuerTrustStore: ObservableObject {
    @Published private(set) var configuration: IssuerConfiguration?
    @Published private(set) var provisioningError: String?

    private let defaults: UserDefaults
    private let fileManager: FileManager
    private let storageDirectory: URL
    private static let metadataKey = "provisionedIssuer"

    init(defaults: UserDefaults = .standard, fileManager: FileManager = .default) {
        self.defaults = defaults
        self.fileManager = fileManager
        storageDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("DigitalMembershipScanner", isDirectory: true)
        configuration = Self.loadConfiguration(defaults: defaults, fileManager: fileManager, directory: storageDirectory)
    }

    var isConfigured: Bool { configuration != nil }

    func validator() -> MembershipCredentialValidator {
        guard let configuration else { return MembershipCredentialValidator() }
        return MembershipCredentialValidator(
            verifier: BLSTMembershipSignatureVerifier(trustedPublicKeys: [configuration.keyID: configuration.publicKey]),
            nameDecoder: NameCompressionMembershipNameDecoder(models: [configuration.keyID: configuration.model])
        )
    }

    func provision(from input: String) async {
        do {
            guard let endpoint = URL(string: input),
                  let scheme = endpoint.scheme?.lowercased(), ["http", "https"].contains(scheme)
            else { throw IssuerProvisioningError.invalidURL }

            let (responseData, response) = try await URLSession.shared.data(from: endpoint)
            guard let httpResponse = response as? HTTPURLResponse,
                  (200..<300).contains(httpResponse.statusCode)
            else { throw IssuerProvisioningError.unexpectedResponse }
            let issuer = try JSONDecoder().decode(IssuerProvisioningResponse.self, from: responseData)
            guard let modelURL = URL(string: issuer.nameModelURL, relativeTo: endpoint)?.absoluteURL else {
                throw IssuerProvisioningError.invalidModelURL
            }
            let (modelData, modelResponse) = try await URLSession.shared.data(from: modelURL)
            guard let modelHTTPResponse = modelResponse as? HTTPURLResponse,
                  (200..<300).contains(modelHTTPResponse.statusCode)
            else { throw IssuerProvisioningError.unexpectedResponse }

            let configuration = try issuer.validatedConfiguration(modelData: modelData)
            try save(configuration, modelData: modelData, sourceURL: endpoint)
            self.configuration = configuration
            provisioningError = nil
        } catch {
            provisioningError = error.localizedDescription
        }
    }

    private func save(_ configuration: IssuerConfiguration, modelData: Data, sourceURL: URL) throws {
        try fileManager.createDirectory(at: storageDirectory, withIntermediateDirectories: true)
        let modelFile = "name-model-\(configuration.keyID).ncmp"
        try modelData.write(to: storageDirectory.appendingPathComponent(modelFile), options: .atomic)
        let metadata = StoredIssuer(
            sourceURL: sourceURL.absoluteString,
            keyID: configuration.keyID,
            publicKey: configuration.publicKey,
            modelID: configuration.model.id,
            modelFile: modelFile
        )
        defaults.set(try JSONEncoder().encode(metadata), forKey: Self.metadataKey)
    }

    private static func loadConfiguration(defaults: UserDefaults, fileManager: FileManager, directory: URL) -> IssuerConfiguration? {
        guard let metadataData = defaults.data(forKey: metadataKey),
              let metadata = try? JSONDecoder().decode(StoredIssuer.self, from: metadataData),
              let modelData = try? Data(contentsOf: directory.appendingPathComponent(metadata.modelFile)),
              BLSTMembershipSignatureVerifier.isValidTrustedPublicKey(metadata.publicKey),
              let model = try? NameCompressionTable(encoded: modelData),
              model.id == metadata.modelID
        else { return nil }
        return IssuerConfiguration(keyID: metadata.keyID, publicKey: metadata.publicKey, model: model)
    }
}

private struct StoredIssuer: Codable {
    let sourceURL: String
    let keyID: UInt8
    let publicKey: Data
    let modelID: UInt32
    let modelFile: String
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64.append(contentsOf: String(repeating: "=", count: (4 - base64.count % 4) % 4))
        self.init(base64Encoded: base64)
    }
}
