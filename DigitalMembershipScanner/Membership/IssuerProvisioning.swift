import Combine
import Foundation

enum IssuerProvisioningError: LocalizedError, Equatable {
    case invalidURL
    case invalidSetupURL
    case invalidProvisioningURL
    case unsupportedAlgorithm(String)
    case invalidPublicKey
    case invalidModelURL
    case invalidResponse(String)
    case invalidModelID

    var errorDescription: String? {
        switch self {
        case .invalidURL: "Enter a valid HTTP or HTTPS provisioning URL."
        case .invalidSetupURL: "Enter a valid HTTP or HTTPS setup URL."
        case .invalidProvisioningURL: "The setup response contains an invalid provisioning URL."
        case let .unsupportedAlgorithm(algorithm): "Unsupported signature algorithm: \(algorithm)."
        case .invalidPublicKey: "The issuer supplied an invalid BLS public key."
        case .invalidModelURL: "The issuer supplied an invalid name-model URL."
        case let .invalidResponse(message): message
        case .invalidModelID: "The downloaded name model does not match the issuer response."
        }
    }
}

struct IssuerSetupResponse: Decodable, Equatable, Sendable {
    let issuers: [SetupIssuer]
}

struct SetupIssuer: Decodable, Equatable, Identifiable, Sendable {
    let id: String
    let name: String
    let description: String?
    let provisionURL: String

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case description
        case provisionURL = "provision_url"
    }

    func provisioningEndpoint(relativeTo setupURL: URL) throws -> URL {
        guard let reference = URL(string: provisionURL),
              reference.scheme == nil,
              reference.host == nil,
              let endpoint = URL(string: provisionURL, relativeTo: setupURL)?.absoluteURL,
              let scheme = endpoint.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              endpoint.host != nil
        else { throw IssuerProvisioningError.invalidProvisioningURL }
        return endpoint
    }
}

struct IssuerProvisioningResponse: Decodable, Sendable {
    let algorithm: String
    let id: String
    let name: String
    let description: String?
    let nameModelID: UInt32
    let nameModelURL: String
    let publicKey: String
    let flags: [String]

    enum CodingKeys: String, CodingKey {
        case algorithm
        case id
        case name
        case description
        case nameModelID = "name_model_id"
        case nameModelURL = "name_model_url"
        case publicKey = "public_key"
        case flags
    }

    func validatedConfiguration(modelData: Data) throws -> IssuerConfiguration {
        guard algorithm == String(decoding: BLSTMembershipSignatureVerifier.ciphersuite, as: UTF8.self) else {
            throw IssuerProvisioningError.unsupportedAlgorithm(algorithm)
        }
        guard let publicKey = Data(base64URLEncoded: publicKey),
              BLSTMembershipSignatureVerifier.isValidTrustedPublicKey(publicKey)
        else { throw IssuerProvisioningError.invalidPublicKey }

        let table = try NameCompressionTable(encoded: modelData)
        guard table.id == nameModelID else { throw IssuerProvisioningError.invalidModelID }
        return IssuerConfiguration(
            publicKey: publicKey,
            model: table,
            issuer: IssuerProfile(id: id, name: name, description: description ?? "", flagLabels: flags)
        )
    }
}

struct IssuerProfile: Codable, Equatable, Sendable {
    let id: String
    let name: String
    let description: String
    let flagLabels: [String]

    func label(for flag: Int) -> String? {
        guard flagLabels.indices.contains(flag), !flagLabels[flag].isEmpty else { return nil }
        return flagLabels[flag]
    }
}

struct IssuerConfiguration: Sendable {
    let publicKey: Data
    let model: NameCompressionTable
    let issuer: IssuerProfile
}

@MainActor
final class IssuerTrustStore: ObservableObject {
    static let defaultSetupURL = "https://dm.noa.re/setup"

    @Published private(set) var configuration: IssuerConfiguration?
    @Published private(set) var availableIssuers: [SetupIssuer] = []
    @Published private(set) var setupError: String?
    @Published private(set) var provisioningError: String?

    private let defaults: UserDefaults
    private let fileManager: FileManager
    private let storageDirectory: URL
    private var setupURL: URL?
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
            verifier: BLSTMembershipSignatureVerifier(trustedPublicKey: configuration.publicKey),
            nameDecoder: NameCompressionMembershipNameDecoder(model: configuration.model)
        )
    }

    func discoverIssuers(from input: String) async {
        availableIssuers = []
        setupError = nil
        provisioningError = nil

        do {
            guard let endpoint = Self.httpURL(from: input) else {
                throw IssuerProvisioningError.invalidSetupURL
            }
            let (responseData, response) = try await URLSession.shared.data(from: endpoint)
            try Self.validate(response, from: "setup service")
            let setup = try IssuerResponseDecoder.decode(
                IssuerSetupResponse.self,
                from: responseData,
                responseName: "setup service"
            )
            for issuer in setup.issuers {
                _ = try issuer.provisioningEndpoint(relativeTo: endpoint)
            }
            setupURL = endpoint
            availableIssuers = setup.issuers
        } catch {
            setupURL = nil
            setupError = error.localizedDescription
        }
    }

    func provision(_ issuer: SetupIssuer) async {
        do {
            guard let setupURL else { throw IssuerProvisioningError.invalidSetupURL }
            try await provision(from: issuer.provisioningEndpoint(relativeTo: setupURL))
        } catch {
            provisioningError = error.localizedDescription
        }
    }

    func provision(from input: String) async {
        do {
            guard let endpoint = Self.httpURL(from: input)
            else { throw IssuerProvisioningError.invalidURL }

            try await provision(from: endpoint)
        } catch {
            provisioningError = error.localizedDescription
        }
    }

    private func provision(from endpoint: URL) async throws {
        provisioningError = nil

        let (responseData, response) = try await URLSession.shared.data(from: endpoint)
        try Self.validate(response, from: "issuer provisioning endpoint")
        let issuer = try IssuerResponseDecoder.decode(
            IssuerProvisioningResponse.self,
            from: responseData,
            responseName: "issuer provisioning endpoint"
        )
        guard let modelURL = URL(string: issuer.nameModelURL, relativeTo: endpoint)?.absoluteURL else {
            throw IssuerProvisioningError.invalidModelURL
        }
        let (modelData, modelResponse) = try await URLSession.shared.data(from: modelURL)
        try Self.validate(modelResponse, from: "issuer name-model endpoint")

        let configuration = try issuer.validatedConfiguration(modelData: modelData)
        try save(configuration, modelData: modelData, sourceURL: endpoint)
        self.configuration = configuration
        provisioningError = nil
    }

    private func save(_ configuration: IssuerConfiguration, modelData: Data, sourceURL: URL) throws {
        try fileManager.createDirectory(at: storageDirectory, withIntermediateDirectories: true)
        let modelFile = "name-model-\(configuration.model.id).ncmp"
        try modelData.write(to: storageDirectory.appendingPathComponent(modelFile), options: .atomic)
        let metadata = StoredIssuer(
            sourceURL: sourceURL.absoluteString,
            publicKey: configuration.publicKey,
            modelID: configuration.model.id,
            modelFile: modelFile,
            issuer: configuration.issuer
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
        return IssuerConfiguration(publicKey: metadata.publicKey, model: model, issuer: metadata.issuer)
    }

    private static func httpURL(from input: String) -> URL? {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil
        else { return nil }
        return url
    }

    private static func validate(_ response: URLResponse, from responseName: String) throws {
        guard let httpResponse = response as? HTTPURLResponse else {
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) did not return an HTTP response."
            )
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) returned HTTP \(httpResponse.statusCode)."
            )
        }
    }
}

enum IssuerResponseDecoder {
    static func decode<Response: Decodable>(
        _ type: Response.Type,
        from data: Data,
        responseName: String
    ) throws -> Response {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let DecodingError.keyNotFound(key, context) {
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) response is missing required field “\(path(context.codingPath, appending: key))”."
            )
        } catch let DecodingError.valueNotFound(type, context) {
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) response contains null at “\(path(context.codingPath))”; expected \(typeName(type))."
            )
        } catch let DecodingError.typeMismatch(type, context) {
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) response has the wrong type at “\(path(context.codingPath))”; expected \(typeName(type))."
            )
        } catch let DecodingError.dataCorrupted(context) {
            let location = path(context.codingPath)
            let suffix = location.isEmpty ? "" : " at “\(location)”"
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) response contains invalid data\(suffix): \(context.debugDescription)"
            )
        } catch {
            throw IssuerProvisioningError.invalidResponse(
                "The \(responseName) response could not be decoded: \(error.localizedDescription)"
            )
        }
    }

    private static func path(_ codingPath: [any CodingKey], appending key: (any CodingKey)? = nil) -> String {
        (codingPath + [key].compactMap { $0 }).reduce(into: "") { result, component in
            if let index = component.intValue {
                result += "[\(index)]"
            } else {
                if !result.isEmpty { result += "." }
                result += component.stringValue
            }
        }
    }

    private static func typeName(_ type: Any.Type) -> String {
        switch type {
        case is String.Type: "a string"
        case is Int.Type: "an integer"
        default: String(describing: type)
        }
    }
}

private struct StoredIssuer: Codable {
    let sourceURL: String
    let publicKey: Data
    let modelID: UInt32
    let modelFile: String
    let issuer: IssuerProfile
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64.append(contentsOf: String(repeating: "=", count: (4 - base64.count % 4) % 4))
        self.init(base64Encoded: base64)
    }
}
