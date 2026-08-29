import CXZ
import Foundation

enum NameCompressionError: LocalizedError, Sendable {
    case invalidTable(String)
    case malformedMessage
    case wrongTable
    case unsupportedCompressedTable

    var errorDescription: String? {
        switch self {
        case let .invalidTable(reason): "The name model is invalid: \(reason)."
        case .malformedMessage: "The compressed name is malformed."
        case .wrongTable: "The compressed name does not match its configured model."
        case .unsupportedCompressedTable: "The name model uses an unsupported compression format."
        }
    }
}

struct NameCompressionTable: Sendable {
    static let maximumTableSize = 4 * 1024 * 1024
    private static let xzMagic = Data([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
    private static let zstdMagic = Data([0x28, 0xB5, 0x2F, 0xFD])

    let id: UInt32
    private let checkModulus: UInt32
    private let alphabet: [Unicode.Scalar]
    private let given: Dictionary
    private let surname: Dictionary
    private let characterOrders: [[UInt32: CharacterContext]]

    init(encoded data: Data) throws {
        let rawTable = try Self.rawTable(from: data)
        guard rawTable.count <= Self.maximumTableSize else {
            throw NameCompressionError.invalidTable("it exceeds the 4 MiB size limit")
        }
        var reader = VarintReader(rawTable)
        guard try reader.readBytes(4) == Data("NCMP".utf8) else {
            throw NameCompressionError.invalidTable("missing NCMP magic")
        }
        guard try reader.readUInt16LE() == 1 else {
            throw NameCompressionError.invalidTable("unsupported version")
        }
        let checkModulus = UInt32(try reader.readUInt16LE())
        guard checkModulus > 0 else {
            throw NameCompressionError.invalidTable("zero check modulus")
        }
        let id = try reader.readUInt32LE()
        let alphabet = try Self.readAlphabet(from: &reader)
        let given = try Dictionary(from: &reader)
        let surname = try Dictionary(from: &reader)
        let characterOrders = try Self.readCharacterOrders(from: &reader, symbolCount: alphabet.count + 1)

        self.id = id
        self.checkModulus = checkModulus
        self.alphabet = alphabet
        self.given = given
        self.surname = surname
        self.characterOrders = characterOrders
    }

    func decompress(_ data: Data) throws -> String {
        guard !data.isEmpty else { throw NameCompressionError.malformedMessage }
        var decoder = ArithmeticDecoder(data)
        let name: String
        if try decoder.target(total: 65_536) < 64_500 {
            try decoder.advance(start: 0, size: 64_500, total: 65_536)
            name = try "\(decodeField(&decoder, dictionary: given)) \(decodeField(&decoder, dictionary: surname))"
        } else {
            try decoder.advance(start: 64_500, size: 1_036, total: 65_536)
            let length = Int(try decoder.target(total: 255)) + 1
            try decoder.advance(start: UInt32(length - 1), size: 1, total: 255)
            var bytes = Data()
            bytes.reserveCapacity(length)
            for _ in 0..<length {
                let byte = try decoder.target(total: 256)
                try decoder.advance(start: byte, size: 1, total: 256)
                bytes.append(UInt8(byte))
            }
            guard let decoded = String(data: bytes, encoding: .utf8) else {
                throw NameCompressionError.malformedMessage
            }
            name = decoded
        }

        let checkValue = try decoder.target(total: checkModulus)
        guard Self.checkValue(tableID: id, modulus: checkModulus, name: name) == checkValue else {
            throw NameCompressionError.wrongTable
        }
        return name
    }

    private func decodeField(_ decoder: inout ArithmeticDecoder, dictionary: Dictionary) throws -> String {
        let target = try decoder.target(total: dictionary.scale)
        let symbol = try dictionary.symbol(for: target)
        let range = try dictionary.range(for: symbol)
        try decoder.advance(start: range.start, size: range.size, total: dictionary.scale)

        let canonical: String
        if symbol == dictionary.escapeSymbol {
            var history = [UInt8]()
            while true {
                guard history.count <= 64 else { throw NameCompressionError.malformedMessage }
                let probabilities = try characterDistribution(history: history)
                let target = try decoder.target(total: 65_536)
                var start: UInt32 = 0
                var selected: UInt8?
                for (index, frequency) in probabilities.enumerated() {
                    if target < start + frequency {
                        selected = UInt8(index)
                        try decoder.advance(start: start, size: frequency, total: 65_536)
                        break
                    }
                    start += frequency
                }
                guard let selected else { throw NameCompressionError.malformedMessage }
                if selected == alphabet.count { break }
                history.append(selected)
            }
            canonical = String(String.UnicodeScalarView(history.compactMap { alphabet[safe: Int($0)] }))
            guard canonical.unicodeScalars.count == history.count else { throw NameCompressionError.malformedMessage }
        } else {
            canonical = try dictionary.name(for: symbol)
        }

        let shapeTarget = try decoder.target(total: 65_536)
        let shape: Int
        switch shapeTarget {
        case 0..<61_000: shape = 0
        case 61_000..<63_000: shape = 1
        case 63_000..<64_000: shape = 2
        default: shape = 3
        }
        let shapeRanges: [(UInt32, UInt32)] = [(0, 61_000), (61_000, 2_000), (63_000, 1_000), (64_000, 1_536)]
        try decoder.advance(start: shapeRanges[shape].0, size: shapeRanges[shape].1, total: 65_536)
        return Self.apply(shape: shape, to: canonical)
    }

    private func characterDistribution(history: [UInt8]) throws -> [UInt32] {
        let symbols = alphabet.count + 1
        var probabilities = Array(repeating: Int64(65_536 / symbols), count: symbols)
        for order in 0...min(history.count, 3) {
            let suffix = history.suffix(order)
            let contextKey = suffix.reduce(UInt32(0)) { ($0 << 6) | UInt32($1) }
            guard let context = characterOrders[order][contextKey] else { continue }
            let denominator = Int64(context.total + context.distinct)
            for index in probabilities.indices {
                probabilities[index] = (Int64(context.counts[index]) * 65_536 + Int64(context.distinct) * probabilities[index]) / denominator
            }
            var total: Int64 = 0
            var largest = 0
            for index in probabilities.indices {
                probabilities[index] = max(probabilities[index], 1)
                total += probabilities[index]
                if probabilities[index] > probabilities[largest] { largest = index }
            }
            probabilities[largest] += 65_536 - total
            guard probabilities[largest] > 0 else { throw NameCompressionError.malformedMessage }
        }
        return try probabilities.map {
            guard let value = UInt32(exactly: $0), value > 0 else { throw NameCompressionError.malformedMessage }
            return value
        }
    }

    private static func rawTable(from data: Data) throws -> Data {
        if data.starts(with: xzMagic) {
            var output = Data(repeating: 0, count: maximumTableSize)
            var outputLength = 0
            let result = data.withUnsafeBytes { input in
                output.withUnsafeMutableBytes { destination in
                    xz_decompress_to_buffer(
                        input.bindMemory(to: UInt8.self).baseAddress!, input.count,
                        destination.bindMemory(to: UInt8.self).baseAddress!, destination.count,
                        &outputLength
                    )
                }
            }
            guard result == 0 else { throw NameCompressionError.invalidTable("XZ decompression failed") }
            return Data(output.prefix(outputLength))
        }
        if data.starts(with: zstdMagic) { throw NameCompressionError.unsupportedCompressedTable }
        return data
    }

    private static func readAlphabet(from reader: inout VarintReader) throws -> [Unicode.Scalar] {
        let count = try reader.readVarint()
        guard (1...63).contains(count) else { throw NameCompressionError.invalidTable("alphabet size") }
        var seen = Set<Unicode.Scalar>()
        var alphabet = [Unicode.Scalar]()
        for _ in 0..<count {
            guard let scalarValue = UInt32(exactly: try reader.readVarint()),
                  let scalar = Unicode.Scalar(scalarValue),
                  seen.insert(scalar).inserted
            else {
                throw NameCompressionError.invalidTable("alphabet")
            }
            alphabet.append(scalar)
        }
        return alphabet
    }

    private static func readCharacterOrders(from reader: inout VarintReader, symbolCount: Int) throws -> [[UInt32: CharacterContext]] {
        var orders = [[UInt32: CharacterContext]]()
        for _ in 0...3 {
            let count = try reader.readVarint()
            guard count <= 1_000_000 else { throw NameCompressionError.invalidTable("too many character contexts") }
            var contexts = [UInt32: CharacterContext]()
            var key: UInt32 = 0
            for _ in 0..<count {
                let delta = try reader.readVarint()
                guard delta <= UInt64(UInt32.max - key) else { throw NameCompressionError.invalidTable("character context overflow") }
                key += UInt32(delta)
                let present = try reader.readVarint()
                guard present <= symbolCount else { throw NameCompressionError.invalidTable("character context symbols") }
                var counts = Array(repeating: UInt8(0), count: symbolCount)
                var total: UInt32 = 0
                for _ in 0..<present {
                    let symbol = Int(try reader.readByte())
                    let frequency = try reader.readByte()
                    guard symbol < symbolCount, frequency > 0, counts[symbol] == 0 else {
                        throw NameCompressionError.invalidTable("character frequency")
                    }
                    counts[symbol] = frequency
                    total += UInt32(frequency)
                }
                guard contexts[key] == nil else { throw NameCompressionError.invalidTable("duplicate character context") }
                contexts[key] = CharacterContext(counts: counts, total: total, distinct: UInt32(present))
            }
            orders.append(contexts)
        }
        return orders
    }

    private static func apply(shape: Int, to string: String) -> String {
        switch shape {
        case 0: return string
        case 1: return string.lowercased()
        case 2: return string.uppercased()
        default:
            var output = ""
            var startsRun = true
            for scalar in string.unicodeScalars {
                if scalar.properties.isAlphabetic {
                    output += startsRun ? String(scalar).uppercased() : String(scalar).lowercased()
                    startsRun = false
                } else {
                    output.unicodeScalars.append(scalar)
                    startsRun = true
                }
            }
            return output
        }
    }

    private static func checkValue(tableID: UInt32, modulus: UInt32, name: String) -> UInt32 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in withUnsafeBytes(of: tableID.littleEndian, Array.init) + Array(name.utf8) {
            hash ^= UInt64(byte)
            hash = hash &* 0x00000100000001B3
        }
        return UInt32(hash % UInt64(modulus))
    }
}

private struct Dictionary: Sendable {
    let names: [String]
    let cumulative: [UInt32]
    let scale: UInt32

    var escapeSymbol: Int { names.count }

    init(from reader: inout VarintReader) throws {
        let scale64 = try reader.readVarint()
        let count64 = try reader.readVarint()
        let blobLength64 = try reader.readVarint()
        guard let scale = UInt32(exactly: scale64), (1...16_777_216).contains(scale), count64 < scale64,
              let count = Int(exactly: count64), let blobLength = Int(exactly: blobLength64), blobLength <= NameCompressionTable.maximumTableSize
        else { throw NameCompressionError.invalidTable("dictionary header") }
        let blob = try reader.readBytes(blobLength)
        var position = 0
        var previous = ""
        var names = [String]()
        names.reserveCapacity(count)
        for _ in 0..<count {
            guard position < blob.count else { throw NameCompressionError.invalidTable("dictionary name prefix") }
            let shared = Int(blob[position]); position += 1
            guard shared <= previous.utf8.count else { throw NameCompressionError.invalidTable("dictionary prefix") }
            guard let terminator = blob[position...].firstIndex(of: 0),
                  let suffix = String(data: blob[position..<terminator], encoding: .utf8),
                  let prefix = String(data: Data(previous.utf8.prefix(shared)), encoding: .utf8)
            else { throw NameCompressionError.invalidTable("dictionary name") }
            let name = prefix + suffix
            names.append(name); previous = name; position = terminator + 1
        }
        guard position == blob.count else { throw NameCompressionError.invalidTable("dictionary blob trailing bytes") }
        var cumulative = [UInt32](); cumulative.reserveCapacity(count + 2)
        var running: UInt32 = 0
        for _ in 0...count {
            cumulative.append(running)
            let frequency = try reader.readVarint()
            guard let value = UInt32(exactly: frequency), value > 0, running <= scale - value else {
                throw NameCompressionError.invalidTable("dictionary frequencies")
            }
            running += value
        }
        cumulative.append(running)
        guard running == scale else { throw NameCompressionError.invalidTable("dictionary frequency total") }
        self.names = names; self.cumulative = cumulative; self.scale = scale
    }

    func symbol(for target: UInt32) throws -> Int {
        guard target < scale else { throw NameCompressionError.malformedMessage }
        for index in stride(from: cumulative.count - 2, through: 0, by: -1) where cumulative[index] <= target { return index }
        throw NameCompressionError.malformedMessage
    }

    func range(for symbol: Int) throws -> (start: UInt32, size: UInt32) {
        guard cumulative.indices.contains(symbol + 1) else { throw NameCompressionError.malformedMessage }
        return (cumulative[symbol], cumulative[symbol + 1] - cumulative[symbol])
    }

    func name(for symbol: Int) throws -> String {
        guard names.indices.contains(symbol) else { throw NameCompressionError.malformedMessage }
        return names[symbol]
    }
}

private struct CharacterContext: Sendable { let counts: [UInt8]; let total: UInt32; let distinct: UInt32 }

private struct VarintReader {
    let data: Data
    var position = 0
    init(_ data: Data) { self.data = data }
    mutating func readByte() throws -> UInt8 {
        guard position < data.count else { throw NameCompressionError.invalidTable("truncated data") }
        defer { position += 1 }; return data[position]
    }
    mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, position <= data.count - count else { throw NameCompressionError.invalidTable("truncated data") }
        defer { position += count }; return Data(data[position..<(position + count)])
    }
    mutating func readVarint() throws -> UInt64 {
        var value: UInt64 = 0; var shift: UInt64 = 0
        for _ in 0..<10 {
            let byte = try readByte()
            guard shift < 64 else { throw NameCompressionError.invalidTable("varint") }
            value |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return value }
            shift += 7
        }
        throw NameCompressionError.invalidTable("varint")
    }
    mutating func readUInt16LE() throws -> UInt16 { let b = try readBytes(2); return UInt16(b[b.startIndex]) | UInt16(b[b.startIndex + 1]) << 8 }
    mutating func readUInt32LE() throws -> UInt32 { let b = try readBytes(4); return UInt32(b[b.startIndex]) | UInt32(b[b.startIndex + 1]) << 8 | UInt32(b[b.startIndex + 2]) << 16 | UInt32(b[b.startIndex + 3]) << 24 }
}

private struct ArithmeticDecoder {
    private var low: UInt64 = 0
    private var high: UInt64 = (1 << 32) - 1
    private var value: UInt64 = 0
    private let bytes: Data
    private var bitPosition = 0
    init(_ bytes: Data) { self.bytes = bytes; for _ in 0..<32 { value = (value << 1) | nextBit() } }
    mutating func target(total: UInt32) throws -> UInt32 {
        let range = high - low + 1
        guard value >= low else { throw NameCompressionError.malformedMessage }
        return UInt32(((value - low + 1) * UInt64(total) - 1) / range)
    }
    mutating func advance(start: UInt32, size: UInt32, total: UInt32) throws {
        guard size > 0, start <= total - size, total <= 16_777_216 else { throw NameCompressionError.malformedMessage }
        let range = high - low + 1
        high = low + range * UInt64(start + size) / UInt64(total) - 1
        low += range * UInt64(start) / UInt64(total)
        while true {
            if high < 1 << 31 { } else if low >= 1 << 31 { value -= 1 << 31; low -= 1 << 31; high -= 1 << 31
            } else if low >= 1 << 30, high < 3 << 30 { value -= 1 << 30; low -= 1 << 30; high -= 1 << 30
            } else { break }
            low <<= 1; high = (high << 1) | 1; value = (value << 1) | nextBit()
        }
    }
    private mutating func nextBit() -> UInt64 { defer { bitPosition += 1 }; guard bitPosition / 8 < bytes.count else { return 0 }; return UInt64((bytes[bytes.startIndex + bitPosition / 8] >> (7 - bitPosition % 8)) & 1) }
}

private extension Collection { subscript(safe index: Index) -> Element? { indices.contains(index) ? self[index] : nil } }
