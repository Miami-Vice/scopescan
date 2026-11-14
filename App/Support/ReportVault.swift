import CryptoKit
import Foundation
import Security
import ScopeScanCore

/// Encrypted, on-device storage for scan history.
///
/// Each report is sealed with AES-GCM under a 256-bit key kept in the Keychain
/// as `ThisDeviceOnly`, so it never leaves the phone and is not included in
/// backups. Files are also written with complete file protection, so they are
/// unreadable while the device is locked.
struct ReportVault {
    struct StoredReport: Identifiable, Sendable {
        let id: UUID
        let export: ReportExport
    }

    enum VaultError: Error {
        case keychain(OSStatus)
        case randomness
        case sealFailed
    }

    private static let keychainService = "dev.scopescan.vault"
    private static let keychainAccount = "report-key"

    private let directory: URL

    init() throws {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        directory = support.appendingPathComponent("ScopeScan/Reports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    @discardableResult
    func save(_ export: ReportExport) throws -> UUID {
        let id = UUID()
        let plain = try ReportExporter.json(export)
        let box = try AES.GCM.seal(plain, using: try key())
        guard let combined = box.combined else { throw VaultError.sealFailed }
        try combined.write(to: fileURL(for: id), options: [.atomic, .completeFileProtection])
        return id
    }

    /// Every readable report, newest first. A file that cannot be decrypted is
    /// skipped rather than failing the whole history.
    func loadAll() -> [StoredReport] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        )) ?? []

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let symmetric = try? key() else { return [] }

        return files
            .filter { $0.pathExtension == "sealed" }
            .compactMap { url -> StoredReport? in
                guard let id = UUID(uuidString: url.deletingPathExtension().lastPathComponent),
                      let data = try? Data(contentsOf: url),
                      let box = try? AES.GCM.SealedBox(combined: data),
                      let plain = try? AES.GCM.open(box, using: symmetric),
                      let export = try? decoder.decode(ReportExport.self, from: plain)
                else {
                    return nil
                }
                return StoredReport(id: id, export: export)
            }
            .sorted { $0.export.startedAt > $1.export.startedAt }
    }

    func delete(_ id: UUID) throws {
        try FileManager.default.removeItem(at: fileURL(for: id))
    }

    func deleteAll() throws {
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        for file in files where file.pathExtension == "sealed" {
            try FileManager.default.removeItem(at: file)
        }
    }

    private func fileURL(for id: UUID) -> URL {
        directory.appendingPathComponent("\(id.uuidString).sealed")
    }

    // MARK: - Key

    private func key() throws -> SymmetricKey {
        if let existing = try readKey() {
            return SymmetricKey(data: existing)
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultError.randomness
        }
        let data = Data(bytes)
        try writeKey(data)
        return SymmetricKey(data: data)
    }

    private func readKey() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw VaultError.keychain(status)
        }
        return data
    }

    private func writeKey(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.keychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
    }
}
