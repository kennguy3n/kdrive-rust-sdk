import Foundation
import SwiftUI

@MainActor
final class DriveViewModel: ObservableObject {
    @Published var keyOutput: String = ""
    @Published var plaintext: String = "Hello from iOS + UniFFI!"
    @Published var roundTripResult: String?
    @Published var vectorsOutput: String?

    func generateDek() {
        let dek = generateVersionDek()
        keyOutput = "Version DEK: \(dek)\n"
    }

    func generateEd25519() {
        let kp = generateEd25519Keypair()
        keyOutput += "Ed25519 priv: \(kp.privateKeyHex)\n"
        keyOutput += "Ed25519 pub:  \(kp.publicKeyHex)\n"
    }

    func generateHpke() {
        let kp = generateHpkeKeypair()
        keyOutput += "HPKE priv: \(kp.privateKeyHex)\n"
        keyOutput += "HPKE pub:  \(kp.publicKeyHex)\n"
    }

    func roundTrip() {
        do {
            let dek = generateVersionDek()
            let nodeId = randomIdHex()
            let versionId = randomIdHex()
            let driveId = randomIdHex()
            let domainId = randomIdHex()
            let snapshotHash = String(repeating: "0", count: 64)

            let plaintextData = Data(plaintext.utf8)

            let enc = try encryptFile(
                versionDekHex: dek,
                nodeIdHex: nodeId,
                versionIdHex: versionId,
                driveIdHex: driveId,
                domainIdHex: domainId,
                accessContextRevision: 1,
                accessContextSnapshotHashHex: snapshotHash,
                plaintext: plaintextData
            )

            let dec = try decryptFile(
                versionDekHex: dek,
                nodeIdHex: nodeId,
                versionIdHex: versionId,
                driveIdHex: driveId,
                domainIdHex: domainId,
                accessContextRevision: 1,
                accessContextSnapshotHashHex: snapshotHash,
                manifestCiphertextHex: enc.manifestCiphertextHex,
                manifestNonceHex: enc.manifestNonceHex,
                ciphertextsHex: enc.ciphertextsHex
            )

            let decrypted = String(data: dec.plaintext, encoding: .utf8) ?? "<binary>"
            let ok = decrypted == plaintext

            roundTripResult = """
            Version DEK:  \(dek.prefix(32))…
            Node ID:      \(nodeId)
            Chunk root:   \(enc.chunkPlanRootHex)
            Chunk count:  \(enc.chunkCount)
            Ciphertexts:  \(enc.ciphertextsHex.count) chunk(s)
            Decrypted:    \(decrypted)
            Match:        \(ok ? "YES" : "NO")
            """
        } catch {
            roundTripResult = "Error: \(error)"
        }
    }

    func fetchVectors() {
        let json = getTestVectorsJson()
        if let data = json.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let protocolName = parsed["protocol"] as? String,
           let version = parsed["version"] as? Int {
            vectorsOutput = "Protocol: \(protocolName)\nVersion: \(version)\n\n\(json.prefix(500))…"
        } else {
            vectorsOutput = json.prefix(500) + "…"
        }
    }
}
