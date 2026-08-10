import SwiftUI

struct ContentView: View {
    @StateObject private var vm = DriveViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    headerCard
                    keyGenCard
                    encryptDecryptCard
                    vectorsCard
                }
                .padding()
            }
            .navigationTitle("KChat Drive")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("iOS Sample (UniFFI)")
                .font(.headline)
            Text("Rust crypto core via UniFFI bindings")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }

    private var keyGenCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("1. Key Generation")
                .font(.headline)

            Button("Generate Version DEK") { vm.generateDek() }
                .buttonStyle(.borderedProminent)

            Button("Generate Ed25519 Keypair") { vm.generateEd25519() }
                .buttonStyle(.bordered)

            Button("Generate HPKE Keypair") { vm.generateHpke() }
                .buttonStyle(.bordered)

            if !vm.keyOutput.isEmpty {
                Text(vm.keyOutput)
                    .font(.system(.caption, design: .monospaced))
                    .padding(8)
                    .background(Color(.tertiarySystemBackground))
                    .cornerRadius(8)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }

    private var encryptDecryptCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("2. Encrypt / Decrypt Round-Trip")
                .font(.headline)

            TextField("Plaintext", text: $vm.plaintext)
                .textFieldStyle(.roundedBorder)

            Button("Encrypt + Decrypt") { vm.roundTrip() }
                .buttonStyle(.borderedProminent)
                .disabled(vm.plaintext.isEmpty)

            if let result = vm.roundTripResult {
                Text(result)
                    .font(.system(.caption, design: .monospaced))
                    .padding(8)
                    .background(Color(.tertiarySystemBackground))
                    .cornerRadius(8)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }

    private var vectorsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("3. Cross-Language Test Vectors")
                .font(.headline)

            Button("Fetch Vectors") { vm.fetchVectors() }
                .buttonStyle(.bordered)

            if let vectors = vm.vectorsOutput {
                Text(vectors)
                    .font(.system(.caption, design: .monospaced))
                    .padding(8)
                    .background(Color(.tertiarySystemBackground))
                    .cornerRadius(8)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }
}
