package ai.kchat.drive.sample

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import uniffi.kchat_drive_uniffi.*

class MainActivity : AppCompatActivity() {

    private lateinit var outputText: TextView
    private lateinit var plaintextInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        outputText = findViewById(R.id.output)
        plaintextInput = findViewById(R.id.plaintext)

        findViewById<Button>(R.id.btn_dek).setOnClickListener {
            appendOutput("Version DEK: ${generateVersionDek()}\n")
        }

        findViewById<Button>(R.id.btn_ed25519).setOnClickListener {
            val kp = generateEd25519Keypair()
            appendOutput("Ed25519 priv: ${kp.privateKeyHex}\n")
            appendOutput("Ed25519 pub:  ${kp.publicKeyHex}\n")
        }

        findViewById<Button>(R.id.btn_hpke).setOnClickListener {
            val kp = generateHpkeKeypair()
            appendOutput("HPKE priv: ${kp.privateKeyHex}\n")
            appendOutput("HPKE pub:  ${kp.publicKeyHex}\n")
        }

        findViewById<Button>(R.id.btn_roundtrip).setOnClickListener {
            runRoundTrip()
        }

        findViewById<Button>(R.id.btn_vectors).setOnClickListener {
            val json = getTestVectorsJson()
            appendOutput("Test vectors: ${json.take(200)}…\n")
        }
    }

    private fun runRoundTrip() {
        try {
            val dek = generateVersionDek()
            val nodeId = randomIdHex()
            val versionId = randomIdHex()
            val driveId = randomIdHex()
            val domainId = randomIdHex()
            val snapshotHash = "0".repeat(64)
            val plaintext = plaintextInput.text.toString().toByteArray()

            val enc = encryptFile(
                versionDekHex = dek,
                nodeIdHex = nodeId,
                versionIdHex = versionId,
                driveIdHex = driveId,
                domainIdHex = domainId,
                accessContextRevision = 1u,
                accessContextSnapshotHashHex = snapshotHash,
                plaintext = plaintext,
            )

            val dec = decryptFile(
                versionDekHex = dek,
                nodeIdHex = nodeId,
                versionIdHex = versionId,
                driveIdHex = driveId,
                domainIdHex = domainId,
                accessContextRevision = 1u,
                accessContextSnapshotHashHex = snapshotHash,
                manifestCiphertextHex = enc.manifestCiphertextHex,
                manifestNonceHex = enc.manifestNonceHex,
                ciphertextsHex = enc.ciphertextsHex,
            )

            val decrypted = String(dec.plaintext)
            val ok = decrypted == plaintextInput.text.toString()

            appendOutput("--- Round-Trip ---\n")
            appendOutput("Chunk root:  ${enc.chunkPlanRootHex}\n")
            appendOutput("Chunk count: ${enc.chunkCount}\n")
            appendOutput("Decrypted:   $decrypted\n")
            appendOutput("Match:       ${if (ok) "YES" else "NO"}\n")
        } catch (e: Exception) {
            appendOutput("Error: $e\n")
        }
    }

    private fun appendOutput(text: String) {
        outputText.append(text)
        findViewById<ScrollView>(R.id.scroll).fullScroll(ScrollView.FOCUS_DOWN)
    }
}
