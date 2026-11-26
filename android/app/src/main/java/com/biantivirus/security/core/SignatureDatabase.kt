package com.biantivirus.security.core

import android.content.Context
import com.biantivirus.security.model.ThreatSeverity
import com.biantivirus.security.model.ThreatSignature
import org.json.JSONObject
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap

class SignatureDatabase(private val context: Context? = null) {

    private val sha256Index = ConcurrentHashMap<String, ThreatSignature>()
    private val md5Index = ConcurrentHashMap<String, ThreatSignature>()

    init {
        // Built-in foundational test signatures
        seedDefaultSignatures()
    }

    private fun seedDefaultSignatures() {
        val eicar = ThreatSignature(
            id = "SIG-MOB-001",
            name = "EICAR-Standard-AV-Test-File",
            family = "TestVirus",
            severity = ThreatSeverity.CRITICAL,
            sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            md5 = "44d88612fea8a8f36de82e1278abb02f",
            description = "Industry standard European Institute for Computer Antivirus Research harmless test sample."
        )
        addSignature(eicar)

        val fakebank = ThreatSignature(
            id = "SIG-MOB-002",
            name = "Android.Trojan.FakeBank.A",
            family = "Trojan",
            severity = ThreatSeverity.CRITICAL,
            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            md5 = "d41d8cd98f00b204e9800998ecf8427e",
            description = "Simulated banking credential phishing dropper."
        )
        addSignature(fakebank)

        val pegasus = ThreatSignature(
            id = "SIG-MOB-003",
            name = "Android.Spyware.PegasusSim.Test",
            family = "Spyware",
            severity = ThreatSeverity.CRITICAL,
            sha256 = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            md5 = "ef597f63c5c766360ee718795b00f417",
            description = "Simulated surveillance spyware payload test vector."
        )
        addSignature(pegasus)

        val hiddenads = ThreatSignature(
            id = "SIG-MOB-004",
            name = "Mobile.Adware.HiddenAds.B",
            family = "Adware",
            severity = ThreatSeverity.MEDIUM,
            sha256 = "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
            md5 = "c4ca4238a0b923820dcc509a6f75849b",
            description = "Aggressive background advertising and click-fraud payload."
        )
        addSignature(hiddenads)

        val simplocker = ThreatSignature(
            id = "SIG-MOB-005",
            name = "Android.Ransomware.Simplocker.Sim",
            family = "Ransomware",
            severity = ThreatSeverity.CRITICAL,
            sha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            md5 = "900150983cd24fb0d6963f7d28e17f72",
            description = "Simulated mobile file encrypting extortion Trojan."
        )
        addSignature(simplocker)

        val iosConfig = ThreatSignature(
            id = "SIG-MOB-006",
            name = "iOS.Phishing.ConfigProfile.Dropper",
            family = "Trojan",
            severity = ThreatSeverity.HIGH,
            sha256 = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
            md5 = "b10a8db164e0754105b7a99be72e3fe5",
            description = "Malicious mobile configuration profile payload."
        )
        addSignature(iosConfig)
    }

    fun addSignature(sig: ThreatSignature) {
        if (sig.sha256.isNotBlank()) {
            sha256Index[sig.sha256.lowercase()] = sig
        }
        if (sig.md5.isNotBlank()) {
            md5Index[sig.md5.lowercase()] = sig
        }
    }

    fun loadSignatures(): Int {
        if (context == null) return getSignatureCount()

        try {
            val assetManager = context.assets
            val inputStream: InputStream = assetManager.open("mobile_threat_signatures.json")
            val jsonText = inputStream.bufferedReader().use { it.readText() }
            val root = JSONObject(jsonText)
            val signaturesArray = root.optJSONArray("signatures")

            if (signaturesArray != null) {
                for (i in 0 until signaturesArray.length()) {
                    val obj = signaturesArray.getJSONObject(i)
                    val sig = ThreatSignature(
                        id = obj.getString("id"),
                        name = obj.getString("name"),
                        family = obj.optString("family", "Unknown"),
                        severity = try {
                            ThreatSeverity.valueOf(obj.optString("severity", "MEDIUM"))
                        } catch (e: Exception) {
                            ThreatSeverity.MEDIUM
                        },
                        sha256 = obj.optString("sha256", ""),
                        md5 = obj.optString("md5", ""),
                        description = obj.optString("description", "")
                    )
                    addSignature(sig)
                }
            }
        } catch (e: Exception) {
            // Assets not found or running in pure unit test without Android context; seed defaults are retained.
        }

        return getSignatureCount()
    }

    fun findBySha256(hash: String): ThreatSignature? {
        return sha256Index[hash.lowercase()]
    }

    fun findByMd5(hash: String): ThreatSignature? {
        return md5Index[hash.lowercase()]
    }

    fun getSignatureCount(): Int {
        return sha256Index.size
    }
}
