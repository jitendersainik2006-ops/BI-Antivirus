package com.biantivirus.security.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class QuarantineStatus {
    QUARANTINED,
    RESTORED,
    DELETED
}

sealed class RestoreResult {
    data class Success(val restoredFile: File, val sha256: String) : RestoreResult()
    data class TamperDetected(val reason: String) : RestoreResult()
    data class DestinationExists(val path: String) : RestoreResult()
    data class RecordNotFound(val id: String) : RestoreResult()
    data class Error(val message: String) : RestoreResult()
}

data class QuarantineRecord(
    val id: String,
    val originalFileName: String,
    val originalPath: String,
    val quarantinedTimestamp: Long,
    val sha256: String,
    val threatName: String,
    val vaultFilePath: String,
    val fileSize: Long,
    var status: QuarantineStatus = QuarantineStatus.QUARANTINED,
    var restoredTimestamp: Long? = null
)

/**
 * Hardened Quarantine Vault utilizing Authenticated Encryption (AES-GCM with 256-bit key and 12-byte unique nonces).
 * Guarantees confidentiality, authenticity, and tamper detection for quarantined files.
 */
class QuarantineManager(private val baseDirectory: File) {

    constructor(context: Context) : this(File(context.filesDir, "quarantine"))

    private val quarantineDir: File = baseDirectory.apply {
        if (!exists()) {
            mkdirs()
        }
    }

    private val ledgerFile: File = File(quarantineDir, "quarantine_ledger.json")
    private val keyFile: File = File(quarantineDir, "vault_master.key")

    private val secureRandom = SecureRandom()
    private val records = mutableListOf<QuarantineRecord>()
    private val vaultSecretKey: SecretKey by lazy { getOrCreateVaultKey() }

    companion object {
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val GCM_NONCE_LENGTH_BYTES = 12
        private val VAULT_MAGIC_HEADER = "BI_AES_GCM_V1\n".toByteArray(Charsets.US_ASCII)
    }

    init {
        loadLedger()
    }

    @Synchronized
    private fun getOrCreateVaultKey(): SecretKey {
        if (keyFile.exists() && keyFile.length() == 32L) {
            val keyBytes = keyFile.readBytes()
            return SecretKeySpec(keyBytes, "AES")
        }
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, secureRandom)
        val key = keyGen.generateKey()
        FileOutputStream(keyFile).use { it.write(key.encoded) }
        return key
    }

    @Synchronized
    private fun loadLedger() {
        records.clear()
        if (!ledgerFile.exists()) return

        try {
            val content = ledgerFile.readText(Charsets.UTF_8)
            val jsonArray = JSONArray(content)
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                records.add(
                    QuarantineRecord(
                        id = obj.getString("id"),
                        originalFileName = obj.getString("originalFileName"),
                        originalPath = obj.getString("originalPath"),
                        quarantinedTimestamp = obj.getLong("quarantinedTimestamp"),
                        sha256 = obj.getString("sha256"),
                        threatName = obj.getString("threatName"),
                        vaultFilePath = obj.getString("vaultFilePath"),
                        fileSize = obj.getLong("fileSize"),
                        status = QuarantineStatus.valueOf(obj.optString("status", QuarantineStatus.QUARANTINED.name)),
                        restoredTimestamp = if (obj.has("restoredTimestamp") && !obj.isNull("restoredTimestamp")) obj.getLong("restoredTimestamp") else null
                    )
                )
            }
        } catch (_: Exception) {
            // Ledger fallback
        }
    }

    @Synchronized
    private fun saveLedger() {
        val jsonArray = JSONArray()
        for (r in records) {
            val obj = JSONObject()
            obj.put("id", r.id)
            obj.put("originalFileName", r.originalFileName)
            obj.put("originalPath", r.originalPath)
            obj.put("quarantinedTimestamp", r.quarantinedTimestamp)
            obj.put("sha256", r.sha256)
            obj.put("threatName", r.threatName)
            obj.put("vaultFilePath", r.vaultFilePath)
            obj.put("fileSize", r.fileSize)
            obj.put("status", r.status.name)
            obj.put("restoredTimestamp", r.restoredTimestamp ?: JSONObject.NULL)
            jsonArray.put(obj)
        }
        ledgerFile.writeText(jsonArray.toString(2), Charsets.UTF_8)
    }

    private fun computeSha256(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data)
        return hash.joinToString("") { "%02x".format(it) }
    }

    @Synchronized
    fun quarantineBytes(
        fileName: String,
        originalPath: String,
        bytes: ByteArray,
        threatName: String,
        sha256: String
    ): QuarantineRecord {
        val id = "Q-" + UUID.randomUUID().toString().substring(0, 8).uppercase()
        val vaultFile = File(quarantineDir, "$id.biq")

        // 1. Generate unique 12-byte nonce for this specific encryption operation
        val nonce = ByteArray(GCM_NONCE_LENGTH_BYTES)
        secureRandom.nextBytes(nonce)

        // 2. Encrypt with AES-GCM (Authenticated Encryption with Associated Data)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, vaultSecretKey, spec)
        cipher.updateAAD(id.toByteArray(Charsets.UTF_8)) // Authenticate the Quarantine ID as AAD
        val cipherTextWithTag = cipher.doFinal(bytes)

        // 3. Write vault file atomically: Header + Nonce + CipherText/Tag
        val tempVaultFile = File(quarantineDir, "$id.tmp")
        FileOutputStream(tempVaultFile).use { out ->
            out.write(VAULT_MAGIC_HEADER)
            out.write(nonce)
            out.write(cipherTextWithTag)
        }
        tempVaultFile.renameTo(vaultFile)

        val record = QuarantineRecord(
            id = id,
            originalFileName = fileName,
            originalPath = originalPath,
            quarantinedTimestamp = System.currentTimeMillis(),
            sha256 = sha256.lowercase(),
            threatName = threatName,
            vaultFilePath = vaultFile.absolutePath,
            fileSize = bytes.size.toLong(),
            status = QuarantineStatus.QUARANTINED
        )

        records.add(record)
        saveLedger()
        return record
    }

    @Synchronized
    fun restoreQuarantinedFile(
        id: String,
        targetDirectory: File,
        allowOverwrite: Boolean = false
    ): RestoreResult {
        val record = records.find { it.id == id } ?: return RestoreResult.RecordNotFound(id)
        val vaultFile = File(record.vaultFilePath)

        if (!vaultFile.exists()) {
            return RestoreResult.Error("Vault file missing: ${record.vaultFilePath}")
        }

        val fileBytes = FileInputStream(vaultFile).use { it.readBytes() }
        val headerLen = VAULT_MAGIC_HEADER.size
        val nonceLen = GCM_NONCE_LENGTH_BYTES

        if (fileBytes.size < headerLen + nonceLen + 16) {
            return RestoreResult.TamperDetected("Vault file truncated or malformed.")
        }

        // Validate Header
        for (i in VAULT_MAGIC_HEADER.indices) {
            if (fileBytes[i] != VAULT_MAGIC_HEADER[i]) {
                return RestoreResult.TamperDetected("Invalid vault file magic header.")
            }
        }

        // Extract Nonce and CipherText
        val nonce = fileBytes.copyOfRange(headerLen, headerLen + nonceLen)
        val cipherTextWithTag = fileBytes.copyOfRange(headerLen + nonceLen, fileBytes.size)

        // Authenticated Decryption
        val plainBytes: ByteArray
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)
            cipher.init(Cipher.DECRYPT_MODE, vaultSecretKey, spec)
            cipher.updateAAD(id.toByteArray(Charsets.UTF_8))
            plainBytes = cipher.doFinal(cipherTextWithTag)
        } catch (e: Exception) {
            return RestoreResult.TamperDetected("Authenticated decryption failed: data or authentication tag modified. (${e.javaClass.simpleName})")
        }

        // Integrity verification: Check unmasked hash matches quarantined hash
        val calculatedSha256 = computeSha256(plainBytes).lowercase()
        if (calculatedSha256 != record.sha256.lowercase()) {
            return RestoreResult.TamperDetected(
                "Cryptographic SHA-256 digest failure: expected ${record.sha256} but payload computed $calculatedSha256"
            )
        }

        // Overwrite protection check
        if (!targetDirectory.exists()) {
            targetDirectory.mkdirs()
        }
        val targetFile = File(targetDirectory, record.originalFileName)
        if (targetFile.exists() && !allowOverwrite) {
            return RestoreResult.DestinationExists(targetFile.absolutePath)
        }

        // Atomic write via temp file
        val tempRestoreFile = File(targetDirectory, ".restoring_${UUID.randomUUID()}.tmp")
        FileOutputStream(tempRestoreFile).use { it.write(plainBytes) }
        if (targetFile.exists() && allowOverwrite) {
            targetFile.delete()
        }
        tempRestoreFile.renameTo(targetFile)

        // Update record status
        record.status = QuarantineStatus.RESTORED
        record.restoredTimestamp = System.currentTimeMillis()
        saveLedger()

        return RestoreResult.Success(targetFile, calculatedSha256)
    }

    @Synchronized
    fun listQuarantinedItems(): List<File> {
        return quarantineDir.listFiles { file -> file.isFile && file.extension == "biq" }?.toList() ?: emptyList()
    }

    @Synchronized
    fun deleteQuarantinedItem(identifier: String): Boolean {
        val record = records.find { it.id == identifier || it.vaultFilePath == identifier || it.id == File(identifier).nameWithoutExtension }
        val targetFile = if (record != null) File(record.vaultFilePath) else File(identifier)
        val deleted = if (targetFile.exists() && (targetFile.parentFile == quarantineDir || targetFile.canonicalPath.startsWith(quarantineDir.canonicalPath))) {
            targetFile.delete()
        } else {
            true
        }

        if (record != null) {
            record.status = QuarantineStatus.DELETED
            saveLedger()
        }
        return deleted
    }

    @Synchronized
    fun deleteQuarantinedFile(file: File): Boolean {
        return deleteQuarantinedItem(file.absolutePath)
    }

    @Synchronized
    fun getQuarantineHistory(): List<QuarantineRecord> {
        return records.toList()
    }

    @Synchronized
    fun getActiveQuarantinedItems(): List<QuarantineRecord> {
        return records.filter { it.status == QuarantineStatus.QUARANTINED }
    }
}
