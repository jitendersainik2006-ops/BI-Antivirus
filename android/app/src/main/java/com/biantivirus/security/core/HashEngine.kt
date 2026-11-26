package com.biantivirus.security.core

import java.io.InputStream
import java.security.MessageDigest

data class HashResult(
    val sha256: String,
    val md5: String,
    val bytesProcessed: Long
)

object HashEngine {

    private const val BUFFER_SIZE = 64 * 1024 // 64 KB memory-safe streaming buffer

    fun calculateHashes(inputStream: InputStream): HashResult {
        val digestSha256 = MessageDigest.getInstance("SHA-256")
        val digestMd5 = MessageDigest.getInstance("MD5")

        val buffer = ByteArray(BUFFER_SIZE)
        var totalBytes = 0L
        var bytesRead: Int

        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            digestSha256.update(buffer, 0, bytesRead)
            digestMd5.update(buffer, 0, bytesRead)
            totalBytes += bytesRead
        }

        val sha256Hex = bytesToHex(digestSha256.digest())
        val md5Hex = bytesToHex(digestMd5.digest())

        return HashResult(
            sha256 = sha256Hex,
            md5 = md5Hex,
            bytesProcessed = totalBytes
        )
    }

    fun calculateSha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return bytesToHex(digest.digest(bytes))
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b.toInt() and 0xFF))
        }
        return sb.toString()
    }
}
