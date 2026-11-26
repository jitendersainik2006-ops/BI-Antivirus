package com.biantivirus.security.core

data class FileTypeAnalysis(
    val detectedMimeType: String,
    val declaredExtension: String,
    val isConsistent: Boolean,
    val isSpoofed: Boolean,
    val details: String
)

object FileTypeChecker {

    // Common magic byte headers
    private val MAGIC_PK_ZIP = byteArrayOf(0x50.toByte(), 0x4B.toByte(), 0x03.toByte(), 0x04.toByte())
    private val MAGIC_ELF = byteArrayOf(0x7F.toByte(), 0x45.toByte(), 0x4C.toByte(), 0x46.toByte())
    private val MAGIC_PDF = byteArrayOf(0x25.toByte(), 0x50.toByte(), 0x44.toByte(), 0x46.toByte())
    private val MAGIC_PNG = byteArrayOf(0x89.toByte(), 0x50.toByte(), 0x4E.toByte(), 0x47.toByte(), 0x0D.toByte(), 0x0A.toByte(), 0x1A.toByte(), 0x0A.toByte())
    private val MAGIC_JPEG = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte())
    private val MAGIC_DEX = byteArrayOf(0x64.toByte(), 0x65.toByte(), 0x78.toByte(), 0x0A.toByte())

    private fun startsWith(data: ByteArray, magic: ByteArray): Boolean {
        if (data.size < magic.size) return false
        for (i in magic.indices) {
            if (data[i] != magic[i]) return false
        }
        return true
    }

    fun analyze(fileName: String, headerBytes: ByteArray): FileTypeAnalysis {
        val extension = fileName.substringAfterLast('.', "").lowercase()

        val detectedType = when {
            startsWith(headerBytes, MAGIC_DEX) -> "application/vnd.android.dex"
            startsWith(headerBytes, MAGIC_PK_ZIP) -> "application/zip" // Includes APK, JAR, ZIP
            startsWith(headerBytes, MAGIC_ELF) -> "application/x-elf"
            startsWith(headerBytes, MAGIC_PDF) -> "application/pdf"
            startsWith(headerBytes, MAGIC_PNG) -> "image/png"
            startsWith(headerBytes, MAGIC_JPEG) -> "image/jpeg"
            else -> "application/octet-stream"
        }

        // Check for extension spoofing
        val isSpoofed = when {
            // Executable / package disguised as benign document or image
            (detectedType == "application/zip" || detectedType == "application/vnd.android.dex" || detectedType == "application/x-elf") &&
                    (extension in listOf("jpg", "jpeg", "png", "gif", "pdf", "txt", "doc", "docx")) -> true
            // Benign image disguised as apk/dex
            (detectedType == "image/png" || detectedType == "image/jpeg") &&
                    (extension in listOf("apk", "dex", "so", "elf")) -> true
            else -> false
        }

        val isConsistent = !isSpoofed

        val details = when {
            isSpoofed -> "CRITICAL: File header identifies as $detectedType but extension declares .$extension (Spoofed Extension Attack)."
            detectedType == "application/octet-stream" -> "Generic binary payload or plaintext document."
            else -> "File header signature matches declared extension .$extension."
        }

        return FileTypeAnalysis(
            detectedMimeType = detectedType,
            declaredExtension = extension,
            isConsistent = isConsistent,
            isSpoofed = isSpoofed,
            details = details
        )
    }
}
