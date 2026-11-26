package com.biantivirus.security.model

data class QuarantineItem(
    val id: String,
    val originalFileName: String,
    val originalPath: String,
    val quarantinedTimestamp: Long = System.currentTimeMillis(),
    val sha256: String,
    val threatName: String,
    val encryptedVaultPath: String,
    val fileSize: Long
)
