package com.biantivirus.security.model

enum class CheckStatus {
    PASS,
    WARN,
    FAIL,
    NOT_APPLICABLE
}

data class PostureCheckItem(
    val checkId: String,
    val name: String,
    val category: String,
    val status: CheckStatus,
    val details: String,
    val recommendation: String
)

data class DevicePosture(
    val reportId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val deviceModel: String,
    val osVersion: String,
    val overallScore: Int,
    val statusText: String,
    val checks: List<PostureCheckItem>
)
