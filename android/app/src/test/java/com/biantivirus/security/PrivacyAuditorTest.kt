package com.biantivirus.security

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import com.biantivirus.security.core.PrivacyAuditor
import com.biantivirus.security.core.PrivacyRiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacyAuditorTest {

    private val auditor = PrivacyAuditor(context = null)

    @Test
    fun testCleanPackageHasLowRisk() {
        val pkg = PackageInfo().apply {
            packageName = "com.clean.tools"
            versionName = "1.0.0"
            applicationInfo = ApplicationInfo().apply { flags = 0 }
            requestedPermissions = arrayOf("android.permission.INTERNET", "android.permission.VIBRATE")
        }

        val profile = auditor.evaluatePackage(pkg)
        assertEquals(PrivacyRiskLevel.LOW, profile.riskLevel)
        assertEquals(0, profile.riskScore)
        assertTrue(profile.sensitivePermissions.isEmpty())
    }

    @Test
    fun testCriticalPackageWithAccessibilityAndOverlay() {
        val pkg = PackageInfo().apply {
            packageName = "com.highrisk.app"
            versionName = "1.0.0"
            applicationInfo = ApplicationInfo().apply { flags = 0 }
            requestedPermissions = arrayOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE", // 30 pts
                "android.permission.SYSTEM_ALERT_WINDOW"        // 20 pts -> total 50 pts
            )
        }

        val profile = auditor.evaluatePackage(pkg)
        assertEquals(PrivacyRiskLevel.CRITICAL, profile.riskLevel)
        assertEquals(50, profile.riskScore)
        assertEquals(2, profile.sensitivePermissions.size)
    }

    @Test
    fun testSurveillancePackageWithCameraAndMicrophone() {
        val pkg = PackageInfo().apply {
            packageName = "com.recorder.app"
            versionName = "1.0.0"
            applicationInfo = ApplicationInfo().apply { flags = 0 }
            requestedPermissions = arrayOf(
                "android.permission.CAMERA",         // 15 pts
                "android.permission.RECORD_AUDIO"    // 15 pts -> total 30 pts
            )
        }

        val profile = auditor.evaluatePackage(pkg)
        assertEquals(PrivacyRiskLevel.HIGH, profile.riskLevel)
        assertEquals(30, profile.riskScore)
        assertEquals(2, profile.sensitivePermissions.size)
    }

    @Test
    fun testSensitivePermissionsCatalogCompleteness() {
        assertTrue(PrivacyAuditor.SENSITIVE_PERMISSIONS_CATALOG.containsKey("android.permission.BIND_ACCESSIBILITY_SERVICE"))
        assertTrue(PrivacyAuditor.SENSITIVE_PERMISSIONS_CATALOG.containsKey("android.permission.SYSTEM_ALERT_WINDOW"))
        assertTrue(PrivacyAuditor.SENSITIVE_PERMISSIONS_CATALOG.containsKey("android.permission.REQUEST_INSTALL_PACKAGES"))
        assertTrue(PrivacyAuditor.SENSITIVE_PERMISSIONS_CATALOG.containsKey("android.permission.RECEIVE_SMS"))
        assertTrue(PrivacyAuditor.SENSITIVE_PERMISSIONS_CATALOG.containsKey("android.permission.ACCESS_FINE_LOCATION"))
    }
}
