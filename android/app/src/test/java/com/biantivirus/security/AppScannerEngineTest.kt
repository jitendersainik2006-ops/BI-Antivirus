package com.biantivirus.security

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import com.biantivirus.security.core.AppScannerEngine
import com.biantivirus.security.core.SignatureDatabase
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppScannerEngineTest {

    private val signatureDb = SignatureDatabase()
    private val engine = AppScannerEngine(
        context = null,
        signatureDb = signatureDb,
        historyDb = null
    )

    @Test
    fun testScanCleanPackageReturnsClean() {
        val pkg = PackageInfo().apply {
            packageName = "com.example.calculator"
            versionName = "1.0.0"
            applicationInfo = ApplicationInfo().apply {
                flags = 0
                sourceDir = "/dummy/calculator.apk"
            }
            requestedPermissions = arrayOf(
                "android.permission.VIBRATE"
            )
        }

        val result = engine.scanPackage(pkg, "Calculator")
        assertEquals(ScanVerdict.CLEAN, result.verdict)
        assertEquals(ThreatSeverity.NONE, result.severity)
        assertTrue(result.matchedRules.isEmpty())
    }

    @Test
    fun testScanBankingTrojanProfileReturnsCriticalThreat() {
        val pkg = PackageInfo().apply {
            packageName = "com.fake.bank.update"
            versionName = "2.1.0"
            applicationInfo = ApplicationInfo().apply {
                flags = 0
                sourceDir = "/dummy/fakebank.apk"
            }
            requestedPermissions = arrayOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS"
            )
        }

        val result = engine.scanPackage(pkg, "Bank Security Update")
        assertEquals(ScanVerdict.THREAT_DETECTED, result.verdict)
        assertEquals(ThreatSeverity.CRITICAL, result.severity)
        assertEquals("Trojan.AndroidOS.Banker.Heur", result.threatName)
        assertTrue(result.matchedRules.any { it.contains("BANKING_TROJAN_PROFILE") })
    }

    @Test
    fun testScanDropperProfileReturnsSuspicious() {
        val pkg = PackageInfo().apply {
            packageName = "com.suspicious.installer"
            versionName = "1.0"
            applicationInfo = ApplicationInfo().apply {
                flags = 0
                sourceDir = "/dummy/installer.apk"
            }
            requestedPermissions = arrayOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            )
        }

        val result = engine.scanPackage(pkg, "App Installer")
        assertEquals(ScanVerdict.SUSPICIOUS, result.verdict)
        assertEquals(ThreatSeverity.HIGH, result.severity)
        assertEquals("Dropper.AndroidOS.Generic", result.threatName)
        assertTrue(result.matchedRules.any { it.contains("DROPPER_PROFILE") })
    }

    @Test
    fun testScanSmsStealerProfileReturnsSuspicious() {
        val pkg = PackageInfo().apply {
            packageName = "com.stealth.sms"
            versionName = "1.0"
            applicationInfo = ApplicationInfo().apply {
                flags = 0
                sourceDir = "/dummy/sms.apk"
            }
            requestedPermissions = arrayOf(
                "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS"
            )
        }

        val result = engine.scanPackage(pkg, "SMS Manager")
        assertEquals(ScanVerdict.SUSPICIOUS, result.verdict)
        assertEquals(ThreatSeverity.HIGH, result.severity)
        assertEquals("Spyware.AndroidOS.SmsStealer", result.threatName)
        assertTrue(result.matchedRules.any { it.contains("SMS_STEALER_PROFILE") })
    }
}
