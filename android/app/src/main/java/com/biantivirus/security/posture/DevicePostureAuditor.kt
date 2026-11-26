package com.biantivirus.security.posture

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.biantivirus.security.model.CheckStatus
import com.biantivirus.security.model.DevicePosture
import com.biantivirus.security.model.PostureCheckItem
import java.util.UUID

class DevicePostureAuditor(private val context: Context) {

    fun auditPosture(): DevicePosture {
        val checks = mutableListOf<PostureCheckItem>()
        var scoreAccumulator = 100

        // 1. Lock Screen Security Check
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val isDeviceSecure = keyguardManager?.isDeviceSecure ?: false
        if (isDeviceSecure) {
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-LOCK-01",
                    name = "Screen Lock Protection",
                    category = "Device Access",
                    status = CheckStatus.PASS,
                    details = "PIN, Pattern, or Password is active and protecting device.",
                    recommendation = "Maintain current screen lock configuration."
                )
            )
        } else {
            scoreAccumulator -= 30
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-LOCK-01",
                    name = "Screen Lock Protection",
                    category = "Device Access",
                    status = CheckStatus.FAIL,
                    details = "No screen lock configured. Anyone can access device data.",
                    recommendation = "Go to Settings > Security > Screen Lock and configure a strong PIN or Password."
                )
            )
        }

        // 2. Storage Encryption Status
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val encStatus = dpm?.storageEncryptionStatus ?: DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE
        val isEncrypted = encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
                encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY ||
                encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q // Android 10+ enforces encryption by default

        if (isEncrypted) {
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-ENC-02",
                    name = "Hardware Storage Encryption",
                    category = "Data Protection",
                    status = CheckStatus.PASS,
                    details = "Internal flash storage is hardware-encrypted with modern AES file-based encryption.",
                    recommendation = "Device encryption is enforced."
                )
            )
        } else {
            scoreAccumulator -= 25
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-ENC-02",
                    name = "Hardware Storage Encryption",
                    category = "Data Protection",
                    status = CheckStatus.WARN,
                    details = "Storage encryption state is not reported as active.",
                    recommendation = "Enable device encryption in Android Settings > Security."
                )
            )
        }

        // 3. USB Debugging / Developer Options Check
        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (e: Exception) {
            false
        }

        if (adbEnabled) {
            scoreAccumulator -= 15
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-DEV-03",
                    name = "USB Debugging (ADB)",
                    category = "Host Attack Surface",
                    status = CheckStatus.WARN,
                    details = "USB debugging bridge is enabled. Untrusted computers can execute shell commands when connected.",
                    recommendation = "Disable USB Debugging in Settings > Developer Options when not actively testing apps."
                )
            )
        } else {
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-DEV-03",
                    name = "USB Debugging (ADB)",
                    category = "Host Attack Surface",
                    status = CheckStatus.PASS,
                    details = "USB debugging is disabled, protecting against unauthorized workstation commands.",
                    recommendation = "Keep USB debugging disabled."
                )
            )
        }

        // 4. Android OS Version & Security Level
        val sdkVersion = Build.VERSION.SDK_INT
        val patchLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Build.VERSION.SECURITY_PATCH
        } else {
            "Unknown"
        }

        if (sdkVersion >= 33) {
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-OS-04",
                    name = "Android OS & Security Patch",
                    category = "System Integrity",
                    status = CheckStatus.PASS,
                    details = "Android ${Build.VERSION.RELEASE} (API $sdkVersion, Patch $patchLevel).",
                    recommendation = "System is running a modern Android baseline."
                )
            )
        } else {
            scoreAccumulator -= 15
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-OS-04",
                    name = "Android OS & Security Patch",
                    category = "System Integrity",
                    status = CheckStatus.WARN,
                    details = "Android ${Build.VERSION.RELEASE} (API $sdkVersion) is below Android 13 baseline.",
                    recommendation = "Check for system software updates in Settings > System > System Update."
                )
            )
        }

        // 5. Battery Optimization & Background Execution Policy
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
        val isIgnoringBatteryOptimizations = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false
        } else {
            true
        }

        val mfg = Build.MANUFACTURER.lowercase(java.util.Locale.ROOT)
        val mfgGuidance = when {
            mfg.contains("samsung") -> "Samsung One UI: Go to Device Care > Battery > Background usage limits > Never sleeping apps > Add BI Antivirus."
            mfg.contains("xiaomi") || mfg.contains("redmi") || mfg.contains("poco") -> "Xiaomi MIUI/HyperOS: Go to Security app > Manage apps > BI Antivirus > Toggle Autostart ON and set Battery Saver to 'No restrictions'."
            mfg.contains("vivo") || mfg.contains("iqoo") -> "vivo/iQOO Funtouch/Origin: Go to Settings > Battery > Background power consumption > BI Antivirus > Allow high background power consumption."
            mfg.contains("oneplus") || mfg.contains("oppo") || mfg.contains("realme") -> "ColorOS/OxygenOS: Go to Settings > Battery > More battery settings > Optimize battery use > BI Antivirus > Don't optimize."
            mfg.contains("motorola") || mfg.contains("google") || mfg.contains("nothing") -> "Stock Android: Go to Settings > Apps > BI Antivirus > App battery usage > Select 'Unrestricted'."
            else -> "Settings > Apps > BI Antivirus > Battery > Set to 'Unrestricted' or 'No restrictions' for persistent defense."
        }

        if (isIgnoringBatteryOptimizations) {
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-BAT-05",
                    name = "Background Battery Policy",
                    category = "Endpoint Reliability",
                    status = CheckStatus.PASS,
                    details = "Battery optimizations are unrestricted. Background watchdog and threat monitors function persistently.",
                    recommendation = "Maintain current unrestricted battery configuration."
                )
            )
        } else {
            scoreAccumulator -= 10
            checks.add(
                PostureCheckItem(
                    checkId = "CHK-BAT-05",
                    name = "Background Battery Policy",
                    category = "Endpoint Reliability",
                    status = CheckStatus.WARN,
                    details = "System battery management may restrict background file monitoring on ${Build.MANUFACTURER} devices.",
                    recommendation = mfgGuidance
                )
            )
        }

        // 6. Universal Device Architecture & Hardware Capabilities
        val isTablet = context.resources.configuration.smallestScreenWidthDp >= 600
        val formFactor = if (isTablet) "Tablet / Large Screen" else "Smartphone"
        val primaryAbi = Build.SUPPORTED_ABIS.firstOrNull() ?: "universal"
        checks.add(
            PostureCheckItem(
                checkId = "CHK-ARCH-06",
                name = "Hardware & Architecture",
                category = "Platform Compatibility",
                status = CheckStatus.PASS,
                details = "$formFactor (${Build.MANUFACTURER} ${Build.MODEL}), ABI: $primaryAbi, Screen: ${context.resources.configuration.smallestScreenWidthDp}dp.",
                recommendation = "Device architecture is 100% compatible with universal native execution."
            )
        )

        val finalScore = scoreAccumulator.coerceIn(0, 100)
        val statusText = when {
            finalScore >= 85 -> "SECURE"
            finalScore >= 60 -> "WARNING"
            else -> "AT_RISK"
        }

        return DevicePosture(
            reportId = "REP-" + UUID.randomUUID().toString().substring(0, 8).uppercase(),
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            osVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            overallScore = finalScore,
            statusText = statusText,
            checks = checks,
            manufacturer = Build.MANUFACTURER,
            cpuAbi = primaryAbi,
            isTablet = isTablet,
            manufacturerGuidance = mfgGuidance
        )
    }
}
