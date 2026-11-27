package com.biantivirus.security.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import java.util.Locale

enum class OEMType {
    SAMSUNG,
    XIAOMI,
    VIVO_IQOO,
    OPPO_REALME_ONEPLUS,
    MOTOROLA,
    GOOGLE_PIXEL,
    NOTHING,
    HUAWEI_HONOR,
    GENERIC
}

data class OEMBackgroundStatus(
    val manufacturer: String,
    val model: String,
    val oemType: OEMType,
    val isBatteryOptimizationIgnored: Boolean,
    val killRiskLevel: String, // "HIGH", "MEDIUM", "LOW"
    val guidanceTitle: String,
    val stepByStepInstructions: List<String>,
    val actionLabel: String
)

class OEMBackgroundManager(private val context: Context? = null) {

    fun detectOEM(): OEMType {
        val mfg = (Build.MANUFACTURER ?: "").lowercase(Locale.ROOT)
        return when {
            mfg.contains("samsung") -> OEMType.SAMSUNG
            mfg.contains("xiaomi") || mfg.contains("redmi") || mfg.contains("poco") -> OEMType.XIAOMI
            mfg.contains("vivo") || mfg.contains("iqoo") -> OEMType.VIVO_IQOO
            mfg.contains("oppo") || mfg.contains("realme") || mfg.contains("oneplus") -> OEMType.OPPO_REALME_ONEPLUS
            mfg.contains("motorola") -> OEMType.MOTOROLA
            mfg.contains("google") -> OEMType.GOOGLE_PIXEL
            mfg.contains("nothing") -> OEMType.NOTHING
            mfg.contains("huawei") || mfg.contains("honor") -> OEMType.HUAWEI_HONOR
            else -> OEMType.GENERIC
        }
    }

    fun getBackgroundStatus(): OEMBackgroundStatus {
        val oem = detectOEM()
        val mfg = Build.MANUFACTURER ?: "Universal"
        val model = Build.MODEL ?: "Device"

        val isIgnored = context?.let { ctx ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
                pm?.isIgnoringBatteryOptimizations(ctx.packageName) ?: false
            } else {
                true
            }
        } ?: false

        val (riskLevel, title, steps, actionLabel) = when (oem) {
            OEMType.SAMSUNG -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Device Care > Battery.",
                    "Tap 'Background usage limits'.",
                    "Add 'BI Antivirus' to 'Never sleeping apps'.",
                    "Ensure 'Put unused apps to sleep' does not target BI Antivirus."
                )
                Quad(risk, "Samsung One UI Background Shield", stepsList, "Configure Device Care")
            }
            OEMType.XIAOMI -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Xiaomi Security app > Manage apps.",
                    "Select 'BI Antivirus' and toggle 'Autostart' to ON.",
                    "Scroll down to 'Battery Saver' and select 'No restrictions'.",
                    "Lock BI Antivirus in the Recent Apps carousel with the padlock icon."
                )
                Quad(risk, "Xiaomi MIUI / HyperOS Optimization", stepsList, "Open Autostart Settings")
            }
            OEMType.VIVO_IQOO -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Settings > Battery > Background power consumption.",
                    "Locate 'BI Antivirus' and enable 'Allow high background power consumption'.",
                    "Open iManager > App Manager > Autostart and enable BI Antivirus."
                )
                Quad(risk, "vivo / iQOO Funtouch & Origin OS Policy", stepsList, "Open Battery Settings")
            }
            OEMType.OPPO_REALME_ONEPLUS -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Settings > Battery > More battery settings.",
                    "Tap 'Optimize battery use' > BI Antivirus > select 'Don't optimize'.",
                    "Under App Management > BI Antivirus, enable 'Allow background activity' and 'Allow auto-launch'."
                )
                Quad(risk, "ColorOS / OxygenOS / Realme UI Shield", stepsList, "Open Optimization Settings")
            }
            OEMType.HUAWEI_HONOR -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Settings > Battery > App launch.",
                    "Find 'BI Antivirus', disable automatic management, and enable Auto-launch, Secondary launch, and Run in background."
                )
                Quad(risk, "Huawei EMUI / Honor MagicOS Policy", stepsList, "Configure App Launch")
            }
            OEMType.GOOGLE_PIXEL, OEMType.MOTOROLA, OEMType.NOTHING -> {
                val risk = if (isIgnored) "LOW" else "MEDIUM"
                val stepsList = listOf(
                    "Open Settings > Apps > BI Antivirus.",
                    "Tap 'App battery usage' (or 'Battery').",
                    "Select 'Unrestricted' so real-time background protection is never paused."
                )
                Quad(risk, "Stock Android Unrestricted Execution", stepsList, "Set Unrestricted Battery")
            }
            OEMType.GENERIC -> {
                val risk = if (isIgnored) "LOW" else "MEDIUM"
                val stepsList = listOf(
                    "Open Settings > Apps > BI Antivirus > Battery.",
                    "Set battery optimization policy to 'Unrestricted' or 'Do not optimize'."
                )
                Quad(risk, "Universal Background Execution", stepsList, "Adjust Battery Optimization")
            }
        }

        return OEMBackgroundStatus(
            manufacturer = mfg,
            model = model,
            oemType = oem,
            isBatteryOptimizationIgnored = isIgnored,
            killRiskLevel = riskLevel,
            guidanceTitle = title,
            stepByStepInstructions = steps,
            actionLabel = actionLabel
        )
    }

    fun createOptimizationIntent(): Intent {
        val ctx = context ?: return Intent(Settings.ACTION_SETTINGS)
        val oem = detectOEM()

        // 1. Try OEM specific Autostart / Battery intents first
        val specificIntent: Intent? = when (oem) {
            OEMType.XIAOMI -> {
                Intent().apply {
                    component = ComponentName(
                        "com.miui.securitycenter",
                        "com.miui.permcenter.autostart.AutoStartManagementActivity"
                    )
                }
            }
            OEMType.VIVO_IQOO -> {
                Intent().apply {
                    component = ComponentName(
                        "com.iqoo.secure",
                        "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity"
                    )
                }
            }
            OEMType.OPPO_REALME_ONEPLUS -> {
                Intent().apply {
                    component = ComponentName(
                        "com.coloros.safecenter",
                        "com.coloros.safecenter.permission.startup.StartupAppListActivity"
                    )
                }
            }
            OEMType.SAMSUNG -> {
                Intent().apply {
                    component = ComponentName(
                        "com.samsung.android.lool",
                        "com.samsung.android.sm.battery.ui.BatteryActivity"
                    )
                }
            }
            else -> null
        }

        if (specificIntent != null) {
            try {
                if (ctx.packageManager.resolveActivity(specificIntent, 0) != null) {
                    specificIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    return specificIntent
                }
            } catch (_: Exception) {}
        }

        // 2. Standard Android battery optimization prompt (API 23+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val standardIntent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:${ctx.packageName}")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                if (ctx.packageManager.resolveActivity(standardIntent, 0) != null) {
                    return standardIntent
                }
            } catch (_: Exception) {}

            try {
                val listIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                if (ctx.packageManager.resolveActivity(listIntent, 0) != null) {
                    return listIntent
                }
            } catch (_: Exception) {}
        }

        // 3. Fallback: App Details Settings
        return Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", ctx.packageName, null)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
}
