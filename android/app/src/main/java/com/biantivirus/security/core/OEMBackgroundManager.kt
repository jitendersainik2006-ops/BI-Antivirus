package com.biantivirus.security.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
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

enum class DeviceFormFactor {
    PHONE,
    TABLET,
    FOLDABLE
}

data class OEMBackgroundStatus(
    val manufacturer: String,
    val model: String,
    val oemType: OEMType,
    val isBatteryOptimizationIgnored: Boolean,
    val killRiskLevel: String, // "HIGH", "MEDIUM", "LOW"
    val guidanceTitle: String,
    val stepByStepInstructions: List<String>,
    val actionLabel: String,
    val formFactor: DeviceFormFactor = DeviceFormFactor.PHONE,
    val osFlavor: String = "Universal Android"
)

class OEMBackgroundManager(private val context: Context? = null) {

    fun detectOEM(): OEMType {
        val mfg = (Build.MANUFACTURER ?: "").lowercase(Locale.ROOT)
        val brand = (Build.BRAND ?: "").lowercase(Locale.ROOT)
        val combined = "$mfg $brand"
        return when {
            combined.contains("samsung") -> OEMType.SAMSUNG
            combined.contains("xiaomi") || combined.contains("redmi") || combined.contains("poco") -> OEMType.XIAOMI
            combined.contains("vivo") || combined.contains("iqoo") -> OEMType.VIVO_IQOO
            combined.contains("oppo") || combined.contains("realme") || combined.contains("oneplus") -> OEMType.OPPO_REALME_ONEPLUS
            combined.contains("motorola") || combined.contains("lenovo") -> OEMType.MOTOROLA
            combined.contains("google") -> OEMType.GOOGLE_PIXEL
            combined.contains("nothing") -> OEMType.NOTHING
            combined.contains("huawei") || combined.contains("honor") -> OEMType.HUAWEI_HONOR
            else -> OEMType.GENERIC
        }
    }

    fun detectFormFactor(): DeviceFormFactor {
        val ctx = context ?: return DeviceFormFactor.PHONE
        return try {
            val config = ctx.resources.configuration
            val screenLayout = config.screenLayout and Configuration.SCREENLAYOUT_SIZE_MASK
            val isLargeScreen = screenLayout >= Configuration.SCREENLAYOUT_SIZE_LARGE
            val smallestScreenWidthDp = config.smallestScreenWidthDp

            val modelLower = (Build.MODEL ?: "").lowercase(Locale.ROOT)
            val isKnownFoldable = modelLower.contains("fold") || modelLower.contains("flip") || modelLower.contains("razr")

            when {
                isKnownFoldable -> DeviceFormFactor.FOLDABLE
                isLargeScreen || smallestScreenWidthDp >= 600 -> DeviceFormFactor.TABLET
                else -> DeviceFormFactor.PHONE
            }
        } catch (_: Exception) {
            DeviceFormFactor.PHONE
        }
    }

    fun detectOSFlavor(oem: OEMType): String {
        return when (oem) {
            OEMType.SAMSUNG -> if (Build.VERSION.SDK_INT >= 34) "Samsung One UI 6" else "Samsung One UI"
            OEMType.XIAOMI -> if (Build.VERSION.SDK_INT >= 34) "Xiaomi HyperOS / MIUI" else "Xiaomi MIUI"
            OEMType.VIVO_IQOO -> "vivo / iQOO Funtouch OS / OriginOS"
            OEMType.OPPO_REALME_ONEPLUS -> "ColorOS / OxygenOS / Realme UI"
            OEMType.MOTOROLA -> "Motorola My UX"
            OEMType.GOOGLE_PIXEL -> "Google Pixel Experience"
            OEMType.NOTHING -> "Nothing OS"
            OEMType.HUAWEI_HONOR -> "Huawei EMUI / MagicOS"
            OEMType.GENERIC -> "Universal AOSP"
        }
    }

    fun getBackgroundStatus(): OEMBackgroundStatus {
        val oem = detectOEM()
        val formFactor = detectFormFactor()
        val osFlavor = detectOSFlavor(oem)
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
                    "Open Device Care (or Settings) > Battery.",
                    "Tap 'Background usage limits'.",
                    "Add 'BI Antivirus' to 'Never sleeping apps'.",
                    "Ensure 'Put unused apps to sleep' does not target BI Antivirus."
                )
                Quad(risk, "$osFlavor Background Shield", stepsList, "Configure Device Care")
            }
            OEMType.XIAOMI -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Xiaomi Security app > Manage apps.",
                    "Select 'BI Antivirus' and toggle 'Autostart' to ON.",
                    "Scroll down to 'Battery Saver' and select 'No restrictions'.",
                    "Lock BI Antivirus in the Recent Apps carousel with the padlock icon."
                )
                Quad(risk, "$osFlavor Background Persistence", stepsList, "Open Autostart Settings")
            }
            OEMType.VIVO_IQOO -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Settings > Battery > Background power consumption.",
                    "Locate 'BI Antivirus' and enable 'Allow high background power consumption'.",
                    "Open iManager > App Manager > Autostart and enable BI Antivirus."
                )
                Quad(risk, "$osFlavor Policy Manager", stepsList, "Open Battery Settings")
            }
            OEMType.OPPO_REALME_ONEPLUS -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Settings > Battery > More battery settings.",
                    "Tap 'Optimize battery use' > BI Antivirus > select 'Don't optimize'.",
                    "Under App Management > BI Antivirus, enable 'Allow background activity' and 'Allow auto-launch'."
                )
                Quad(risk, "$osFlavor Execution Shield", stepsList, "Open Optimization Settings")
            }
            OEMType.HUAWEI_HONOR -> {
                val risk = if (isIgnored) "LOW" else "HIGH"
                val stepsList = listOf(
                    "Open Settings > Battery > App launch.",
                    "Find 'BI Antivirus', disable automatic management, and enable Auto-launch, Secondary launch, and Run in background."
                )
                Quad(risk, "$osFlavor Startup Policy", stepsList, "Configure App Launch")
            }
            OEMType.GOOGLE_PIXEL, OEMType.MOTOROLA, OEMType.NOTHING -> {
                val risk = if (isIgnored) "LOW" else "MEDIUM"
                val stepsList = listOf(
                    "Open Settings > Apps > BI Antivirus.",
                    "Tap 'App battery usage' (or 'Battery').",
                    "Select 'Unrestricted' so real-time background protection is never paused."
                )
                Quad(risk, "$osFlavor Unrestricted Mode", stepsList, "Set Unrestricted Battery")
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
            actionLabel = actionLabel,
            formFactor = formFactor,
            osFlavor = osFlavor
        )
    }

    fun createOptimizationIntent(): Intent {
        val ctx = context ?: return Intent(Settings.ACTION_SETTINGS)
        val oem = detectOEM()

        // 1. Try OEM specific candidate intents
        val candidates: List<Intent> = when (oem) {
            OEMType.XIAOMI -> listOf(
                Intent().apply {
                    component = ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")
                },
                Intent().apply {
                    component = ComponentName("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity")
                },
                Intent("miui.intent.action.POWER_HIDE_MODE_APP_LIST"),
                Intent().apply {
                    component = ComponentName("com.miui.securitycenter", "com.miui.powercenter.PowerSettings")
                }
            )
            OEMType.VIVO_IQOO -> listOf(
                Intent().apply {
                    component = ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity")
                },
                Intent().apply {
                    component = ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager")
                },
                Intent().apply {
                    component = ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")
                },
                Intent().apply {
                    component = ComponentName("com.vivo.abe", "com.vivo.applicationbehaviorengine.ui.ExcessivePowerManagerActivity")
                }
            )
            OEMType.OPPO_REALME_ONEPLUS -> listOf(
                Intent().apply {
                    component = ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")
                },
                Intent().apply {
                    component = ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startupfake.StartupBookActivity")
                },
                Intent().apply {
                    component = ComponentName("com.oplus.battery", "com.oplus.powermanager.fuelgaue.PowerUsageModelActivity")
                },
                Intent().apply {
                    component = ComponentName("com.coloros.oppoguardelf", "com.coloros.powermanager.fuelgaue.PowerUsageModelActivity")
                }
            )
            OEMType.SAMSUNG -> listOf(
                Intent().apply {
                    component = ComponentName("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity")
                },
                Intent().apply {
                    component = ComponentName("com.samsung.android.sm", "com.samsung.android.sm.ui.battery.BatteryActivity")
                },
                Intent().apply {
                    component = ComponentName("com.samsung.android.sm_cn", "com.samsung.android.sm.ui.battery.BatteryActivity")
                },
                Intent("com.samsung.android.sm.ACTION_BATTERY")
            )
            OEMType.HUAWEI_HONOR -> listOf(
                Intent().apply {
                    component = ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")
                },
                Intent().apply {
                    component = ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity")
                },
                Intent().apply {
                    component = ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")
                }
            )
            else -> emptyList()
        }

        for (candidate in candidates) {
            try {
                if (ctx.packageManager.resolveActivity(candidate, 0) != null) {
                    candidate.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    return candidate
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
        try {
            val detailsIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.fromParts("package", ctx.packageName, null)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (ctx.packageManager.resolveActivity(detailsIntent, 0) != null) {
                return detailsIntent
            }
        } catch (_: Exception) {}

        // 4. Ultimate fallback: System Settings
        return Intent(Settings.ACTION_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
}
