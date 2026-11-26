package com.biantivirus.security.storage

import android.content.Context
import android.content.SharedPreferences

class PreferencesManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "bi_antivirus_preferences"
        private const val KEY_FIRST_RUN_COMPLETED = "first_run_completed"
        private const val KEY_HEURISTIC_ENABLED = "heuristic_enabled"
        private const val KEY_ENTROPY_THRESHOLD = "entropy_threshold"
        private const val KEY_AUTO_QUARANTINE = "auto_quarantine"
        private const val KEY_NOTIFY_THREATS_ONLY = "notify_threats_only"
    }

    var isFirstRunCompleted: Boolean
        get() = prefs.getBoolean(KEY_FIRST_RUN_COMPLETED, false)
        set(value) = prefs.edit().putBoolean(KEY_FIRST_RUN_COMPLETED, value).apply()

    var isHeuristicEnabled: Boolean
        get() = prefs.getBoolean(KEY_HEURISTIC_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_HEURISTIC_ENABLED, value).apply()

    var entropyThreshold: Float
        get() = prefs.getFloat(KEY_ENTROPY_THRESHOLD, 7.2f)
        set(value) = prefs.edit().putFloat(KEY_ENTROPY_THRESHOLD, value).apply()

    var isAutoQuarantine: Boolean
        get() = prefs.getBoolean(KEY_AUTO_QUARANTINE, false) // Default false for safety
        set(value) = prefs.edit().putBoolean(KEY_AUTO_QUARANTINE, value).apply()

    var notifyThreatsOnly: Boolean
        get() = prefs.getBoolean(KEY_NOTIFY_THREATS_ONLY, false)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFY_THREATS_ONLY, value).apply()
}
