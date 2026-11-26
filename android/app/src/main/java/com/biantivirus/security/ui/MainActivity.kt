package com.biantivirus.security.ui

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.lifecycle.lifecycleScope
import com.biantivirus.security.BIAntivirusApp
import com.biantivirus.security.model.DevicePosture
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.posture.DevicePostureAuditor
import com.biantivirus.security.ui.screens.*
import com.biantivirus.security.ui.theme.BIAntivirusTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class CurrentScreen {
    ONBOARDING,
    DASHBOARD,
    SCANNER,
    POSTURE,
    QUARANTINE,
    HISTORY,
    SETTINGS
}

class MainActivity : ComponentActivity() {

    private val app by lazy { application as BIAntivirusApp }
    private val postureAuditor by lazy { DevicePostureAuditor(this) }

    private var currentScreen by mutableStateOf(CurrentScreen.DASHBOARD)
    private var lastScanResult by mutableStateOf<ScanResult?>(null)
    private var isScanning by mutableStateOf(false)
    private var currentPosture by mutableStateOf<DevicePosture?>(null)

    // Storage Access Framework launcher - respects user authorization
    private val openDocumentLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            currentScreen = CurrentScreen.SCANNER
            scanDocumentUri(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Show onboarding if not yet completed
        if (!app.preferencesManager.isFirstRunCompleted) {
            currentScreen = CurrentScreen.ONBOARDING
        }

        setContent {
            BIAntivirusTheme {
                when (currentScreen) {
                    CurrentScreen.ONBOARDING -> OnboardingScreen(
                        onActivateProtection = {
                            app.preferencesManager.isFirstRunCompleted = true
                            currentScreen = CurrentScreen.DASHBOARD
                        }
                    )

                    CurrentScreen.DASHBOARD -> DashboardScreen(
                        onScanDocumentClick = { openDocumentLauncher.launch(arrayOf("*/*")) },
                        onAuditPostureClick = {
                            currentPosture = postureAuditor.auditPosture()
                            currentScreen = CurrentScreen.POSTURE
                        },
                        onQuarantineClick = { currentScreen = CurrentScreen.QUARANTINE },
                        onHistoryClick = { currentScreen = CurrentScreen.HISTORY },
                        onSettingsClick = { currentScreen = CurrentScreen.SETTINGS }
                    )

                    CurrentScreen.SCANNER -> ScannerScreen(
                        scanResult = lastScanResult,
                        isScanning = isScanning,
                        onPickFileClick = { openDocumentLauncher.launch(arrayOf("*/*")) },
                        onQuarantineClick = { result ->
                            quarantineThreat(result)
                        },
                        onBackClick = { currentScreen = CurrentScreen.DASHBOARD }
                    )

                    CurrentScreen.POSTURE -> {
                        val posture = currentPosture ?: postureAuditor.auditPosture()
                        PostureScreen(
                            posture = posture,
                            onBackClick = { currentScreen = CurrentScreen.DASHBOARD }
                        )
                    }

                    CurrentScreen.QUARANTINE -> QuarantineScreen(
                        vaultFiles = app.quarantineManager.listQuarantinedItems(),
                        onDeleteVaultFile = { file ->
                            app.quarantineManager.deleteQuarantinedItem(file.absolutePath)
                            Toast.makeText(this, "Vault file purged.", Toast.LENGTH_SHORT).show()
                        },
                        onBackClick = { currentScreen = CurrentScreen.DASHBOARD }
                    )

                    CurrentScreen.HISTORY -> HistoryScreen(
                        scans = app.historyDatabase.getRecentScans(),
                        onClearHistoryClick = {
                            app.historyDatabase.clearHistory()
                            Toast.makeText(this, "History cleared.", Toast.LENGTH_SHORT).show()
                        },
                        onBackClick = { currentScreen = CurrentScreen.DASHBOARD }
                    )

                    CurrentScreen.SETTINGS -> SettingsScreen(
                        prefs = app.preferencesManager,
                        onBackClick = { currentScreen = CurrentScreen.DASHBOARD }
                    )
                }
            }
        }
    }

    private fun scanDocumentUri(uri: Uri) {
        isScanning = true
        lifecycleScope.launch(Dispatchers.IO) {
            var fileName = "document"
            var fileSize = 0L

            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (cursor.moveToFirst()) {
                    if (nameIndex != -1) fileName = cursor.getString(nameIndex)
                    if (sizeIndex != -1) fileSize = cursor.getLong(sizeIndex)
                }
            }

            try {
                contentResolver.openInputStream(uri)?.use { stream ->
                    val result = app.scannerEngine.scanStream(
                        fileName = fileName,
                        filePath = uri.toString(),
                        fileSize = fileSize,
                        inputStream = stream
                    )
                    withContext(Dispatchers.Main) {
                        lastScanResult = result
                        isScanning = false
                    }
                } ?: run {
                    withContext(Dispatchers.Main) {
                        isScanning = false
                        Toast.makeText(this@MainActivity, "Unable to read document stream.", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    isScanning = false
                    Toast.makeText(this@MainActivity, "Scan error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun quarantineThreat(result: ScanResult) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val uri = Uri.parse(result.filePath)
                val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                if (bytes != null) {
                    app.quarantineManager.quarantineBytes(
                        fileName = result.fileName,
                        originalPath = result.filePath,
                        bytes = bytes,
                        threatName = result.threatName ?: "Threat",
                        sha256 = result.sha256
                    )
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Quarantined to encrypted vault.", Toast.LENGTH_LONG).show()
                        currentScreen = CurrentScreen.QUARANTINE
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Quarantine failed: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}
