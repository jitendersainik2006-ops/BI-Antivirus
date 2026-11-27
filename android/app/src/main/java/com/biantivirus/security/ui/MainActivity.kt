package com.biantivirus.security.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.lifecycle.lifecycleScope
import com.biantivirus.security.BIAntivirusApp
import com.biantivirus.security.core.AppScanProgress
import com.biantivirus.security.core.InstalledAppThreat
import com.biantivirus.security.core.QuarantineRecord
import com.biantivirus.security.core.RestoreResult
import com.biantivirus.security.model.DevicePosture
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.posture.DevicePostureAuditor
import com.biantivirus.security.ui.screens.*
import com.biantivirus.security.ui.theme.BIAntivirusTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

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

    // App Scanner States
    private var isAppScanning by mutableStateOf(false)
    private var appScanProgress by mutableStateOf<AppScanProgress?>(null)
    private var appScanResults by mutableStateOf<List<InstalledAppThreat>>(emptyList())

    // Quarantine States
    private var quarantineRecords by mutableStateOf<List<QuarantineRecord>>(emptyList())

    // SAF Document Picker (Single File)
    private val openDocumentLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            currentScreen = CurrentScreen.SCANNER
            scanDocumentUri(uri)
        }
    }

    // SAF Directory Picker (Folder / Tree Scan)
    private val openDocumentTreeLauncher = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            currentScreen = CurrentScreen.SCANNER
            scanDocumentTree(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Pre-load active quarantine items
        quarantineRecords = app.quarantineManager.getActiveQuarantinedItems()

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
                        onScanAllAppsClick = {
                            currentScreen = CurrentScreen.SCANNER
                            startAppScan()
                        },
                        onScanDocumentClick = { openDocumentLauncher.launch(arrayOf("*/*")) },
                        onScanDirectoryClick = { openDocumentTreeLauncher.launch(null) },
                        onAuditPostureClick = {
                            currentPosture = postureAuditor.auditPosture()
                            currentScreen = CurrentScreen.POSTURE
                        },
                        onQuarantineClick = {
                            quarantineRecords = app.quarantineManager.getActiveQuarantinedItems()
                            currentScreen = CurrentScreen.QUARANTINE
                        },
                        onHistoryClick = { currentScreen = CurrentScreen.HISTORY },
                        onSettingsClick = { currentScreen = CurrentScreen.SETTINGS }
                    )

                    CurrentScreen.SCANNER -> ScannerScreen(
                        scanResult = lastScanResult,
                        isScanning = isScanning,
                        onPickFileClick = { openDocumentLauncher.launch(arrayOf("*/*")) },
                        onQuarantineClick = { result -> quarantineThreat(result) },
                        onBackClick = { currentScreen = CurrentScreen.DASHBOARD },
                        isAppScanning = isAppScanning,
                        appScanProgress = appScanProgress,
                        appScanResults = appScanResults,
                        onStartAppScanClick = { startAppScan() },
                        onUninstallAppClick = { pkgName -> uninstallThreatApp(pkgName) }
                    )

                    CurrentScreen.POSTURE -> {
                        val posture = currentPosture ?: postureAuditor.auditPosture()
                        PostureScreen(
                            posture = posture,
                            onBackClick = { currentScreen = CurrentScreen.DASHBOARD }
                        )
                    }

                    CurrentScreen.QUARANTINE -> QuarantineScreen(
                        records = quarantineRecords,
                        onRestoreRecord = { record -> restoreQuarantinedRecord(record) },
                        onDeleteRecord = { record -> deleteQuarantinedRecord(record) },
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

    private fun startAppScan() {
        if (isAppScanning) return
        isAppScanning = true
        appScanProgress = null

        lifecycleScope.launch(Dispatchers.IO) {
            val results = app.appScannerEngine.scanAllApps(
                includeSystemApps = false
            ) { progress ->
                appScanProgress = progress
            }

            withContext(Dispatchers.Main) {
                appScanResults = results
                isAppScanning = false
                val threats = results.count { it.verdict == ScanVerdict.THREAT_DETECTED || it.verdict == ScanVerdict.SUSPICIOUS }
                val msg = if (threats > 0) {
                    "Audit finished: $threats threat(s) detected across ${results.size} apps!"
                } else {
                    "All ${results.size} installed applications verified clean."
                }
                Toast.makeText(this@MainActivity, msg, Toast.LENGTH_LONG).show()
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

    private fun scanDocumentTree(treeUri: Uri) {
        isScanning = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val docUri = DocumentsContract.buildDocumentUriUsingTree(
                    treeUri,
                    DocumentsContract.getTreeDocumentId(treeUri)
                )
                val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
                    treeUri,
                    DocumentsContract.getTreeDocumentId(treeUri)
                )

                var scannedFiles = 0
                var threatsFound = 0
                contentResolver.query(childrenUri, arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE
                ), null, null, null)?.use { cursor ->
                    val idCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    val sizeCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                    while (cursor.moveToNext()) {
                        val docId = cursor.getString(idCol)
                        val name = cursor.getString(nameCol) ?: "unknown"
                        val mime = cursor.getString(mimeCol) ?: ""
                        val size = if (sizeCol != -1) cursor.getLong(sizeCol) else 0L

                        if (mime != DocumentsContract.Document.MIME_TYPE_DIR) {
                            val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                            try {
                                contentResolver.openInputStream(fileUri)?.use { stream ->
                                    val result = app.scannerEngine.scanStream(name, fileUri.toString(), size, stream)
                                    scannedFiles++
                                    if (result.verdict == ScanVerdict.THREAT_DETECTED || result.verdict == ScanVerdict.SUSPICIOUS) {
                                        threatsFound++
                                        withContext(Dispatchers.Main) {
                                            lastScanResult = result
                                        }
                                    }
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }

                withContext(Dispatchers.Main) {
                    isScanning = false
                    Toast.makeText(
                        this@MainActivity,
                        "Folder sweep finished: $scannedFiles files inspected, $threatsFound threats.",
                        Toast.LENGTH_LONG
                    ).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    isScanning = false
                    Toast.makeText(this@MainActivity, "Tree scan error: ${e.message}", Toast.LENGTH_SHORT).show()
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

                    // Safely delete original infected file from device storage
                    try {
                        DocumentsContract.deleteDocument(contentResolver, uri)
                    } catch (_: Exception) {
                        try {
                            contentResolver.delete(uri, null, null)
                        } catch (_: Exception) {
                            try {
                                val f = File(result.filePath)
                                if (f.exists()) f.delete()
                            } catch (_: Exception) {}
                        }
                    }

                    withContext(Dispatchers.Main) {
                        quarantineRecords = app.quarantineManager.getActiveQuarantinedItems()
                        Toast.makeText(this@MainActivity, "Threat isolated in AES-GCM vault & purged from storage.", Toast.LENGTH_LONG).show()
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

    private fun restoreQuarantinedRecord(record: QuarantineRecord) {
        lifecycleScope.launch(Dispatchers.IO) {
            val restoreDir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                ?: getExternalFilesDir(null)
                ?: filesDir

            val result = app.quarantineManager.restoreQuarantinedFile(
                id = record.id,
                targetDirectory = restoreDir,
                allowOverwrite = true
            )

            withContext(Dispatchers.Main) {
                when (result) {
                    is RestoreResult.Success -> {
                        quarantineRecords = app.quarantineManager.getActiveQuarantinedItems()
                        Toast.makeText(
                            this@MainActivity,
                            "File restored: ${result.restoredFile.name}\nLocation: ${result.restoredFile.parent}",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    is RestoreResult.TamperDetected -> {
                        Toast.makeText(this@MainActivity, "SECURITY ERROR: ${result.reason}", Toast.LENGTH_LONG).show()
                    }
                    is RestoreResult.Error -> {
                        Toast.makeText(this@MainActivity, "Restore error: ${result.message}", Toast.LENGTH_SHORT).show()
                    }
                    is RestoreResult.DestinationExists -> {
                        Toast.makeText(this@MainActivity, "Destination file already exists.", Toast.LENGTH_SHORT).show()
                    }
                    is RestoreResult.RecordNotFound -> {
                        Toast.makeText(this@MainActivity, "Quarantine record not found.", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun deleteQuarantinedRecord(record: QuarantineRecord) {
        val deleted = app.quarantineManager.deleteQuarantinedItem(record.id)
        quarantineRecords = app.quarantineManager.getActiveQuarantinedItems()
        if (deleted) {
            Toast.makeText(this, "Threat permanently purged from vault.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun uninstallThreatApp(packageName: String) {
        try {
            val intent = Intent(Intent.ACTION_DELETE).apply {
                data = Uri.parse("package:$packageName")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(intent)
        } catch (_: Exception) {
            try {
                @Suppress("DEPRECATION")
                val fallbackIntent = Intent(Intent.ACTION_UNINSTALL_PACKAGE).apply {
                    data = Uri.parse("package:$packageName")
                    putExtra(Intent.EXTRA_RETURN_RESULT, true)
                }
                startActivity(fallbackIntent)
            } catch (e: Exception) {
                Toast.makeText(this, "Cannot prompt uninstall: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
