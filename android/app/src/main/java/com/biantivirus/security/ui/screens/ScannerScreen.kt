package com.biantivirus.security.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.core.AppScanProgress
import com.biantivirus.security.core.InstalledAppThreat
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.ui.theme.*

@Composable
fun ScannerScreen(
    scanResult: ScanResult?,
    isScanning: Boolean,
    onPickFileClick: () -> Unit,
    onQuarantineClick: (ScanResult) -> Unit,
    onBackClick: () -> Unit,
    isAppScanning: Boolean = false,
    appScanProgress: AppScanProgress? = null,
    appScanResults: List<InstalledAppThreat> = emptyList(),
    onStartAppScanClick: () -> Unit = {},
    onUninstallAppClick: (String) -> Unit = {}
) {
    var selectedTab by remember { mutableIntStateOf(0) } // 0: App Scanner, 1: File Scanner

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDarkest)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 840.dp)
                .align(Alignment.TopCenter)
                .padding(16.dp)
        ) {
            // Top Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBackClick) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = GoldAccent)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Threat Scanner",
                color = TextPrimary,
                fontSize = 18.sp,
                style = MaterialTheme.typography.titleMedium
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Tab Selector (Bitdefender-style App Scanner vs Storage File Scanner)
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = BgCard,
            contentColor = GoldAccent,
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .border(1.dp, BorderSubtle, RoundedCornerShape(8.dp))
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text("Installed Apps", fontSize = 13.sp) }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { Text("File & Storage", fontSize = 13.sp) }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (selectedTab == 0) {
            // TAB 0: INSTALLED APPS SCANNER (Bitdefender Mobile Parity)
            Column(modifier = Modifier.fillMaxSize()) {
                // Scan trigger card
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(BgCard)
                        .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                        .padding(16.dp)
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text(
                                    text = "Device Application Inspection",
                                    color = TextPrimary,
                                    fontSize = 15.sp,
                                    style = MaterialTheme.typography.titleSmall
                                )
                                Text(
                                    text = "Full heuristic & signature audit of installed APKs",
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                            Button(
                                onClick = onStartAppScanClick,
                                enabled = !isAppScanning,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GoldAccent,
                                    contentColor = BgDarkest
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                if (isAppScanning) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        color = BgDarkest,
                                        strokeWidth = 2.dp
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Scanning...", fontSize = 12.sp)
                                } else {
                                    Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Scan Apps", fontSize = 12.sp)
                                }
                            }
                        }

                        // Live scanning progress bar
                        AnimatedVisibility(visible = isAppScanning && appScanProgress != null) {
                            appScanProgress?.let { prog ->
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(top = 14.dp)
                                ) {
                                    LinearProgressIndicator(
                                        progress = { prog.percentage },
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(6.dp)
                                            .clip(RoundedCornerShape(3.dp)),
                                        color = GoldAccent,
                                        trackColor = BgDarkest
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = "Auditing: ${prog.currentAppName}",
                                            color = GoldBright,
                                            fontSize = 11.sp,
                                            maxLines = 1,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Text(
                                            text = "${prog.scannedCount}/${prog.totalCount} (${(prog.percentage * 100).toInt()}%)",
                                            color = TextSecondary,
                                            fontSize = 11.sp
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Scan Results List
                if (appScanResults.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                            .clip(RoundedCornerShape(10.dp))
                            .background(BgCard)
                            .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                            .padding(24.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(
                                Icons.Default.Security,
                                contentDescription = null,
                                tint = TextSecondary,
                                modifier = Modifier.size(40.dp)
                            )
                            Spacer(modifier = Modifier.height(10.dp))
                            Text("Ready to Audit Applications", color = TextPrimary, fontSize = 14.sp)
                            Text(
                                "Tap 'Scan Apps' to verify all installed packages for banking trojans, spyware, and signature anomalies.",
                                color = TextSecondary,
                                fontSize = 12.sp,
                                modifier = Modifier.padding(horizontal = 24.dp),
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                        }
                    }
                } else {
                    val threatCount = appScanResults.count { it.verdict == ScanVerdict.THREAT_DETECTED || it.verdict == ScanVerdict.SUSPICIOUS }

                    Text(
                        text = "AUDIT RESULTS: ${appScanResults.size} APPS SCANNED ($threatCount THREATS)",
                        color = if (threatCount > 0) StatusThreat else StatusSafe,
                        fontSize = 11.sp,
                        style = MaterialTheme.typography.labelMedium
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(appScanResults) { app ->
                            val isThreat = app.verdict == ScanVerdict.THREAT_DETECTED || app.verdict == ScanVerdict.SUSPICIOUS
                            val itemBorder = if (isThreat) StatusThreat else BorderSubtle

                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(BgCard)
                                    .border(1.dp, itemBorder, RoundedCornerShape(8.dp))
                                    .padding(12.dp)
                            ) {
                                Column {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(
                                            modifier = Modifier.weight(1f),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Icon(
                                                imageVector = if (isThreat) Icons.Default.Dangerous else Icons.Default.CheckCircle,
                                                contentDescription = null,
                                                tint = if (isThreat) StatusThreat else StatusSafe,
                                                modifier = Modifier.size(20.dp)
                                            )
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Column {
                                                Text(
                                                    text = app.appName,
                                                    color = TextPrimary,
                                                    fontSize = 13.sp,
                                                    style = MaterialTheme.typography.titleSmall
                                                )
                                                Text(
                                                    text = app.packageName,
                                                    color = TextSecondary,
                                                    fontSize = 10.sp
                                                )
                                            }
                                        }

                                        if (isThreat) {
                                            Button(
                                                onClick = { onUninstallAppClick(app.packageName) },
                                                colors = ButtonDefaults.buttonColors(
                                                    containerColor = StatusThreat,
                                                    contentColor = TextPrimary
                                                ),
                                                shape = RoundedCornerShape(6.dp),
                                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                            ) {
                                                Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(14.dp))
                                                Spacer(modifier = Modifier.width(4.dp))
                                                Text("Uninstall", fontSize = 11.sp)
                                            }
                                        } else {
                                            Surface(
                                                color = StatusSafe.copy(alpha = 0.15f),
                                                shape = RoundedCornerShape(4.dp)
                                            ) {
                                                Text(
                                                    text = "CLEAN",
                                                    color = StatusSafe,
                                                    fontSize = 10.sp,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                        }
                                    }

                                    if (isThreat) {
                                        Spacer(modifier = Modifier.height(6.dp))
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = "Threat: ${app.threatName ?: "Suspicious Application"}",
                                                color = StatusThreat,
                                                fontSize = 11.sp,
                                                style = MaterialTheme.typography.titleSmall
                                            )
                                            Surface(
                                                color = GoldAccent.copy(alpha = 0.2f),
                                                shape = RoundedCornerShape(4.dp)
                                            ) {
                                                Text(
                                                    text = "Confidence: ${app.confidenceScore}%",
                                                    color = GoldBright,
                                                    fontSize = 10.sp,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                        }
                                        if (app.explainableReason.isNotEmpty()) {
                                            Spacer(modifier = Modifier.height(3.dp))
                                            Text(
                                                text = app.explainableReason,
                                                color = TextSecondary,
                                                fontSize = 10.sp,
                                                lineHeight = 13.sp
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(3.dp))
                                        app.matchedRules.forEach { rule ->
                                            Text(" • $rule", color = GoldBright, fontSize = 10.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // TAB 1: FILE & STORAGE SCANNER (SAF Scoped Document Scanner)
            val scrollState = rememberScrollState()
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(scrollState)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(BgCard)
                        .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                        .padding(20.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            imageVector = Icons.Default.FolderOpen,
                            contentDescription = "Folder",
                            tint = GoldAccent,
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Storage Access Framework",
                            color = TextPrimary,
                            fontSize = 16.sp,
                            style = MaterialTheme.typography.titleSmall
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Explicit user-selected file scanning with zero invasive permissions.",
                            color = TextSecondary,
                            fontSize = 12.sp,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = onPickFileClick,
                            enabled = !isScanning,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GoldAccent,
                                contentColor = BgDarkest
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            if (isScanning) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    color = BgDarkest,
                                    strokeWidth = 2.dp
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Analyzing File...")
                            } else {
                                Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Select File to Scan")
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                if (scanResult != null) {
                    val (verdictColor, verdictIcon) = when (scanResult.verdict) {
                        ScanVerdict.CLEAN -> Pair(StatusSafe, Icons.Default.CheckCircle)
                        ScanVerdict.SUSPICIOUS -> Pair(StatusWarning, Icons.Default.Warning)
                        ScanVerdict.THREAT_DETECTED -> Pair(StatusThreat, Icons.Default.Dangerous)
                        ScanVerdict.UNSUPPORTED -> Pair(TextSecondary, Icons.Default.Info)
                        ScanVerdict.SCAN_ERROR -> Pair(StatusThreat, Icons.Default.Error)
                    }

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(BgCard)
                            .border(1.dp, verdictColor, RoundedCornerShape(12.dp))
                            .padding(16.dp)
                    ) {
                        Column {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(verdictIcon, contentDescription = null, tint = verdictColor, modifier = Modifier.size(24.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = scanResult.verdict.name,
                                        color = verdictColor,
                                        fontSize = 16.sp,
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                }
                                if (scanResult.severity.name != "NONE") {
                                    Text(
                                        text = scanResult.severity.name,
                                        color = verdictColor,
                                        fontSize = 12.sp,
                                        style = MaterialTheme.typography.labelSmall
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(12.dp))
                            Divider(color = BorderSubtle)
                            Spacer(modifier = Modifier.height(12.dp))

                            Text("File: ${scanResult.fileName}", color = TextPrimary, fontSize = 13.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Size: ${scanResult.fileSize} bytes", color = TextSecondary, fontSize = 12.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Entropy: ${scanResult.entropy} / 8.0", color = TextSecondary, fontSize = 12.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("SHA-256: ${scanResult.sha256}", color = TextSecondary, fontSize = 11.sp)

                            if (scanResult.threatName != null) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "Threat: ${scanResult.threatName}",
                                    color = StatusThreat,
                                    fontSize = 13.sp,
                                    style = MaterialTheme.typography.titleSmall
                                )
                            }

                            if (scanResult.matchedRules.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text("Matched Rules:", color = TextSecondary, fontSize = 11.sp)
                                scanResult.matchedRules.forEach { rule ->
                                    Text(" • $rule", color = GoldBright, fontSize = 11.sp)
                                }
                            }

                            if (scanResult.verdict == ScanVerdict.THREAT_DETECTED || scanResult.verdict == ScanVerdict.SUSPICIOUS) {
                                Spacer(modifier = Modifier.height(16.dp))
                                Button(
                                    onClick = { onQuarantineClick(scanResult) },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = StatusThreat,
                                        contentColor = TextPrimary
                                    ),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Quarantine to Isolated Vault")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
}
