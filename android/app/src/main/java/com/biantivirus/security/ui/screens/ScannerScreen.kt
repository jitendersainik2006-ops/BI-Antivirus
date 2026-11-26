package com.biantivirus.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.ui.theme.*

@Composable
fun ScannerScreen(
    scanResult: ScanResult?,
    isScanning: Boolean,
    onPickFileClick: () -> Unit,
    onQuarantineClick: (ScanResult) -> Unit,
    onBackClick: () -> Unit
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDarkest)
            .padding(16.dp)
            .verticalScroll(scrollState)
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
                text = "Document Scanner",
                color = TextPrimary,
                fontSize = 18.sp,
                style = MaterialTheme.typography.titleMedium
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Scanner Trigger Card
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
                    fontSize = 12.sp
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

        // Result Card
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
