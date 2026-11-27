package com.biantivirus.security.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.R
import com.biantivirus.security.core.SecurityScoreReport
import com.biantivirus.security.ui.theme.*

@Composable
fun DashboardScreen(
    scoreReport: SecurityScoreReport?,
    onScanAllAppsClick: () -> Unit,
    onScanDocumentClick: () -> Unit,
    onScanDirectoryClick: () -> Unit,
    onAuditPostureClick: () -> Unit,
    onPrivacyClick: () -> Unit,
    onOEMShieldClick: () -> Unit,
    onQuarantineClick: () -> Unit,
    onHistoryClick: () -> Unit,
    onSettingsClick: () -> Unit
) {
    val scrollState = rememberScrollState()
    var showBreakdownDialog by remember { mutableStateOf(false) }

    val score = scoreReport?.overallScore ?: 95
    val statusText = scoreReport?.statusText ?: "SECURE"
    val scoreColor = when {
        score >= 85 -> StatusSafe
        score >= 60 -> GoldAccent
        else -> StatusDanger
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDarkest)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 720.dp)
                .align(Alignment.TopCenter)
                .padding(16.dp)
                .verticalScroll(scrollState)
        ) {
            // App Header with Official Black Intel Eagle Emblem
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(
                        painter = painterResource(id = R.drawable.ic_black_intel_emblem),
                        contentDescription = "Black Intel Eagle Emblem",
                        modifier = Modifier
                            .size(46.dp)
                            .clip(RoundedCornerShape(10.dp))
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "BI ANTIVIRUS",
                            color = GoldAccent,
                            fontSize = 20.sp,
                            style = MaterialTheme.typography.titleLarge
                        )
                        Text(
                            text = "Enterprise Sovereign Defense",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                }
                IconButton(onClick = onSettingsClick) {
                    Icon(Icons.Default.Settings, contentDescription = "Settings", tint = GoldAccent)
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Hero Health Dial Card (Intelligent Security Score 0-100)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(BgCard)
                    .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                    .padding(20.dp)
            ) {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Circular Health Dial Indicator
                        Box(
                            modifier = Modifier
                                .size(72.dp)
                                .clip(CircleShape)
                                .background(BgElevated)
                                .border(3.dp, scoreColor, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "$score",
                                    color = scoreColor,
                                    fontSize = 22.sp,
                                    style = MaterialTheme.typography.titleLarge
                                )
                                Text(
                                    text = "HEALTH",
                                    color = TextSecondary,
                                    fontSize = 8.sp
                                )
                            }
                        }

                        Spacer(modifier = Modifier.width(16.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = when (statusText) {
                                        "SECURE" -> "SYSTEM SECURE"
                                        "ATTENTION" -> "ATTENTION REQUIRED"
                                        else -> "ENDPOINT AT RISK"
                                    },
                                    color = scoreColor,
                                    fontSize = 17.sp,
                                    style = MaterialTheme.typography.titleMedium
                                )
                            }
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "AI-assisted heuristics, posture audit & offline DB",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "View Score Breakdown",
                                color = GoldAccent,
                                fontSize = 12.sp,
                                modifier = Modifier.clickable { showBreakdownDialog = true }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(18.dp))

                    // Primary 1-Tap Full Scan CTA
                    Button(
                        onClick = onScanAllAppsClick,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = GoldAccent,
                            contentColor = BgDarkest
                        ),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Scan All Installed Apps",
                            fontSize = 14.sp,
                            style = MaterialTheme.typography.titleSmall
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = BorderSubtle)
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("Signatures", color = TextSecondary, fontSize = 11.sp)
                            Text("OFFLINE DB", color = TextPrimary, fontSize = 12.sp)
                        }
                        Column {
                            Text("App Shield", color = TextSecondary, fontSize = 11.sp)
                            Text("ACTIVE", color = StatusSafe, fontSize = 12.sp)
                        }
                        Column {
                            Text("Storage Mode", color = TextSecondary, fontSize = 11.sp)
                            Text("Scoped SAF", color = GoldAccent, fontSize = 12.sp)
                        }
                    }
                }
            }

            // Smart Recommendation Banner
            if (scoreReport != null && scoreReport.actionableRecommendations.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(BgElevated)
                        .border(1.dp, GoldAccent.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = null,
                            tint = GoldAccent,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = scoreReport.actionableRecommendations.first(),
                            color = TextPrimary,
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "SECURITY OPERATIONS",
                color = TextSecondary,
                fontSize = 12.sp,
                style = MaterialTheme.typography.labelMedium
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Action Grid Row 1
            Row(modifier = Modifier.fillMaxWidth()) {
                ActionCard(
                    title = "Scan Apps",
                    subtitle = "Audit all installed APKs",
                    icon = Icons.Default.Apps,
                    modifier = Modifier.weight(1f),
                    onClick = onScanAllAppsClick
                )
                Spacer(modifier = Modifier.width(12.dp))
                ActionCard(
                    title = "Scan File",
                    subtitle = "SAF user-selected file",
                    icon = Icons.Default.FindInPage,
                    modifier = Modifier.weight(1f),
                    onClick = onScanDocumentClick
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Action Grid Row 2
            Row(modifier = Modifier.fillMaxWidth()) {
                ActionCard(
                    title = "Scan Folder",
                    subtitle = "Audit tree with Zip Slip defense",
                    icon = Icons.Default.FolderSpecial,
                    modifier = Modifier.weight(1f),
                    onClick = onScanDirectoryClick
                )
                Spacer(modifier = Modifier.width(12.dp))
                ActionCard(
                    title = "Device Posture",
                    subtitle = "Lock & encryption audit",
                    icon = Icons.Default.Security,
                    modifier = Modifier.weight(1f),
                    onClick = onAuditPostureClick
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Action Grid Row 3
            Row(modifier = Modifier.fillMaxWidth()) {
                ActionCard(
                    title = "Privacy Audit",
                    subtitle = "Sensitive runtime permissions",
                    icon = Icons.Default.PrivacyTip,
                    modifier = Modifier.weight(1f),
                    onClick = onPrivacyClick
                )
                Spacer(modifier = Modifier.width(12.dp))
                ActionCard(
                    title = "OEM Shield",
                    subtitle = "Background saver defense",
                    icon = Icons.Default.BatterySaver,
                    modifier = Modifier.weight(1f),
                    onClick = onOEMShieldClick
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Action Grid Row 4
            Row(modifier = Modifier.fillMaxWidth()) {
                ActionCard(
                    title = "Quarantine Vault",
                    subtitle = "AES-GCM encrypted vault",
                    icon = Icons.Default.Lock,
                    modifier = Modifier.weight(1f),
                    onClick = onQuarantineClick
                )
                Spacer(modifier = Modifier.width(12.dp))
                ActionCard(
                    title = "Scan History",
                    subtitle = "Audit log & reports",
                    icon = Icons.Default.History,
                    modifier = Modifier.weight(1f),
                    onClick = onHistoryClick
                )
            }
        }

        // Breakdown Dialog
        if (showBreakdownDialog && scoreReport != null) {
            AlertDialog(
                onDismissRequest = { showBreakdownDialog = false },
                containerColor = BgCard,
                titleContentColor = GoldAccent,
                textContentColor = TextPrimary,
                title = {
                    Text(
                        text = "SECURITY SCORE FACTORS",
                        fontSize = 16.sp,
                        style = MaterialTheme.typography.titleMedium
                    )
                },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState())
                    ) {
                        Text(
                            text = "Transparent scoring breakdown (Total: ${scoreReport.overallScore}/100)",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                        Spacer(modifier = Modifier.height(12.dp))

                        for (factor in scoreReport.factors) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(factor.title, color = TextPrimary, fontSize = 13.sp)
                                    Text(factor.explanation, color = TextSecondary, fontSize = 11.sp)
                                }
                                Text(
                                    text = "${factor.earnedPoints}/${factor.maxPoints}",
                                    color = if (factor.isOptimal) StatusSafe else GoldAccent,
                                    fontSize = 13.sp
                                )
                            }
                            Divider(color = BorderSubtle, modifier = Modifier.padding(vertical = 4.dp))
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showBreakdownDialog = false }) {
                        Text("OK", color = GoldAccent)
                    }
                }
            )
        }
    }
}

@Composable
fun ActionCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(BgCard)
            .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(16.dp)
    ) {
        Column {
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = GoldAccent,
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = title,
                color = TextPrimary,
                fontSize = 14.sp,
                style = MaterialTheme.typography.titleSmall
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = subtitle,
                color = TextSecondary,
                fontSize = 11.sp
            )
        }
    }
}
