package com.biantivirus.security.ui.screens

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.core.AppPrivacyProfile
import com.biantivirus.security.core.PrivacyAuditReport
import com.biantivirus.security.core.PrivacyRiskLevel
import com.biantivirus.security.ui.theme.*

@Composable
fun PrivacyScreen(
    report: PrivacyAuditReport,
    isAuditing: Boolean,
    onRefreshAudit: () -> Unit,
    onManageApp: (String) -> Unit,
    onBackClick: () -> Unit
) {
    var selectedCategory by remember { mutableStateOf("ALL") }

    val categories = listOf("ALL", "Full System Control", "Screen Overlay", "SMS & Telephony", "Audio Surveillance", "Visual Surveillance", "Physical Tracking")

    val filteredProfiles = remember(report, selectedCategory) {
        if (selectedCategory == "ALL") {
            report.profiles
        } else {
            report.profiles.filter { profile ->
                profile.sensitivePermissions.any { it.category == selectedCategory }
            }
        }
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
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBackClick) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = "Back",
                        tint = GoldAccent
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text(
                        text = "PRIVACY & PERMISSIONS",
                        color = GoldAccent,
                        fontSize = 18.sp,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "Zero-telemetry runtime permission exposure auditor",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }
                Spacer(modifier = Modifier.weight(1f))
                IconButton(onClick = onRefreshAudit, enabled = !isAuditing) {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = "Refresh",
                        tint = if (isAuditing) TextSecondary else GoldAccent
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Score Banner
            val scoreColor = when {
                report.privacyScore >= 85 -> StatusSafe
                report.privacyScore >= 60 -> GoldAccent
                else -> StatusDanger
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(BgCard)
                    .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                    .padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("PRIVACY HEALTH SCORE", color = TextSecondary, fontSize = 11.sp)
                        Text(
                            text = "${report.privacyScore} / 100",
                            color = scoreColor,
                            fontSize = 28.sp,
                            style = MaterialTheme.typography.titleLarge
                        )
                        Text(
                            text = if (report.privacyScore >= 85) "Minimal exposure to third-party data tracking"
                            else "${report.highRiskAppsCount} apps hold critical hardware or intercept permissions",
                            color = TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text("${report.totalAppsAudited} Apps Audited", color = TextPrimary, fontSize = 13.sp)
                        Text("${report.highRiskAppsCount} High Risk", color = StatusDanger, fontSize = 13.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Category Filter Pills
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Horizontal category filter chips
                val topCategories = listOf("ALL", "Full System Control", "Screen Overlay", "SMS & Telephony")
                for (cat in topCategories) {
                    val isSelected = selectedCategory == cat
                    val displayLabel = when (cat) {
                        "ALL" -> "All (${report.profiles.size})"
                        "Full System Control" -> "System Admin"
                        "Screen Overlay" -> "Overlay"
                        "SMS & Telephony" -> "SMS / Calls"
                        else -> cat
                    }
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(16.dp))
                            .background(if (isSelected) GoldAccent else BgCard)
                            .border(1.dp, if (isSelected) GoldAccent else BorderSubtle, RoundedCornerShape(16.dp))
                            .clickable { selectedCategory = cat }
                            .padding(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text(
                            text = displayLabel,
                            color = if (isSelected) BgDarkest else TextPrimary,
                            fontSize = 11.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // App List
            if (filteredProfiles.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (isAuditing) "Auditing installed app permissions..." else "No applications match the selected filter.",
                        color = TextSecondary,
                        fontSize = 14.sp
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredProfiles, key = { it.packageName }) { profile ->
                        AppPrivacyCard(
                            profile = profile,
                            onManageClick = { onManageApp(profile.packageName) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AppPrivacyCard(
    profile: AppPrivacyProfile,
    onManageClick: () -> Unit
) {
    val badgeColor = when (profile.riskLevel) {
        PrivacyRiskLevel.CRITICAL -> StatusDanger
        PrivacyRiskLevel.HIGH -> GoldAccent
        PrivacyRiskLevel.MEDIUM -> Color(0xFF4A90E2)
        PrivacyRiskLevel.LOW -> StatusSafe
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(BgCard)
            .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
            .padding(14.dp)
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = profile.appName,
                        color = TextPrimary,
                        fontSize = 15.sp,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = profile.packageName,
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(badgeColor.copy(alpha = 0.15f))
                        .border(1.dp, badgeColor, RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = profile.riskLevel.name,
                        color = badgeColor,
                        fontSize = 10.sp,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Sensitive permissions summary
            if (profile.sensitivePermissions.isNotEmpty()) {
                Text(
                    text = "Granted Capabilities:",
                    color = TextSecondary,
                    fontSize = 11.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                for (perm in profile.sensitivePermissions) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(vertical = 2.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = GoldAccent,
                            modifier = Modifier.size(12.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "${perm.displayName} (${perm.category})",
                            color = TextPrimary,
                            fontSize = 11.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Risk: ${profile.riskScore}/100",
                    color = badgeColor,
                    fontSize = 12.sp
                )
                OutlinedButton(
                    onClick = onManageClick,
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = GoldAccent),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(text = "Manage Settings", fontSize = 11.sp)
                }
            }
        }
    }
}
