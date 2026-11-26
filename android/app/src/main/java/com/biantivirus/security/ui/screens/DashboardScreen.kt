package com.biantivirus.security.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.R
import com.biantivirus.security.ui.theme.*

@Composable
fun DashboardScreen(
    onScanDocumentClick: () -> Unit,
    onAuditPostureClick: () -> Unit,
    onQuarantineClick: () -> Unit,
    onHistoryClick: () -> Unit,
    onSettingsClick: () -> Unit
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDarkest)
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
                        .size(44.dp)
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

        // Hero Status Card
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(BgCard)
                .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                .padding(20.dp)
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "Shield",
                        tint = StatusSafe,
                        modifier = Modifier.size(36.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "DEVICE SECURE",
                            color = StatusSafe,
                            fontSize = 18.sp,
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Local offline heuristics & signatures active",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
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
                        Text("OFFLINE DB", color = TextPrimary, fontSize = 13.sp)
                    }
                    Column {
                        Text("Integrity", color = TextSecondary, fontSize = 11.sp)
                        Text("SHA-256", color = TextPrimary, fontSize = 13.sp)
                    }
                    Column {
                        Text("Sandbox Mode", color = TextSecondary, fontSize = 11.sp)
                        Text("Scoped SAF", color = GoldAccent, fontSize = 13.sp)
                    }
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

        // Action Grid
        Row(modifier = Modifier.fillMaxWidth()) {
            ActionCard(
                title = "Scan File",
                subtitle = "User-selected SAF file",
                icon = Icons.Default.FindInPage,
                modifier = Modifier.weight(1f),
                onClick = onScanDocumentClick
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

        Row(modifier = Modifier.fillMaxWidth()) {
            ActionCard(
                title = "Quarantine Vault",
                subtitle = "Isolated encrypted files",
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
