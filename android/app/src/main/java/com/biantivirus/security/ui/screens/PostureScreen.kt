package com.biantivirus.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.model.CheckStatus
import com.biantivirus.security.model.DevicePosture
import com.biantivirus.security.ui.theme.*

@Composable
fun PostureScreen(
    posture: DevicePosture,
    onBackClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDarkest)
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
                text = "Device Security Posture",
                color = TextPrimary,
                fontSize = 18.sp,
                style = MaterialTheme.typography.titleMedium
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Overall Score Card
        val scoreColor = when {
            posture.overallScore >= 85 -> StatusSafe
            posture.overallScore >= 60 -> StatusWarning
            else -> StatusThreat
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(BgCard)
                .border(1.dp, scoreColor, RoundedCornerShape(12.dp))
                .padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("SECURITY SCORE", color = TextSecondary, fontSize = 11.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "${posture.overallScore} / 100",
                        color = scoreColor,
                        fontSize = 28.sp,
                        style = MaterialTheme.typography.headlineMedium
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Status: ${posture.statusText}",
                        color = scoreColor,
                        fontSize = 12.sp
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(posture.deviceModel, color = TextPrimary, fontSize = 12.sp)
                    Text(posture.osVersion, color = TextSecondary, fontSize = 11.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = "SECURITY BASELINE CONTROLS",
            color = TextSecondary,
            fontSize = 12.sp,
            style = MaterialTheme.typography.labelMedium
        )

        Spacer(modifier = Modifier.height(12.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(posture.checks) { check ->
                val (statusColor, statusIcon) = when (check.status) {
                    CheckStatus.PASS -> Pair(StatusSafe, Icons.Default.CheckCircle)
                    CheckStatus.WARN -> Pair(StatusWarning, Icons.Default.Warning)
                    CheckStatus.FAIL -> Pair(StatusThreat, Icons.Default.Cancel)
                    CheckStatus.NOT_APPLICABLE -> Pair(TextSecondary, Icons.Default.Info)
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
                            Text(
                                text = check.name,
                                color = TextPrimary,
                                fontSize = 14.sp,
                                style = MaterialTheme.typography.titleSmall
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(statusIcon, contentDescription = null, tint = statusColor, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = check.status.name,
                                    color = statusColor,
                                    fontSize = 12.sp
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(check.details, color = TextSecondary, fontSize = 12.sp)

                        if (check.status != CheckStatus.PASS) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Recommendation: ${check.recommendation}",
                                color = GoldBright,
                                fontSize = 11.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
