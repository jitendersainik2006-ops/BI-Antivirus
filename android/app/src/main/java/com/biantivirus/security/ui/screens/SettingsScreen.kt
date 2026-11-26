package com.biantivirus.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.storage.PreferencesManager
import com.biantivirus.security.ui.theme.*

@Composable
fun SettingsScreen(
    prefs: PreferencesManager,
    onBackClick: () -> Unit
) {
    var heuristicEnabled by remember { mutableStateOf(prefs.isHeuristicEnabled) }
    var autoQuarantine by remember { mutableStateOf(prefs.isAutoQuarantine) }
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
                text = "Security & Privacy Settings",
                color = TextPrimary,
                fontSize = 18.sp,
                style = MaterialTheme.typography.titleMedium
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Settings Card
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(BgCard)
                .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                .padding(16.dp)
        ) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Heuristic Threat Analysis", color = TextPrimary, fontSize = 14.sp)
                        Text("Inspects Shannon entropy & double extensions", color = TextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = heuristicEnabled,
                        onCheckedChange = {
                            heuristicEnabled = it
                            prefs.isHeuristicEnabled = it
                        },
                        colors = SwitchDefaults.colors(checkedThumbColor = GoldAccent, checkedTrackColor = BgCardHover)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))
                Divider(color = BorderSubtle)
                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Automatic Threat Vaulting", color = TextPrimary, fontSize = 14.sp)
                        Text("Requires explicit approval by default", color = TextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = autoQuarantine,
                        onCheckedChange = {
                            autoQuarantine = it
                            prefs.isAutoQuarantine = it
                        },
                        colors = SwitchDefaults.colors(checkedThumbColor = GoldAccent, checkedTrackColor = BgCardHover)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "SOVEREIGN PRIVACY COMMITMENT",
            color = TextSecondary,
            fontSize = 12.sp,
            style = MaterialTheme.typography.labelMedium
        )

        Spacer(modifier = Modifier.height(12.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(BgCard)
                .border(1.dp, BorderSubtle, RoundedCornerShape(12.dp))
                .padding(16.dp)
        ) {
            Column {
                Text(
                    text = "Zero Cloud Telemetry Leakage",
                    color = GoldAccent,
                    fontSize = 14.sp,
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "BI Antivirus runs 100% locally on your device. No document contents, hashes, filenames, or identity metrics are uploaded to external clouds. The engine operates entirely offline.",
                    color = TextSecondary,
                    fontSize = 12.sp
                )
            }
        }
    }
}
