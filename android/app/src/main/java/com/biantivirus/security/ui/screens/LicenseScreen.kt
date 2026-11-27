package com.biantivirus.security.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.core.Edition
import com.biantivirus.security.core.LicenseStatusSummary
import com.biantivirus.security.ui.theme.*

@Composable
fun LicenseScreen(
    status: LicenseStatusSummary,
    onActivateKey: (String) -> Pair<Boolean, String>,
    onDeactivate: () -> Unit,
    onBackClick: () -> Unit
) {
    val scrollState = rememberScrollState()
    var keyInput by remember { mutableStateOf("") }
    val context = LocalContext.current

    val isPremium = status.isPremium
    val badgeColor = if (isPremium) StatusSafe else GoldAccent

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
                        text = "SUBSCRIPTION & LICENSING",
                        color = GoldAccent,
                        fontSize = 18.sp,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "Black Intel Cyber Defense Edition Management",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Current Status Card
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
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = if (isPremium) "PREMIUM EDITION" else "FREE EDITION",
                                color = badgeColor,
                                fontSize = 18.sp,
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = if (isPremium) "Unlimited Sovereign Defense Active" else "Standard Protection & Daily Quota",
                                color = TextSecondary,
                                fontSize = 12.sp
                            )
                        }
                        Icon(
                            imageVector = if (isPremium) Icons.Default.CheckCircle else Icons.Default.Star,
                            contentDescription = null,
                            tint = badgeColor,
                            modifier = Modifier.size(32.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    HorizontalDivider(color = BorderSubtle)
                    Spacer(modifier = Modifier.height(12.dp))

                    if (isPremium) {
                        Text(
                            text = "License Key: ${status.licenseKey ?: "Active"}",
                            color = TextPrimary,
                            fontSize = 13.sp
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Entitlement: Unlimited On-Demand & Deep Scans",
                            color = StatusSafe,
                            fontSize = 12.sp
                        )
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text("Daily Scans Used", color = TextSecondary, fontSize = 11.sp)
                                Text("${status.scansUsedToday} / ${status.maxFreeScansPerDay}", color = TextPrimary, fontSize = 14.sp)
                            }
                            Column {
                                Text("Remaining Today", color = TextSecondary, fontSize = 11.sp)
                                Text("${status.remainingScans} Scans", color = if (status.remainingScans > 0) StatusSafe else StatusThreat, fontSize = 14.sp)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text("Resets In", color = TextSecondary, fontSize = 11.sp)
                                Text(status.resetTimeRemainingText, color = GoldAccent, fontSize = 14.sp)
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Edition Comparison Card
            Text(
                text = "EDITION CAPABILITY COMPARISON",
                color = TextSecondary,
                fontSize = 12.sp,
                style = MaterialTheme.typography.labelMedium
            )

            Spacer(modifier = Modifier.height(10.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(BgCard)
                    .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                    .padding(16.dp)
            ) {
                Column {
                    ComparisonRow("Feature", "Free", "Premium", isHeader = true)
                    HorizontalDivider(color = BorderSubtle, modifier = Modifier.padding(vertical = 6.dp))
                    ComparisonRow("Daily Scans", "5 Scans/Day", "Unlimited")
                    ComparisonRow("App Integrity Scan", "Included", "Included")
                    ComparisonRow("SAF File & Folder Scan", "Included", "Included")
                    ComparisonRow("Premium Deep Scan", "Locked 🔒", "Unlocked ✨")
                    ComparisonRow("Privacy Exposure Audit", "Basic", "Advanced")
                    ComparisonRow("Zip-Slip Archive Defense", "Included", "Included")
                    ComparisonRow("OEM Background Shield", "Standard", "Full Persistence")
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Activation Card
            Text(
                text = "LICENSE ACTIVATION",
                color = TextSecondary,
                fontSize = 12.sp,
                style = MaterialTheme.typography.labelMedium
            )

            Spacer(modifier = Modifier.height(10.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(BgCard)
                    .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                    .padding(16.dp)
            ) {
                Column {
                    Text(
                        text = "Enter License Key",
                        color = GoldAccent,
                        fontSize = 14.sp,
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = "Format: BI-PREM-XXXX-XXXX-XXXX-XXXX",
                        color = TextSecondary,
                        fontSize = 11.sp
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedTextField(
                        value = keyInput,
                        onValueChange = { keyInput = it.uppercase() },
                        placeholder = { Text("BI-PREM-7170-...", color = TextSecondary) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = GoldAccent,
                            unfocusedBorderColor = BorderSubtle,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        singleLine = true
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = {
                                val (ok, msg) = onActivateKey(keyInput)
                                Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                                if (ok) keyInput = ""
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GoldAccent,
                                contentColor = BgDarkest
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Activate Key", fontSize = 13.sp)
                        }

                        if (isPremium) {
                            OutlinedButton(
                                onClick = {
                                    onDeactivate()
                                    Toast.makeText(context, "Reverted to Free Edition.", Toast.LENGTH_SHORT).show()
                                },
                                shape = RoundedCornerShape(8.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusThreat),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Deactivate", fontSize = 13.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ComparisonRow(
    feature: String,
    free: String,
    premium: String,
    isHeader: Boolean = false
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = feature,
            color = if (isHeader) GoldAccent else TextPrimary,
            fontSize = 12.sp,
            style = if (isHeader) MaterialTheme.typography.titleSmall else MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1.4f)
        )
        Text(
            text = free,
            color = if (isHeader) TextSecondary else (if (free.contains("Locked")) StatusThreat else TextSecondary),
            fontSize = 11.sp,
            modifier = Modifier.weight(1f)
        )
        Text(
            text = premium,
            color = if (isHeader) GoldAccent else StatusSafe,
            fontSize = 11.sp,
            modifier = Modifier.weight(1f)
        )
    }
}
