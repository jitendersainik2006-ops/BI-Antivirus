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
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.biantivirus.security.core.QuarantineRecord
import com.biantivirus.security.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun QuarantineScreen(
    records: List<QuarantineRecord>,
    onRestoreRecord: (QuarantineRecord) -> Unit,
    onDeleteRecord: (QuarantineRecord) -> Unit,
    onBackClick: () -> Unit
) {
    var recordToRestore by remember { mutableStateOf<QuarantineRecord?>(null) }
    var recordToDelete by remember { mutableStateOf<QuarantineRecord?>(null) }

    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()) }

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
                text = "Quarantine Vault",
                color = TextPrimary,
                fontSize = 18.sp,
                style = MaterialTheme.typography.titleMedium
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "HARDENED ENCRYPTED ISOLATION (${records.size} ITEMS)",
            color = TextSecondary,
            fontSize = 12.sp,
            style = MaterialTheme.typography.labelMedium
        )

        Spacer(modifier = Modifier.height(12.dp))

        if (records.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(BgCard)
                    .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = StatusSafe,
                        modifier = Modifier.size(36.dp)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Vault is Empty", color = TextPrimary, fontSize = 14.sp)
                    Text("No threats are currently isolated.", color = TextSecondary, fontSize = 12.sp)
                }
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(records) { record ->
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(BgCard)
                            .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                            .padding(16.dp)
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
                                        Icons.Default.Shield,
                                        contentDescription = null,
                                        tint = StatusThreat,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = record.originalFileName,
                                        color = TextPrimary,
                                        fontSize = 14.sp,
                                        style = MaterialTheme.typography.titleSmall
                                    )
                                }
                                Surface(
                                    color = StatusThreat.copy(alpha = 0.15f),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = record.threatName,
                                        color = StatusThreat,
                                        fontSize = 11.sp,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            Divider(color = BorderSubtle)
                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = "Path: ${record.originalPath}",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Quarantined: ${dateFormat.format(Date(record.quarantinedTimestamp))}",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Size: ${record.fileSize} bytes  •  ID: ${record.id}",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "SHA-256: ${record.sha256.take(20)}...",
                                color = GoldBright,
                                fontSize = 10.sp
                            )

                            Spacer(modifier = Modifier.height(12.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.End
                            ) {
                                OutlinedButton(
                                    onClick = { recordToRestore = record },
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = GoldAccent
                                    ),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, GoldAccent),
                                    shape = RoundedCornerShape(6.dp),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Restore,
                                        contentDescription = "Restore",
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Restore", fontSize = 12.sp)
                                }

                                Spacer(modifier = Modifier.width(8.dp))

                                Button(
                                    onClick = { recordToDelete = record },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = StatusThreat.copy(alpha = 0.2f),
                                        contentColor = StatusThreat
                                    ),
                                    shape = RoundedCornerShape(6.dp),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = "Delete",
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Delete", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

    // Restore Confirmation Dialog
    if (recordToRestore != null) {
        val rec = recordToRestore!!
        AlertDialog(
            onDismissRequest = { recordToRestore = null },
            title = { Text("Restore Quarantined File?", color = TextPrimary) },
            text = {
                Text(
                    "Are you sure you want to decrypt and restore '${rec.originalFileName}' to your device storage?\n\nThis file was flagged as: ${rec.threatName}.",
                    color = TextSecondary,
                    fontSize = 13.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        onRestoreRecord(rec)
                        recordToRestore = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = GoldAccent,
                        contentColor = BgDarkest
                    )
                ) {
                    Text("Confirm Restore")
                }
            },
            dismissButton = {
                TextButton(onClick = { recordToRestore = null }) {
                    Text("Cancel", color = TextSecondary)
                }
            },
            containerColor = BgCard
        )
    }

    // Delete Confirmation Dialog
    if (recordToDelete != null) {
        val rec = recordToDelete!!
        AlertDialog(
            onDismissRequest = { recordToDelete = null },
            title = { Text("Permanently Delete Threat?", color = StatusThreat) },
            text = {
                Text(
                    "This will permanently purge '${rec.originalFileName}' from the encrypted vault. This action cannot be undone.",
                    color = TextSecondary,
                    fontSize = 13.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        onDeleteRecord(rec)
                        recordToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StatusThreat,
                        contentColor = TextPrimary
                    )
                ) {
                    Text("Purge File")
                }
            },
            dismissButton = {
                TextButton(onClick = { recordToDelete = null }) {
                    Text("Cancel", color = TextSecondary)
                }
            },
            containerColor = BgCard
        )
    }
}
