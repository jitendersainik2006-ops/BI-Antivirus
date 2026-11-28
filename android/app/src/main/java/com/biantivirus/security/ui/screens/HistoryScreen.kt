package com.biantivirus.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun HistoryScreen(
    scans: List<ScanResult>,
    onClearHistoryClick: () -> Unit,
    onBackClick: () -> Unit
) {
    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())

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
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = GoldAccent)
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Scan History",
                        color = TextPrimary,
                        fontSize = 18.sp,
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                if (scans.isNotEmpty()) {
                    IconButton(onClick = onClearHistoryClick) {
                        Icon(Icons.Default.DeleteSweep, contentDescription = "Clear History", tint = TextSecondary)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (scans.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(BgCard)
                        .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text("No scan events recorded.", color = TextSecondary, fontSize = 13.sp)
                }
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(scans) { scan ->
                        val (vColor, vIcon) = when (scan.verdict) {
                            ScanVerdict.CLEAN -> Pair(StatusSafe, Icons.Default.CheckCircle)
                            ScanVerdict.SUSPICIOUS -> Pair(StatusWarning, Icons.Default.Warning)
                            ScanVerdict.THREAT_DETECTED -> Pair(StatusThreat, Icons.Default.Dangerous)
                            ScanVerdict.UNSUPPORTED -> Pair(TextSecondary, Icons.Default.Info)
                            ScanVerdict.SCAN_ERROR -> Pair(StatusThreat, Icons.Default.Error)
                        }

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(BgCard)
                                .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                                .padding(12.dp)
                        ) {
                            Column {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(vIcon, contentDescription = scan.verdict.name, tint = vColor, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(scan.fileName, color = TextPrimary, fontSize = 13.sp, maxLines = 1)
                                    }
                                    Text(scan.verdict.name, color = vColor, fontSize = 11.sp)
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(dateFormat.format(Date(scan.timestamp)), color = TextSecondary, fontSize = 10.sp)
                                    Text("${scan.fileSize} bytes", color = TextSecondary, fontSize = 10.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
