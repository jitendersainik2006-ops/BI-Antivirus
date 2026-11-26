package com.biantivirus.security.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = GoldAccent,
    onPrimary = BgDarkest,
    primaryContainer = BgCard,
    onPrimaryContainer = GoldBright,
    secondary = StatusSafe,
    onSecondary = BgDarkest,
    background = BgDarkest,
    onBackground = TextPrimary,
    surface = BgCard,
    onSurface = TextPrimary,
    surfaceVariant = BgCardHover,
    onSurfaceVariant = TextSecondary,
    outline = BorderSubtle,
    error = StatusThreat,
    onError = TextPrimary
)

@Composable
fun BIAntivirusTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
