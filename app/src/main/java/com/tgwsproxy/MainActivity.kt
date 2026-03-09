package com.tgwsproxy

import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {

    private var statusReceiver: BroadcastReceiver? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            var isRunning by remember { mutableStateOf(ProxyService.isRunning) }
            var connections by remember { mutableStateOf(ProxyService.activeConnections) }

            // Listen for service status broadcasts
            DisposableEffect(Unit) {
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(context: Context?, intent: Intent?) {
                        isRunning = intent?.getBooleanExtra(ProxyService.EXTRA_RUNNING, false) ?: false
                        connections = intent?.getIntExtra(ProxyService.EXTRA_CONNECTIONS, 0) ?: 0
                    }
                }
                registerReceiver(receiver, IntentFilter(ProxyService.ACTION_STATUS))
                statusReceiver = receiver
                onDispose { unregisterReceiver(receiver) }
            }

            TgWsProxyApp(
                isRunning = isRunning,
                connections = connections,
                onToggle = {
                    if (isRunning) {
                        stopService(Intent(this, ProxyService::class.java))
                    } else {
                        startForegroundService(Intent(this, ProxyService::class.java))
                    }
                },
                onOpenInTelegram = {
                    val url = "tg://socks?server=127.0.0.1&port=${ProxyService.PROXY_PORT}"
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                    } catch (e: Exception) {
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("proxy", url))
                        Toast.makeText(this, "Ссылка скопирована", Toast.LENGTH_SHORT).show()
                    }
                }
            )
        }
    }
}

val BG = Color(0xFF0E0E0E)
val SURFACE = Color(0xFF1A1A1A)
val ACCENT = Color(0xFF2AABEE)  // Telegram blue
val ACCENT_DIM = Color(0xFF1A6E9A)
val TEXT_PRIMARY = Color(0xFFEEEEEE)
val TEXT_SECONDARY = Color(0xFF888888)
val SUCCESS = Color(0xFF4CAF50)
val BORDER = Color(0xFF2A2A2A)

@Composable
fun TgWsProxyApp(
    isRunning: Boolean,
    connections: Int,
    onToggle: () -> Unit,
    onOpenInTelegram: () -> Unit
) {
    val buttonColor by animateColorAsState(
        targetValue = if (isRunning) ACCENT else SURFACE,
        animationSpec = tween(400), label = "btnColor"
    )
    val dotColor by animateColorAsState(
        targetValue = if (isRunning) SUCCESS else Color(0xFF444444),
        animationSpec = tween(400), label = "dotColor"
    )
    val scale by animateFloatAsState(
        targetValue = if (isRunning) 1.05f else 1f,
        animationSpec = tween(200), label = "scale"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(BG),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(0.dp)
        ) {

            // Header
            Spacer(Modifier.height(60.dp))
            Text(
                "TG WS Proxy",
                color = TEXT_PRIMARY,
                fontSize = 22.sp,
                fontWeight = FontWeight.Light,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 2.sp
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "WebSocket tunnel for Telegram",
                color = TEXT_SECONDARY,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace
            )

            Spacer(Modifier.height(64.dp))

            // Big toggle button
            Box(
                modifier = Modifier
                    .size(160.dp)
                    .scale(scale)
                    .clip(CircleShape)
                    .background(buttonColor)
                    .border(1.dp, if (isRunning) ACCENT else BORDER, CircleShape)
                    .clickable { onToggle() },
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        if (isRunning) "■" else "▶",
                        color = if (isRunning) Color.White else TEXT_SECONDARY,
                        fontSize = 36.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        if (isRunning) "СТОП" else "СТАРТ",
                        color = if (isRunning) Color.White else TEXT_SECONDARY,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 3.sp
                    )
                }
            }

            Spacer(Modifier.height(48.dp))

            // Status row
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(dotColor)
                )
                Text(
                    text = when {
                        !isRunning -> "не активен"
                        connections > 0 -> "активных соединений: $connections"
                        else -> "слушает порт 1080"
                    },
                    color = TEXT_SECONDARY,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(Modifier.weight(1f))

            // Info block
            if (isRunning) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(SURFACE)
                        .border(1.dp, BORDER, RoundedCornerShape(12.dp))
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        "Как подключить Telegram",
                        color = TEXT_PRIMARY,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium
                    )
                    InfoRow("Тип", "SOCKS5")
                    InfoRow("Сервер", "127.0.0.1")
                    InfoRow("Порт", "1080")

                    Spacer(Modifier.height(4.dp))

                    // Open in Telegram button
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(ACCENT.copy(alpha = 0.15f))
                            .border(1.dp, ACCENT.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                            .clickable { onOpenInTelegram() }
                            .padding(12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "Открыть в Telegram →",
                            color = ACCENT,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(SURFACE)
                        .border(1.dp, BORDER, RoundedCornerShape(12.dp))
                        .padding(16.dp)
                ) {
                    Text(
                        "Нажмите СТАРТ, затем в Telegram:\nНастройки → Конфиденциальность → Прокси → SOCKS5\nСервер: 127.0.0.1 Порт: 1080",
                        color = TEXT_SECONDARY,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        lineHeight = 20.sp,
                        textAlign = TextAlign.Start
                    )
                }
            }

            Spacer(Modifier.height(40.dp))
        }
    }
}

@Composable
fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = TEXT_SECONDARY, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        Text(value, color = TEXT_PRIMARY, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
    }
}
