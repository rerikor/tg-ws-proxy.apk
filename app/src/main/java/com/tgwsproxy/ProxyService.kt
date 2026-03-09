package com.tgwsproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import javax.net.ssl.SSLSocketFactory

class ProxyService : Service() {

    companion object {
        const val TAG = "TgWsProxy"
        const val NOTIF_CHANNEL = "tgwsproxy"
        const val NOTIF_ID = 1
        const val PROXY_PORT = 1080

        // Telegram DC IP ranges to intercept
        val TG_DC_IPS = setOf(
            "149.154.175.50",  "149.154.175.51",  "149.154.175.100",
            "149.154.167.51",  "149.154.167.91",  "149.154.167.92",
            "149.154.167.151", "149.154.167.198", "149.154.167.220",
            "91.108.4.200",    "91.108.56.100",   "91.108.56.150",
            "91.108.56.180",   "91.108.56.190",   "91.108.8.190",
            "95.161.76.100",   "149.154.171.5",
        )

        // DC index by IP (fallback to DC2)
        val IP_TO_DC = mapOf(
            "149.154.175.50" to 1, "149.154.175.51" to 1, "149.154.175.100" to 1,
            "149.154.167.51" to 2, "149.154.167.91" to 2, "149.154.167.92" to 2,
            "149.154.167.151" to 2,"149.154.167.198" to 2,"149.154.167.220" to 2,
            "91.108.4.200" to 3,   "91.108.56.100" to 4,  "91.108.56.150" to 4,
            "91.108.56.180" to 4,  "91.108.56.190" to 4,  "91.108.8.190" to 5,
            "149.154.171.5" to 5,  "95.161.76.100" to 2,
        )

        // Broadcast actions
        const val ACTION_STATUS = "com.tgwsproxy.STATUS"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_CONNECTIONS = "connections"

        var isRunning = false
        var activeConnections = 0
    }

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification("Запущен • порт $PROXY_PORT"))
        startProxy()
        isRunning = true
        broadcastStatus()
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        isRunning = false
        broadcastStatus()
        scope.cancel()
        super.onDestroy()
    }

    private fun startProxy() {
        serverJob = scope.launch {
            try {
                val serverSocket = ServerSocket(PROXY_PORT, 50, InetAddress.getByName("127.0.0.1"))
                Log.i(TAG, "SOCKS5 proxy listening on 127.0.0.1:$PROXY_PORT")
                while (isActive) {
                    val client = serverSocket.accept()
                    launch { handleClient(client) }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server error: ${e.message}")
            }
        }
    }

    private fun stopProxy() {
        serverJob?.cancel()
    }

    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        activeConnections++
        broadcastStatus()
        try {
            client.soTimeout = 30_000
            val cin = DataInputStream(client.getInputStream())
            val cout = client.getOutputStream()

            // SOCKS5 handshake
            val ver = cin.readByte().toInt() and 0xFF
            if (ver != 5) { client.close(); return@withContext }

            val nmethods = cin.readByte().toInt() and 0xFF
            cin.skipBytes(nmethods)
            cout.write(byteArrayOf(5, 0)) // no auth

            // SOCKS5 request
            val ver2 = cin.readByte().toInt() and 0xFF
            if (ver2 != 5) { client.close(); return@withContext }
            val cmd = cin.readByte().toInt() and 0xFF
            cin.readByte() // reserved
            val atyp = cin.readByte().toInt() and 0xFF

            val destAddr: String
            val destPort: Int

            when (atyp) {
                1 -> { // IPv4
                    val b = ByteArray(4)
                    cin.readFully(b)
                    destAddr = "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}.${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}"
                    destPort = (cin.readByte().toInt() and 0xFF shl 8) or (cin.readByte().toInt() and 0xFF)
                }
                3 -> { // Domain
                    val len = cin.readByte().toInt() and 0xFF
                    val domainBytes = ByteArray(len)
                    cin.readFully(domainBytes)
                    destAddr = String(domainBytes)
                    destPort = (cin.readByte().toInt() and 0xFF shl 8) or (cin.readByte().toInt() and 0xFF)
                }
                else -> { client.close(); return@withContext }
            }

            if (cmd != 1) { // only CONNECT supported
                cout.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0))
                client.close(); return@withContext
            }

            Log.d(TAG, "CONNECT $destAddr:$destPort")

            // Send SOCKS5 success response
            cout.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            cout.flush()

            // Determine if this is a Telegram IP
            val isTelegram = destAddr in TG_DC_IPS
            val dcId = if (isTelegram) (IP_TO_DC[destAddr] ?: 2) else -1

            if (isTelegram) {
                // Try WebSocket tunnel first
                val wsSuccess = tryWebSocketTunnel(client, cin, cout, dcId, destAddr, destPort)
                if (!wsSuccess) {
                    // Fallback to direct TCP
                    directTcpRelay(client, cin, cout, destAddr, destPort)
                }
            } else {
                directTcpRelay(client, cin, cout, destAddr, destPort)
            }
        } catch (e: Exception) {
            Log.d(TAG, "Client error: ${e.message}")
        } finally {
            activeConnections--
            broadcastStatus()
            runCatching { client.close() }
        }
    }

    private fun tryWebSocketTunnel(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        dcId: Int, destAddr: String, destPort: Int
    ): Boolean {
        return try {
            val wsHost = "kws${dcId}.web.telegram.org"
            Log.d(TAG, "Trying WebSocket tunnel via $wsHost")

            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val wsSocket = sslFactory.createSocket(wsHost, 443) as javax.net.ssl.SSLSocket
            wsSocket.soTimeout = 15_000

            val wsOut = wsSocket.outputStream
            val wsIn = DataInputStream(wsSocket.inputStream)

            // Send WebSocket upgrade request
            val wsKey = generateWsKey()
            val upgradeRequest = buildString {
                append("GET /apiws HTTP/1.1\r\n")
                append("Host: $wsHost\r\n")
                append("Upgrade: websocket\r\n")
                append("Connection: Upgrade\r\n")
                append("Sec-WebSocket-Key: $wsKey\r\n")
                append("Sec-WebSocket-Protocol: binary\r\n")
                append("Sec-WebSocket-Version: 13\r\n")
                append("Origin: https://web.telegram.org\r\n")
                append("\r\n")
            }
            wsOut.write(upgradeRequest.toByteArray())
            wsOut.flush()

            // Read HTTP response
            val responseLines = StringBuilder()
            var line: String
            val reader = BufferedReader(InputStreamReader(wsSocket.inputStream))
            line = reader.readLine() ?: return false
            if (!line.contains("101")) {
                // WebSocket upgrade failed (likely 302 redirect)
                Log.d(TAG, "WS upgrade failed: $line — falling back to TCP")
                wsSocket.close()
                return false
            }
            // Drain remaining headers
            while (true) {
                val h = reader.readLine() ?: break
                if (h.isEmpty()) break
            }

            Log.i(TAG, "WebSocket tunnel established via $wsHost")

            // Relay data: client <-> WebSocket frames
            val clientToWs = scope.launch {
                try {
                    val buf = ByteArray(8192)
                    while (true) {
                        val n = cin.read(buf)
                        if (n < 0) break
                        sendWsFrame(wsOut, buf, n)
                    }
                } catch (_: Exception) {}
                runCatching { wsSocket.close() }
            }

            val wsToClient = scope.launch {
                try {
                    while (true) {
                        val payload = readWsFrame(DataInputStream(wsSocket.inputStream)) ?: break
                        cout.write(payload)
                        cout.flush()
                    }
                } catch (_: Exception) {}
                runCatching { client.close() }
            }

            runBlocking {
                clientToWs.join()
                wsToClient.cancelAndJoin()
            }
            true
        } catch (e: Exception) {
            Log.d(TAG, "WS tunnel error: ${e.message}")
            false
        }
    }

    private fun directTcpRelay(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        destAddr: String, destPort: Int
    ) {
        try {
            val remote = Socket(destAddr, destPort)
            remote.soTimeout = 30_000
            val remoteIn = remote.inputStream
            val remoteOut = remote.outputStream

            val t1 = scope.launch {
                try { cin.copyTo(remoteOut) } catch (_: Exception) {}
                runCatching { remote.close() }
            }
            val t2 = scope.launch {
                try { remoteIn.copyTo(cout) } catch (_: Exception) {}
                runCatching { client.close() }
            }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) {
            Log.d(TAG, "Direct relay error: ${e.message}")
        }
    }

    private fun sendWsFrame(out: OutputStream, data: ByteArray, length: Int) {
        val frame = ByteArrayOutputStream()
        frame.write(0x82) // binary frame, FIN
        val maskBit = 0x80
        when {
            length <= 125 -> frame.write(maskBit or length)
            length <= 65535 -> {
                frame.write(maskBit or 126)
                frame.write(length shr 8)
                frame.write(length and 0xFF)
            }
            else -> {
                frame.write(maskBit or 127)
                val buf = ByteBuffer.allocate(8).putLong(length.toLong()).array()
                frame.write(buf)
            }
        }
        val mask = ByteArray(4) { (Math.random() * 256).toInt().toByte() }
        frame.write(mask)
        val masked = ByteArray(length) { i -> (data[i].toInt() xor mask[i % 4].toInt()).toByte() }
        frame.write(masked)
        out.write(frame.toByteArray())
        out.flush()
    }

    private fun readWsFrame(din: DataInputStream): ByteArray? {
        return try {
            val b0 = din.readByte().toInt() and 0xFF
            val b1 = din.readByte().toInt() and 0xFF
            val masked = (b1 and 0x80) != 0
            var payloadLen = (b1 and 0x7F).toLong()
            if (payloadLen == 126L) {
                payloadLen = ((din.readByte().toInt() and 0xFF shl 8) or (din.readByte().toInt() and 0xFF)).toLong()
            } else if (payloadLen == 127L) {
                payloadLen = din.readLong()
            }
            val maskKey = if (masked) ByteArray(4).also { din.readFully(it) } else null
            val payload = ByteArray(payloadLen.toInt())
            din.readFully(payload)
            if (maskKey != null) {
                for (i in payload.indices) payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
            }
            payload
        } catch (e: Exception) { null }
    }

    private fun generateWsKey(): String {
        val random = ByteArray(16) { (Math.random() * 256).toInt().toByte() }
        return android.util.Base64.encodeToString(random, android.util.Base64.NO_WRAP)
    }

    private fun broadcastStatus() {
        val intent = Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING, isRunning)
            putExtra(EXTRA_CONNECTIONS, activeConnections)
        }
        sendBroadcast(intent)
        // Update notification
        if (isRunning) {
            val notifManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            val text = if (activeConnections > 0) "Активных соединений: $activeConnections" else "Запущен • порт $PROXY_PORT"
            notifManager.notify(NOTIF_ID, buildNotification(text))
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle("TG WS Proxy")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIF_CHANNEL, "TG WS Proxy",
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Proxy status" }
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
    }
}
