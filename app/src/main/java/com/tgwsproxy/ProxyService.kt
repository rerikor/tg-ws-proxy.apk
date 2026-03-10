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
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.*
import java.net.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ProxyService : Service() {

    companion object {
        const val TAG = "TgWsProxy"
        const val NOTIF_CHANNEL = "tgwsproxy"
        const val NOTIF_ID = 1
        const val PROXY_PORT = 1080

        private val TG_RANGES = listOf(
            Pair(ipToLong("149.154.160.0"), ipToLong("149.154.175.255")),
            Pair(ipToLong("91.108.0.0"),    ipToLong("91.108.255.255")),
            Pair(ipToLong("91.105.192.0"),  ipToLong("91.105.193.255")),
            Pair(ipToLong("185.76.151.0"),  ipToLong("185.76.151.255")),
        )

        val IP_TO_DC = mapOf(
            "149.154.175.50" to 1, "149.154.175.51" to 1, "149.154.175.54" to 1,
            "149.154.167.41" to 2, "149.154.167.50" to 2, "149.154.167.51" to 2,
            "149.154.167.220" to 2, "149.154.167.151" to 2, "149.154.167.223" to 2,
            "149.154.175.100" to 3, "149.154.175.101" to 3,
            "149.154.167.91" to 4, "149.154.167.92" to 4,
            "149.154.166.120" to 4, "149.154.166.121" to 4,
            "91.108.56.100" to 5, "91.108.56.101" to 5,
            "91.108.56.116" to 5, "91.108.56.126" to 5,
        )

        val DC_TARGET_IP = mapOf(
            1 to "149.154.175.50",
            2 to "149.154.167.220",
            3 to "149.154.175.100",
            4 to "149.154.167.91",
            5 to "91.108.56.100",
        )

        const val ACTION_STATUS = "com.tgwsproxy.STATUS"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_CONNECTIONS = "connections"

        var isRunning = false
        var activeConnections = 0

        fun ipToLong(ip: String): Long {
            val parts = ip.split(".")
            return parts.fold(0L) { acc, s -> (acc shl 8) or s.toLong() }
        }

        fun isTelegramIp(ip: String): Boolean {
            return try {
                val n = ipToLong(ip)
                TG_RANGES.any { (lo, hi) -> n in lo..hi }
            } catch (e: Exception) { false }
        }
    }

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val baseOkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()
    }

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
                Log.i(TAG, "SOCKS5 listening on 127.0.0.1:$PROXY_PORT")
                while (isActive) {
                    val client = serverSocket.accept()
                    launch { handleClient(client) }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server error: ${e.message}")
            }
        }
    }

    private fun stopProxy() { serverJob?.cancel() }

    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        activeConnections++
        broadcastStatus()
        try {
            client.soTimeout = 30_000
            val cin = DataInputStream(client.getInputStream())
            val cout = client.getOutputStream()

            val ver = cin.readByte().toInt() and 0xFF
            if (ver != 5) { client.close(); return@withContext }
            val nmethods = cin.readByte().toInt() and 0xFF
            cin.skipBytes(nmethods)
            cout.write(byteArrayOf(5, 0))
            cout.flush()

            cin.readByte()
            val cmd = cin.readByte().toInt() and 0xFF
            cin.readByte()
            val atyp = cin.readByte().toInt() and 0xFF

            val destAddr: String
            val destPort: Int

            when (atyp) {
                1 -> {
                    val b = ByteArray(4); cin.readFully(b)
                    destAddr = "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}.${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}"
                    destPort = (cin.readByte().toInt() and 0xFF shl 8) or (cin.readByte().toInt() and 0xFF)
                }
                3 -> {
                    val len = cin.readByte().toInt() and 0xFF
                    val domainBytes = ByteArray(len); cin.readFully(domainBytes)
                    destAddr = String(domainBytes)
                    destPort = (cin.readByte().toInt() and 0xFF shl 8) or (cin.readByte().toInt() and 0xFF)
                }
                else -> { client.close(); return@withContext }
            }

            if (cmd != 1) {
                cout.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0))
                client.close(); return@withContext
            }

            cout.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            cout.flush()

            val isTelegram = isTelegramIp(destAddr)
            Log.d(TAG, "CONNECT $destAddr:$destPort isTg=$isTelegram")

            if (!isTelegram) {
                directTcpRelay(client, cin, cout, destAddr, destPort, null)
                return@withContext
            }

            val init = ByteArray(64)
            try { cin.readFully(init) }
            catch (e: Exception) { Log.d(TAG, "init read failed: ${e.message}"); return@withContext }

            val dcId = IP_TO_DC[destAddr] ?: extractDcFromInit(init) ?: 2
            Log.d(TAG, "DC=$dcId for $destAddr")

            val domains = listOf("kws${dcId}.web.telegram.org", "kws${dcId}-1.web.telegram.org")
            val targetIp = DC_TARGET_IP[dcId] ?: destAddr

            var wsSuccess = false
            for (domain in domains) {
                wsSuccess = tryWebSocketTunnel(client, cin, cout, domain, targetIp, init)
                if (wsSuccess) break
            }

            if (!wsSuccess) directTcpRelay(client, cin, cout, destAddr, destPort, init)

        } catch (e: Exception) {
            Log.d(TAG, "Client error: ${e.message}")
        } finally {
            activeConnections--
            broadcastStatus()
            runCatching { client.close() }
        }
    }

    private fun extractDcFromInit(data: ByteArray): Int? {
        if (data.size < 64) return null
        return try {
            val key = data.copyOfRange(8, 40)
            val iv = data.copyOfRange(40, 56)
            val cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(key, "AES"),
                javax.crypto.spec.IvParameterSpec(iv))
            val ks = cipher.update(ByteArray(64))
            val plain = ByteArray(8) { i -> (data[56+i].toInt() xor ks[56+i].toInt()).toByte() }
            val dcRaw = (plain[4].toInt() and 0xFF) or ((plain[5].toInt() and 0xFF) shl 8)
            val dc = Math.abs(if (dcRaw > 32767) dcRaw - 65536 else dcRaw)
            if (dc in 1..1000) dc else null
        } catch (e: Exception) { null }
    }

    private fun tryWebSocketTunnel(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        domain: String, targetIp: String, init: ByteArray
    ): Boolean {
        val done = CountDownLatch(1)
        var success = false
        val pipe = PipedInputStream(65536)
        val pipeOut = PipedOutputStream(pipe)

        // DNS override: resolve domain to targetIp directly, bypassing РКН DNS
        val dns = Dns { _ -> listOf(InetAddress.getByName(targetIp)) }
        val httpClient = baseOkHttpClient.newBuilder().dns(dns).build()

        val request = Request.Builder()
            .url("wss://$domain/apiws")
            .header("Origin", "https://web.telegram.org")
            .header("Sec-WebSocket-Protocol", "binary")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .build()

        val wsListener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WS open: $domain via $targetIp")
                success = true
                webSocket.send(init.toByteString()) // send init first!
                scope.launch {
                    try {
                        val buf = ByteArray(65536)
                        while (true) {
                            val n = cin.read(buf)
                            if (n < 0) break
                            webSocket.send(buf.copyOf(n).toByteString())
                        }
                    } catch (e: Exception) { Log.d(TAG, "c→ws: ${e.message}") }
                    webSocket.close(1000, null)
                    done.countDown()
                }
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                try { pipeOut.write(bytes.toByteArray()); pipeOut.flush() }
                catch (e: Exception) { webSocket.close(1000, null) }
            }
            override fun onMessage(webSocket: WebSocket, text: String) {}
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null); runCatching { pipeOut.close() }; done.countDown()
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                runCatching { pipeOut.close() }; done.countDown()
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.d(TAG, "WS fail $domain: ${t.message}")
                runCatching { pipeOut.close() }; done.countDown()
            }
        }

        val ws = httpClient.newWebSocket(request, wsListener)
        val relayJob = scope.launch {
            try {
                val buf = ByteArray(65536)
                while (true) { val n = pipe.read(buf); if (n < 0) break; cout.write(buf, 0, n); cout.flush() }
            } catch (e: Exception) { Log.d(TAG, "ws→c: ${e.message}") }
        }

        done.await(3600, TimeUnit.SECONDS)
        relayJob.cancel()
        ws.cancel()
        runCatching { pipe.close() }
        return success
    }

    private fun directTcpRelay(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        destAddr: String, destPort: Int, init: ByteArray?
    ) {
        try {
            val remote = Socket(destAddr, destPort)
            if (init != null) { remote.outputStream.write(init); remote.outputStream.flush() }
            val t1 = scope.launch { try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}; runCatching { remote.close() } }
            val t2 = scope.launch { try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}; runCatching { client.close() } }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) { Log.d(TAG, "TCP: ${e.message}") }
    }

    private fun broadcastStatus() {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING, isRunning); putExtra(EXTRA_CONNECTIONS, activeConnections)
        })
        if (isRunning) {
            val text = if (activeConnections > 0) "Активных соединений: $activeConnections" else "Запущен • порт $PROXY_PORT"
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_ID, buildNotification(text))
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle("TG WS Proxy").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(pi).setOngoing(true).build()
    }

    private fun createNotificationChannel() {
        val ch = NotificationChannel(NOTIF_CHANNEL, "TG WS Proxy", NotificationManager.IMPORTANCE_LOW)
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(ch)
    }
}
