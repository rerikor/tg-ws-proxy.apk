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
import kotlinx.coroutines.channels.Channel
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.*
import java.net.*
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
            "149.154.175.50" to 1, "149.154.175.51" to 1,
            "149.154.175.53" to 1, "149.154.175.54" to 1,
            "149.154.167.41" to 2, "149.154.167.50" to 2, "149.154.167.51" to 2,
            "149.154.167.220" to 2, "149.154.167.151" to 2, "149.154.167.223" to 2,
            "149.154.165.111" to 2,
            "149.154.175.100" to 3, "149.154.175.101" to 3,
            "149.154.167.91" to 4, "149.154.167.92" to 4,
            "149.154.166.120" to 4, "149.154.166.121" to 4,
            "91.108.56.100" to 5, "91.108.56.101" to 5,
            "91.108.56.116" to 5, "91.108.56.126" to 5,
        )

        // Всё туннелируется через DC2 IP — как в оригинале (--dc-ip 4:149.154.167.220)
        const val TUNNEL_IP = "149.154.167.220"

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

        fun getDcForIp(ip: String): Int {
            return IP_TO_DC[ip] ?: when {
                ip.startsWith("149.154.175.") -> 1
                ip.startsWith("149.154.167.") || ip.startsWith("149.154.165.") -> 2
                ip.startsWith("149.154.166.") -> 4
                ip.startsWith("91.108.56.") -> 5
                else -> 2
            }
        }

        // Извлекает DC и isMedia из 64-байтного MTProto init пакета
        // Возвращает Pair(dcId, isMedia) или null
        fun dcFromInit(data: ByteArray): Pair<Int, Boolean>? {
            if (data.size < 64) return null
            return try {
                val key = data.copyOfRange(8, 40)
                val iv = data.copyOfRange(40, 56)
                val cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
                val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
                val ivSpec = javax.crypto.spec.IvParameterSpec(iv)
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                val keystream = cipher.update(ByteArray(64))
                val plain = ByteArray(8) { i -> (data[56 + i].toInt() xor keystream[56 + i].toInt()).toByte() }
                val proto = ((plain[3].toInt() and 0xFF) shl 24) or
                            ((plain[2].toInt() and 0xFF) shl 16) or
                            ((plain[1].toInt() and 0xFF) shl 8) or
                            (plain[0].toInt() and 0xFF)
                val dcRaw = (plain[4].toInt() and 0xFF) or ((plain[5].toInt() and 0xFF) shl 8)
                val dcSigned = if (dcRaw > 32767) dcRaw - 65536 else dcRaw
                Log.d(TAG, "dcFromInit: proto=0x${proto.toString(16)} dcRaw=$dcSigned plain=${plain.take(8).map { it.toInt() and 0xFF }}")
                // Оригинал проверяет proto: 0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD
                val validProtos = setOf(0xEFEFEFEF.toInt(), 0xEEEEEEEE.toInt(), 0xDDDDDDDD.toInt())
                if (proto in validProtos) {
                    val dc = Math.abs(dcSigned)
                    if (dc in 1..1000) return Pair(dc, dcSigned < 0)
                }
                null
            } catch (e: Exception) {
                Log.d(TAG, "dcFromInit failed: ${e.message}")
                null
            }
        }

        fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
            val base = if (dc > 5) "telegram.org" else "web.telegram.org"
            // Медиа: сначала -1, потом обычный (как в оригинале)
            return if (isMedia) {
                listOf("kws$dc-1.$base", "kws$dc.$base")
            } else {
                listOf("kws$dc.$base", "kws$dc-1.$base")
            }
        }
    }

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val baseOkHttpClient by lazy {
    val trustAll = arrayOf<javax.net.ssl.TrustManager>(
        object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        }
    )
    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
    sslContext.init(null, trustAll, java.security.SecureRandom())
    OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustAll[0] as javax.net.ssl.X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .writeTimeout(0, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
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

            // Читаем ровно 64 байта — как оригинал
            val init = ByteArray(64)
            try { cin.readFully(init) }
            catch (e: Exception) {
                Log.d(TAG, "init read failed: ${e.message}")
                return@withContext
            }

            // Определяем DC из init пакета (включая isMedia)
            val (dcId, isMedia) = dcFromInit(init)?.let { it } ?: run {
                val dc = getDcForIp(destAddr)
                Pair(dc, false)
            }
            Log.d(TAG, "DC=$dcId isMedia=$isMedia for $destAddr")

            val domains = wsDomains(dcId, isMedia)

            var wsSuccess = false
            for (domain in domains) {
                Log.d(TAG, "Trying wss://$domain (ip=$TUNNEL_IP)")
                wsSuccess = tryWebSocketTunnel(client, cin, cout, domain, TUNNEL_IP, init)
                if (wsSuccess) break
            }

            if (!wsSuccess) {
                Log.w(TAG, "WS failed for DC$dcId, falling back to TCP $destAddr:$destPort")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
            }

        } catch (e: Exception) {
            Log.d(TAG, "Client error: ${e.message}")
        } finally {
            activeConnections--
            broadcastStatus()
            runCatching { client.close() }
        }
    }

    private suspend fun tryWebSocketTunnel(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        domain: String, targetIp: String, init: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        val connected = CompletableDeferred<Boolean>()
        val tunnelDone = CompletableDeferred<Unit>()
        val channel = Channel<ByteArray>(Channel.UNLIMITED)

        val dns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByName(targetIp))
        }
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
                connected.complete(true)
                webSocket.send(init.toByteString())
                scope.launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(32768)
                        while (true) {
                            val n = cin.read(buf)
                            if (n < 0) break
                            webSocket.send(buf.copyOf(n).toByteString())
                        }
                    } catch (e: Exception) { Log.d(TAG, "c→ws: ${e.message}") }
                    webSocket.close(1000, null)
                    channel.close()
                    tunnelDone.complete(Unit)
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                channel.trySend(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {}

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                channel.close()
                tunnelDone.complete(Unit)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                channel.close()
                tunnelDone.complete(Unit)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.d(TAG, "WS fail $domain: ${t.message}")
                connected.complete(false)
                channel.close()
                tunnelDone.complete(Unit)
            }
        }

        val ws = httpClient.newWebSocket(request, wsListener)
        val success = withTimeoutOrNull(10_000) { connected.await() } ?: false

        if (success) {
            val relayJob = launch(Dispatchers.IO) {
                try {
                    for (chunk in channel) {
                        cout.write(chunk)
                        cout.flush()
                    }
                } catch (e: Exception) { Log.d(TAG, "ws→c: ${e.message}") }
            }
            tunnelDone.await()
            relayJob.cancelAndJoin()
        }

        ws.cancel()
        success
    }

    private fun directTcpRelay(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        destAddr: String, destPort: Int, init: ByteArray?
    ) {
        try {
            val remote = Socket(destAddr, destPort)
            if (init != null) { remote.outputStream.write(init); remote.outputStream.flush() }
            val t1 = scope.launch {
                try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}
                runCatching { remote.close() }
            }
            val t2 = scope.launch {
                try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}
                runCatching { client.close() }
            }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) {
            Log.d(TAG, "TCP error: ${e.message}")
        }
    }

    private fun broadcastStatus() {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING, isRunning)
            putExtra(EXTRA_CONNECTIONS, activeConnections)
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
