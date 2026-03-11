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

        // IP → (dcId, isMedia)
        // Медиа IP помечены isMedia=true
        private val IP_TO_DC: Map<String, Pair<Int, Boolean>> = mapOf(
            // DC1 обычные
            "149.154.175.50"  to Pair(1, false),
            "149.154.175.51"  to Pair(1, false),
            "149.154.175.54"  to Pair(1, false),
            // DC2 обычные
            "149.154.167.41"  to Pair(2, false),
            "149.154.167.50"  to Pair(2, false),
            "149.154.167.51"  to Pair(2, false),
            "149.154.167.220" to Pair(2, false),
            // DC2 медиа
            "149.154.167.151" to Pair(2, true),
            "149.154.167.223" to Pair(2, true),
            "149.154.165.111" to Pair(2, true),
            // DC3 обычные
            "149.154.175.100" to Pair(3, false),
            "149.154.175.101" to Pair(3, false),
            // DC4 обычные
            "149.154.167.91"  to Pair(4, false),
            "149.154.167.92"  to Pair(4, false),
            // DC4 медиа
            "149.154.166.120" to Pair(4, true),
            "149.154.166.121" to Pair(4, true),
            // DC5 обычные
            "91.108.56.100"   to Pair(5, false),
            "91.108.56.101"   to Pair(5, false),
            "91.108.56.116"   to Pair(5, false),
            "91.108.56.126"   to Pair(5, false),
        )

        // Туннелируем всё через DC2 IP (как оригинал --dc-ip 2:149.154.167.220 4:149.154.167.220)
        private const val TUNNEL_IP = "149.154.167.220"

        const val ACTION_STATUS = "com.tgwsproxy.STATUS"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_CONNECTIONS = "connections"

        var isRunning = false
        var activeConnections = 0

        fun ipToLong(ip: String): Long =
            ip.split(".").fold(0L) { acc, s -> (acc shl 8) or s.toLong() }

        fun isTelegramIp(ip: String): Boolean = try {
            val n = ipToLong(ip)
            TG_RANGES.any { (lo, hi) -> n in lo..hi }
        } catch (_: Exception) { false }

        fun isHttpTransport(data: ByteArray): Boolean {
            if (data.size < 8) return false
            val s = data.copyOf(8).toString(Charsets.ISO_8859_1)
            return s.startsWith("POST ") || s.startsWith("GET ") ||
                   s.startsWith("HEAD ") || s.startsWith("OPTIONS ")
        }

        // Определяем DC и isMedia по IP
        // Для неизвестных IP — fallback по подсети
        fun getDcInfoForIp(ip: String): Pair<Int, Boolean> {
            IP_TO_DC[ip]?.let { return it }
            // Fallback по подсети (isMedia=false — не знаем)
            val dc = when {
                ip.startsWith("149.154.175.") -> 1
                ip.startsWith("149.154.167.") -> 2
                ip.startsWith("149.154.165.") -> 2
                ip.startsWith("149.154.166.") -> 4
                ip.startsWith("91.108.56.")   -> 5
                else -> 2
            }
            // Медиа подсети
            val isMedia = ip.startsWith("149.154.165.") || ip.startsWith("149.154.166.")
            return Pair(dc, isMedia)
        }

        // Маппим DC на поддерживаемый (у нас tunnel через один TUNNEL_IP)
        // DC1,3 → DC2; DC5 → DC4
        fun resolveToSupportedDc(dc: Int): Int = when (dc) {
            1, 3 -> 2
            5    -> 4
            2, 4 -> dc
            else -> if (dc % 2 == 0) 4 else 2
        }

        /**
         * Пробуем извлечь DC и isMedia из 64-байтного MTProto init пакета.
         * Если не получается (мусор в dc_raw) — возвращаем null.
         * Python _dc_from_init():
         *   key=data[8:40], iv=data[40:56]
         *   keystream = AES-CTR(key,iv).encrypt(0x00*64)
         *   plain = data[56:64] XOR keystream[56:64]
         *   proto = LE uint32 plain[0:4]
         *   dc_raw = LE int16 plain[4:6]
         *   if proto valid and 1 <= abs(dc_raw) <= 1000: return abs(dc_raw), dc_raw<0
         */
        fun dcFromInit(data: ByteArray): Pair<Int, Boolean>? {
            if (data.size < 64) return null
            return try {
                val key = data.copyOfRange(8, 40)
                val iv  = data.copyOfRange(40, 56)
                val cipher  = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(
                    javax.crypto.Cipher.ENCRYPT_MODE,
                    javax.crypto.spec.SecretKeySpec(key, "AES"),
                    javax.crypto.spec.IvParameterSpec(iv)
                )
                val ks = cipher.update(ByteArray(64))
                val plain = ByteArray(8) { i -> (data[56+i].toInt() xor ks[56+i].toInt()).toByte() }
                val proto = (plain[0].toInt() and 0xFF) or
                            ((plain[1].toInt() and 0xFF) shl 8) or
                            ((plain[2].toInt() and 0xFF) shl 16) or
                            ((plain[3].toInt() and 0xFF) shl 24)
                val dcRaw = ((plain[4].toInt() and 0xFF) or ((plain[5].toInt() and 0xFF) shl 8))
                              .toShort().toInt()
                Log.d(TAG, "dcFromInit proto=0x${proto.toLong().and(0xFFFFFFFFL).toString(16)} dc_raw=$dcRaw plain=${plain.map{it.toInt() and 0xFF}}")
                val validProtos = setOf(0xEFEFEFEF.toInt(), 0xEEEEEEEE.toInt(), 0xDDDDDDDD.toInt())
                if (proto in validProtos) {
                    val dc = Math.abs(dcRaw)
                    if (dc in 1..1000) return Pair(dc, dcRaw < 0)
                }
                null
            } catch (e: Exception) {
                Log.d(TAG, "dcFromInit failed: ${e.message}")
                null
            }
        }

        // Python _ws_domains()
        // isMedia → kws{dc}-1 сначала; иначе kws{dc} сначала
        fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
            val base = if (dc > 5) "telegram.org" else "web.telegram.org"
            return if (isMedia)
                listOf("kws$dc-1.$base", "kws$dc.$base")
            else
                listOf("kws$dc.$base", "kws$dc-1.$base")
        }
    }

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val baseOkHttpClient by lazy {
        val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        })
        val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS")
        sslCtx.init(null, trustAll, java.security.SecureRandom())
        OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, trustAll[0] as javax.net.ssl.X509TrustManager)
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(0, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null
    override fun onCreate() { super.onCreate(); createNotificationChannel() }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification("Запущен • порт $PROXY_PORT"))
        startProxy(); isRunning = true; broadcastStatus()
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy(); isRunning = false; broadcastStatus(); scope.cancel()
        super.onDestroy()
    }

    private fun startProxy() {
        serverJob = scope.launch {
            try {
                val srv = ServerSocket(PROXY_PORT, 50, InetAddress.getByName("127.0.0.1"))
                Log.i(TAG, "SOCKS5 listening on 127.0.0.1:$PROXY_PORT")
                while (isActive) { val c = srv.accept(); launch { handleClient(c) } }
            } catch (e: Exception) { Log.e(TAG, "Server error: ${e.message}") }
        }
    }

    private fun stopProxy() { serverJob?.cancel() }

    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        activeConnections++; broadcastStatus()
        try {
            // soTimeout только для SOCKS5 handshake и чтения init (64 байт)
            // После этого снимаем таймаут — иначе idle соединения (медиа) закрываются
            client.soTimeout = 15_000
            val cin  = DataInputStream(client.getInputStream())
            val cout = client.getOutputStream()

            // SOCKS5 greeting
            if ((cin.readByte().toInt() and 0xFF) != 5) { client.close(); return@withContext }
            val nm = cin.readByte().toInt() and 0xFF; repeat(nm) { cin.readByte() }
            cout.write(byteArrayOf(0x05, 0x00)); cout.flush()

            // SOCKS5 CONNECT
            cin.readByte()
            val cmd = cin.readByte().toInt() and 0xFF
            cin.readByte()
            val atyp = cin.readByte().toInt() and 0xFF
            if (cmd != 1) { cout.write(socks5Reply(0x07)); cout.flush(); client.close(); return@withContext }

            val destAddr: String
            val destPort: Int
            when (atyp) {
                0x01 -> {
                    val b = ByteArray(4); cin.readFully(b)
                    destAddr = "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}.${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}"
                    destPort = readPort(cin)
                }
                0x03 -> {
                    val len = cin.readByte().toInt() and 0xFF
                    val db = ByteArray(len); cin.readFully(db)
                    destAddr = String(db, Charsets.UTF_8); destPort = readPort(cin)
                }
                0x04 -> {
                    val b = ByteArray(16); cin.readFully(b)
                    destAddr = InetAddress.getByAddress(b).hostAddress ?: "::1"; destPort = readPort(cin)
                }
                else -> { cout.write(socks5Reply(0x08)); cout.flush(); client.close(); return@withContext }
            }

            Log.d(TAG, "CONNECT $destAddr:$destPort")

            // Non-Telegram → прямой passthrough
            if (!isTelegramIp(destAddr)) {
                try {
                    val remote = withTimeoutOrNull(10_000) { withContext(Dispatchers.IO) { Socket(destAddr, destPort) } }
                        ?: run { cout.write(socks5Reply(0x05)); cout.flush(); client.close(); return@withContext }
                    cout.write(socks5Reply(0x00)); cout.flush()
                    directBridge(client, cin, cout, remote)
                } catch (e: Exception) {
                    runCatching { cout.write(socks5Reply(0x05)); cout.flush() }
                    client.close()
                }
                return@withContext
            }

            // Telegram → ответ success, читаем 64-байтный MTProto init
            cout.write(socks5Reply(0x00)); cout.flush()
            val init = ByteArray(64)
            try { cin.readFully(init) } catch (e: Exception) {
                Log.d(TAG, "init read failed for $destAddr: ${e.message}"); return@withContext
            }
            if (isHttpTransport(init)) { client.close(); return@withContext }

            // Снимаем таймаут — туннель может быть idle долго (особенно медиа)
            client.soTimeout = 0

            // Определяем DC и isMedia:
            // 1. Пробуем dcFromInit (читает из зашифрованного пакета)
            // 2. Fallback — по IP (включая isMedia для медиа-IP)
            val initResult = dcFromInit(init)
            val rawDc: Int
            val isMedia: Boolean

            if (initResult != null && initResult.first in 1..1000) {
                rawDc   = initResult.first
                isMedia = initResult.second
                Log.d(TAG, "dcFromInit OK: DC$rawDc isMedia=$isMedia for $destAddr")
            } else {
                val ipInfo = getDcInfoForIp(destAddr)
                rawDc   = ipInfo.first
                isMedia = ipInfo.second
                Log.d(TAG, "dcFromInit null/invalid for $destAddr → IP fallback DC$rawDc isMedia=$isMedia")
            }

            val dcId    = resolveToSupportedDc(rawDc)
            val mediaTag = if (isMedia) " media" else ""
            Log.i(TAG, "→ DC$dcId$mediaTag (raw=$rawDc) for $destAddr:$destPort")

            val domains = wsDomains(dcId, isMedia)
            var wsOk = false
            for (domain in domains) {
                Log.d(TAG, "  trying wss://$domain via $TUNNEL_IP")
                wsOk = tryWebSocketTunnel(cin, cout, client, domain, TUNNEL_IP, init)
                if (wsOk) break
            }

            if (!wsOk) {
                Log.w(TAG, "WS failed DC$dcId$mediaTag → TCP $destAddr:$destPort")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
            }

        } catch (e: Exception) {
            Log.d(TAG, "handleClient error: ${e.message}")
        } finally {
            activeConnections--; broadcastStatus(); runCatching { client.close() }
        }
    }

    private suspend fun tryWebSocketTunnel(
        cin: DataInputStream, cout: OutputStream, client: Socket,
        domain: String, targetIp: String, init: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        val connected  = CompletableDeferred<Boolean>()
        val tunnelDone = CompletableDeferred<Unit>()
        val fromWs     = Channel<ByteArray>(Channel.UNLIMITED)

        val httpClient = baseOkHttpClient.newBuilder()
            .dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> =
                    listOf(InetAddress.getByName(targetIp))
            }).build()

        val request = Request.Builder()
            .url("wss://$domain/apiws")
            .header("Host",                   domain)
            .header("Origin",                 "https://web.telegram.org")
            .header("Upgrade",                "websocket")
            .header("Connection",             "Upgrade")
            .header("Sec-WebSocket-Protocol", "binary")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .build()

        val ws = httpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, r: Response) {
                Log.i(TAG, "WS opened: $domain")
                connected.complete(true)
                ws.send(init.toByteString())
                scope.launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(65536)
                        while (true) { val n = cin.read(buf); if (n < 0) break; if (!ws.send(buf.copyOf(n).toByteString())) break }
                    } catch (_: Exception) {}
                    runCatching { ws.close(1000, null) }
                    fromWs.close(); tunnelDone.complete(Unit)
                }
            }
            override fun onMessage(ws: WebSocket, b: ByteString) { fromWs.trySend(b.toByteArray()) }
            override fun onMessage(ws: WebSocket, t: String) {}
            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                runCatching { ws.close(1000, null) }; fromWs.close(); tunnelDone.complete(Unit)
            }
            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                fromWs.close(); tunnelDone.complete(Unit)
            }
            override fun onFailure(ws: WebSocket, t: Throwable, r: Response?) {
                Log.d(TAG, "WS onFailure $domain: ${t.message} code=${r?.code}")
                if (!connected.isCompleted) connected.complete(false)
                fromWs.close(); tunnelDone.complete(Unit)
            }
        })

        val success = withTimeoutOrNull(10_000) { connected.await() } ?: false

        if (success) {
            val relay = launch(Dispatchers.IO) {
                try { for (chunk in fromWs) { cout.write(chunk); cout.flush() } } catch (_: Exception) {}
            }
            tunnelDone.await(); relay.cancelAndJoin()
        }
        runCatching { ws.cancel() }
        success
    }

    private fun directTcpRelay(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        destAddr: String, destPort: Int, init: ByteArray?
    ) {
        try {
            val remote = Socket(destAddr, destPort)
            if (init != null) { remote.outputStream.write(init); remote.outputStream.flush() }
            val t1 = scope.launch(Dispatchers.IO) {
                try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}; runCatching { remote.close() }
            }
            val t2 = scope.launch(Dispatchers.IO) {
                try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}; runCatching { client.close() }
            }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) { Log.d(TAG, "TCP relay error $destAddr: ${e.message}") }
    }

    private fun directBridge(client: Socket, cin: DataInputStream, cout: OutputStream, remote: Socket) {
        val t1 = scope.launch(Dispatchers.IO) {
            try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}; runCatching { remote.close() }
        }
        val t2 = scope.launch(Dispatchers.IO) {
            try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}; runCatching { client.close() }
        }
        runBlocking { t1.join(); t2.cancelAndJoin() }
    }

    private fun readPort(cin: DataInputStream): Int =
        ((cin.readByte().toInt() and 0xFF) shl 8) or (cin.readByte().toInt() and 0xFF)

    private fun socks5Reply(status: Int): ByteArray =
        byteArrayOf(0x05, status.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

    private fun broadcastStatus() {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING, isRunning); putExtra(EXTRA_CONNECTIONS, activeConnections)
        })
        if (isRunning) {
            val text = if (activeConnections > 0) "Активных: $activeConnections" else "Запущен • порт $PROXY_PORT"
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
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(NotificationChannel(NOTIF_CHANNEL, "TG WS Proxy", NotificationManager.IMPORTANCE_LOW))
    }
}
