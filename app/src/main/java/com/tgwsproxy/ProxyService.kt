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

        // Диапазоны Telegram IP — порт _TG_RANGES из Python
        private val TG_RANGES = listOf(
            Pair(ipToLong("149.154.160.0"), ipToLong("149.154.175.255")),
            Pair(ipToLong("91.108.0.0"),    ipToLong("91.108.255.255")),
            Pair(ipToLong("91.105.192.0"),  ipToLong("91.105.193.255")),
            Pair(ipToLong("185.76.151.0"),  ipToLong("185.76.151.255")),
        )

        // Порт _IP_TO_DC из Python (без медиа-IP которые закомментированы в оригинале)
        private val IP_TO_DC = mapOf(
            "149.154.175.50"  to 1, "149.154.175.51"  to 1, "149.154.175.54"  to 1,
            "149.154.167.41"  to 2,
            "149.154.167.50"  to 2, "149.154.167.51"  to 2, "149.154.167.220" to 2,
            "149.154.175.100" to 3, "149.154.175.101" to 3,
            "149.154.167.91"  to 4, "149.154.167.92"  to 4,
            "91.108.56.100"   to 5, "91.108.56.126"   to 5,
            "91.108.56.101"   to 5, "91.108.56.116"   to 5,
            "91.105.192.100"  to 203,
        )

        // Туннелируем всё через DC2 IP — как в оригинале: --dc-ip 2:149.154.167.220 4:149.154.167.220
        // В Python _dc_opt = {2: "149.154.167.220", 4: "149.154.167.220"} (дефолт)
        private const val TUNNEL_IP = "149.154.167.220"

        // DC которые мы "поддерживаем" (как _dc_opt в Python)
        // Python: if dc not in _dc_opt -> TCP fallback
        // Мы: маппим неподдерживаемые DC на ближайший поддерживаемый
        private val SUPPORTED_DCS = setOf(2, 4)

        const val ACTION_STATUS = "com.tgwsproxy.STATUS"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_CONNECTIONS = "connections"

        var isRunning = false
        var activeConnections = 0

        fun ipToLong(ip: String): Long =
            ip.split(".").fold(0L) { acc, s -> (acc shl 8) or s.toLong() }

        // Порт _is_telegram_ip из Python
        fun isTelegramIp(ip: String): Boolean = try {
            val n = ipToLong(ip)
            TG_RANGES.any { (lo, hi) -> n in lo..hi }
        } catch (_: Exception) { false }

        // Порт _is_http_transport из Python
        fun isHttpTransport(data: ByteArray): Boolean {
            if (data.size < 8) return false
            val s = data.copyOf(8).toString(Charsets.ISO_8859_1)
            return s.startsWith("POST ") || s.startsWith("GET ") ||
                   s.startsWith("HEAD ") || s.startsWith("OPTIONS ")
        }

        // IP → DC (с fallback по подсети)
        fun getDcForIp(ip: String): Int = IP_TO_DC[ip] ?: when {
            ip.startsWith("149.154.175.") -> 1
            ip.startsWith("149.154.167.") -> 2
            ip.startsWith("149.154.165.") -> 2
            ip.startsWith("149.154.166.") -> 4
            ip.startsWith("91.108.56.")   -> 5
            ip.startsWith("91.105.192.")  -> 203
            else -> 2
        }

        // Маппим DC на поддерживаемый (аналог проверки dc not in _dc_opt в Python,
        // но вместо TCP fallback мы пробуем ближайший DC через WS)
        fun resolveToSupportedDc(dc: Int): Int = when {
            dc in SUPPORTED_DCS -> dc
            dc == 1 || dc == 3  -> 2
            dc == 5             -> 4
            dc > 5              -> if (dc % 2 == 0) 4 else 2
            else                -> 2
        }

        /**
         * Порт Python _dc_from_init():
         *   key      = data[8:40]
         *   iv       = data[40:56]
         *   keystream = AES-CTR(key, iv).encrypt(b'\x00' * 64)
         *   plain    = data[56:64] XOR keystream[56:64]
         *   proto    = struct.unpack('<I', plain[0:4])[0]   -- uint32 LE
         *   dc_raw   = struct.unpack('<h', plain[4:6])[0]   -- int16 LE signed!
         *   if proto in (0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD)
         *      and 1 <= abs(dc_raw) <= 1000:
         *     return abs(dc_raw), dc_raw < 0
         *   return None, False
         */
        fun dcFromInit(data: ByteArray): Pair<Int, Boolean>? {
            if (data.size < 64) return null
            return try {
                val key = data.copyOfRange(8, 40)
                val iv  = data.copyOfRange(40, 56)
                val cipher  = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
                val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
                val ivSpec  = javax.crypto.spec.IvParameterSpec(iv)
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                // Шифруем 64 нулевых байта → получаем keystream
                val keystream = cipher.update(ByteArray(64))
                // plain = data[56:64] XOR keystream[56:64]
                val plain = ByteArray(8) { i ->
                    (data[56 + i].toInt() xor keystream[56 + i].toInt()).toByte()
                }
                // proto = uint32 little-endian из plain[0:4]
                val proto = (plain[0].toInt() and 0xFF) or
                            ((plain[1].toInt() and 0xFF) shl 8) or
                            ((plain[2].toInt() and 0xFF) shl 16) or
                            ((plain[3].toInt() and 0xFF) shl 24)
                // dc_raw = int16 signed little-endian из plain[4:6]
                val dcRawUnsigned = (plain[4].toInt() and 0xFF) or
                                    ((plain[5].toInt() and 0xFF) shl 8)
                val dcSigned = dcRawUnsigned.toShort().toInt()  // signed int16
                Log.d(TAG, "dcFromInit proto=0x${proto.toLong().and(0xFFFFFFFFL).toString(16)} dc_raw=$dcSigned plain=${plain.map { it.toInt() and 0xFF }}")
                val validProtos = setOf(
                    0xEFEFEFEF.toInt(), 0xEEEEEEEE.toInt(), 0xDDDDDDDD.toInt()
                )
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

        /**
         * Порт Python _ws_domains():
         *   DC 1-5:  kws{N}[-1].web.telegram.org
         *   DC >5:   kws{N}[-1].telegram.org
         *   isMedia: сначала kws{dc}-1, потом kws{dc}
         *   !isMedia: сначала kws{dc}, потом kws{dc}-1
         *
         * Также Python: if is_media is None or is_media → медиа-порядок
         */
        fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
            val base = if (dc > 5) "telegram.org" else "web.telegram.org"
            return if (isMedia) {
                listOf("kws$dc-1.$base", "kws$dc.$base")
            } else {
                listOf("kws$dc.$base", "kws$dc-1.$base")
            }
        }
    }

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // OkHttp с отключённой TLS проверкой — как ssl_ctx с verify_mode=CERT_NONE в Python
    private val baseOkHttpClient by lazy {
        val trustAll = arrayOf<javax.net.ssl.TrustManager>(
            object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(
                    chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkServerTrusted(
                    chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            }
        )
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

    private fun stopProxy() { serverJob?.cancel() }

    // Порт Python _handle_client()
    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        activeConnections++
        broadcastStatus()
        try {
            client.soTimeout = 30_000
            val cin  = DataInputStream(client.getInputStream())
            val cout = client.getOutputStream()

            // --- SOCKS5 greeting ---
            val ver = cin.readByte().toInt() and 0xFF
            if (ver != 5) {
                Log.d(TAG, "Not SOCKS5 (ver=$ver)")
                client.close(); return@withContext
            }
            val nmethods = cin.readByte().toInt() and 0xFF
            repeat(nmethods) { cin.readByte() }
            cout.write(byteArrayOf(0x05, 0x00)) // no-auth
            cout.flush()

            // --- SOCKS5 CONNECT request ---
            cin.readByte() // ver
            val cmd  = cin.readByte().toInt() and 0xFF
            cin.readByte() // rsv
            val atyp = cin.readByte().toInt() and 0xFF

            if (cmd != 1) {
                cout.write(socks5Reply(0x07))
                cout.flush()
                client.close(); return@withContext
            }

            val destAddr: String
            val destPort: Int

            when (atyp) {
                0x01 -> { // IPv4
                    val b = ByteArray(4); cin.readFully(b)
                    destAddr = "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}" +
                               ".${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}"
                    destPort = readPort(cin)
                }
                0x03 -> { // domain
                    val len = cin.readByte().toInt() and 0xFF
                    val domainBytes = ByteArray(len); cin.readFully(domainBytes)
                    destAddr = String(domainBytes, Charsets.UTF_8)
                    destPort = readPort(cin)
                }
                0x04 -> { // IPv6 — passthrough
                    val b = ByteArray(16); cin.readFully(b)
                    destAddr = InetAddress.getByAddress(b).hostAddress ?: "::1"
                    destPort = readPort(cin)
                }
                else -> {
                    cout.write(socks5Reply(0x08))
                    cout.flush()
                    client.close(); return@withContext
                }
            }

            Log.d(TAG, "CONNECT $destAddr:$destPort")

            // --- Non-Telegram → прямой passthrough (порт Python: if not _is_telegram_ip) ---
            if (!isTelegramIp(destAddr)) {
                Log.d(TAG, "passthrough -> $destAddr:$destPort")
                try {
                    val remote = withTimeoutOrNull(10_000) {
                        withContext(Dispatchers.IO) { Socket(destAddr, destPort) }
                    } ?: run {
                        cout.write(socks5Reply(0x05)); cout.flush()
                        client.close(); return@withContext
                    }
                    cout.write(socks5Reply(0x00)); cout.flush()
                    directBridge(client, cin, cout, remote)
                } catch (e: Exception) {
                    Log.w(TAG, "passthrough failed $destAddr: ${e.message}")
                    runCatching { cout.write(socks5Reply(0x05)); cout.flush() }
                    client.close()
                }
                return@withContext
            }

            // --- Telegram IP: отправляем SOCKS5 success, читаем 64-байтный init ---
            cout.write(socks5Reply(0x00))
            cout.flush()

            val init = ByteArray(64)
            try { cin.readFully(init) }
            catch (e: Exception) {
                Log.d(TAG, "init read failed for $destAddr: ${e.message}")
                return@withContext
            }

            // HTTP transport → отбрасываем (как в Python)
            if (isHttpTransport(init)) {
                Log.d(TAG, "HTTP transport rejected for $destAddr:$destPort")
                client.close(); return@withContext
            }

            // --- Определяем DC (точный порт Python строки 641-648) ---
            //   dc, is_media = _dc_from_init(init)
            //   if dc is None and dst in _IP_TO_DC: dc = _IP_TO_DC[dst]
            //   if dc is None or dc not in _dc_opt: TCP fallback
            val initResult = dcFromInit(init)
            var dc: Int? = initResult?.first
            val isMediaFromInit: Boolean = initResult?.second ?: false

            if (dc == null) {
                dc = IP_TO_DC[destAddr]
                Log.d(TAG, "dcFromInit=null for $destAddr, IP_TO_DC -> DC$dc")
            }

            if (dc == null) {
                Log.w(TAG, "Unknown DC for $destAddr:$destPort -> TCP fallback")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
                return@withContext
            }

            // isMedia берётся только из dcFromInit; IP fallback не знает про медиа
            val isMedia = isMediaFromInit
            val mediaTag = if (isMedia) " media" else ""

            // Резолвим DC на поддерживаемый (у нас один TUNNEL_IP для всех)
            val resolvedDc = resolveToSupportedDc(dc)

            Log.i(TAG, "DC$resolvedDc$mediaTag (raw DC=$dc) for $destAddr:$destPort")

            // --- Пробуем WebSocket (порт Python строки 681-742) ---
            val domains = wsDomains(resolvedDc, isMedia)
            var wsSuccess = false

            for (domain in domains) {
                Log.d(TAG, "Trying wss://$domain via $TUNNEL_IP")
                wsSuccess = tryWebSocketTunnel(cin, cout, client, domain, TUNNEL_IP, init)
                if (wsSuccess) break
            }

            // --- WS не получилось → TCP fallback (порт Python строки 735-742) ---
            if (!wsSuccess) {
                Log.w(TAG, "WS failed for DC$resolvedDc$mediaTag -> TCP fallback to $destAddr:$destPort")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
            }

        } catch (e: Exception) {
            Log.d(TAG, "handleClient error: ${e.message}")
        } finally {
            activeConnections--
            broadcastStatus()
            runCatching { client.close() }
        }
    }

    /**
     * Порт Python RawWebSocket.connect() + _bridge_ws():
     * Подключаемся к targetIp:443 с TLS SNI = domain,
     * делаем WebSocket upgrade на /apiws,
     * отправляем init, затем двунаправленный relay.
     * Возвращает true если WS установлен успешно.
     */
    private suspend fun tryWebSocketTunnel(
        cin: DataInputStream,
        cout: OutputStream,
        client: Socket,
        domain: String,
        targetIp: String,
        init: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {

        val connected   = CompletableDeferred<Boolean>()
        val tunnelDone  = CompletableDeferred<Unit>()
        val fromWs      = Channel<ByteArray>(Channel.UNLIMITED)

        // DNS override: всегда резолвим в targetIp (как Python connect(ip=target, domain=domain))
        val dns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByName(targetIp))
        }
        val httpClient = baseOkHttpClient.newBuilder().dns(dns).build()

        val request = Request.Builder()
            .url("wss://$domain/apiws")
            .header("Host",                   domain)
            .header("Origin",                 "https://web.telegram.org")
            .header("Upgrade",                "websocket")
            .header("Connection",             "Upgrade")
            .header("Sec-WebSocket-Protocol", "binary")
            .header("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) " +
                "Chrome/131.0.0.0 Safari/537.36")
            .build()

        val wsListener = object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WS opened: $domain via $targetIp")
                connected.complete(true)
                // Отправляем init сразу после открытия — как Python: await ws.send(init)
                webSocket.send(init.toByteString())
                // Читаем от клиента → пишем в WS (tcp_to_ws)
                scope.launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(65536)
                        while (true) {
                            val n = cin.read(buf)
                            if (n < 0) break
                            if (!webSocket.send(buf.copyOf(n).toByteString())) break
                        }
                    } catch (_: Exception) {}
                    runCatching { webSocket.close(1000, null) }
                    fromWs.close()
                    tunnelDone.complete(Unit)
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                fromWs.trySend(bytes.toByteArray())
            }

            // Текстовые фреймы игнорируем
            override fun onMessage(webSocket: WebSocket, text: String) {}

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                runCatching { webSocket.close(1000, null) }
                fromWs.close()
                tunnelDone.complete(Unit)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                fromWs.close()
                tunnelDone.complete(Unit)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.d(TAG, "WS onFailure $domain: ${t.message} response=${response?.code}")
                if (!connected.isCompleted) connected.complete(false)
                fromWs.close()
                tunnelDone.complete(Unit)
            }
        }

        val ws = httpClient.newWebSocket(request, wsListener)

        // Ждём открытия (10 сек таймаут — как timeout=10 в Python)
        val success = withTimeoutOrNull(10_000) { connected.await() } ?: run {
            Log.d(TAG, "WS connect timeout: $domain")
            false
        }

        if (success) {
            // Читаем из WS → пишем клиенту (ws_to_tcp) пока туннель жив
            val relayJob = launch(Dispatchers.IO) {
                try {
                    for (chunk in fromWs) {
                        cout.write(chunk)
                        cout.flush()
                    }
                } catch (_: Exception) {}
            }
            tunnelDone.await()
            relayJob.cancelAndJoin()
        }

        runCatching { ws.cancel() }
        success
    }

    // Порт Python _tcp_fallback() + _bridge_tcp()
    private fun directTcpRelay(
        client: Socket,
        cin: DataInputStream,
        cout: OutputStream,
        destAddr: String,
        destPort: Int,
        init: ByteArray?
    ) {
        try {
            val remote = Socket(destAddr, destPort)
            Log.d(TAG, "TCP relay connected to $destAddr:$destPort")
            if (init != null) {
                remote.outputStream.write(init)
                remote.outputStream.flush()
            }
            val t1 = scope.launch(Dispatchers.IO) {
                try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}
                runCatching { remote.close() }
            }
            val t2 = scope.launch(Dispatchers.IO) {
                try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}
                runCatching { client.close() }
            }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) {
            Log.d(TAG, "TCP relay error to $destAddr:$destPort: ${e.message}")
        }
    }

    // Прямой passthrough для не-Telegram трафика
    private fun directBridge(
        client: Socket,
        cin: DataInputStream,
        cout: OutputStream,
        remote: Socket
    ) {
        val t1 = scope.launch(Dispatchers.IO) {
            try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}
            runCatching { remote.close() }
        }
        val t2 = scope.launch(Dispatchers.IO) {
            try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}
            runCatching { client.close() }
        }
        runBlocking { t1.join(); t2.cancelAndJoin() }
    }

    private fun readPort(cin: DataInputStream): Int =
        ((cin.readByte().toInt() and 0xFF) shl 8) or (cin.readByte().toInt() and 0xFF)

    // Порт Python _socks5_reply(): bytes([0x05, status, 0x00, 0x01]) + b'\x00' * 6
    private fun socks5Reply(status: Int): ByteArray =
        byteArrayOf(0x05, status.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

    private fun broadcastStatus() {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING, isRunning)
            putExtra(EXTRA_CONNECTIONS, activeConnections)
        })
        if (isRunning) {
            val text = if (activeConnections > 0)
                "Активных соединений: $activeConnections"
            else
                "Запущен • порт $PROXY_PORT"
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIF_ID, buildNotification(text))
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle("TG WS Proxy")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        val ch = NotificationChannel(
            NOTIF_CHANNEL, "TG WS Proxy", NotificationManager.IMPORTANCE_LOW
        )
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(ch)
    }
}
