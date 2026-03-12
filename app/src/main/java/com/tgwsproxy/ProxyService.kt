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
import kotlinx.coroutines.selects.select
import java.io.*
import java.net.*
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.*

class ProxyService : Service() {

    companion object {
        const val TAG = "TgWsProxy"
        const val NOTIF_CHANNEL = "tgwsproxy"
        const val NOTIF_ID = 1
        const val PROXY_PORT = 1080
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA

        private val TG_RANGES = listOf(
            Pair(ipToLong("149.154.160.0"), ipToLong("149.154.175.255")),
            Pair(ipToLong("91.108.0.0"),    ipToLong("91.108.255.255")),
            Pair(ipToLong("91.105.192.0"),  ipToLong("91.105.193.255")),
            Pair(ipToLong("185.76.151.0"),  ipToLong("185.76.151.255")),
        )

        // Из логов Android Telegram активно использует IPv6-адреса вида
        // 2001:67c:4e8:f004::a / ::b (иначе уходят в медленный passthrough).
        private val TG_IPV6_PREFIXES = listOf(
            "2001:67c:4e8:f004:"
        )

        // IP → (dcId, isMedia)
        private val IP_TO_DC: Map<String, Pair<Int, Boolean>> = mapOf(
            "149.154.175.50"  to Pair(1, false), "149.154.175.51" to Pair(1, false),
            "149.154.175.54"  to Pair(1, false),
            "149.154.167.41"  to Pair(2, false), "149.154.167.50" to Pair(2, false),
            "149.154.167.51"  to Pair(2, false), "149.154.167.220" to Pair(2, false),
            "149.154.167.151" to Pair(2, true),  "149.154.167.223" to Pair(2, true),
            "149.154.165.111" to Pair(2, true),
            "149.154.175.100" to Pair(3, false), "149.154.175.101" to Pair(3, false),
            "149.154.167.91"  to Pair(4, false), "149.154.167.92"  to Pair(4, false),
            "149.154.166.120" to Pair(4, true),  "149.154.166.121" to Pair(4, true),
            "91.108.56.100"   to Pair(5, false), "91.108.56.101"   to Pair(5, false),
            "91.108.56.116"   to Pair(5, false), "91.108.56.126"   to Pair(5, false),
        )

        private const val TUNNEL_IP = "149.154.167.220"

        const val ACTION_STATUS = "com.tgwsproxy.STATUS"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_CONNECTIONS = "connections"

        var isRunning = false
        var activeConnections = 0

        private const val WS_FAIL_COOLDOWN_MS = 60_000L
        private val wsDcBlacklist = ConcurrentHashMap.newKeySet<String>()
        private val wsDcFailUntil = ConcurrentHashMap<String, Long>()

        fun wsDcKey(dc: Int, isMedia: Boolean): String = "$dc:${if (isMedia) 1 else 0}"

        fun ipToLong(ip: String): Long =
            ip.split(".").fold(0L) { acc, s -> (acc shl 8) or s.toLong() }

        fun isTelegramIp(ip: String): Boolean {
            if (ip.contains(':')) {
                val normalized = ip.lowercase()
                return TG_IPV6_PREFIXES.any { normalized.startsWith(it) }
            }
            return try {
                val n = ipToLong(ip)
                TG_RANGES.any { (lo, hi) -> n in lo..hi }
            } catch (_: Exception) { false }
        }

        fun isHttpTransport(data: ByteArray): Boolean {
            if (data.size < 5) return false
            val s = data.copyOf(8).toString(Charsets.ISO_8859_1)
            return s.startsWith("POST ") || s.startsWith("GET ") ||
                   s.startsWith("HEAD ") || s.startsWith("OPTIONS ")
        }

        fun getDcInfoForIp(ip: String): Pair<Int, Boolean> {
            IP_TO_DC[ip]?.let { return it }

            if (ip.contains(':')) {
                val normalized = ip.lowercase()
                if (normalized.startsWith("2001:67c:4e8:f004:")) {
                    // Для IPv6 Telegram не всегда очевидно media/non-media,
                    // поэтому используем DC2 как стабильный базовый роут,
                    // а media уточнится из dcFromInit (если возможно).
                    return Pair(2, false)
                }
            }

            val dc = when {
                ip.startsWith("149.154.175.") -> 1
                ip.startsWith("149.154.167.") -> 2
                ip.startsWith("149.154.165.") -> 2
                ip.startsWith("149.154.166.") -> 4
                ip.startsWith("91.108.56.")   -> 5
                else -> 2
            }
            val isMedia = ip.startsWith("149.154.165.") || ip.startsWith("149.154.166.")
            return Pair(dc, isMedia)
        }

        fun resolveToSupportedDc(dc: Int): Int = when {
            dc in 1..5 -> dc
            dc > 5 -> dc
            else -> 2
        }

        fun dcFromInit(data: ByteArray): Pair<Int, Boolean>? {
            if (data.size < 64) return null
            return try {
                val key = data.copyOfRange(8, 40)
                val iv  = data.copyOfRange(40, 56)
                val cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(
                    javax.crypto.Cipher.ENCRYPT_MODE,
                    javax.crypto.spec.SecretKeySpec(key, "AES"),
                    javax.crypto.spec.IvParameterSpec(iv)
                )
                val ks = cipher.update(ByteArray(64))
                val plain = ByteArray(8) { i -> (data[56+i].toInt() xor ks[56+i].toInt()).toByte() }
                val proto = (plain[0].toInt() and 0xFF) or ((plain[1].toInt() and 0xFF) shl 8) or
                            ((plain[2].toInt() and 0xFF) shl 16) or ((plain[3].toInt() and 0xFF) shl 24)
                val dcRaw = ((plain[4].toInt() and 0xFF) or ((plain[5].toInt() and 0xFF) shl 8))
                              .toShort().toInt()
                Log.d(TAG, "dcFromInit proto=0x${proto.toLong().and(0xFFFFFFFFL).toString(16)} dc_raw=$dcRaw")
                val validProtos = setOf(0xEFEFEFEF.toInt(), 0xEEEEEEEE.toInt(), 0xDDDDDDDD.toInt())
                if (proto in validProtos) {
                    val dc = Math.abs(dcRaw)
                    // На практике корректные DC для этого транспорта обычно 1..5.
                    // Значения вроде 9515/27628 — шум, их нельзя принимать.
                    if (dc in 1..5) return Pair(dc, dcRaw < 0)
                }
                null
            } catch (e: Exception) { null }
        }

        fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
            val base = if (dc > 5) "telegram.org" else "web.telegram.org"
            return if (isMedia) listOf("kws$dc-1.$base", "kws$dc.$base")
            else listOf("kws$dc.$base", "kws$dc-1.$base")
        }

        // TrustAll SSL context — как ssl_ctx с verify_mode=CERT_NONE в Python
        val trustAllSslContext: SSLContext by lazy {
            val tm = object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
            SSLContext.getInstance("TLS").also { it.init(null, arrayOf(tm), SecureRandom()) }
        }

        val trustAllHostname = HostnameVerifier { _, _ -> true }
    }

    // -------------------------------------------------------------------------
    // RawWebSocket — точный порт Python класса RawWebSocket
    // Подключается напрямую к IP:443 с TLS SNI=domain, делает HTTP Upgrade,
    // предоставляет send()/recv() для бинарных фреймов с маскировкой
    // -------------------------------------------------------------------------
    inner class RawWebSocket(private val input: InputStream, private val output: OutputStream) {


        private val rng = SecureRandom()

        // Отправить бинарный фрейм с маской (как клиент → сервер)
        fun send(data: ByteArray) {
            val frame = buildFrame(OP_BINARY, data, mask = true)
            output.write(frame)
            output.flush()
        }

        // Получить следующий data-фрейм. Ping/Pong/Close обрабатываются внутри.
        // Поддерживает fragmented WebSocket frames (opcode=0 continuation).
        // Возвращает null при закрытии соединения.
        fun recv(): ByteArray? {
            var fragmentedOpcode = -1
            var fragmentedPayload: ByteArrayOutputStream? = null

            while (true) {
                val frame = readFrame()
                val opcode = frame.first
                val payload = frame.second
                val fin = frame.third

                when (opcode) {
                    OP_BINARY, 0x1 -> {
                        if (fin) return payload
                        fragmentedOpcode = opcode
                        fragmentedPayload = ByteArrayOutputStream().also { it.write(payload) }
                    }
                    0x0 -> {
                        val acc = fragmentedPayload
                        if (acc == null) {
                            // continuation без стартового фрейма — игнорируем
                        } else {
                            acc.write(payload)
                            if (fin) {
                            val op = fragmentedOpcode
                            fragmentedOpcode = -1
                            fragmentedPayload = null
                                if (op == OP_BINARY || op == 0x1) return acc.toByteArray()
                            }
                        }
                    }
                    OP_CLOSE -> {
                        runCatching {
                            output.write(buildFrame(OP_CLOSE, if (payload.size >= 2) payload.copyOf(2) else byteArrayOf(), mask = true))
                            output.flush()
                        }
                        return null
                    }
                    OP_PING -> {
                        runCatching {
                            output.write(buildFrame(OP_PONG, payload, mask = true))
                            output.flush()
                        }
                    }
                    OP_PONG -> { /* игнорируем */ }
                    else -> { /* неизвестный opcode — пропускаем */ }
                }
            }
        }

        private fun buildFrame(opcode: Int, data: ByteArray, mask: Boolean): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(0x80 or opcode) // FIN=1
            val len = data.size
            val maskBit = if (mask) 0x80 else 0x00
            when {
                len < 126   -> out.write(maskBit or len)
                len < 65536 -> { out.write(maskBit or 126); out.write((len shr 8) and 0xFF); out.write(len and 0xFF) }
                else        -> {
                    out.write(maskBit or 127)
                    for (i in 7 downTo 0) out.write(((len.toLong() shr (i * 8)) and 0xFF).toInt())
                }
            }
            if (mask) {
                val maskKey = ByteArray(4).also { rng.nextBytes(it) }
                out.write(maskKey)
                val masked = ByteArray(data.size) { i -> (data[i].toInt() xor maskKey[i and 3].toInt()).toByte() }
                out.write(masked)
            } else {
                out.write(data)
            }
            return out.toByteArray()
        }

        private fun readFrame(): Triple<Int, ByteArray, Boolean> {
            val b0 = input.read()
            val b1 = input.read()
            if (b0 < 0 || b1 < 0) throw EOFException("WS connection closed")

            val fin = (b0 and 0x80) != 0
            val opcode = b0 and 0x0F
            val isMasked = (b1 and 0x80) != 0

            var length = (b1 and 0x7F).toLong()
            if (length == 126L) {
                val x0 = input.read(); val x1 = input.read()
                if (x0 < 0 || x1 < 0) throw EOFException("Unexpected EOF reading WS frame length")
                length = ((x0 shl 8) or x1).toLong()
            } else if (length == 127L) {
                length = 0L
                repeat(8) {
                    val b = input.read()
                    if (b < 0) throw EOFException("Unexpected EOF reading WS frame length")
                    length = (length shl 8) or b.toLong()
                }
            }

            if (length > Int.MAX_VALUE) throw IOException("WS frame too large: $length")

            val maskKey = if (isMasked) ByteArray(4).also { input.readNBytes(it, 0, 4) } else null
            val payload = ByteArray(length.toInt()).also { input.readNBytes(it, 0, it.size) }
            if (maskKey != null) {
                for (i in payload.indices) payload[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
            }
            return Triple(opcode, payload, fin)
        }

        private fun InputStream.readNBytes(buf: ByteArray, off: Int, len: Int) {
            var read = 0
            while (read < len) {
                val n = this.read(buf, off + read, len - read)
                if (n < 0) throw EOFException("Unexpected EOF reading WS frame")
                read += n
            }
        }
    }


    // Читаем HTTP заголовок побайтово — не используем BufferedReader чтобы не съесть WS данные
    private fun readHttpLine(inp: InputStream): String {
        val sb = StringBuilder()
        var prev = -1
        while (true) {
            val b = inp.read()
            if (b < 0) break
            if (prev == '\r'.code && b == '\n'.code) { sb.deleteCharAt(sb.length - 1); break }
            if (b == '\n'.code) break
            sb.append(b.toChar())
            prev = b
        }
        return sb.toString().trim()
    }

        private data class WsConnectResult(val ws: RawWebSocket?, val statusCode: Int)

    // Устанавливает WS соединение: TCP+TLS к targetIp:443 с SNI=domain, HTTP Upgrade
    // Возвращает RawWebSocket + HTTP status code (если удалось прочитать HTTP-ответ)
    private fun wsConnect(targetIp: String, domain: String): WsConnectResult {
        return try {
            val sock = Socket()
            sock.tcpNoDelay = true
            sock.keepAlive = true
            sock.connect(InetSocketAddress(targetIp, 443), 10_000)
            sock.soTimeout = 0 // бесконечный — как в Python

            val sslSock = trustAllSslContext.socketFactory
                .createSocket(sock, domain, 443, true) as SSLSocket
            sslSock.enabledProtocols = sslSock.supportedProtocols
                .filter { it.startsWith("TLS") }.toTypedArray()
            val params = sslSock.sslParameters
            params.serverNames = listOf(SNIHostName(domain))
            sslSock.sslParameters = params
            sslSock.startHandshake()

            val rawIn  = sslSock.inputStream
            val rawOut = BufferedOutputStream(sslSock.outputStream)

            // HTTP Upgrade запрос — точно как в Python RawWebSocket.connect()
            val wsKey = java.util.Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
            val req = buildString {
                append("GET /apiws HTTP/1.1\r\n")
                append("Host: $domain\r\n")
                append("Upgrade: websocket\r\n")
                append("Connection: Upgrade\r\n")
                append("Sec-WebSocket-Key: $wsKey\r\n")
                append("Sec-WebSocket-Version: 13\r\n")
                append("Sec-WebSocket-Protocol: binary\r\n")
                append("Origin: https://web.telegram.org\r\n")
                append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n")
                append("\r\n")
            }
            rawOut.write(req.toByteArray())
            rawOut.flush()

            // Читаем HTTP ответ побайтово (не BufferedReader!) чтобы не съесть WS данные
            val firstLine = readHttpLine(rawIn)
            Log.d(TAG, "WS handshake response: $firstLine for $domain")

            val statusCode = firstLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0
            if (statusCode != 101) {
                Log.w(TAG, "WS handshake failed: $firstLine for $domain")
                while (true) { val line = readHttpLine(rawIn); if (line.isEmpty()) break }
                return WsConnectResult(null, statusCode)
            }
            // Читаем оставшиеся заголовки до пустой строки
            while (true) { val line = readHttpLine(rawIn); if (line.isEmpty()) break }

            Log.i(TAG, "WS connected: $domain via $targetIp")
            WsConnectResult(RawWebSocket(rawIn, rawOut), 101)
        } catch (e: Exception) {
            Log.d(TAG, "WS connect failed $domain: ${e.message}")
            WsConnectResult(null, 0)
        }
    }

    // -------------------------------------------------------------------------

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

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
            client.soTimeout = 15_000
            val cin  = DataInputStream(client.getInputStream())
            val cout = client.getOutputStream()

            // SOCKS5 greeting
            if ((cin.readByte().toInt() and 0xFF) != 5) { client.close(); return@withContext }
            val nm = cin.readByte().toInt() and 0xFF; repeat(nm) { cin.readByte() }
            cout.write(byteArrayOf(0x05, 0x00)); cout.flush()

            // SOCKS5 CONNECT
            cin.readByte()
            val cmd  = cin.readByte().toInt() and 0xFF
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
                    val db  = ByteArray(len); cin.readFully(db)
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
                    val remote = withTimeoutOrNull(10_000) {
                        withContext(Dispatchers.IO) {
                            Socket(destAddr, destPort).also {
                                it.tcpNoDelay = true
                                it.keepAlive = true
                            }
                        }
                    }
                        ?: run { cout.write(socks5Reply(0x05)); cout.flush(); client.close(); return@withContext }
                    cout.write(socks5Reply(0x00)); cout.flush()
                    directBridge(client, cin, cout, remote)
                } catch (e: Exception) {
                    runCatching { cout.write(socks5Reply(0x05)); cout.flush() }
                    client.close()
                }
                return@withContext
            }

            // Telegram → success, читаем 64-байтный MTProto init
            cout.write(socks5Reply(0x00)); cout.flush()
            val init = ByteArray(64)
            try { cin.readFully(init) } catch (e: Exception) {
                Log.d(TAG, "init read failed for $destAddr: ${e.message}"); return@withContext
            }
            if (isHttpTransport(init)) { client.close(); return@withContext }

            // Снимаем таймаут — туннель может быть idle
            client.soTimeout = 0

            // Определяем DC и isMedia.
            // По логам dcFromInit иногда дает мусорные значения, поэтому baseline берем из IP.
            val ipInfo = getDcInfoForIp(destAddr)
            val initResult = dcFromInit(init)
            val rawDc: Int
            val isMedia: Boolean
            if (initResult != null && initResult.first == ipInfo.first && initResult.second == ipInfo.second) {
                rawDc = initResult.first
                isMedia = initResult.second
                Log.d(TAG, "dcFromInit confirmed: DC$rawDc isMedia=$isMedia for $destAddr")
            } else {
                rawDc = ipInfo.first
                isMedia = ipInfo.second
                if (initResult != null) {
                    Log.d(TAG, "dcFromInit mismatch (init=DC${initResult.first} media=${initResult.second}, ip=DC${ipInfo.first} media=${ipInfo.second}) for $destAddr; using IP")
                } else {
                    Log.d(TAG, "IP fallback: DC$rawDc isMedia=$isMedia for $destAddr")
                }
            }

            val dcId     = resolveToSupportedDc(rawDc)
            val mediaTag = if (isMedia) " media" else ""
            Log.i(TAG, "→ DC$dcId$mediaTag (raw=$rawDc) for $destAddr:$destPort")

            // Пробуем WebSocket через RawWebSocket
            val dcKey = wsDcKey(dcId, isMedia)
            val now = System.currentTimeMillis()
            if (wsDcBlacklist.contains(dcKey)) {
                Log.w(TAG, "WS blacklisted for DC$dcId$mediaTag → TCP $destAddr:$destPort")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
                return@withContext
            }
            val failUntil = wsDcFailUntil[dcKey] ?: 0L
            if (now < failUntil) {
                val left = (failUntil - now) / 1000
                Log.d(TAG, "WS cooldown for DC$dcId$mediaTag (${left}s left) → TCP $destAddr:$destPort")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
                return@withContext
            }

            val domains = wsDomains(dcId, isMedia)
            var wsOk = false
            var sawRedirect = false
            var allRedirects = true
            for (domain in domains) {
                Log.d(TAG, "  trying wss://$domain via $TUNNEL_IP")
                val result = wsConnect(TUNNEL_IP, domain)
                val ws = result.ws
                if (ws != null) {
                    wsOk = true
                    wsDcFailUntil.remove(dcKey)
                    bridgeWs(cin, cout, ws, init, domain)
                    break
                }
                if (result.statusCode in 300..399) {
                    sawRedirect = true
                } else {
                    allRedirects = false
                }
            }

            // Если этот DC отдаёт редиректы (302), пробуем стабильный fallback-DC через WS,
            // чтобы не скатываться сразу в медленный прямой TCP.
            if (!wsOk && sawRedirect) {
                val fallbackDc = when (dcId) {
                    1, 3 -> 2
                    5 -> 4
                    else -> dcId
                }
                if (fallbackDc != dcId) {
                    val fallbackDomains = wsDomains(fallbackDc, isMedia)
                    for (domain in fallbackDomains) {
                        Log.d(TAG, "  redirect-fallback trying wss://$domain via $TUNNEL_IP")
                        val result = wsConnect(TUNNEL_IP, domain)
                        val ws = result.ws
                        if (ws != null) {
                            wsOk = true
                            wsDcFailUntil.remove(dcKey)
                            Log.i(TAG, "WS redirect-fallback DC$dcId -> DC$fallbackDc via $domain")
                            bridgeWs(cin, cout, ws, init, domain)
                            break
                        }
                    }
                }
            }

            if (!wsOk) {
                if (sawRedirect && allRedirects) {
                    wsDcBlacklist.add(dcKey)
                    Log.w(TAG, "WS blacklisting DC$dcId$mediaTag after redirects")
                }
                wsDcFailUntil[dcKey] = System.currentTimeMillis() + WS_FAIL_COOLDOWN_MS
                Log.w(TAG, "WS failed DC$dcId$mediaTag → TCP $destAddr:$destPort")
                directTcpRelay(client, cin, cout, destAddr, destPort, init)
            }
        } catch (e: CancellationException) {
            Log.d(TAG, "handleClient cancelled")
        } catch (e: EOFException) {
            Log.d(TAG, "handleClient EOF: ${e.message ?: "closed"}")
        } catch (e: SocketException) {
            Log.d(TAG, "handleClient socket: ${e.message ?: "closed"}")
        } catch (e: Exception) {
            val msg = e.message ?: "no-message"
            Log.d(TAG, "handleClient ${e.javaClass.simpleName.lowercase()}: $msg")
        } finally {
            activeConnections--; broadcastStatus(); runCatching { client.close() }
        }
    }

    // Двунаправленный bridge: TCP клиент ↔ RawWebSocket
    // Точный порт Python _bridge_ws()
    private suspend fun bridgeWs(
        cin: DataInputStream, cout: OutputStream,
        ws: RawWebSocket, init: ByteArray, domain: String
    ) = withContext(Dispatchers.IO) {
        // Отправляем init сразу после открытия — как Python: await ws.send(init)
        try { ws.send(init) } catch (e: Exception) {
            Log.d(TAG, "WS send init failed: ${e.message}"); return@withContext
        }

        try {
            coroutineScope {
                val tcpToWs = launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(65536)
                        while (true) {
                            val n = cin.read(buf)
                            if (n < 0) break
                            ws.send(buf.copyOf(n))
                        }
                    } catch (_: Exception) {
                    }
                }

                val wsToTcp = launch(Dispatchers.IO) {
                    try {
                        while (true) {
                            val data = ws.recv() ?: break
                            cout.write(data)
                            cout.flush()
                        }
                    } catch (_: Exception) {
                    }
                }

                // Ждем, пока завершится любая сторона моста, затем останавливаем вторую.
                select<Unit> {
                    tcpToWs.onJoin { }
                    wsToTcp.onJoin { }
                }
                tcpToWs.cancelAndJoin()
                wsToTcp.cancelAndJoin()
            }
        } catch (_: Exception) {
        }
        Log.d(TAG, "WS bridge closed: $domain")
    }

    private fun directTcpRelay(
        client: Socket, cin: DataInputStream, cout: OutputStream,
        destAddr: String, destPort: Int, init: ByteArray?
    ) {
        try {
            val remote = Socket(destAddr, destPort)
            remote.tcpNoDelay = true
            remote.keepAlive = true
            if (init != null) { remote.outputStream.write(init); remote.outputStream.flush() }
            val t1 = scope.launch(Dispatchers.IO) {
                try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}
                runCatching { remote.close() }
            }
            val t2 = scope.launch(Dispatchers.IO) {
                try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}
                runCatching { client.close() }
            }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) { Log.d(TAG, "TCP relay error $destAddr: ${e.message}") }
    }

    private fun directBridge(client: Socket, cin: DataInputStream, cout: OutputStream, remote: Socket) {
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

    private fun socks5Reply(status: Int): ByteArray =
        byteArrayOf(0x05, status.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

    private fun broadcastStatus() {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING, isRunning); putExtra(EXTRA_CONNECTIONS, activeConnections)
        })
        if (isRunning) {
            val text = if (activeConnections > 0) "Активных: $activeConnections" else "Запущен • порт $PROXY_PORT"
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIF_ID, buildNotification(text))
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
