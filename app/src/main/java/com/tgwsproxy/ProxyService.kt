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
import java.util.concurrent.TimeUnit

class ProxyService : Service() {

    companion object {
        const val TAG = "TgWsProxy"
        const val NOTIF_CHANNEL = "tgwsproxy"
        const val NOTIF_ID = 1
        const val PROXY_PORT = 1080

        val TG_DC_IPS = setOf(
            "149.154.175.50",  "149.154.175.51",  "149.154.175.100",
            "149.154.167.51",  "149.154.167.91",  "149.154.167.92",
            "149.154.167.151", "149.154.167.198", "149.154.167.220",
            "91.108.4.200",    "91.108.56.100",   "91.108.56.150",
            "91.108.56.180",   "91.108.56.190",   "91.108.8.190",
            "95.161.76.100",   "149.154.171.5",
        )

        val IP_TO_DC = mapOf(
            "149.154.175.50" to 1, "149.154.175.51" to 1, "149.154.175.100" to 1,
            "149.154.167.51" to 2, "149.154.167.91" to 2, "149.154.167.92" to 2,
            "149.154.167.151" to 2,"149.154.167.198" to 2,"149.154.167.220" to 2,
            "91.108.4.200" to 3,   "91.108.56.100" to 4,  "91.108.56.150" to 4,
            "91.108.56.180" to 4,  "91.108.56.190" to 4,  "91.108.8.190" to 5,
            "149.154.171.5" to 5,  "95.161.76.100" to 2,
        )

        const val ACTION_STATUS = "com.tgwsproxy.STATUS"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_CONNECTIONS = "connections"

        var isRunning = false
        var activeConnections = 0
    }

    private var serverJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val okHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
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

            val isTelegram = destAddr in TG_DC_IPS
            val dcId = if (isTelegram) (IP_TO_DC[destAddr] ?: 2) else -1
            Log.d(TAG, "CONNECT $destAddr:$destPort isTg=$isTelegram dc=$dcId")

            if (isTelegram) {
                val wsSuccess = tryWebSocketTunnel(client, cin, cout, dcId)
                if (!wsSuccess) directTcpRelay(client, cin, cout, destAddr, destPort)
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

    private fun tryWebSocketTunnel(client: Socket, cin: DataInputStream, cout: OutputStream, dcId: Int): Boolean {
        val wsHost = "kws${dcId}.web.telegram.org"
        Log.d(TAG, "Trying WS via $wsHost")

        val done = java.util.concurrent.CountDownLatch(1)
        var success = false
        val pipe = PipedInputStream()
        val pipeOut = PipedOutputStream(pipe)

        val request = Request.Builder()
            .url("wss://$wsHost/apiws")
            .header("Origin", "https://web.telegram.org")
            .header("Sec-WebSocket-Protocol", "binary")
            .build()

        val wsListener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WS open: $wsHost")
                success = true
                scope.launch {
                    try {
                        val buf = ByteArray(8192)
                        while (true) {
                            val n = cin.read(buf)
                            if (n < 0) break
                            webSocket.send(buf.copyOf(n).toByteString())
                        }
                    } catch (e: Exception) { Log.d(TAG, "client→ws: ${e.message}") }
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
                Log.d(TAG, "WS fail: ${t.message}"); runCatching { pipeOut.close() }; done.countDown()
            }
        }

        val ws = okHttpClient.newWebSocket(request, wsListener)
        val relayJob = scope.launch {
            try {
                val buf = ByteArray(8192)
                while (true) { val n = pipe.read(buf); if (n < 0) break; cout.write(buf, 0, n); cout.flush() }
            } catch (e: Exception) { Log.d(TAG, "ws→client: ${e.message}") }
        }

        done.await(3600, TimeUnit.SECONDS)
        relayJob.cancel()
        ws.cancel()
        return success
    }

    private fun directTcpRelay(client: Socket, cin: DataInputStream, cout: OutputStream, destAddr: String, destPort: Int) {
        try {
            val remote = Socket(destAddr, destPort)
            val t1 = scope.launch { try { cin.copyTo(remote.outputStream) } catch (_: Exception) {}; runCatching { remote.close() } }
            val t2 = scope.launch { try { remote.inputStream.copyTo(cout) } catch (_: Exception) {}; runCatching { client.close() } }
            runBlocking { t1.join(); t2.cancelAndJoin() }
        } catch (e: Exception) { Log.d(TAG, "TCP error: ${e.message}") }
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
