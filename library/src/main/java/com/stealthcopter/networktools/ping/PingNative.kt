package com.stealthcopter.networktools.ping

import com.stealthcopter.networktools.IPTools
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.max

object PingNative {
    data class StreamPingResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val firstMatchElapsedMs: Float?,
        val timedOut: Boolean
    )

    @JvmStatic
    @Throws(IOException::class, InterruptedException::class)
    fun pingOnceStream(
        hostOrAddress: String,
        ttl: Int,
        timeoutMillis: Int,
        noDns: Boolean = false,
        forceIPv6: Boolean = false,
        cancelFlag: AtomicBoolean? = null,
        setProc: ((Process?) -> Unit)? = null,
        onLine: ((isStdErr: Boolean, line: String) -> Unit)? = null
    ): StreamPingResult {
        val timeoutSeconds = max(timeoutMillis / 1000, 1)
        val preferIPv6 = forceIPv6 || IPTools.isIPv6Address(hostOrAddress) || hostOrAddress.contains(':')

        fun buildArgs(bin: String, addDash6: Boolean, withTimestamp: Boolean): Array<String> {
            val args = mutableListOf<String>()
            args += bin
            if (noDns) args += "-n"
            if (addDash6) args += "-6"
            if (withTimestamp) args += "-D"
            args += listOf(
                "-c", "1",
                "-W", timeoutSeconds.toString(),
                "-t", max(ttl, 1).toString(),
                hostOrAddress
            )
            return args.toTypedArray()
        }

        fun runStream(cmd: Array<String>): StreamPingResult {
            val startNs = System.nanoTime()
            val startWallMs = System.currentTimeMillis()
            val firstMatchNs = AtomicLong(0L)
            var rttFromTimestampMs: Float? = null

            val reFinal = Regex("""bytes from\s+[^\s(]+(?:\s+\([^)]+\))?:""", RegexOption.IGNORE_CASE)
            val reHop = Regex("""from\s+[^\s(]+(?:\s+\([^)]+\))?.*?(ttl|time to live).*?(exceeded|expired)""", RegexOption.IGNORE_CASE)
            val reUnreach = Regex("""unreachable|prohibited|filtered""", RegexOption.IGNORE_CASE)
            val reTs = Regex("""^\s*\[\s*([0-9]+(?:\.[0-9]+)?)\s*\]\s*(.*)$""")

            val proc = Runtime.getRuntime().exec(cmd)
            setProc?.invoke(proc)

            val outSb = StringBuilder()
            val errSb = StringBuilder()

            fun processLine(raw: String, isErr: Boolean, sb: StringBuilder) {
                var s = raw
                val mTs = reTs.find(raw)
                if (mTs != null) {
                    mTs.groupValues[1].toDoubleOrNull()?.let { ts ->
                        if (rttFromTimestampMs == null) {
                            val recvMs = (ts * 1000.0).toLong()
                            val delta = (recvMs - startWallMs).toFloat()
                            if (delta >= 0f) rttFromTimestampMs = delta
                        }
                    }
                    s = mTs.groupValues[2]
                }

                sb.append(s).append('\n')
                onLine?.invoke(isErr, s)

                if (firstMatchNs.get() == 0L &&
                    (reFinal.containsMatchIn(s) || reHop.containsMatchIn(s) || reUnreach.containsMatchIn(s))) {
                    if (firstMatchNs.compareAndSet(0L, System.nanoTime())) {
                        try { proc.destroy() } catch (_: Throwable) {}
                    }
                }
            }

            fun startReaderThread(`in`: InputStream, isErr: Boolean, sb: StringBuilder): Thread {
                return Thread {
                    try {
                        BufferedReader(InputStreamReader(`in`)).use { r ->
                            var line: String?
                            while (r.readLine().also { line = it } != null) {
                                val raw = line ?: continue
                                processLine(raw, isErr, sb)
                            }
                        }
                    } catch (_: Throwable) {}
                }.also { it.start() }
            }

            val outThread = startReaderThread(proc.inputStream, false, outSb)
            val errThread = startReaderThread(proc.errorStream, true, errSb)

            val deadlineNs = startNs + (timeoutMillis + 500L) * 1_000_000L
            var exit: Int? = null
            while (true) {
                if (cancelFlag?.get() == true) {
                    try { proc.destroy() } catch (_: Throwable) {}
                    break
                }
                try {
                    exit = proc.exitValue(); break
                } catch (_: IllegalThreadStateException) {}
                if (System.nanoTime() >= deadlineNs) {
                    try { proc.destroy() } catch (_: Throwable) {}
                    break
                }
                try { Thread.sleep(8) } catch (_: InterruptedException) { break }
            }

            try { outThread.join(200) } catch (_: Throwable) {}
            try { errThread.join(200) } catch (_: Throwable) {}
            setProc?.invoke(null)

            val lower = (outSb.toString() + "\n" + errSb.toString()).lowercase()
            val elapsedMatchMs = when {
                rttFromTimestampMs != null -> rttFromTimestampMs
                firstMatchNs.get() != 0L -> ((firstMatchNs.get() - startNs) / 1_000_000.0f)
                else -> null
            }
            val timedOut = elapsedMatchMs == null && (
                    lower.contains("100% packet loss") ||
                            lower.contains("no answer yet") ||
                            lower.contains("request timeout") ||
                            lower.contains("deadline exceeded")
                    )

            return StreamPingResult(
                exitCode = exit ?: -1,
                stdout = outSb.toString(),
                stderr = errSb.toString(),
                firstMatchElapsedMs = elapsedMatchMs,
                timedOut = timedOut
            )
        }

        fun needsTimestampFallback(res: StreamPingResult): Boolean {
            val lower = (res.stdout + "\n" + res.stderr).lowercase()
            return lower.contains("unknown option") ||
                    lower.contains("invalid option") ||
                    lower.contains("bad option") ||
                    (lower.contains("usage") && lower.contains("-d"))
        }

        val result: StreamPingResult = try {
            if (preferIPv6) {
                try {
                    val r = runStream(buildArgs("ping6", addDash6 = false, withTimestamp = true))
                    if (needsTimestampFallback(r)) runStream(buildArgs("ping6", addDash6 = false, withTimestamp = false)) else r
                } catch (_: IOException) {
                    val r = runStream(buildArgs("ping", addDash6 = true, withTimestamp = true))
                    if (needsTimestampFallback(r)) runStream(buildArgs("ping", addDash6 = true, withTimestamp = false)) else r
                }
            } else {
                val r = runStream(buildArgs("ping", addDash6 = false, withTimestamp = true))
                if (needsTimestampFallback(r)) runStream(buildArgs("ping", addDash6 = false, withTimestamp = false)) else r
            }
        } finally {
            setProc?.invoke(null)
        }

        return result
    }

    @JvmStatic
    @Throws(IOException::class, InterruptedException::class)
    fun ping(host: InetAddress?, pingOptions: PingOptions): PingResult {
        val pingResult = host?.let { PingResult(it) }
        if (host == null) {
            pingResult?.isReachable = false
            return pingResult!!
        }
        val echo = StringBuilder()
        val runtime = Runtime.getRuntime()
        val timeoutSeconds = max(pingOptions.getTimeoutMillis() / 1000, 1)
        val ttl = max(pingOptions.getTimeToLive(), 1)
        var address = host.hostAddress
        var pingCommand = "ping"
        if (address != null) {
            if (IPTools.isIPv6Address(address)) {
                // If we detect this is a IPv6 address, change the to the ping6 binary
                pingCommand = "ping6"
            } else if (!IPTools.isIPv4Address(address)) {
                // Address doesn't look to be IPv4 or IPv6, but we could be mistaken
            }
        } else {
            // Use the hostname as a fallback
            address = host.hostName
        }
        val proc = runtime.exec("$pingCommand -c 1 -W $timeoutSeconds -t $ttl $address")
        proc.waitFor()
        val exit = proc.exitValue()
        val pingError: String
        when (exit) {
            0 -> {
                val reader = InputStreamReader(proc.inputStream)
                val buffer = BufferedReader(reader)
                var line: String?
                while (buffer.readLine().also { line = it } != null) echo.append(line).append("\n")
                return pingResult?.let { getPingStats(it, echo.toString()) }!!
            }
            1 -> pingError = "failed, exit = 1"
            else -> pingError = "error, exit = 2"
        }
        pingResult?.error = pingError
        proc.destroy()
        return pingResult!!
    }

    /**
     * getPingStats interprets the text result of a Linux activity_ping command
     *
     * Set pingError on error and return null
     *
     * http://en.wikipedia.org/wiki/Ping
     *
     * PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
     * 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.251 ms
     * 64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.294 ms
     * 64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.295 ms
     * 64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.300 ms
     *
     * --- 127.0.0.1 activity_ping statistics ---
     * 4 packets transmitted, 4 received, 0% packet loss, time 0ms
     * rtt min/avg/max/mdev = 0.251/0.285/0.300/0.019 ms
     *
     * PING 192.168.0.2 (192.168.0.2) 56(84) bytes of data.
     *
     * --- 192.168.0.2 activity_ping statistics ---
     * 1 packets transmitted, 0 received, 100% packet loss, time 0ms
     *
     * # activity_ping 321321.
     * activity_ping: unknown host 321321.
     *
     * 1. Check if output contains 0% packet loss : Branch to success - Get stats
     * 2. Check if output contains 100% packet loss : Branch to fail - No stats
     * 3. Check if output contains 25% packet loss : Branch to partial success - Get stats
     * 4. Check if output contains "unknown host"
     *
     * @param pingResult - the current ping result
     * @param s - result from ping command
     *
     * @return The ping result
     */
    fun getPingStats(pingResult: PingResult, s: String): PingResult {
        var s = s
        val pingError: String
        if (s.contains("0% packet loss")) {
            val start = s.indexOf("/mdev = ")
            val end = s.indexOf(" ms\n", start)
            pingResult.fullString = s
            if (start == -1 || end == -1) {
                pingError = "Error: $s"
            } else {
                s = s.substring(start + 8, end)
                val stats = s.split("/".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                pingResult.isReachable = true
                pingResult.result = s
                pingResult.timeTaken = stats[1].toFloat()
                return pingResult
            }
        } else if (s.contains("100% packet loss")) {
            pingError = "100% packet loss"
        } else if (s.contains("% packet loss")) {
            pingError = "partial packet loss"
        } else if (s.contains("unknown host")) {
            pingError = "unknown host"
        } else {
            pingError = "unknown error in getPingStats"
        }
        pingResult.error = pingError
        return pingResult
    }
}