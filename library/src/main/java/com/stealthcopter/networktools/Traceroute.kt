package com.stealthcopter.networktools

import com.stealthcopter.networktools.ping.PingNative
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.ceil
import kotlin.math.max

class Traceroute private constructor(
    private val target: String,
    private val maxTtl: Int,
    private val timeoutPerProbeMs: Int,
    private val attemptsPerHop: Int,
    private val resolveDns: Boolean,
    private val useIPv6: Boolean,
    private val interHopDelayMs: Int,
    private val pingBinary: String?,
    private val extraArgs: List<String>
) {

    data class HopResult(
        val ttl: Int,
        val host: String?,
        val ip: String?,
        val rttMs: Float?,
        val isTimeout: Boolean,
        val isFinal: Boolean
    )

    interface Listener {
        fun onHop(result: HopResult) {}
        fun onFinished(results: List<HopResult>, reachedTarget: Boolean) {}
        fun onError(error: Throwable) {}
    }

    class Session internal constructor(
        private val cancelFlag: AtomicBoolean,
        private val currentProc: () -> Process?,
        private val worker: Future<*>
    ) {
        fun cancel() {
            cancelFlag.set(true)
            try { currentProc()?.destroy() } catch (_: Throwable) {}
            try { worker.cancel(true) } catch (_: Throwable) {}
        }
    }

    fun start(listener: Listener): Session {
        val cancelFlag = AtomicBoolean(false)
        val procRef = AtomicReference<Process?>(null)
        val worker = Executors.newSingleThreadExecutor().submit {
            try {
                val results = runInternal(cancelFlag, { p -> procRef.set(p) }, listener)
                val reached = results.any { it.isFinal }
                if (!cancelFlag.get()) listener.onFinished(results, reached)
            } catch (t: Throwable) {
                if (!cancelFlag.get()) listener.onError(t)
            }
        }
        return Session(cancelFlag, { procRef.get() }, worker)
    }

    fun runBlocking(): List<HopResult> =
        runInternal(AtomicBoolean(false), { /* no-op */ }, null)

    private fun runInternal(
        cancelFlag: AtomicBoolean,
        setProc: (Process?) -> Unit,
        progress: Listener? = null
    ): List<HopResult> {
        val results = mutableListOf<HopResult>()
        val canUsePingNative = pingBinary.isNullOrBlank() && extraArgs.isEmpty()
        val cmdBase = if (canUsePingNative) emptyList() else buildCmdBase()

        for (ttl in 1..maxTtl) {
            if (cancelFlag.get()) break

            var hopResult: HopResult? = null
            var lastError: Throwable? = null

            repeat(max(1, attemptsPerHop)) attempt@{
                if (cancelFlag.get()) return@attempt
                val start = System.nanoTime()

                val probe = if (canUsePingNative) {
                    // API 21-safe path using ping -W
                    try {
                        val raw = PingNative.pingOnceRaw(
                            hostOrAddress = target,
                            ttl = ttl,
                            timeoutMillis = timeoutPerProbeMs,
                            noDns = !resolveDns,
                            forceIPv6 = useIPv6
                        )
                        ProcResult(raw.exitCode, raw.stdout, raw.stderr, timedOut = false)
                    } catch (t: Throwable) {
                        ProcResult(-2, "", t.message ?: "", timedOut = false, exception = t)
                    }
                } else {
                    // Custom binary/args path with actual host-side timeout
                    val cmd = buildCmdForTtl(cmdBase, ttl)
                    runPingWithTimeoutCompat(cmd, timeoutPerProbeMs.toLong(), cancelFlag, setProc)
                }

                val elapsedMs = ((System.nanoTime() - start) / 1_000_000.0).toFloat()
                val parsed = parsePingOutput(probe.stdout, probe.stderr, elapsedMs)

                when (parsed.kind) {
                    ParseKind.Final -> {
                        hopResult = HopResult(
                            ttl = ttl,
                            host = parsed.host,
                            ip = parsed.ip,
                            rttMs = parsed.rttMs ?: elapsedMs,
                            isTimeout = false,
                            isFinal = true
                        )
                        return@attempt
                    }
                    ParseKind.Hop -> {
                        hopResult = HopResult(
                            ttl = ttl,
                            host = parsed.host,
                            ip = parsed.ip,
                            rttMs = parsed.rttMs ?: elapsedMs,
                            isTimeout = false,
                            isFinal = false
                        )
                        return@attempt
                    }
                    ParseKind.Timeout -> {
                        hopResult = HopResult(
                            ttl = ttl,
                            host = null,
                            ip = null,
                            rttMs = null,
                            isTimeout = true,
                            isFinal = false
                        )
                        // try next attempt
                    }
                    ParseKind.Error -> {
                        lastError = parsed.error
                        // try next attempt
                    }
                }
            }

            val finalHop = hopResult ?: HopResult(ttl, null, null, null, isTimeout = true, isFinal = false)
            results.add(finalHop)

            if (!cancelFlag.get()) {
                try { progress?.onHop(finalHop) } catch (_: Throwable) {}
            }

            if (finalHop.isFinal) break
            if (interHopDelayMs > 0 && !cancelFlag.get()) {
                try { Thread.sleep(interHopDelayMs.toLong()) } catch (_: InterruptedException) {}
            }
        }
        return results
    }

    private fun buildCmdBase(): MutableList<String> {
        val base = mutableListOf<String>()
        val bin = pingBinary ?: defaultPingBinary()
        base += bin

        // Force IPv6 when requested and binary is iputils ping
        if (useIPv6 && bin.endsWith("ping")) {
            base += "-6"
        }

        if (!resolveDns) base += "-n"
        base.addAll(extraArgs)
        return base
    }

    private fun buildCmdForTtl(base: List<String>, ttl: Int): List<String> {
        val sec = max(1, ceil(timeoutPerProbeMs / 1000.0).toInt())
        val out = ArrayList<String>(base.size + 8)
        out.addAll(base)
        out += listOf(
            "-c", "1",
            "-t", ttl.toString(),
            "-W", sec.toString(),
            target
        )
        return out
    }

    private fun defaultPingBinary(): String {
        // Prefer /system/bin/ping; add -6 flag if needed rather than assuming ping6 exists
        return "/system/bin/ping"
    }

    private fun runPingWithTimeoutCompat(
        cmd: List<String>,
        waitMs: Long,
        cancelFlag: AtomicBoolean,
        setProc: (Process?) -> Unit
    ): ProcResult {
        var proc: Process? = null
        var pool: ExecutorService? = null
        try {
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(false)
            proc = pb.start()
            setProc(proc)

            val outSb = StringBuilder()
            val errSb = StringBuilder()
            val outThread = Thread {
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { r ->
                        var line: String?
                        while (r.readLine().also { line = it } != null) outSb.append(line).append('\n')
                    }
                } catch (_: Throwable) {}
            }
            val errThread = Thread {
                try {
                    BufferedReader(InputStreamReader(proc.errorStream)).use { r ->
                        var line: String?
                        while (r.readLine().also { line = it } != null) errSb.append(line).append('\n')
                    }
                } catch (_: Throwable) {}
            }
            outThread.start()
            errThread.start()

            pool = Executors.newSingleThreadExecutor()
            val future = pool.submit(Callable {
                try {
                    proc.waitFor()
                    proc.exitValue()
                } catch (_: Throwable) {
                    -2
                }
            })

            val finished = if (waitMs > 0) {
                try {
                    future.get(waitMs + 300L, TimeUnit.MILLISECONDS)
                    true
                } catch (_: TimeoutException) {
                    try { proc.destroy() } catch (_: Throwable) {}
                    future.cancel(true)
                    false
                }
            } else {
                future.get()
                true
            }

            try { outThread.join(200) } catch (_: Throwable) {}
            try { errThread.join(200) } catch (_: Throwable) {}

            if (!finished) {
                return ProcResult(-1, outSb.toString(), errSb.toString(), timedOut = true)
            }
            return ProcResult(proc.exitValue(), outSb.toString(), errSb.toString(), timedOut = false)
        } catch (t: Throwable) {
            if (!cancelFlag.get()) {
                return ProcResult(-2, "", t.message ?: "", timedOut = false, exception = t)
            }
            return ProcResult(-2, "", "canceled", timedOut = false)
        } finally {
            try { pool?.shutdownNow() } catch (_: Throwable) {}
            setProc(null)
        }
    }

    private data class ProcResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val timedOut: Boolean,
        val exception: Throwable? = null
    )

    private data class Parsed(
        val kind: ParseKind,
        val host: String? = null,
        val ip: String? = null,
        val rttMs: Float? = null,
        val error: Throwable? = null
    )
    private enum class ParseKind { Hop, Final, Timeout, Error }

    private fun parsePingOutput(stdout: String, stderr: String, elapsedMs: Float): Parsed {
        val text = stdout + "\n" + stderr
        val lower = text.lowercase()

        // Final: "bytes from name (ip): ... time=xx ms" OR "bytes from ip: ... time=xx ms"
        run {
            val re = Regex(
                "bytes from\\s+([^\\s(]+)(?:\\s+\\(([^)]+)\\))?:.*?\\btime[=<]?\\s*([0-9.]+)\\s*ms",
                RegexOption.IGNORE_CASE
            )
            val m = re.find(text)
            if (m != null) {
                val hostTok = m.groupValues.getOrNull(1)?.trim()
                val ipTok = m.groupValues.getOrNull(2)?.trim()
                val timeTok = m.groupValues.getOrNull(3)?.trim()
                val ip = ipTok ?: hostTok
                val rtt = timeTok?.toFloatOrNull() ?: elapsedMs
                return Parsed(ParseKind.Final, host = hostTok, ip = ip, rttMs = rtt)
            }
        }

        // TTL exceeded hop:
        // "From router (192.168.1.1) ... Time to live exceeded"
        // "From 192.168.1.1 ... ttl expired in transit"
        run {
            val re = Regex(
                "^From\\s+([^\\s(]+)(?:\\s+\\(([^)]+)\\))?.*?(ttl|time to live).*?(exceeded|expired)",
                setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)
            )
            val m = re.find(text)
            if (m != null) {
                val hostTok = m.groupValues.getOrNull(1)?.trim()
                val ipTok = m.groupValues.getOrNull(2)?.trim()
                val ip = ipTok ?: hostTok
                return Parsed(ParseKind.Hop, host = hostTok, ip = ip, rttMs = elapsedMs)
            }
        }

        // Destination unreachable/filtered — treat as a hop
        run {
            val re = Regex("(destination .* unreachable|packet filtered)", RegexOption.IGNORE_CASE)
            if (re.containsMatchIn(text)) {
                val reFrom = Regex(
                    "^From\\s+([^\\s(]+)(?:\\s+\\(([^)]+)\\))?",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)
                )
                val m = reFrom.find(text)
                val hostTok = m?.groupValues?.getOrNull(1)?.trim()
                val ipTok = m?.groupValues?.getOrNull(2)?.trim()
                val ip = ipTok ?: hostTok
                return Parsed(ParseKind.Hop, host = hostTok, ip = ip, rttMs = elapsedMs)
            }
        }

        // Timeouts
        if (
            lower.contains("100% packet loss") ||
            lower.contains("no answer yet") ||
            lower.contains("request timeout") ||
            lower.contains("deadline exceeded")
        ) {
            return Parsed(ParseKind.Timeout)
        }

        // Treat unknown as timeout to keep traceroute moving
        return if (stdout.isBlank() && stderr.isBlank()) {
            Parsed(ParseKind.Timeout)
        } else {
            Parsed(ParseKind.Timeout)
        }
    }

    class Builder {
        private var target: String? = null
        private var maxTtl: Int = 30
        private var timeoutPerProbeMs: Int = 3000
        private var attemptsPerHop: Int = 2
        private var resolveDns: Boolean = true
        private var useIPv6: Boolean = false
        private var interHopDelayMs: Int = 0
        private var pingBinary: String? = null
        private val extraArgs: MutableList<String> = mutableListOf()

        fun setTarget(hostOrIp: String) = apply { target = hostOrIp.trim() }
        fun setMaxTtl(ttl: Int) = apply { maxTtl = ttl.coerceIn(1, 128) }
        fun setTimeoutPerProbeMillis(ms: Int) = apply { timeoutPerProbeMs = ms.coerceAtLeast(200) }
        fun setAttemptsPerHop(n: Int) = apply { attemptsPerHop = n.coerceIn(1, 5) }
        fun setResolveDns(enable: Boolean) = apply { resolveDns = enable }
        fun setUseIPv6(enable: Boolean) = apply { useIPv6 = enable }
        fun setInterHopDelayMillis(ms: Int) = apply { interHopDelayMs = ms.coerceIn(0, 2000) }
        fun setPingBinary(path: String?) = apply { pingBinary = path?.trim()?.takeIf { it.isNotEmpty() } }
        fun addExtraArgs(args: List<String>) = apply { extraArgs.addAll(args) }

        fun build(): Traceroute {
            val tgt = requireNotNull(target) { "target is required" }
            return Traceroute(
                target = tgt,
                maxTtl = maxTtl,
                timeoutPerProbeMs = timeoutPerProbeMs,
                attemptsPerHop = attemptsPerHop,
                resolveDns = resolveDns,
                useIPv6 = useIPv6,
                interHopDelayMs = interHopDelayMs,
                pingBinary = pingBinary,
                extraArgs = extraArgs.toList()
            )
        }

        fun start(listener: Listener): Session = build().start(listener)
        fun runBlocking(): List<HopResult> = build().runBlocking()
    }

    companion object {
        @JvmStatic fun builder(): Builder = Builder()
    }
}