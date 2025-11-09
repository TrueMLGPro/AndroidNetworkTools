package com.stealthcopter.networktools

import com.stealthcopter.networktools.ping.PingNative
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.max

class Traceroute private constructor(
    private val target: String,
    private val maxTtl: Int,
    private val timeoutPerProbeMs: Int,
    private val attemptsPerHop: Int,
    private val resolveDns: Boolean,
    private val useIPv6: Boolean,
    private val interHopDelayMs: Int
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
        progress: Listener?
    ): List<HopResult> {
        val results = mutableListOf<HopResult>()

        for (ttl in 1..maxTtl) {
            if (cancelFlag.get()) break

            var hopResult: HopResult? = null

            repeat(max(1, attemptsPerHop)) attempt@{
                if (cancelFlag.get()) return@attempt
                val startNs = System.nanoTime()

                val raw: PingNative.StreamPingResult = try {
                    PingNative.pingOnceStream(
                        hostOrAddress = target,
                        ttl = ttl,
                        timeoutMillis = timeoutPerProbeMs,
                        noDns = !resolveDns,
                        forceIPv6 = useIPv6,
                        setProc = setProc,
                        onLine = null
                    )
                } catch (t: Throwable) {
                    PingNative.StreamPingResult(
                        exitCode = -2,
                        stdout = "",
                        stderr = t.message ?: "",
                        firstMatchElapsedMs = null,
                        timedOut = true
                    )
                }

                val elapsedMs = raw.firstMatchElapsedMs
                    ?: ((System.nanoTime() - startNs) / 1_000_000.0f)

                val parsed = parsePingOutput(raw.stdout, raw.stderr, elapsedMs)

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
                    }
                    ParseKind.Error -> {
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

    private data class Parsed(
        val kind: ParseKind,
        val host: String? = null,
        val ip: String? = null,
        val rttMs: Float? = null,
        val error: Throwable? = null
    )
    private enum class ParseKind { Hop, Final, Timeout, Error }

    // Parse ping outputs for: hop (TTL exceeded), final (bytes from...), or timeout
    private fun parsePingOutput(stdout: String, stderr: String, elapsedMs: Float): Parsed {
        val text = stdout + "\n" + stderr
        val lower = text.lowercase()

        // Final: "64 bytes from name (ip): ... time=xx ms" OR "64 bytes from ip: ... time=xx ms"
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

        // Treat destination unreachable/filtered as a hop
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

        // Treat unknown/empty as timeout to keep traceroute moving
        return Parsed(ParseKind.Timeout)
    }

    class Builder {
        private var target: String? = null
        private var maxTtl: Int = 30
        private var timeoutPerProbeMs: Int = 3000
        private var attemptsPerHop: Int = 2
        private var resolveDns: Boolean = true
        private var useIPv6: Boolean = false
        private var interHopDelayMs: Int = 0

        fun setTarget(hostOrIp: String) = apply { target = hostOrIp.trim() }
        fun setMaxTtl(ttl: Int) = apply { maxTtl = ttl.coerceIn(1, 128) }
        fun setTimeoutPerProbeMillis(ms: Int) = apply { timeoutPerProbeMs = ms.coerceAtLeast(200) }
        fun setAttemptsPerHop(n: Int) = apply { attemptsPerHop = n.coerceIn(1, 5) }
        fun setResolveDns(enable: Boolean) = apply { resolveDns = enable }
        fun setUseIPv6(enable: Boolean) = apply { useIPv6 = enable }
        fun setInterHopDelayMillis(ms: Int) = apply { interHopDelayMs = ms.coerceIn(0, 2000) }

        fun build(): Traceroute {
            val tgt = requireNotNull(target) { "target is required" }
            return Traceroute(
                target = tgt,
                maxTtl = maxTtl,
                timeoutPerProbeMs = timeoutPerProbeMs,
                attemptsPerHop = attemptsPerHop,
                resolveDns = resolveDns,
                useIPv6 = useIPv6,
                interHopDelayMs = interHopDelayMs
            )
        }

        fun start(listener: Listener): Session = build().start(listener)
        fun runBlocking(): List<HopResult> = build().runBlocking()
    }

    companion object {
        @JvmStatic fun builder(): Builder = Builder()
    }
}