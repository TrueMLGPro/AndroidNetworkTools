package com.stealthcopter.networktools

import com.stealthcopter.networktools.ssl.SslReportFormatter
import java.io.IOException
import java.math.BigInteger
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Locale
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object SslCertTools {
    data class Result(
        val chain: List<X509Certificate> = emptyList(),
        val isTrustedBySystem: Boolean = false,
        val trustError: String? = null,
        val hostnameMatches: Boolean = false,
        val hostnameError: String? = null,
        val protocol: String? = null,
        val cipherSuite: String? = null,
        val handshakeSucceeded: Boolean = false,
        val sniHost: String? = null,
        val verifyHost: String? = null
    )

    @JvmStatic
    @Throws(Exception::class)
    fun fetchCertificate(
        connectHost: String,
        port: Int = 443,
        timeoutMs: Int = 10_000,
        sniOverride: String? = null
    ): Result {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val defaultTm = pickX509TrustManager(tmf.trustManagers)
            ?: throw IllegalStateException("No X509TrustManager available")

        val savingTm = SavingTrustManager(defaultTm)

        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(savingTm), null)
        val factory: SSLSocketFactory = ctx.socketFactory

        var protocol: String? = null
        var cipherSuite: String? = null
        var handshakeSucceeded = false

        var socket: SSLSocket? = null
        try {
            socket = factory.createSocket() as SSLSocket
            socket.soTimeout = timeoutMs

            // Prefer TLS 1.3 and 1.2
            enablePreferredProtocols(socket)

            // Connect
            socket.connect(InetSocketAddress(connectHost, port), timeoutMs)

            val sniHost = (sniOverride?.trim()).takeUnless { it.isNullOrEmpty() } ?: connectHost
            setSniIfPossible(socket, sniHost)

            // Capture negotiated protocol and cipher
            socket.addHandshakeCompletedListener { event ->
                try {
                    protocol = event.session?.protocol
                    cipherSuite = event.cipherSuite
                } catch (_: Throwable) { /* ignored */ }
            }

            try {
                socket.startHandshake()
                handshakeSucceeded = true
            } catch (e: SSLHandshakeException) {
                handshakeSucceeded = false
            }

            val receivedChain = savingTm.chain?.toList() ?: emptyList()
            if (receivedChain.isEmpty()) throw IOException("No certificate chain received")

            // Check system trust
            var trusted = false
            var trustErr: String? = null
            try {
                val authType = receivedChain.first().publicKey.algorithm
                defaultTm.checkServerTrusted(receivedChain.toTypedArray(), authType)
                trusted = true
            } catch (ce: CertificateException) {
                trusted = false
                trustErr = ce.message
            }

            // Hostname verification (CN/SAN with wildcard support)
            val verifyHost = sniHost
            val hostMatch = hostnameMatches(verifyHost, receivedChain.first())
            val hostErr = if (hostMatch) null else "Hostname does not match CN/SAN"

            return Result(
                chain = receivedChain,
                isTrustedBySystem = trusted,
                trustError = trustErr,
                hostnameMatches = hostMatch,
                hostnameError = hostErr,
                protocol = protocol,
                cipherSuite = cipherSuite,
                handshakeSucceeded = handshakeSucceeded,
                sniHost = sniHost,
                verifyHost = verifyHost
            )
        } finally {
            try {
                socket?.close()
            } catch (_: Throwable) {
            }
        }
    }

    @JvmStatic
    fun buildReport(host: String, port: Int, result: Result): String {
        return SslReportFormatter.buildReport(host, port, result)
    }

    // ------- Internals -------

    private fun enablePreferredProtocols(socket: SSLSocket) {
        val enabled = socket.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
        if (enabled.isNotEmpty()) {
            socket.enabledProtocols = enabled.toTypedArray()
        }
    }

    private fun pickX509TrustManager(tms: Array<TrustManager>): X509TrustManager? {
        for (tm in tms) if (tm is X509TrustManager) return tm
        return null
    }

    private class SavingTrustManager(private val delegate: X509TrustManager) : X509TrustManager {
        @Volatile
        var chain: Array<X509Certificate>? = null

        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            delegate.checkClientTrusted(chain, authType)
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            this.chain = chain.clone()
            delegate.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }

    private fun setSniIfPossible(socket: SSLSocket, host: String) {
        // 1) Standard SSLParameters#setServerNames with SNIHostName (use reflection to be safe on older APIs)
        try {
            val params = socket.sslParameters
            val sniHostNameCls = Class.forName("javax.net.ssl.SNIHostName")
            val sni = sniHostNameCls.getConstructor(String::class.java).newInstance(host)
            val serverNames = java.util.ArrayList<Any>()
            serverNames.add(sni)
            val setServerNames = javax.net.ssl.SSLParameters::class.java
                .getMethod("setServerNames", java.util.List::class.java)
            setServerNames.invoke(params, serverNames)
            socket.sslParameters = params
            return
        } catch (_: Throwable) {
        }

        // 2) Android's SSLCertificateSocketFactory.setHostname(Socket, String)
        try {
            val cls = Class.forName("android.net.SSLCertificateSocketFactory")
            val m = cls.getMethod("setHostname", java.net.Socket::class.java, String::class.java)
            m.invoke(null, socket, host)
            return
        } catch (_: Throwable) {
        }

        // 3) setHostname on implementation (some providers expose it)
        try {
            val m = socket.javaClass.getMethod("setHostname", String::class.java)
            m.invoke(socket, host)
        } catch (_: Throwable) {
        }
    }

    // -------- Hostname verification (CN/SAN with wildcard) --------

    private fun hostnameMatches(host: String, cert: X509Certificate): Boolean {
        val h = host.lowercase(Locale.US)
        val isIp = isIpLiteral(h)

        try {
            val altNames = cert.subjectAlternativeNames
            if (altNames != null) {
                for (item in altNames) {
                    val type = (item[0] as? Int) ?: continue
                    val value = (item[1]?.toString() ?: "").lowercase(Locale.US)
                    if (isIp && type == 7) { // iPAddress
                        if (h == value) return true
                    } else if (!isIp && type == 2) { // dNSName
                        if (matchDns(h, value)) return true
                    }
                }
                // If SAN is present but no match, per modern rules CN is ignored.
                // We still fallback to CN for completeness.
            }
        } catch (_: Exception) {
        }

        if (!isIp) {
            val cn = extractCN(cert.subjectX500Principal)?.lowercase(Locale.US)
            if (!cn.isNullOrEmpty()) return matchDns(h, cn)
        }
        return false
    }

    private fun matchDns(host: String, pattern: String): Boolean {
        if (host == pattern) return true
        if (pattern.startsWith("*.")) {
            val suffix = pattern.substring(2)
            if (!host.endsWith(".$suffix")) return false
            val leftMost = host.substring(0, host.length - suffix.length - 1)
            return !leftMost.contains(".")
        }
        return false
    }

    private fun extractCN(p: Principal?): String? {
        val dn = p?.name ?: return null
        val attrs = parseDn(dn)
        for (a in attrs) if (a.type.equals("CN", ignoreCase = true)) return a.value
        return null
    }

    private data class DnAttr(val type: String, val value: String)

    private fun parseDn(dn: String?): List<DnAttr> {
        val out = mutableListOf<DnAttr>()
        if (dn.isNullOrEmpty()) return out

        val tokens = mutableListOf<String>()
        val sb = StringBuilder()
        var inQuotes = false
        var escaped = false

        for (c in dn) {
            when {
                escaped -> {
                    sb.append(c)
                    escaped = false
                }
                c == '\\' -> {
                    sb.append(c)
                    escaped = true
                }
                c == '"' -> {
                    sb.append(c)
                    inQuotes = !inQuotes
                }
                !inQuotes && (c == ',' || c == ';' || c == '+') -> {
                    tokens.add(sb.toString().trim())
                    sb.setLength(0)
                }
                else -> sb.append(c)
            }
        }
        if (sb.isNotEmpty()) tokens.add(sb.toString().trim())

        for (t in tokens) {
            val eq = indexOfUnescapedEquals(t)
            if (eq <= 0) continue
            val type = t.substring(0, eq).trim()
            var value = t.substring(eq + 1).trim()
            if (value.length >= 2 && value.first() == '"' && value.last() == '"') {
                value = value.substring(1, value.length - 1)
            }
            value = unescapeRfc2253(value)
            out.add(DnAttr(type, value))
        }
        return out
    }

    private fun indexOfUnescapedEquals(s: String): Int {
        var inQuotes = false
        var escaped = false
        for (i in s.indices) {
            val c = s[i]
            when {
                escaped -> escaped = false
                c == '\\' -> escaped = true
                c == '"' -> inQuotes = !inQuotes
                !inQuotes && c == '=' -> return i
            }
        }
        return -1
    }

    private fun unescapeRfc2253(s: String): String {
        if (s.isEmpty()) return s
        val out = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                val n1 = s[i + 1]
                if (isHex(n1) && i + 2 < s.length && isHex(s[i + 2])) {
                    val v = Integer.parseInt("${s[i + 1]}${s[i + 2]}", 16)
                    out.append(v.toChar())
                    i += 3
                    continue
                } else {
                    out.append(n1)
                    i += 2
                    continue
                }
            }
            out.append(c)
            i++
        }
        return out.toString()
    }

    private fun isHex(c: Char): Boolean =
        (c in '0'..'9') || (c in 'a'..'f') || (c in 'A'..'F')

    private fun isIpLiteral(s: String?): Boolean {
        if (s.isNullOrEmpty()) return false
        if (s.contains(":")) return true // rough IPv6 check
        // IPv4 quick check
        val parts = s.split(".")
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || (p.length > 1 && p.startsWith("0"))) return false
            val v = p.toIntOrNull() ?: return false
            if (v !in 0..255) return false
        }
        return true
    }

    // These are used by SslReportFormatter; provided here for convenience if needed elsewhere too.
    internal fun publicKeyInfo(cert: X509Certificate): String {
        return try {
            val pk: PublicKey = cert.publicKey
            val alg = pk.algorithm
            val size = when (pk) {
                is RSAPublicKey -> pk.modulus.bitLength()
                is ECPublicKey -> pk.params.curve.field.fieldSize
                else -> -1
            }
            if (size > 0) "$alg $size bit" else alg
        } catch (_: Throwable) {
            cert.publicKey.algorithm
        }
    }

    internal fun fingerprint(cert: X509Certificate, algo: String): String {
        return try {
            val md = MessageDigest.getInstance(algo)
            val der = cert.encoded
            val digest = md.digest(der)
            buildString(digest.size * 3) {
                digest.forEachIndexed { idx, b ->
                    append(String.format(Locale.US, "%02X", b))
                    if (idx < digest.size - 1) append(':')
                }
            }
        } catch (_: Exception) {
            "(unavailable)"
        }
    }

    internal fun hex(bi: BigInteger): String = bi.toString(16).uppercase(Locale.US)
}