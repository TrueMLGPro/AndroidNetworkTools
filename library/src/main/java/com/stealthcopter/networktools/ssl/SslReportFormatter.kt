package com.stealthcopter.networktools.ssl

import com.stealthcopter.networktools.SslCertTools
import java.security.Principal
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import javax.security.auth.x500.X500Principal

internal object SslReportFormatter {
    private const val LINE_SEPARATOR = "-------------------------------------------\n"

    private val DATE_FMT = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).apply {
        timeZone = TimeZone.getDefault()
    }

    fun buildReport(host: String, port: Int, result: SslCertTools.Result): String {
        val sb = StringBuilder()

        sb.append("TLS endpoint: ").append(host).append(":").append(port).append("\n")
        result.sniHost?.takeIf { it.isNotBlank() }?.let {
            sb.append("SNI host: ").append(it).append("\n")
        }
        result.verifyHost?.takeIf { it.isNotBlank() }?.let {
            sb.append("Verify host: ").append(it).append("\n")
        }
        sb.append("Handshake: ").append(if (result.handshakeSucceeded) "succeeded" else "failed").append("\n")
        result.protocol?.let {
            sb.append("Negotiated: ").append(it)
                .append("  ")
                .append(result.cipherSuite ?: "")
                .append("\n")
        }
        sb.append("System trust: ").append(if (result.isTrustedBySystem) "trusted" else "NOT trusted")
        result.trustError?.takeIf { it.isNotBlank() }?.let { sb.append(" (").append(it).append(")") }
        sb.append("\n")
        sb.append("Hostname check: ").append(if (result.hostnameMatches) "match" else "NO match")
        result.hostnameError?.takeIf { it.isNotBlank() }?.let { sb.append(" (").append(it).append(")") }
        sb.append("\n\n")

        sb.append("Certificates:\n")
        sb.append(LINE_SEPARATOR)

        result.chain.forEachIndexed { idx, cert ->
            sb.append(formatCertificate(cert, idx + 1))
            if (idx < result.chain.size - 1) sb.append("\n")
        }
        return sb.toString()
    }

    private fun formatCertificate(cert: X509Certificate, index: Int): String {
        val sb = StringBuilder()

        sb.append("#").append(index)
            .append(" Subject: ").append(rdn(cert.subjectX500Principal)).append("\n")
        sb.append("   Issuer : ").append(rdn(cert.issuerX500Principal)).append("\n")

        sb.append("   Serial : 0x").append(SslCertTools.hex(cert.serialNumber)).append("\n")
        sb.append("   Valid  : ")
            .append(DATE_FMT.format(cert.notBefore))
            .append("  ->  ")
            .append(DATE_FMT.format(cert.notAfter))

        val now = System.currentTimeMillis()
        val notBefore = cert.notBefore.time
        val notAfter = cert.notAfter.time
        if (now < notBefore) {
            sb.append("  [Not yet valid]")
        } else if (now > notAfter) {
            sb.append("  [Expired]")
        } else {
            val daysLeft = (notAfter - now) / (1000L * 60 * 60 * 24)
            sb.append("  [~").append(daysLeft).append(" days left]")
        }
        sb.append("\n")

        sb.append("   PubKey : ").append(SslCertTools.publicKeyInfo(cert)).append("\n")
        sb.append("   SigAlg : ").append(cert.sigAlgName).append("\n")

        subjectAltNames(cert).takeIf { it.isNotBlank() }?.let {
            sb.append("   SAN    : ").append(it).append("\n")
        }

        keyUsage(cert).takeIf { it.isNotBlank() }?.let {
            sb.append("   KeyUse : ").append(it).append("\n")
        }

        extKeyUsage(cert).takeIf { it.isNotBlank() }?.let {
            sb.append("   ExtKU  : ").append(it).append("\n")
        }

        val bc = cert.basicConstraints
        if (bc >= 0) {
            sb.append("   CA     : true")
            sb.append(" (pathLen=").append(bc).append(")").append("\n")
        } else {
            sb.append("   CA     : false").append("\n")
        }

        if (isSelfSigned(cert)) {
            sb.append("   Note   : self-signed").append("\n")
        }

        sb.append("   SHA-1   FP: ").append(SslCertTools.fingerprint(cert, "SHA-1")).append("\n")
        sb.append("   SHA-256 FP: ").append(SslCertTools.fingerprint(cert, "SHA-256")).append("\n")

        sb.append(LINE_SEPARATOR)
        return sb.toString()
    }

    private fun rdn(p: Principal?): String {
        return try {
            when (p) {
                is X500Principal -> p.getName(X500Principal.RFC2253)
                else -> p?.name ?: ""
            }
        } catch (_: Throwable) {
            p?.name ?: ""
        }
    }

    private fun subjectAltNames(cert: X509Certificate): String {
        return try {
            val col: MutableCollection<MutableList<*>> = cert.subjectAlternativeNames ?: return ""
            val dns = mutableListOf<String>()
            val ip = mutableListOf<String>()
            for (item in col) {
                val type = (item[0] as? Int) ?: continue
                val value = item[1]?.toString() ?: continue
                when (type) {
                    2 -> dns.add(value) // dNSName
                    7 -> ip.add(value) // iPAddress
                }
            }
            buildString {
                if (dns.isNotEmpty()) append("DNS=").append(dns.joinToString(", "))
                if (ip.isNotEmpty()) {
                    if (isNotEmpty()) append("  ")
                    append("IP=").append(ip.joinToString(", "))
                }
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun keyUsage(cert: X509Certificate): String {
        val ku = cert.keyUsage ?: return ""
        val names = arrayOf(
            "digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment",
            "keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"
        )
        val out = mutableListOf<String>()
        for (i in ku.indices) {
            if (i < names.size && ku[i]) out.add(names[i])
        }
        return out.joinToString(", ")
    }

    private fun extKeyUsage(cert: X509Certificate): String {
        return try {
            val oids = cert.extendedKeyUsage ?: return ""
            oids.joinToString(", ") { mapEkuOid(it) }
        } catch (_: CertificateException) {
            ""
        }
    }

    private fun mapEkuOid(oid: String): String {
        return when (oid) {
            "1.3.6.1.5.5.7.3.1" -> "serverAuth"
            "1.3.6.1.5.5.7.3.2" -> "clientAuth"
            "1.3.6.1.5.5.7.3.3" -> "codeSigning"
            "1.3.6.1.5.5.7.3.4" -> "emailProtection"
            "1.3.6.1.5.5.7.3.8" -> "timeStamping"
            "1.3.6.1.5.5.7.3.9" -> "OCSPSigning"
            else -> oid
        }
    }

    private fun isSelfSigned(cert: X509Certificate): Boolean {
        return try {
            cert.verify(cert.publicKey)
            cert.subjectX500Principal == cert.issuerX500Principal
        } catch (_: Exception) {
            false
        }
    }
}