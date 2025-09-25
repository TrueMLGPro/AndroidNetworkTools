package com.stealthcopter.networktools.discovery

import com.stealthcopter.networktools.SubnetDevices
import jcifs.CIFSContext
import jcifs.CIFSException
import jcifs.NetbiosAddress
import jcifs.config.PropertyConfiguration
import jcifs.context.BaseContext
import java.net.UnknownHostException
import java.util.Properties

object NetBiosTools {
    data class Name(
        val name: String,
        val suffix: String?, // two-hex suffix, e.g. "20"
        val isGroup: Boolean
    )

    data class Info(
        val primaryName: String?,
        val mac: String?, // often null or 00:00:00:00:00:00
        val names: List<Name>
    )

    data class SuffixMeta(
        val descUnique: String? = null,
        val descGroup: String? = null,
        val notes: String? = null // optional extra info
    )

    // Known NetBIOS suffixes
    val META: Map<String, SuffixMeta> = mapOf(
        "00" to SuffixMeta(
            descUnique = "Workstation Service",
            descGroup = "Workgroup/Domain (LAN Manager Browse Service)"
        ),
        "01" to SuffixMeta(descUnique = "Messenger Service (alt calling name)"),
        "03" to SuffixMeta(descUnique = "Messenger Service (WinPopup)"),
        "06" to SuffixMeta(descUnique = "RAS Server Service"),
        "1F" to SuffixMeta(descUnique = "NetDDE Service"),
        "20" to SuffixMeta(descUnique = "File Server Service"),
        "21" to SuffixMeta(descUnique = "RAS Client Service"),
        "22" to SuffixMeta(descUnique = "Microsoft Exchange"),
        "23" to SuffixMeta(descUnique = "Microsoft Exchange"),
        "24" to SuffixMeta(descUnique = "Microsoft Exchange"),
        "2B" to SuffixMeta(descGroup = "Lotus Notes Server Service"),
        "30" to SuffixMeta(descUnique = "Modem Sharing Server Service"),
        "31" to SuffixMeta(descUnique = "Modem Sharing Client Service"),
        "42" to SuffixMeta(descUnique = "McAfee Anti-virus (legacy)"),
        "43" to SuffixMeta(descUnique = "SMS Client Remote Control"),
        "44" to SuffixMeta(descUnique = "SMS Admin Remote Control Tool"),
        "45" to SuffixMeta(descUnique = "SMS Client Chat"),
        "46" to SuffixMeta(descUnique = "SMS Client Remote Transfer"),
        "4C" to SuffixMeta(descUnique = "DEC Pathworks TCP/IP for Windows NT"),
        "52" to SuffixMeta(descUnique = "DEC Pathworks TCP/IP for Windows NT"),
        "6A" to SuffixMeta(descUnique = "Microsoft Exchange"),
        "87" to SuffixMeta(descUnique = "Microsoft Exchange"),
        "BE" to SuffixMeta(descUnique = "Network Monitor Agent"),
        "BF" to SuffixMeta(descUnique = "Network Monitor Client Application"),

        // Browser/Domain
        "1B" to SuffixMeta(descUnique = "Domain Master Browser (DMB)"),
        "1C" to SuffixMeta(descGroup = "Domain Controllers (Internet Group)"),
        "1D" to SuffixMeta(descUnique = "Local Master Browser (LMB) (LAN-unique)"),
        "1E" to SuffixMeta(descGroup = "Browser Election Service")
    )

    // Special hard-coded name for LMB interop: \x01\x02__MSBROWSE__\x02 <01> (group)
    const val MSBROWSE = "\u0001\u0002__MSBROWSE__\u0002"

    @JvmStatic
    fun queryInfo(ip: String, timeoutMs: Int = 2000): Info? {
        return try {
            val props = Properties().apply {
                setProperty("jcifs.smb.client.responseTimeout", timeoutMs.toString())
                setProperty("jcifs.smb.client.soTimeout", timeoutMs.toString())
            }
            val ctx = buildGuestContext(props)
            val addrs: Array<NetbiosAddress> = ctx.nameServiceClient.getNbtAllByAddress(ip)

            val names = mutableListOf<Name>()
            var primary: String? = null
            var mac: String? = null

            val regex = Regex("^(.*?)(?:<([0-9A-Fa-f]{2})>)?\$")

            for (addr in addrs) {
                val raw = addr.name.toString()
                val m = regex.find(raw)
                val base = m?.groupValues?.getOrNull(1)?.trim().orEmpty()
                val suffix = m?.groupValues?.getOrNull(2)?.uppercase()
                val group = try { addr.isGroupAddress(ctx) } catch (_: Throwable) { false }
                if (base.isNotEmpty()) {
                    names += Name(base, suffix, group)
                    if (!group && primary == null) primary = base
                }

                if (mac == null || mac == "00:00:00:00:00:00") {
                    mac = tryMacFromAddress(addr) ?: mac
                }
            }

            Info(
                primaryName = primary?.ifBlank { null },
                mac = mac?.takeIf { it.isNotBlank() && it != "00:00:00:00:00:00" },
                names = names
            )
        } catch (_: UnknownHostException) {
            null
        } catch (_: CIFSException) {
            null
        } catch (_: Throwable) {
            null
        }
    }

    @JvmStatic
    fun queryPrimaryName(ip: String, timeoutMs: Int = 2000): String? {
        return queryInfo(ip, timeoutMs)?.primaryName
    }

    private fun tryMacFromAddress(addr: Any): String? {
        fun bytesToMac(b: ByteArray?): String? {
            if (b == null || b.size < 6) return null
            return (0 until 6).joinToString(":") { i -> "%02X".format(b[i].toInt() and 0xFF) }
        }
        // Reflection to jcifs-ng
        try {
            val m = addr.javaClass.getMethod("getMacAddress")
            val ba = m.invoke(addr) as? ByteArray
            bytesToMac(ba)?.let { return it }
        } catch (_: Throwable) {}
        try {
            val f = addr.javaClass.getDeclaredField("macAddress")
            f.isAccessible = true
            val ba = f.get(addr) as? ByteArray
            bytesToMac(ba)?.let { return it }
        } catch (_: Throwable) {}
        return null
    }

    private fun buildGuestContext(props: Properties): CIFSContext {
        val base = BaseContext(PropertyConfiguration(props))
        return try {
            val m = BaseContext::class.java.getMethod("withGuestCredentials")
            m.invoke(base) as CIFSContext
        } catch (_: Throwable) {
            base
        }
    }
}
