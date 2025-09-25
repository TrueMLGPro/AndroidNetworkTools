package com.stealthcopter.networktools.discovery

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
