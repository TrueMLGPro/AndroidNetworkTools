package com.stealthcopter.networktools.discovery

import jcifs.CIFSContext
import jcifs.CIFSException
import jcifs.NetbiosAddress
import jcifs.config.PropertyConfiguration
import jcifs.context.BaseContext
import java.net.UnknownHostException
import java.util.Properties

object NetBiosTools {
    @JvmStatic
    fun queryPrimaryName(ip: String, timeoutMs: Int = 2000): String? {
        return try {
            val props = Properties().apply {
                setProperty("jcifs.smb.client.responseTimeout", timeoutMs.toString())
                setProperty("jcifs.smb.client.soTimeout", timeoutMs.toString())
            }
            val ctx = buildGuestContext(props)
            val addrs: Array<NetbiosAddress> = ctx.nameServiceClient.getNbtAllByAddress(ip)
            var primary: String? = null
            for (addr in addrs) {
                if (!addr.isGroupAddress(ctx)) {
                    primary = (addr.name.toString())
                        .replace(Regex("<[0-9A-Fa-f]+>"), "")
                        .trim()
                    if (primary.isNotEmpty()) break
                }
            }
            primary?.ifBlank { null }
        } catch (_: UnknownHostException) {
            null
        } catch (_: CIFSException) {
            null
        } catch (_: Throwable) {
            null
        }
    }

    private fun buildGuestContext(props: Properties): CIFSContext {
        val base = BaseContext(PropertyConfiguration(props))
        return try {
            val m = BaseContext::class.java.getMethod("withGuestCredentials")
            m.invoke(base) as CIFSContext
        } catch (_: Throwable) {
            try {
                val m = BaseContext::class.java.getMethod("withGuestCrendentials")
                m.invoke(base) as CIFSContext
            } catch (_: Throwable) {
                base
            }
        }
    }
}
