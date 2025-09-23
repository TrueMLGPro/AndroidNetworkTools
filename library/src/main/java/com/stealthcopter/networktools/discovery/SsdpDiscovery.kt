package com.stealthcopter.networktools.discovery

import org.w3c.dom.Document
import java.net.*
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory

object SsdpDiscovery {
    data class SsdpDevice(
        val ip: String,
        val location: String?,
        val server: String?,
        val st: String?,
        val usn: String?,
        val headers: Map<String, String>,
        val friendlyName: String? = null,
        val modelName: String? = null,
        val manufacturer: String? = null,
        val deviceType: String? = null
    )

    @JvmStatic
    fun discover(timeoutMs: Int = 3000, mx: Int = 2, retries: Int = 2): List<SsdpDevice> {
        val results = mutableMapOf<String, SsdpDevice>()
        val group = InetAddress.getByName("239.255.255.250")
        val port = 1900
        val socket = DatagramSocket().apply {
            soTimeout = 500
            reuseAddress = true
        }

        try {
            val req = """
                M-SEARCH * HTTP/1.1
                HOST: 239.255.255.250:1900
                MAN: "ssdp:discover"
                MX: $mx
                ST: ssdp:all
                USER-AGENT: AndroidNetworkTools/Android
            """.trimIndent().replace("\n", "\r\n") + "\r\n\r\n"

            val data = req.toByteArray(Charsets.UTF_8)
            val dp = DatagramPacket(data, data.size, InetSocketAddress(group, port))

            repeat(retries) { socket.send(dp) }

            val start = System.currentTimeMillis()
            val buf = ByteArray(64 * 1024)

            while (System.currentTimeMillis() - start < timeoutMs) {
                try {
                    val p = DatagramPacket(buf, buf.size)
                    socket.receive(p)
                    val text = String(p.data, p.offset, p.length, Charsets.UTF_8)
                    val headers = parseHeaders(text)

                    val remoteIp = p.address.hostAddress
                    val loc = headers["location"]
                    val server = headers["server"]
                    val st = headers["st"]
                    val usn = headers["usn"]

                    var friendlyName: String? = null
                    var modelName: String? = null
                    var manufacturer: String? = null
                    var deviceType: String? = null

                    if (!loc.isNullOrBlank()) {
                        try {
                            val desc = fetchDeviceDescription(loc, 1500)
                            friendlyName = desc["friendlyName"]
                            modelName = desc["modelName"]
                            manufacturer = desc["manufacturer"]
                            deviceType = desc["deviceType"]
                        } catch (_: Throwable) {}
                    }

                    results[remoteIp] = SsdpDevice(
                        ip = remoteIp,
                        location = loc,
                        server = server,
                        st = st,
                        usn = usn,
                        headers = headers,
                        friendlyName = friendlyName,
                        modelName = modelName,
                        manufacturer = manufacturer,
                        deviceType = deviceType
                    )
                } catch (_: SocketTimeoutException) {
                    // continue until overall timeout
                } catch (_: Throwable) {
                    break
                }
            }
        } finally {
            try { socket.close() } catch (_: Throwable) {}
        }
        return results.values.toList()
    }

    private fun parseHeaders(text: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        val lines = text.split("\r\n")
        for (line in lines) {
            val idx = line.indexOf(':')
            if (idx > 0) {
                val key = line.substring(0, idx).trim().lowercase(Locale.US)
                val value = line.substring(idx + 1).trim()
                map[key] = value
            }
        }
        return map
    }

    private fun fetchDeviceDescription(location: String, timeoutMs: Int): Map<String, String> {
        val url = URL(location)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            instanceFollowRedirects = true
        }
        return try {
            conn.inputStream.use { input ->
                val doc: Document = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder().parse(input)
                doc.documentElement.normalize()
                fun get(tag: String) = doc.getElementsByTagName(tag)?.item(0)?.textContent?.trim()?.takeIf { it.isNotEmpty() }
                mapOf(
                    "friendlyName" to get("friendlyName"),
                    "modelName" to get("modelName"),
                    "manufacturer" to get("manufacturer"),
                    "deviceType" to get("deviceType")
                ).filterValues { it != null } as Map<String, String>
            }
        } finally {
            conn.disconnect()
        }
    }
}