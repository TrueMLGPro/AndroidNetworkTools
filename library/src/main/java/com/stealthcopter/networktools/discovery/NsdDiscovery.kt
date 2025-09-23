package com.stealthcopter.networktools.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

object NsdDiscovery {

    data class Service(
        val name: String,
        val type: String,
        val host: String?,
        val port: Int
    )

    // Default service types to look for
    val defaultTypes = listOf(
        //"_services._dns-sd._udp",
        "_http._tcp.",
        "_workstation._tcp.",
        "_smb._tcp.",
        "_afpovertcp._tcp.",
        "_ipp._tcp.",
        "_printer._tcp.",
        "_airplay._tcp.",
        "_googlecast._tcp.",
        "_ftp._tcp.",
        "_ssh._tcp.",
        "_device-info._tcp."
    )

    @JvmStatic
    fun discover(context: Context, timeoutMs: Int = 5000, serviceTypes: List<String> = defaultTypes): List<Service> {
        val appCtx = context.applicationContext
        val nsd = appCtx.getSystemService(Context.NSD_SERVICE) as? NsdManager ?: return emptyList()
        if (serviceTypes.isEmpty()) return emptyList()

        val results = Collections.synchronizedList(mutableListOf<Service>())
        val main = Handler(Looper.getMainLooper())
        val stopLatch = CountDownLatch(serviceTypes.size)
        val activeDiscoveries = AtomicInteger(0)
        val listeners = mutableListOf<NsdManager.DiscoveryListener>()

        serviceTypes.forEach { _ ->
            val listener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType: String) {
                    activeDiscoveries.incrementAndGet()
                }
                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    main.post {
                        nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
                            override fun onServiceResolved(resolved: NsdServiceInfo) {
                                val host = resolved.host?.hostAddress
                                val port = resolved.port
                                val name = resolved.serviceName ?: serviceInfo.serviceName ?: "Service"
                                val t = resolved.serviceType ?: serviceInfo.serviceType
                                results.add(Service(name = name, type = t, host = host, port = port))
                            }
                        })
                    }
                }
                override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
                override fun onDiscoveryStopped(serviceType: String) {
                    if (activeDiscoveries.decrementAndGet() == 0) stopLatch.countDown()
                }
                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                    try { nsd.stopServiceDiscovery(this) } catch (_: Throwable) {}
                    if (activeDiscoveries.decrementAndGet() == 0) stopLatch.countDown()
                }
                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                    if (activeDiscoveries.decrementAndGet() == 0) stopLatch.countDown()
                }
            }
            listeners.add(listener)
        }

        // Start on main thread
        serviceTypes.forEachIndexed { idx, type ->
            main.post {
                try { nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, listeners[idx]) } catch (_: Throwable) {}
            }
        }

        // Schedule stop after timeout
        main.postDelayed({
            listeners.forEach { l ->
                try { nsd.stopServiceDiscovery(l) } catch (_: Throwable) {}
            }
        }, timeoutMs.toLong())

        // Wait for stop
        stopLatch.await((timeoutMs + 1000).toLong(), TimeUnit.MILLISECONDS)
        return results.toList()
    }
}