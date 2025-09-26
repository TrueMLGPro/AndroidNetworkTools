package com.stealthcopter.networktools

import android.content.Context
import com.stealthcopter.networktools.ARPInfo.allIPAddressesInARPCache
import com.stealthcopter.networktools.ARPInfo.allIPAndMACAddressesInARPCache
import com.stealthcopter.networktools.ARPInfo.allIPandMACAddressesFromIPSleigh
import com.stealthcopter.networktools.IPTools.isIPv4Address
import com.stealthcopter.networktools.IPTools.localIPv4Address
import com.stealthcopter.networktools.Ping.Companion.onAddress
import com.stealthcopter.networktools.discovery.NetBiosTools
import com.stealthcopter.networktools.discovery.NsdDiscovery
import com.stealthcopter.networktools.discovery.SsdpDiscovery
import com.stealthcopter.networktools.subnet.Device
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class SubnetDevices  // This class is not to be instantiated
private constructor() {
    private var noThreads = 100
    private var addresses: ArrayList<String>? = null
    private var devicesFound: ArrayList<Device>? = null
    private var listener: OnSubnetDeviceFound? = null
    private var timeOutMillis = 2500
    private var cancelled = false
    private var disableProcNetMethod = false
    private var ipMacHashMap: HashMap<String, String>? = null

    // Progress callback for the scan
    interface OnScanProgress { fun onProgress(done: Int, total: Int) }
    private var scanProgressListener: OnScanProgress? = null

    fun setScanProgressListener(l: OnScanProgress?): SubnetDevices {
        scanProgressListener = l
        return this
    }

    @Volatile private var totalToScan: Int = 0
    private val processedCount = AtomicInteger(0)

    interface OnSubnetDeviceFound {
        fun onDeviceFound(device: Device?)
        fun onFinished(devicesFound: ArrayList<Device>?)
    }

    /**
     * @param noThreads set the number of threads to work with, note we default to a large number
     * as these requests are network heavy not cpu heavy.
     *
     * @throws IllegalArgumentException - if invalid number of threads requested
     *
     * @return - this for chaining
     */
    @Throws(IllegalArgumentException::class)
    fun setNoThreads(noThreads: Int): SubnetDevices {
        require(noThreads >= 1) { "Cannot have less than 1 thread" }
        this.noThreads = noThreads
        return this
    }

    /**
     * Sets the timeout for each address we try to ping
     *
     * @param timeOutMillis - timeout in milliseconds for each ping
     *
     * @return this object to allow chaining
     *
     * @throws IllegalArgumentException - if timeout is less than zero
     */
    @Throws(IllegalArgumentException::class)
    fun setTimeOutMillis(timeOutMillis: Int): SubnetDevices {
        require(timeOutMillis >= 0) { "Timeout cannot be less than 0" }
        this.timeOutMillis = timeOutMillis
        return this
    }

    /**
     * Cancel a running scan
     */
    fun cancel() {
        cancelled = true
    }

    /**
     * Starts the scan to find other devices on the subnet
     *
     * @param listener - to pass on the results
     * @return this object so we can call cancel on it if needed
     */
    fun findDevices(listener: OnSubnetDeviceFound): SubnetDevices {
        this.listener = listener
        cancelled = false
        devicesFound = ArrayList()

        totalToScan = addresses?.size ?: 0
        processedCount.set(0)

        Thread { // Load mac addresses into cache var (to avoid hammering the /proc/net/arp file when
            // lots of devices are found on the network.
            ipMacHashMap =
                if (disableProcNetMethod) allIPandMACAddressesFromIPSleigh else allIPAndMACAddressesInARPCache
            val executor = Executors.newFixedThreadPool(noThreads)
            for (add in addresses!!) {
                val worker: Runnable = SubnetDeviceFinderRunnable(add)
                executor.execute(worker)
            }

            // This will make the executor accept no new threads
            // and finish all existing threads in the queue
            executor.shutdown()
            // Wait until all threads are finish
            try {
                executor.awaitTermination(1, TimeUnit.HOURS)
            } catch (e: InterruptedException) {
                e.printStackTrace()
            }

            // Loop over devices found and add in the MAC addresses if missing.
            // We do this after scanning for all devices as /proc/net/arp may add info
            // because of the scan.
            ipMacHashMap =
                if (disableProcNetMethod) allIPandMACAddressesFromIPSleigh else allIPAndMACAddressesInARPCache
            for (device in devicesFound!!) {
                if (device.mac == null && ipMacHashMap!!.containsKey(device.ip)) {
                    device.mac = ipMacHashMap!![device.ip]
                }
            }
            listener.onFinished(devicesFound)
        }.start()
        return this
    }

    @Synchronized
    private fun subnetDeviceFound(device: Device) {
        devicesFound!!.add(device)
        listener!!.onDeviceFound(device)
    }

    inner class SubnetDeviceFinderRunnable internal constructor(private val address: String?) :
        Runnable {
        override fun run() {
            if (cancelled) return
            try {
                val ia = InetAddress.getByName(address)
                val pingResult = onAddress(ia).setTimeOutMillis(timeOutMillis).doPing()
                if (pingResult.isReachable) {
                    val device = Device(ia)

                    // Add the device MAC address if it is in the cache
                    if (ipMacHashMap!!.containsKey(ia.hostAddress?.toString())) {
                        device.mac = ipMacHashMap!![ia.hostAddress?.toString()]
                    }
                    device.time = pingResult.timeTaken
                    subnetDeviceFound(device)
                }
            } catch (e: UnknownHostException) {
                e.printStackTrace()
            } finally {
                val done = processedCount.incrementAndGet()
                scanProgressListener?.onProgress(done, totalToScan)
            }
        }
    }

    object NetBiosSuffixUtils {
        @JvmStatic
        fun findGroup(nb: NetBiosInfo?): String? {
            val names = nb?.names ?: return null
            // 1) group <00> (workgroup/domain)
            names.firstOrNull { it.isGroup && it.suffix.equals("00", true) }?.name?.let { return it }
            // 2) group <1E> (browser election)
            names.firstOrNull { it.isGroup && it.suffix.equals("1E", true) }?.name?.let { return it }
            // 3) "Internet group" <1C> (domain controllers)
            names.firstOrNull { it.isGroup && it.suffix.equals("1C", true) }?.name?.let { return it }
            // 4) any group name
            return names.firstOrNull { it.isGroup }?.name
        }

        // Returns a human-readable label for a NetBIOS name based on suffix + group flag + special names
        @JvmStatic
        fun describeSuffix(suffix: String?, isGroup: Boolean, rawName: String? = null): String? {
            // MSBROWSE marker
            if (rawName == NetBiosTools.MSBROWSE && suffix.equals("01", true)) {
                return "Local Master Browser (MSBROWSE)"
            }
            val key = suffix?.uppercase() ?: return null
            val meta = NetBiosTools.META[key] ?: return null
            val base = if (isGroup) meta.descGroup ?: meta.descUnique else meta.descUnique ?: meta.descGroup
            return base ?: meta.notes
        }
    }

    companion object {
        @Volatile
        private var defaultDisableProcNetMethod: Boolean = false

        /**
         * @param disable if true we will not attempt to read /proc/net/arp directly.
         * This avoids Android 10+ permission logs.
         * Returns Companion so you can chain `.fromLocalAddress()` like before.
         */
        fun setDisableProcNetMethod(disable: Boolean): Companion {
            defaultDisableProcNetMethod = disable
            return this
        }

        /**
         * Find devices on the subnet working from the local device ip address
         *
         * @return - this for chaining
         */
        fun fromLocalAddress(): SubnetDevices {
            val ipv4 = localIPv4Address
                ?: throw IllegalAccessError("Could not access local IP address")
            return fromIPAddress(ipv4.hostAddress)
        }

        /**
         * @param inetAddress - an ip address in the subnet
         *
         * @return - this for chaining
         */
        fun fromIPAddress(inetAddress: InetAddress): SubnetDevices = fromIPAddress(inetAddress.hostAddress)

        /**
         * @param ipAddress - the ipAddress string of any device in the subnet i.e. "192.168.0.1"
         * the final part will be ignored
         *
         * @return - this for chaining
         */
        fun fromIPAddress(ipAddress: String): SubnetDevices {
            require(isIPv4Address(ipAddress)) { "Invalid IP Address, IPv4 needed" }
            val segment = ipAddress.substring(0, ipAddress.lastIndexOf(".") + 1)
            val subnetDevice = SubnetDevices().apply { disableProcNetMethod = defaultDisableProcNetMethod }
            subnetDevice.addresses = ArrayList()

            // Get addresses from ARP Info first as they are likely to be reachable
            if (!subnetDevice.disableProcNetMethod) {
                for (ip in allIPAddressesInARPCache) {
                    if (ip.startsWith(segment)) {
                        subnetDevice.addresses!!.add(ip)
                    }
                }
            }

            // Add all missing addresses in subnet
            for (j in 0..254) {
                if (!subnetDevice.addresses!!.contains("$segment$j")) {
                    subnetDevice.addresses!!.add("$segment$j")
                }
            }
            return subnetDevice
        }

        /**
         * @param ipAddresses - the ipAddresses of devices to be checked
         *
         * @return - this for chaining
         */
        fun fromIPList(ipAddresses: List<String>?): SubnetDevices {
            val subnetDevice = SubnetDevices().apply { disableProcNetMethod = defaultDisableProcNetMethod }
            subnetDevice.addresses = ArrayList()
            subnetDevice.addresses!!.addAll(ipAddresses!!)
            return subnetDevice
        }

        @JvmStatic
        fun discovery(): DiscoveryBuilder = DiscoveryBuilder()
    }

    data class NsdService(
        val name: String,
        val type: String,
        val host: String?,
        val port: Int,
        val attributes: Map<String, String> = emptyMap()
    )

    data class UpnpInfo(
        val server: String? = null,
        val st: String? = null,
        val usn: String? = null,
        val location: String? = null,
        val friendlyName: String? = null,
        val modelName: String? = null,
        val manufacturer: String? = null,
        val deviceType: String? = null
    )

    data class NetBiosName(
        val name: String,
        val suffix: String?,
        val isGroup: Boolean
    )

    data class NetBiosInfo(
        val primaryName: String?,
        val mac: String?,
        val names: List<NetBiosName>
    )

    data class NetworkDeviceInfo(
        val ip: String,
        var mac: String? = null,
        var timeMs: Float? = null,
        var vendor: String? = null,
        var netbios: NetBiosInfo? = null,
        var upnp: UpnpInfo? = null,
        var nsdServices: List<NsdService>? = null
    )

    interface DiscoveryListener {
        fun onDeviceFound(device: NetworkDeviceInfo) {}
        fun onDeviceUpdated(device: NetworkDeviceInfo) {}
        fun onFinished(devices: List<NetworkDeviceInfo>) {}
        fun onStageChanged(stageIndex: Int, stageCount: Int, stageName: String) {}
        fun onProgress(done: Int, total: Int) {}
    }

    class DiscoverySession internal constructor(
        private val cancelFlag: AtomicBoolean,
        private val subnetScanner: SubnetDevices?,
        private val pendingJobs: MutableList<Future<*>>,
        private val executor: ExecutorService
    ) {
        fun cancel() {
            cancelFlag.set(true)
            subnetScanner?.cancel()
            synchronized(pendingJobs) {
                for (f in pendingJobs) {
                    try { f.cancel(true) } catch (_: Throwable) {}
                }
                pendingJobs.clear()
            }
            try { executor.shutdownNow() } catch (_: Throwable) {}
        }
    }

    class DiscoveryBuilder {
        private var threads: Int = 256
        private var timeoutMs: Int = 3000
        private var disableProcNetMethod: Boolean = false

        private var enableNetBios: Boolean = true
        private var enableUpnp: Boolean = true
        private var enableNsd: Boolean = false
        private var nsdContext: Context? = null
        private var nsdServiceTypes: List<String> = emptyList()
        private var extrasTimeoutMs: Int = 5000
        private var vendorResolver: ((String) -> String?)? = null

        fun setNoThreads(n: Int) = apply { threads = n }
        fun setTimeOutMillis(ms: Int) = apply { timeoutMs = ms }
        fun setDisableProcNetMethod(disable: Boolean) = apply { disableProcNetMethod = disable }

        fun enableNetBios(enabled: Boolean) = apply { enableNetBios = enabled }
        fun enableUpnp(enabled: Boolean) = apply { enableUpnp = enabled }
        fun enableNsd(context: Context?, enabled: Boolean = true) = apply {
            enableNsd = enabled
            nsdContext = context?.applicationContext
        }
        fun setNsdServiceTypes(types: List<String>) = apply { nsdServiceTypes = types }
        // fun setExtrasTimeoutMillis(ms: Int) = apply { extrasTimeoutMs = ms }
        fun setVendorResolver(resolver: (String) -> String?) = apply { vendorResolver = resolver }

        fun findDevices(listener: DiscoveryListener): DiscoverySession {
            val cancelFlag = AtomicBoolean(false)
            val executor: ExecutorService = Executors.newCachedThreadPool()
            val pendingJobs = Collections.synchronizedList(mutableListOf<Future<*>>())
            val devices = ConcurrentHashMap<String, NetworkDeviceInfo>()
            var scanRef: SubnetDevices? = null

            val stageNames = mutableListOf<String>().apply {
                add("Scan") // Ping/ARP scan (NetBIOS runs alongside)
                if (enableUpnp) add("UPnP")
                if (enableNsd) add("NSD")
            }
            val stageCount = stageNames.size
            var stageIndex = 1

            // Stage 1
            listener.onStageChanged(stageIndex, stageCount, stageNames[0])

            fun getOrCreate(ip: String): NetworkDeviceInfo {
                devices[ip]?.let { return it }
                val new = NetworkDeviceInfo(ip = ip)
                val prev = devices.putIfAbsent(ip, new)
                return prev ?: new
            }

            // Kick off UPnP early
            val upnpFuture: Future<Map<String, UpnpInfo>>? = if (enableUpnp) {
                executor.submit<Map<String, UpnpInfo>> {
                    val byIp = mutableMapOf<String, UpnpInfo>()
                    try {
                        val found = SsdpDiscovery.discover(timeoutMs = extrasTimeoutMs)
                        for (ssdp in found) {
                            val ip = ssdp.ip
                            val info = UpnpInfo(
                                server = ssdp.server,
                                st = ssdp.st,
                                usn = ssdp.usn,
                                location = ssdp.location,
                                friendlyName = ssdp.friendlyName,
                                modelName = ssdp.modelName,
                                manufacturer = ssdp.manufacturer,
                                deviceType = ssdp.deviceType
                            )
                            byIp[ip] = info
                        }
                    } catch (_: Throwable) { /* ignore */ }
                    byIp
                }.also { pendingJobs.add(it) }
            } else null

            // Kick off NSD early
            val nsdFuture: Future<Map<String, List<NsdService>>>? =
                if (enableNsd && nsdContext != null) {
                    executor.submit<Map<String, List<NsdService>>> {
                        val results = mutableMapOf<String, MutableList<NsdService>>()
                        try {
                            val list = NsdDiscovery.discover(
                                context = nsdContext!!,
                                timeoutMs = extrasTimeoutMs,
                                serviceTypes = nsdServiceTypes.ifEmpty { NsdDiscovery.defaultTypes }
                            )
                            list.forEach { svc ->
                                val ip = svc.host
                                if (!ip.isNullOrBlank()) {
                                    results.getOrPut(ip) { mutableListOf() }
                                        .add(NsdService(
                                            name = svc.name,
                                            type = svc.type,
                                            host = ip,
                                            port = svc.port,
                                            attributes = svc.attributes
                                        ))
                                }
                            }
                        } catch (_: Throwable) { /* ignore */ }
                        results
                    }.also { pendingJobs.add(it) }
                } else null

            // Start SubnetDevices ping scan
            scanRef = SubnetDevices
                .setDisableProcNetMethod(disableProcNetMethod)
                .fromLocalAddress()
                .setNoThreads(threads)
                .setTimeOutMillis(timeoutMs)
                .setScanProgressListener(object : OnScanProgress {
                    override fun onProgress(done: Int, total: Int) {
                        listener.onProgress(done, total)
                    }
                })
                .findDevices(object : OnSubnetDeviceFound {
                    override fun onDeviceFound(device: Device?) {
                        if (device == null || cancelFlag.get()) return
                        val info = getOrCreate(device.ip)
                        synchronized(info) {
                            if (device.mac != null) info.mac = device.mac
                            if (device.time > 0f) info.timeMs = device.time
                            if (!info.mac.isNullOrBlank() && vendorResolver != null) {
                                info.vendor = vendorResolver!!.invoke(info.mac!!.uppercase())
                            }
                        }
                        listener.onDeviceFound(info)

                        if (enableNetBios) {
                            val job = executor.submit {
                                try {
                                    val nb = NetBiosTools.queryInfo(device.ip, timeoutMs = 2000)
                                    if (nb != null && !cancelFlag.get()) {
                                        val again = devices[device.ip]
                                        if (again != null) {
                                            var changed = false
                                            synchronized(again) {
                                                val converted = NetBiosInfo(
                                                    primaryName = nb.primaryName,
                                                    mac = nb.mac,
                                                    names = nb.names.map { NetBiosName(it.name, it.suffix, it.isGroup) }
                                                )
                                                if (again.netbios != converted) {
                                                    again.netbios = converted
                                                    changed = true
                                                }
                                                if (again.mac.isNullOrBlank() && !nb.mac.isNullOrBlank()) {
                                                    again.mac = nb.mac
                                                    if (vendorResolver != null) {
                                                        again.vendor = vendorResolver!!.invoke(nb.mac.uppercase())
                                                    }
                                                    changed = true
                                                }
                                            }
                                            if (changed) listener.onDeviceUpdated(again)
                                        }
                                    }
                                } catch (_: Throwable) {}
                            }
                            pendingJobs.add(job)
                        }
                    }

                    override fun onFinished(devicesFound: ArrayList<Device>?) {
                        // Refresh mac/time from final ARP pass
                        devicesFound?.forEach { d ->
                            val entry = getOrCreate(d.ip)
                            synchronized(entry) {
                                if (d.mac != null) entry.mac = d.mac
                                if (d.time > 0f) entry.timeMs = d.time
                                if (!entry.mac.isNullOrEmpty() && vendorResolver != null) {
                                    entry.vendor = vendorResolver!!.invoke(entry.mac!!.uppercase())
                                }
                            }
                            listener.onDeviceUpdated(entry)
                        }

                        // Stage 2: UPnP (if enabled)
                        val hasUpnp = (upnpFuture != null)
                        if (hasUpnp) {
                            stageIndex = 2
                            listener.onStageChanged(stageIndex, stageCount, "UPnP")
                        }

                        // Merge UPnP + NSD results
                        val upnpByIp = try {
                            upnpFuture?.get()
                        } catch (_: Throwable) { null } ?: emptyMap()
                        upnpByIp.forEach { (ip, upnp) ->
                            val info = getOrCreate(ip)
                            synchronized(info) { info.upnp = upnp }
                            listener.onDeviceUpdated(info)
                        }

                        // Stage 3: NSD (or Stage 2 if no UPnP)
                        val hasNsd = (nsdFuture != null)
                        if (hasNsd) {
                            stageIndex = if (hasUpnp) 3 else 2
                            listener.onStageChanged(stageIndex, stageCount, "NSD")
                        }

                        val nsdByIp = try {
                            nsdFuture?.get()
                        } catch (_: Throwable) { null } ?: emptyMap()
                        nsdByIp.forEach { (ip, nsdList) ->
                            val info = getOrCreate(ip)
                            synchronized(info) { info.nsdServices = nsdList }
                            listener.onDeviceUpdated(info)
                        }

                        synchronized(pendingJobs) {
                            for (f in pendingJobs) {
                                if (cancelFlag.get()) break
                                try { f.get() } catch (_: Throwable) {}
                            }
                            pendingJobs.clear()
                        }

                        val sorted = devices.values.sortedBy { ipToLong(it.ip) }
                        listener.onFinished(sorted)
                        try { executor.shutdownNow() } catch (_: Throwable) {}
                    }
                })

            return DiscoverySession(cancelFlag, scanRef, pendingJobs, executor)
        }

        private fun ipToLong(ip: String): Long {
            return try {
                val addr = InetAddress.getByName(ip) as? java.net.Inet4Address ?: return Long.MAX_VALUE
                val b = addr.address
                ((b[0].toLong() and 0xff) shl 24) or
                        ((b[1].toLong() and 0xff) shl 16) or
                        ((b[2].toLong() and 0xff) shl 8) or
                        (b[3].toLong() and 0xff)
            } catch (_: Throwable) { Long.MAX_VALUE }
        }
    }
}