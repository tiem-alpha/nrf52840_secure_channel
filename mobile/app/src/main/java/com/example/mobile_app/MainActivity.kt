package com.example.mobile_app

import android.Manifest
import android.bluetooth.BluetoothManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.mobile_app.ble.FotaClient
import com.example.mobile_app.ble.NusTransport
import com.example.mobile_app.lkp1.ClientSession
import com.example.mobile_app.lkp1.PrototypeIdentity

/** Prototype console. The lock serial must come from a trusted setup record. */
class MainActivity : ComponentActivity(), NusTransport.Listener {
    private var identity: PrototypeIdentity? = null
    private var session: ClientSession? = null
    private var transport: NusTransport? = null
    private var fota: FotaClient? = null
    private var fotaMode = false
    private var status by mutableStateOf("Import phone identity to begin")
    private var address by mutableStateOf("")
    private var serialHex by mutableStateOf("")
    private val importIdentity = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) try {
            val content = contentResolver.openInputStream(uri)!!.bufferedReader().use { it.readText() }
            identity = PrototypeIdentity.fromJson(content)
            status = "Phone identity loaded for this app session"
        } catch (e: Exception) { status = "Identity import failed" }
    }
    private val importImage = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) try {
            val bytes = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
            fota?.start(bytes)
            status = "FOTA upload started"
        } catch (e: Exception) { status = "FOTA failed: " + e.javaClass.simpleName }
    }
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        if (result.values.any { !it }) status = "Bluetooth permission required" else connect()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("LKP1 lock console", style = MaterialTheme.typography.headlineMedium)
                    Text(status)
                    Button(onClick = { importIdentity.launch(arrayOf("application/json", "text/plain")) }) { Text("Import phone identity") }
                    OutlinedTextField(value = address, onValueChange = { address = it }, label = { Text("BLE address") })
                    OutlinedTextField(value = serialHex, onValueChange = { serialHex = it }, label = { Text("Pinned lock serial (32 hex digits)") })
                    Button(onClick = { requestConnect() }) { Text("Connect securely") }
                    Button(enabled = session?.state == ClientSession.State.OPEN, onClick = {
                        try { transport?.send(session!!.appData(byteArrayOf(1) + "demo".toByteArray()))
                            status = "Demo command sent" } catch (e: Exception) { status = "Send failed" }
                    }) { Text("Send demo command") }
                    Button(onClick = { try {
                        val device = (getSystemService(BLUETOOTH_SERVICE) as BluetoothManager).adapter.getRemoteDevice(address)
                        // Firmware permits one BLE connection. Release NUS before SMP connects.
                        fotaMode = true
                        session?.close(); session = null
                        status = "Closing LKP1 before FOTA"
                        val oldTransport = transport
                        transport = null
                        val openFotaPicker = {
                            runOnUiThread {
                                fota?.release(); fota = FotaClient(this@MainActivity, device)
                                status = "Select signed image for encrypted SMP update"
                                importImage.launch(arrayOf("application/octet-stream", "application/zip"))
                            }
                        }
                        if (oldTransport == null) openFotaPicker()
                        else oldTransport.disconnectForFota(openFotaPicker)
                    } catch (e: Exception) { status = "Invalid BLE address" } }) { Text("Select signed MCUboot image for FOTA") }
                }
            }
        }
    }
    private fun requestConnect() {
        val requested = if (Build.VERSION.SDK_INT >= 31)
            arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN)
        else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        permissions.launch(requested)
    }
    private fun connect() {
        try {
            fotaMode = false
            fota?.release(); fota = null
            val id = identity ?: throw IllegalArgumentException("Import phone identity")
            require(serialHex.length == 32)
            val serial = serialHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            session = ClientSession(id, id.roots, serial)
            val device = (getSystemService(BLUETOOTH_SERVICE) as BluetoothManager).adapter.getRemoteDevice(address)
            transport?.close()
            transport = NusTransport(this, this).also { it.connect(device) }
            status = "Connecting"
        } catch (e: Exception) { status = "Connect setup failed: " + e.message }
    }
    override fun onReady() = runOnUiThread {
        try { transport?.send(session!!.start()); status = "Authenticating lock" }
        catch (e: Exception) { status = "Handshake failed"; transport?.close() }
    }
    override fun onBytes(bytes: ByteArray) = runOnUiThread {
        try {
            val s = session ?: return@runOnUiThread
            s.receive(bytes).forEach { transport?.send(it) }
            val reply = s.lastAppData
            status = when {
                reply?.contentEquals(byteArrayOf(0x81.toByte()) + "ready".toByteArray()) == true -> "Lock ready"
                s.state == ClientSession.State.OPEN -> "Secure channel open"
                else -> "Authenticating lock"
            }
        } catch (e: Exception) { status = "Secure channel rejected"; transport?.close() }
    }
    override fun onRecordSent() = runOnUiThread {
        val s = session
        if (s?.state == ClientSession.State.SENT_F3) {
            s.confirmF3Sent()
            status = "Secure channel open"
        }
    }
    override fun onClosed(reason: String) = runOnUiThread {
        if (!fotaMode) { session?.close(); status = reason }
    }
    override fun onDestroy() { transport?.close(); fota?.release(); session?.close(); super.onDestroy() }
}
