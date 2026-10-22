package com.example.mobile_app.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.os.Build
import java.util.UUID

/** ATT transport for NUS. Record parsing belongs to the protocol layer. */
@SuppressLint("MissingPermission")
class NusTransport(private val context: Context, private val listener: Listener) {
    interface Listener {
        fun onReady()
        fun onBytes(bytes: ByteArray)
        fun onRecordSent()
        fun onClosed(reason: String)
    }
    companion object {
        private val SERVICE = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e")
        private val RX = UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
        private val TX = UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e")
        private val CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
    private var gatt: BluetoothGatt? = null
    private var rx: BluetoothGattCharacteristic? = null
    private var mtu = 23
    private val pending = ArrayDeque<Pair<ByteArray, Boolean>>()
    private var writing = false
    private var afterDisconnect: (() -> Unit)? = null

    fun connect(device: BluetoothDevice) {
        close()
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
    }
    fun close() {
        afterDisconnect = null
        gatt?.disconnect()
        gatt?.close()
        gatt = null
        rx = null
        pending.clear()
        writing = false
    }
    /** Wait for the controller to release the single BLE connection before SMP. */
    fun disconnectForFota(done: () -> Unit) {
        if (gatt == null) { done(); return }
        afterDisconnect = done
        gatt?.disconnect()
    }
    fun send(record: ByteArray) {
        require(rx != null) { "NUS unavailable" }
        val chunk = (mtu - 3).coerceAtLeast(20)
        for (start in record.indices step chunk) {
            val end = minOf(start + chunk, record.size)
            pending.addLast(record.copyOfRange(start, end) to (end == record.size))
        }
        writeNext()
    }
    private fun writeNext() {
        if (writing || pending.isEmpty()) return
        val g = gatt ?: return
        val characteristic = rx ?: return
        writing = true
        val data = pending.first().first
        val ok = if (Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(characteristic, data, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = data
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            @Suppress("DEPRECATION")
            g.writeCharacteristic(characteristic)
        }
        if (!ok) { writing = false; listener.onClosed("NUS write failed"); close() }
    }
    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, state: Int) {
            if (state == BluetoothProfile.STATE_DISCONNECTED && afterDisconnect != null) {
                val done = afterDisconnect
                afterDisconnect = null
                g.close(); gatt = null; rx = null; pending.clear(); writing = false
                done?.invoke()
                return
            }
            if (status != BluetoothGatt.GATT_SUCCESS || state == BluetoothProfile.STATE_DISCONNECTED) {
                listener.onClosed("BLE disconnected: " + status); close(); return
            }
            if (state == BluetoothProfile.STATE_CONNECTED) g.requestMtu(247)
        }
        override fun onMtuChanged(g: BluetoothGatt, value: Int, status: Int) {
            mtu = if (status == BluetoothGatt.GATT_SUCCESS) value else 23
            g.discoverServices()
        }
        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            val service = g.getService(SERVICE)
            rx = service?.getCharacteristic(RX)
            val tx = service?.getCharacteristic(TX)
            if (status != BluetoothGatt.GATT_SUCCESS || rx == null || tx == null) {
                listener.onClosed("NUS unavailable"); close(); return
            }
            g.setCharacteristicNotification(tx, true)
            val cccd = tx.getDescriptor(CCCD)
            if (cccd == null) { listener.onClosed("NUS notifications unavailable"); close(); return }
            val started = if (Build.VERSION.SDK_INT >= 33) {
                g.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                @Suppress("DEPRECATION")
                g.writeDescriptor(cccd)
            }
            if (!started) { listener.onClosed("NUS notification setup failed"); close() }
        }
        override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) listener.onReady()
            else { listener.onClosed("NUS notification setup failed"); close() }
        }
        override fun onCharacteristicWrite(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            writing = false
            if (status != BluetoothGatt.GATT_SUCCESS) { listener.onClosed("NUS write failed"); close(); return }
            val completedRecord = pending.removeFirst().second
            if (completedRecord) listener.onRecordSent()
            writeNext()
        }
        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            listener.onBytes(value)
        }
        @Deprecated("Android compatibility")
        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            if (Build.VERSION.SDK_INT < 33) listener.onBytes(characteristic.value ?: ByteArray(0))
        }
    }
}
