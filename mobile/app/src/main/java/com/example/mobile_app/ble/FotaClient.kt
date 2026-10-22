package com.example.mobile_app.ble

import android.bluetooth.BluetoothDevice
import android.content.Context
import io.runtime.mcumgr.ble.McuMgrBleTransport
import io.runtime.mcumgr.dfu.mcuboot.FirmwareUpgradeManager

/** Signed MCUboot image upload over Zephyr's BLE SMP service. */
class FotaClient(context: Context, device: BluetoothDevice) {
    private val transport = McuMgrBleTransport(context, device)
    private val manager = FirmwareUpgradeManager(transport)

    fun start(signedImage: ByteArray) {
        require(signedImage.isNotEmpty())
        manager.start(signedImage, FirmwareUpgradeManager.Settings.Builder().build())
    }
    fun cancel() = manager.cancel()
    fun release() = transport.release()
}
