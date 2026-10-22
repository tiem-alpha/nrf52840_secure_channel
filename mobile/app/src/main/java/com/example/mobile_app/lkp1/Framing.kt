package com.example.mobile_app.lkp1

/** LKP1 record framing is independent of ATT packet boundaries. */
object Framing {
    const val HANDSHAKE = 1
    const val HANDSHAKE_ENC = 2
    const val APP_DATA = 3
    const val ALERT = 4
    const val MAX_BODY = 1024

    fun record(type: Int, body: ByteArray): ByteArray {
        require(type in 1..4 && body.size <= MAX_BODY)
        return byteArrayOf(1, type.toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
    }

    fun message(type: Int, body: ByteArray): ByteArray {
        require(body.size <= MAX_BODY - 3)
        return byteArrayOf(type.toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
    }

    fun parseMessage(data: ByteArray, expectedType: Int): ByteArray {
        require(data.size >= 3 && (data[0].toInt() and 255) == expectedType)
        val length = u16(data, 1)
        require(length == data.size - 3)
        return data.copyOfRange(3, data.size)
    }

    fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 255) shl 8) or (data[offset + 1].toInt() and 255)
}

/** One assembler per BLE connection. Rejects oversized records before allocating their body. */
class RecordAssembler(private val nowMs: () -> Long = System::currentTimeMillis) {
    private var buffer = ByteArray(0)
    private var lastFragment = 0L

    fun reset() { buffer = ByteArray(0); lastFragment = 0L }

    fun accept(fragment: ByteArray): List<Pair<Int, ByteArray>> {
        val now = nowMs()
        if (buffer.isNotEmpty() && now - lastFragment > 5_000) {
            reset()
            throw IllegalArgumentException("fragment timeout")
        }
        lastFragment = now
        require(fragment.size <= Framing.MAX_BODY + 4)
        // A fragment may finish one record and start the next. Bound the temporary
        // aggregate to two maximum records, then retain at most one partial record.
        buffer += fragment
        val records = mutableListOf<Pair<Int, ByteArray>>()
        while (buffer.size >= 4) {
            require(buffer[0] == 1.toByte()) { "version" }
            val type = buffer[1].toInt() and 255
            require(type in 1..4) { "record type" }
            val length = Framing.u16(buffer, 2)
            require(length <= Framing.MAX_BODY) { "body too long" }
            if (buffer.size < length + 4) break
            records += type to buffer.copyOfRange(4, length + 4)
            buffer = buffer.copyOfRange(length + 4, buffer.size)
        }
        require(buffer.size <= Framing.MAX_BODY + 4) { "record overflow" }
        return records
    }
}
