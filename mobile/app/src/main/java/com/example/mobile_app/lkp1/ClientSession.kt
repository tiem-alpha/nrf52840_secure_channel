package com.example.mobile_app.lkp1

import java.security.SecureRandom
import java.util.Arrays

/** One client session per BLE connection. All methods are called serially by the BLE owner. */
class ClientSession(
    private val identity: KeyStoreProvider,
    private val roots: List<ByteArray>,
    private val serial: ByteArray,
    private val random: SecureRandom = SecureRandom(),
    private val nowMs: () -> Long = System::currentTimeMillis
) {
    enum class State { IDLE, SENT_CH, GOT_F2, SENT_F3, OPEN, CLOSED }
    var state = State.IDLE; private set
    private val assembler = RecordAssembler(nowMs)
    private val transcript = ArrayList<ByteArray>()
    private var started = 0L
    private lateinit var eph: EphemeralX25519
    private lateinit var cNonce: ByteArray
    private lateinit var prk: ByteArray
    private lateinit var cHsKey: ByteArray
    private lateinit var cHsIv: ByteArray
    private lateinit var sHsKey: ByteArray
    private lateinit var sHsIv: ByteArray
    private lateinit var cFin: ByteArray
    private lateinit var sFin: ByteArray
    private lateinit var c2sKey: ByteArray
    private lateinit var c2sIv: ByteArray
    private lateinit var s2cKey: ByteArray
    private lateinit var s2cIv: ByteArray
    private lateinit var sessionId: ByteArray
    private var sendSeq = 0L
    private var recvSeq = 0L
    var lastAppData: ByteArray? = null; private set

    fun start(): ByteArray {
        require(state == State.IDLE)
        started = nowMs()
        eph = EphemeralX25519(random)
        cNonce = ByteArray(32).also(random::nextBytes)
        val m1 = Framing.message(1, byteArrayOf(0, 1) + eph.publicKey + cNonce)
        transcript += m1
        state = State.SENT_CH
        return Framing.record(Framing.HANDSHAKE, m1)
    }

    /** Returns records to send; application data is returned separately by receiveApp. */
    fun receive(fragment: ByteArray): List<ByteArray> {
        try {
            require(state != State.CLOSED && state != State.IDLE)
            require(state == State.OPEN || nowMs() - started <= 10_000)
            return assembler.accept(fragment).mapNotNull { (type, body) ->
                when {
                    type == Framing.ALERT -> throw IllegalArgumentException("peer alert")
                    state == State.SENT_CH && type == Framing.HANDSHAKE -> { serverHello(body); null }
                    state == State.GOT_F2 && type == Framing.HANDSHAKE_ENC -> serverFlight(body)
                    state == State.OPEN && type == Framing.APP_DATA -> { lastAppData = receiveApp(body); null }
                    else -> throw IllegalArgumentException("unexpected record")
                }
            }
        } catch (e: Exception) { close(); throw e }
    }
    private fun serverHello(m2: ByteArray) {
        val body = Framing.parseMessage(m2, 2)
        require(body.size == 66 && body[0] == 0.toByte() && body[1] == 1.toByte())
        transcript += m2
        val shared = try { eph.agree(body.copyOfRange(2, 34)) } finally { eph.destroy() }
        try { prk = Crypto.extract(cNonce + body.copyOfRange(34, 66), shared) }
        finally { shared.fill(0) }
        val ctx = hashTranscript()
        cHsKey = Crypto.expand(prk, "c hs key", ctx, 16)
        cHsIv = Crypto.expand(prk, "c hs iv", ctx, 12)
        sHsKey = Crypto.expand(prk, "s hs key", ctx, 16)
        sHsIv = Crypto.expand(prk, "s hs iv", ctx, 12)
        cFin = Crypto.expand(prk, "c finished", ctx, 32)
        sFin = Crypto.expand(prk, "s finished", ctx, 32)
        state = State.GOT_F2
    }
    private fun serverFlight(body: ByteArray): ByteArray {
        require(body.size >= 16)
        val aad = byteArrayOf(1, 2, (body.size ushr 8).toByte(), body.size.toByte())
        val plain = Crypto.open(sHsKey, Crypto.nonce(sHsIv, 0), aad, body)
        val messages = split(plain)
        require(messages.size == 3 && messages[0][0] == 0x0b.toByte() &&
            messages[1][0] == 0x0f.toByte() && messages[2][0] == 0x14.toByte())
        val certBody = Framing.parseMessage(messages[0], 0x0b)
        require(certBody.isNotEmpty())
        val count = certBody[0].toInt() and 255
        require(count in 1..2)
        var offset = 1
        val chain = (0 until count).map {
            require(offset + 2 <= certBody.size)
            val length = Framing.u16(certBody, offset); offset += 2
            require(length == 164 && offset + length <= certBody.size)
            certBody.copyOfRange(offset, offset + length).also { offset += length }
        }
        require(offset == certBody.size)
        val lockKey = Certificates.validateLock(chain, roots, serial, nowMs() / 1000)
        transcript += messages[0]
        val signature = Framing.parseMessage(messages[1], 0x0f)
        require(Certificates.verify(lockKey, "LKP1-SIG-SERVER".toByteArray() + byteArrayOf(0) + hashTranscript(), signature))
        transcript += messages[1]
        val expected = Crypto.hmac(sFin, hashTranscript())
        require(Arrays.equals(expected, Framing.parseMessage(messages[2], 0x14)))
        transcript += messages[2]
        val ownChain = identity.certificateChain
        require(ownChain.size in 1..2 && ownChain.all { it.size == 164 })
        val cert = Framing.message(0x0b, byteArrayOf(ownChain.size.toByte()) + ownChain.fold(ByteArray(0)) { acc, c ->
            acc + byteArrayOf((c.size ushr 8).toByte(), c.size.toByte()) + c
        })
        transcript += cert
        val verify = Framing.message(0x0f, identity.sign("LKP1-SIG-CLIENT".toByteArray() + byteArrayOf(0) + hashTranscript()))
        require(Framing.parseMessage(verify, 0x0f).size == 64)
        transcript += verify
        val finished = Framing.message(0x14, Crypto.hmac(cFin, hashTranscript()))
        transcript += finished
        val payload = cert + verify + finished
        val header = byteArrayOf(1, 2, ((payload.size + 16) ushr 8).toByte(), (payload.size + 16).toByte())
        val encrypted = Crypto.seal(cHsKey, Crypto.nonce(cHsIv, 0), header, payload)
        val master = Crypto.expand(prk, "master", hashTranscript(), 32)
        c2sKey = Crypto.expand(master, "c2s key", ByteArray(0), 16)
        c2sIv = Crypto.expand(master, "c2s iv", ByteArray(0), 12)
        s2cKey = Crypto.expand(master, "s2c key", ByteArray(0), 16)
        s2cIv = Crypto.expand(master, "s2c iv", ByteArray(0), 12)
        sessionId = Crypto.expand(master, "session id", ByteArray(0), 4)
        master.fill(0)
        clearHandshakeSecrets()
        transcript.forEach { it.fill(0) }
        transcript.clear()
        state = State.SENT_F3
        return header + encrypted
    }
    /** Called only after the transport confirms every ATT fragment of F3 was written. */
    fun confirmF3Sent() {
        require(state == State.SENT_F3)
        state = State.OPEN
    }
    fun appData(plain: ByteArray): ByteArray {
        require(state == State.OPEN && plain.size <= 512 && sendSeq < 0xffffffffL && nowMs() - started <= 86_400_000)
        val seq = byteArrayOf((sendSeq ushr 24).toByte(), (sendSeq ushr 16).toByte(), (sendSeq ushr 8).toByte(), sendSeq.toByte())
        val bodyLength = 8 + plain.size + 16
        val header = byteArrayOf(1, 3, (bodyLength ushr 8).toByte(), bodyLength.toByte())
        val ciphertext = Crypto.seal(c2sKey, Crypto.nonce(c2sIv, sendSeq), header + sessionId + seq, plain)
        sendSeq++
        return header + sessionId + seq + ciphertext
    }
    fun receiveApp(body: ByteArray): ByteArray {
        try {
            require(state == State.OPEN && body.size in 24..536 && nowMs() - started <= 86_400_000)
            require(body.copyOfRange(0, 4).contentEquals(sessionId))
            val seq = (0..3).fold(0L) { v, i -> (v shl 8) or (body[4 + i].toLong() and 255) }
            require(seq == recvSeq && seq < 0xffffffffL)
            val header = byteArrayOf(1, 3, (body.size ushr 8).toByte(), body.size.toByte())
            val clear = Crypto.open(s2cKey, Crypto.nonce(s2cIv, seq), header + body.copyOfRange(0, 8), body.copyOfRange(8, body.size))
            recvSeq++
            return clear
        } catch (e: Exception) { close(); throw e }
    }
    fun close() {
        state = State.CLOSED
        assembler.reset()
        if (::eph.isInitialized) eph.destroy()
        clearHandshakeSecrets()
        if (::c2sKey.isInitialized) c2sKey.fill(0)
        if (::s2cKey.isInitialized) s2cKey.fill(0)
        if (::c2sIv.isInitialized) c2sIv.fill(0)
        if (::s2cIv.isInitialized) s2cIv.fill(0)
        if (::sessionId.isInitialized) sessionId.fill(0)
        lastAppData?.fill(0)
        lastAppData = null
        transcript.forEach { it.fill(0) }
        transcript.clear()
    }
    private fun clearHandshakeSecrets() {
        if (::cNonce.isInitialized) cNonce.fill(0)
        if (::prk.isInitialized) prk.fill(0)
        if (::cHsKey.isInitialized) cHsKey.fill(0)
        if (::sHsKey.isInitialized) sHsKey.fill(0)
        if (::cHsIv.isInitialized) cHsIv.fill(0)
        if (::sHsIv.isInitialized) sHsIv.fill(0)
        if (::cFin.isInitialized) cFin.fill(0)
        if (::sFin.isInitialized) sFin.fill(0)
    }
    private fun hashTranscript(): ByteArray = Crypto.sha256(transcript.fold(ByteArray(0), ByteArray::plus))
    private fun split(data: ByteArray): List<ByteArray> {
        val result = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            require(offset + 3 <= data.size)
            val length = Framing.u16(data, offset + 1)
            require(offset + 3 + length <= data.size)
            result += data.copyOfRange(offset, offset + 3 + length)
            offset += 3 + length
        }
        return result
    }
}
