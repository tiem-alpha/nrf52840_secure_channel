package com.example.mobile_app

import com.example.mobile_app.lkp1.*
import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

class ReviewFixTest {
    @Test fun concatenatedRecordsCanFinishPartialMaximumRecord() {
        val large = Framing.record(Framing.HANDSHAKE_ENC, ByteArray(1024) { 7 })
        val next = Framing.record(Framing.ALERT, byteArrayOf(1))
        val assembler = RecordAssembler { 1L }
        assertTrue(assembler.accept(large.copyOfRange(0, 1000)).isEmpty())
        val received = assembler.accept(large.copyOfRange(1000, large.size) + next)
        assertEquals(2, received.size)
        assertEquals(1024, received[0].second.size)
        assertArrayEquals(byteArrayOf(1), received[1].second)
    }

    @Test fun expiredIssuingCaIsRejected() {
        val leaf = ByteArray(164)
        leaf[0] = 1; leaf[1] = 1
        leaf[35] = 1 // SIGN_HANDSHAKE
        val ca = ByteArray(164)
        ca[0] = 1; ca[1] = 0x10
        ca[33] = 1 // not_after = 1 Unix second
        ca[35] = 2 // CA_SIGN
        assertThrows(IllegalArgumentException::class.java) {
            Certificates.validateLock(listOf(leaf, ca), listOf(ByteArray(64)), ByteArray(16), 2)
        }
    }

    @Test fun ephemeralCannotBeUsedAfterDestroy() {
        val key = EphemeralX25519(SecureRandom())
        val peer = EphemeralX25519(SecureRandom())
        assertArrayEquals(key.agree(peer.publicKey), peer.agree(key.publicKey))
        key.destroy()
        val bytes = EphemeralX25519::class.java.getDeclaredField("privateBytes").also { it.isAccessible = true }.get(key) as ByteArray
        assertTrue(bytes.all { it == 0.toByte() })
        assertThrows(IllegalArgumentException::class.java) { key.agree(peer.publicKey) }
    }
}
