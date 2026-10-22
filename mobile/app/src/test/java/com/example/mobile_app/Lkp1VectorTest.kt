package com.example.mobile_app

import com.example.mobile_app.lkp1.*
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.junit.Assert.*
import org.junit.Test

class Lkp1VectorTest {
    private val json = javaClass.getResource("/lkp1_vectors.json")!!.readText()
    private fun hex(name: String): ByteArray {
        val value = Regex("\\\"" + name + "\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").find(json)!!.groupValues[1]
        return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    @Test fun verifiesCertificateAndKeySchedule() {
        val m1 = hex("M1"); val m2 = hex("M2")
        val root = Regex("\\\"roots\\\"\\s*:\\s*\\[\\s*\\\"([0-9a-f]+)\\\"").find(json)!!.groupValues[1]
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val certificate = hex("M3").copyOfRange(6, 170)
        assertArrayEquals(certificate.copyOfRange(36, 100), Certificates.validateLock(listOf(certificate), listOf(root), hex("server_id"), 0))
        val client = X25519PrivateKeyParameters(hex("client_ephemeral_private"), 0)
        val agreement = X25519Agreement().also { it.init(client) }
        val ss = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(m2.copyOfRange(5, 37), 0), ss, 0)
        val prk = Crypto.extract(hex("client_nonce") + hex("server_nonce"), ss)
        val hello = Crypto.sha256(m1 + m2)
        val key = Crypto.expand(prk, "s hs key", hello, 16)
        val iv = Crypto.expand(prk, "s hs iv", hello, 12)
        assertArrayEquals(hex("s_hs_key"), key)
        assertArrayEquals(hex("s_hs_iv"), iv)
        val record = hex("F2b")
        val plain = Crypto.open(key, Crypto.nonce(iv, 0), record.copyOfRange(0, 4), record.copyOfRange(4, record.size))
        assertArrayEquals(hex("M3") + hex("M4") + hex("M5"), plain)
        val all = (1..8).fold(ByteArray(0)) { acc, i -> acc + hex("M$i") }
        val master = Crypto.expand(prk, "master", Crypto.sha256(all), 32)
        assertArrayEquals(hex("master"), master)
        assertArrayEquals(hex("c2s_key"), Crypto.expand(master, "c2s key", ByteArray(0), 16))
        assertArrayEquals(hex("session_id"), Crypto.expand(master, "session id", ByteArray(0), 4))
    }
    @Test fun rejectsTamperedAeadAndWrongCertificateRole() {
        val record = hex("F2b")
        val corrupt = record.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) {
            Crypto.open(hex("s_hs_key"), Crypto.nonce(hex("s_hs_iv"), 0),
                corrupt.copyOfRange(0, 4), corrupt.copyOfRange(4, corrupt.size))
        }
        val m6 = hex("M6")
        val phoneCert = m6.copyOfRange(6, 170)
        val root = Regex("\\\"roots\\\"\\s*:\\s*\\[\\s*\\\"([0-9a-f]+)\\\"").find(json)!!.groupValues[1]
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertThrows(IllegalArgumentException::class.java) {
            Certificates.validateLock(listOf(phoneCert), listOf(root), hex("client_id"), 0)
        }
    }
}
