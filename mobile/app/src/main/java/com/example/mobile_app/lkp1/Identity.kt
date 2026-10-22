package com.example.mobile_app.lkp1

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec

/** Device identity can be backed by provisioned key material or Android Keystore. */
interface KeyStoreProvider {
    val certificateChain: List<ByteArray>
    fun sign(message: ByteArray): ByteArray // Raw P-256 r || s, 64 bytes.
}

/** Raw P-256 certificate operations; certificates are the 164-byte LKP1 format. */
object Certificates {
    private val bc = BouncyCastleProvider()
    fun publicKey(raw: ByteArray): PublicKey {
        require(raw.size == 64)
        val params = ECNamedCurveTable.getParameterSpec("secp256r1")
        val point = params.curve.createPoint(
            BigInteger(1, raw.copyOfRange(0, 32)), BigInteger(1, raw.copyOfRange(32, 64))
        )
        require(!point.isInfinity && point.isValid)
        return KeyFactory.getInstance("EC", bc).generatePublic(ECPublicKeySpec(point, params))
    }
    fun der(raw: ByteArray): ByteArray {
        require(raw.size == 64)
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(0, 32))))
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(32, 64))))
        return DERSequence(v).encoded
    }
    fun raw(der: ByteArray): ByteArray {
        val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
        require(seq.size() == 2)
        fun fixed(i: Int): ByteArray {
            val bytes = ASN1Integer.getInstance(seq.getObjectAt(i)).positiveValue.toByteArray()
            require(bytes.size <= 33)
            return ByteArray(32 - bytes.takeLast(32).size) + bytes.takeLast(32)
        }
        return fixed(0) + fixed(1)
    }
    fun verify(pub: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 64) return false
        return Signature.getInstance("SHA256withECDSA", bc).run {
            initVerify(publicKey(pub)); update(message); verify(der(signature))
        }
    }
    fun validateLock(chain: List<ByteArray>, roots: List<ByteArray>, expectedSerial: ByteArray, nowSeconds: Long): ByteArray {
        require(chain.size in 1..2 && roots.size in 1..2 && expectedSerial.size == 16)
        val leaf = chain[0]
        require(leaf.size == 164 && leaf[0] == 1.toByte() && leaf[1] == 1.toByte())
        require(leaf.copyOfRange(2, 18).contentEquals(expectedSerial))
        require((Framing.u16(leaf, 34) and 1) != 0)
        val notBefore = uint32(leaf, 26)
        val notAfter = uint32(leaf, 30)
        require(nowSeconds >= notBefore && (notAfter == 0L || nowSeconds <= notAfter))
        val issuer = if (chain.size == 2) {
            val ca = chain[1]
            require(ca.size == 164 && ca[0] == 1.toByte() && ca[1] == 0x10.toByte())
            require((Framing.u16(ca, 34) and 2) != 0)
            val caNotBefore = uint32(ca, 26)
            val caNotAfter = uint32(ca, 30)
            require(nowSeconds >= caNotBefore && (caNotAfter == 0L || nowSeconds <= caNotAfter))
            val root = roots.firstOrNull { Crypto.sha256(it).copyOfRange(0, 8).contentEquals(ca.copyOfRange(18, 26)) }
                ?: throw IllegalArgumentException("unknown root")
            require(verify(root, ca.copyOfRange(0, 100), ca.copyOfRange(100, 164)))
            ca.copyOfRange(36, 100)
        } else roots.firstOrNull { Crypto.sha256(it).copyOfRange(0, 8).contentEquals(leaf.copyOfRange(18, 26)) }
            ?: throw IllegalArgumentException("unknown root")
        require(Crypto.sha256(issuer).copyOfRange(0, 8).contentEquals(leaf.copyOfRange(18, 26)))
        require(verify(issuer, leaf.copyOfRange(0, 100), leaf.copyOfRange(100, 164)))
        return leaf.copyOfRange(36, 100)
    }
    private fun uint32(data: ByteArray, at: Int): Long =
        (0..3).fold(0L) { acc, i -> (acc shl 8) or (data[at + i].toLong() and 255) }
}

class EphemeralX25519(random: SecureRandom = SecureRandom()) {
    private val privateBytes = ByteArray(32).also(random::nextBytes)
    private var destroyed = false
    val publicKey: ByteArray = ByteArray(32).also { X25519.scalarMultBase(privateBytes, 0, it, 0) }
    fun agree(peer: ByteArray): ByteArray {
        require(!destroyed && peer.size == 32)
        return ByteArray(32).also {
            X25519.scalarMult(privateBytes, 0, peer, 0, it, 0)
            require(it.any { byte -> byte != 0.toByte() })
        }
    }
    fun destroy() {
        privateBytes.fill(0)
        destroyed = true
    }
}
