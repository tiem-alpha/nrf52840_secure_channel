package com.example.mobile_app.lkp1

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** JCA primitives. Inputs and output lengths follow LKP1 exactly. */
object Crypto {
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    fun hmac(key: ByteArray, data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256")); doFinal(data)
    }
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray = hmac(salt, ikm)
    fun expand(prk: ByteArray, label: String, context: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val info = "LKP1 $label".toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + context
        var previous = ByteArray(0)
        val output = ArrayList<Byte>()
        var count = 1
        while (output.size < length) {
            previous = hmac(prk, previous + info + byteArrayOf(count.toByte()))
            output.addAll(previous.toList())
            count++
        }
        return output.take(length).toByteArray()
    }
    fun nonce(iv: ByteArray, counter: Long): ByteArray {
        require(iv.size == 12 && counter >= 0)
        return iv.clone().also { out ->
            for (i in 0 until 8) out[11 - i] = (out[11 - i].toInt() xor (counter ushr (8 * i)).toInt()).toByte()
        }
    }
    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad); doFinal(plaintext)
        }
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad); doFinal(ciphertext)
        }
}
