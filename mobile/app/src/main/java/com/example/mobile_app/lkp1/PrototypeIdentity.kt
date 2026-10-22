package com.example.mobile_app.lkp1

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature

/** Mode A: import private JSON from the offline provisioning CLI for prototypes only. */
class PrototypeIdentity private constructor(
    private val privateKey: PrivateKey,
    override val certificateChain: List<ByteArray>,
    val roots: List<ByteArray>
) : KeyStoreProvider {
    override fun sign(message: ByteArray): ByteArray = Certificates.raw(
        Signature.getInstance("SHA256withECDSA", BouncyCastleProvider()).run {
            initSign(privateKey); update(message); sign()
        }
    )
    companion object {
        fun fromJson(json: String): PrototypeIdentity {
            val data = JSONObject(json)
            require(data.getString("kind") == "phone")
            val scalar = BigInteger(data.getString("private"), 16)
            val params = ECNamedCurveTable.getParameterSpec("secp256r1")
            val key = KeyFactory.getInstance("EC", BouncyCastleProvider())
                .generatePrivate(ECPrivateKeySpec(scalar, params))
            fun array(name: String): List<ByteArray> = data.getJSONArray(name).let { values ->
                (0 until values.length()).map { index ->
                    values.getString(index).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                }
            }
            val chain = array("chain"); val roots = array("roots")
            require(chain.size in 1..2 && chain.all { it.size == 164 })
            require(roots.size in 1..2 && roots.all { it.size == 64 })
            return PrototypeIdentity(key, chain, roots)
        }
    }
}
