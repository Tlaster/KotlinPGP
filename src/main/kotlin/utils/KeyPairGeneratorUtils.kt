package moe.tlaster.kotlinpgp.utils

import moe.tlaster.kotlinpgp.EdDSAGenParameterSpec
import moe.tlaster.kotlinpgp.data.Algorithm
import moe.tlaster.kotlinpgp.data.Curve
import moe.tlaster.kotlinpgp.data.KeyData
import moe.tlaster.kotlinpgp.data.Primes
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ElGamalParameterSpec
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.*

internal object KeyPairGeneratorUtils {

    fun createKey(keyData: KeyData, creationTime: Date): PGPKeyPair {

        // Some safety checks
        if (keyData.algorithm == Algorithm.ECDH || keyData.algorithm == Algorithm.ECDSA) {
            if (keyData.curve == null) {
                throw Error("curve can not be null")
            }
        } else if (keyData.algorithm != Algorithm.EDDSA) {
            if (keyData.strength < 2048) {
                throw Error("key length must above 2048")
            }
        }

        val algorithm: Int
        val keyGen: KeyPairGenerator

        when (keyData.algorithm) {
            Algorithm.DSA -> {
                keyGen = KeyPairGenerator.getInstance(
                    "DSA",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(keyData.strength, SecureRandom())
                algorithm = PGPPublicKey.DSA
            }

            Algorithm.ELGAMAL -> {
                keyGen = KeyPairGenerator.getInstance(
                    "ElGamal",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                val p = Primes.getBestPrime(keyData.strength)
                val g = BigInteger("2")
                val elParams = ElGamalParameterSpec(p, g)
                keyGen.initialize(elParams)
                algorithm = PGPPublicKey.ELGAMAL_ENCRYPT
            }

            Algorithm.RSA -> {
                keyGen = KeyPairGenerator.getInstance(
                    "RSA",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(keyData.strength, SecureRandom())
                algorithm = PGPPublicKey.RSA_GENERAL
            }

            Algorithm.ECDSA -> {
                val ecParamSpec = getEccParameterSpec(keyData.curve!!)
                keyGen = KeyPairGenerator.getInstance(
                    "ECDSA",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(ecParamSpec, SecureRandom())
                algorithm = PGPPublicKey.ECDSA
            }

            Algorithm.EDDSA -> {
                val edParamSpec = EdDSAGenParameterSpec("ed25519")
                keyGen = KeyPairGenerator.getInstance(
                    "EdDSA",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(edParamSpec, SecureRandom())
                algorithm = PGPPublicKey.EDDSA
            }

            Algorithm.ECDH -> {
                val ecParamSpec = getEccParameterSpec(keyData.curve!!)
                keyGen = KeyPairGenerator.getInstance(
                    "ECDH",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(ecParamSpec, SecureRandom())
                algorithm = PGPPublicKey.ECDH
            }
        }

        return JcaPGPKeyPair(algorithm, keyGen.generateKeyPair(), creationTime)
    }


    private fun getEccParameterSpec(curve: Curve): ECGenParameterSpec {
        return when (curve) {
            Curve.NIST_P256 -> ECGenParameterSpec("P-256")
            Curve.NIST_P384 -> ECGenParameterSpec("P-384")
            Curve.NIST_P521 -> ECGenParameterSpec("P-521")
        }
    }
}