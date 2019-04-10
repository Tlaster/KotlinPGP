package moe.tlaster.kotlinpgp.utils

import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import java.io.ByteArrayOutputStream


internal object OpenPGPUtils {

    fun getSubKeyPublicKey(publicKeyRing: PGPPublicKeyRing): PGPPublicKey? {
        val iterator = publicKeyRing.publicKeys
        while (iterator.hasNext()) {
            val key = iterator.next() as PGPPublicKey
            //TODO: May be master key will be used as encrypt key
            if (!key.isMasterKey && key.isEncryptionKey) {
                return key
            }
        }
        return null
    }

    fun getMasterPrivateKey(keyRing: PGPSecretKeyRing, keyID: Long, pass: CharArray): PGPPrivateKey? {
        val pgpSecKey = keyRing.getSecretKey(keyID)
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass)
        return pgpSecKey?.extractPrivateKey(decryptor)
    }

    fun extractDataFromPgpLiteralData(dataObj: PGPLiteralData): String {
        dataObj.inputStream.use { inputStream ->
            ByteArrayOutputStream().use {
                val buffer = ByteArray(0xFFFF)
                while (true) {
                    val r = inputStream.read(buffer)
                    if (r == -1) break
                    it.write(buffer, 0, r)
                }
                return it.toString()
            }
        }
    }

    fun getMasterPublicKeyFromKeyRing(publicKeyRing: PGPPublicKeyRing): PGPPublicKey? {
        val iterator = publicKeyRing.publicKeys
        while (iterator.hasNext()) {
            val key = iterator.next() as PGPPublicKey
            //TODO: May be master key will be used as encrypt key
            if (key.isMasterKey) {
                return key
            }
        }
        return null
    }

    fun getSignPrivateKey(securet: PGPSecretKeyRing): PGPSecretKey {
        val keyRingIter = securet.secretKeys
        while (keyRingIter.hasNext()) {
            val next = keyRingIter.next()
            when (next) {
                is PGPSecretKeyRing -> {
                    val keyIter = next.secretKeys
                    while (keyIter.hasNext()) {
                        val key = keyIter.next() as PGPSecretKey

                        if (key.isSigningKey) {
                            return key
                        }
                    }
                }
                is PGPSecretKey -> {
                    // TODO: Do we need to check if is master key?
                    if (next.isSigningKey) {
                        return next
                    }
                }
            }
        }
        throw IllegalArgumentException(
            "Can't find signing key in key ring."
        )
    }
}