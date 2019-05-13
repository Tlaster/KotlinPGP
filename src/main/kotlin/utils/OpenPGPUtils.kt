package moe.tlaster.kotlinpgp.utils

import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import java.io.ByteArrayOutputStream


internal object OpenPGPUtils {

    fun getEncryptionPublicKey(publicKeyRing: PGPPublicKeyRing): PGPPublicKey {
        var masterEncryptionKey: PGPPublicKey? = null
        publicKeyRing.publicKeys.forEach { key ->
            val isMaster = key.isMasterKey
            val isEncryption = key.isEncryptionKey
            if (isMaster && isEncryption) {
                masterEncryptionKey = key
            } else if (!isMaster && isEncryption) {
                return key
            }
        }
        if (masterEncryptionKey != null) {
            return masterEncryptionKey!!
        }
        throw IllegalArgumentException(
            "Can't find encryption key in key ring."
        )
    }

    fun getEncryptionPrivateKey(keyRing: PGPSecretKeyRing, keyID: Long, pass: CharArray): PGPPrivateKey? {
        val pgpSecKey = keyRing.getSecretKey(keyID)
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass)
        return pgpSecKey?.extractPrivateKey(decryptor)
    }

    fun getAllEncryptionPrivateKeys(keyRing: PGPSecretKeyRing, pass: CharArray): List<PGPPrivateKey> {
        val keys = arrayListOf<PGPPrivateKey>()
        keyRing.secretKeys.forEach { key ->
            if (key.publicKey.isEncryptionKey) {
                val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass)
                keys.add(key.extractPrivateKey(decryptor))
            }
        }
        return keys
    }

    fun getEncryptionPrivateKey(keyRing: PGPSecretKeyRing, pass: CharArray): PGPPrivateKey? {
        keyRing.secretKeys.forEach { key ->
            if (key.publicKey.isEncryptionKey) {
                val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass)
                return key.extractPrivateKey(decryptor)
            }
        }
        return null
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
        publicKeyRing.publicKeys.forEach { key ->
            if (key.isMasterKey) {
                return key
            }
        }
        return null
    }

    fun getSignPrivateKey(securet: PGPSecretKeyRing): PGPSecretKey {
        securet.secretKeys.forEach {
            when (it) {
                is PGPSecretKeyRing -> {
                    val keyIter = it.secretKeys
                    while (keyIter.hasNext()) {
                        val key = keyIter.next() as PGPSecretKey

                        if (key.isSigningKey) {
                            return key
                        }
                    }
                }
                is PGPSecretKey -> {
                    // TODO: Do we need to check if is master key?
                    if (it.isSigningKey) {
                        return it
                    }
                }
            }
        }
        throw IllegalArgumentException(
            "Can't find signing key in key ring."
        )
    }
}
