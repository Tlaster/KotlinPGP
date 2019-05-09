package moe.tlaster.kotlinpgp.test

import io.kotlintest.specs.AnnotationSpec
import moe.tlaster.kotlinpgp.KotlinPGP
import moe.tlaster.kotlinpgp.data.*

class OtherTest : AnnotationSpec() {
    @Test
    fun hiddenPublicKey() {
        val key = KotlinPGP.generateKeyPair(GenerateKeyData(
            name = "test",
            email = "test@test.com",
            password = "password"
        ))
        val key2 = KotlinPGP.generateKeyPair(GenerateKeyData(
            name = "test",
            email = "test@test.com",
            password = "password"
        ))
        val msg = KotlinPGP.encrypt(EncryptParameter(
            message = "hello",
            publicKey = listOf(PublicKeyData(
                key = key.publicKey,
                isHidden = true
            ), PublicKeyData(
                key = key2.publicKey,
                isHidden = false
            )),
            enableSignature = false
        ))
        val info = KotlinPGP.getEncryptedPackageInfo(msg)
        assert(!info.isClearSign)
        assert(info.containKeys.contains(0L))
        val res = KotlinPGP.tryDecrypt(listOf(PrivateKeyData(key2.secretKey, "password"), PrivateKeyData(key.secretKey, "password")), msg)!!
        assert(res.result == "hello")
    }

    @Test
    fun hiddenPublicKeyWithSignature() {
        val key = KotlinPGP.generateKeyPair(GenerateKeyData(
            name = "test",
            email = "test@test.com",
            password = "password"
        ))
        val key2 = KotlinPGP.generateKeyPair(GenerateKeyData(
            name = "test",
            email = "test@test.com",
            password = "password"
        ))
        val msg = KotlinPGP.encrypt(EncryptParameter(
            message = "hello",
            publicKey = listOf(PublicKeyData(
                key = key.publicKey,
                isHidden = true
            ), PublicKeyData(
                key = key2.publicKey,
                isHidden = false
            )),
            enableSignature = true,
            password = "password",
            privateKey = key2.secretKey
        ))
        val info = KotlinPGP.getEncryptedPackageInfo(msg)
        assert(!info.isClearSign)
        assert(info.containKeys.contains(0L))
        val res = KotlinPGP.tryDecrypt(listOf(PrivateKeyData(key2.secretKey, "password"), PrivateKeyData(key.secretKey, "password")), msg)!!
        assert(res.result == "hello")
        assert(res.hasSignature)
        val verify = KotlinPGP.verify(res.signatureData, listOf(key2.publicKey, key.publicKey))
        assert(verify.verifyStatus == VerifyStatus.SIGNATURE_OK)
    }
}