package moe.tlaster.kotlinpgp

import moe.tlaster.kotlinpgp.data.*
import moe.tlaster.kotlinpgp.utils.OpenPGPUtils
import moe.tlaster.kotlinpgp.utils.TextUtils
import moe.tlaster.kotlinpgp.utils.UserIdUtils
import org.bouncycastle.bcpg.*
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import org.bouncycastle.openpgp.operator.jcajce.*
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.security.Security
import java.util.*


object KotlinPGP {
    init {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    var header = mapOf<String, String?>()

    private val bcKeyFingerprintCalculator = JcaKeyFingerprintCalculator()

    fun getEncryptedPackageInfo(encrypted: String): EncryptedPackageInfo {
        ByteArrayInputStream(encrypted.toByteArray()).use {
            PGPUtil.getDecoderStream(it)
        }.use { inputStream ->
            if (inputStream is ArmoredInputStream && inputStream.isClearText) {
                return EncryptedPackageInfo(
                    isClearSign = true
                )
            } else {
                val encryptedDataKeyId = arrayListOf<Long>()
                PGPObjectFactory(inputStream, bcKeyFingerprintCalculator)
                    .let {
                        val obj = it.nextObject()
                        when (obj) {
                            is PGPEncryptedDataList -> obj
                            else -> it.nextObject() as PGPEncryptedDataList
                        }
                    }.let {
                        it.encryptedDataObjects.iterator()
                    }.let {
                        while (it.hasNext()) {
                            val data = it.next() as PGPPublicKeyEncryptedData
                            encryptedDataKeyId.add(data.keyID)
                        }
                    }
                return EncryptedPackageInfo(
                    isClearSign = false,
                    containKeys = encryptedDataKeyId
                )
            }
        }
    }

    fun generateKeyPair(parameter: GenerateKeyPairParameter): PGPKeyPairData {
        return generateKeyRingGenerator(parameter).let {
            PGPKeyPairData(
                publicKey = it.generatePublicKeyRing().exportToString(),
                secretKey = it.generateSecretKeyRing().exportToString()
            )
        }
    }

    private fun generateKeyRingGenerator(generateKeyPairParameter: GenerateKeyPairParameter): PGPKeyRingGenerator {
        val id = UserIdUtils.createUserId(
            UserId(
                name = generateKeyPairParameter.name,
                email = generateKeyPairParameter.email
            )
        )
        val keyPairGenerator =
            RSAKeyGenerationParameters(
                BigInteger.valueOf(0x10001),
                SecureRandom(),
                generateKeyPairParameter.strength,
                12
            ).let {
                RSAKeyPairGenerator().apply {
                    init(it)
                }
            }
        val masterKey = BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPairGenerator.generateKeyPair(), Date())
        val keyPair = BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPairGenerator.generateKeyPair(), Date())
        val generator = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.SIGN_DATA or KeyFlags.CERTIFY_OTHER)
            setPreferredSymmetricAlgorithms(
                false,
                intArrayOf(
                    SymmetricKeyAlgorithmTags.AES_256,
                    SymmetricKeyAlgorithmTags.AES_192,
                    SymmetricKeyAlgorithmTags.AES_128
                )
            )
            setPreferredHashAlgorithms(
                false,
                intArrayOf(
                    HashAlgorithmTags.SHA256,
                    HashAlgorithmTags.SHA1,
                    HashAlgorithmTags.SHA384,
                    HashAlgorithmTags.SHA512,
                    HashAlgorithmTags.SHA224
                )
            )
            setFeature(false, Features.FEATURE_MODIFICATION_DETECTION)
        }
        val pgpSignatureSubpacketGenerator = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }
        val sha1Calc = JcaPGPDigestCalculatorProviderBuilder()
            .build().get(HashAlgorithmTags.SHA1)
        val encryptor = JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256).let {
            JcePBESecretKeyEncryptorBuilder(
                PGPEncryptedData.AES_256,
                it,
                0x90
            )
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(generateKeyPairParameter.password.toCharArray())
        }
        return PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, masterKey,
            id, sha1Calc, generator.generate(), null, BcPGPContentSignerBuilder(
                masterKey.publicKey.algorithm,
                HashAlgorithmTags.SHA1
            ), encryptor
        ).apply {
            addSubKey(keyPair, pgpSignatureSubpacketGenerator.generate(), null)
        }
    }


    fun getPublicKeyRingFromString(publicKey: String): PGPPublicKeyRing {
        return ArmoredInputStream(ByteArrayInputStream(publicKey.toByteArray())).use {
            val pgpObjectFactory = PGPObjectFactory(it, bcKeyFingerprintCalculator)
            pgpObjectFactory.nextObject() as PGPPublicKeyRing
        }
    }

    fun getSecretKeyRingFromString(privateKey: String, password: String): PGPSecretKeyRing {
        val secretKeyRing = ArmoredInputStream(ByteArrayInputStream(privateKey.toByteArray())).use {
            PGPObjectFactory(it, bcKeyFingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
        // Test if we got the right password
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(password.toCharArray())
        secretKeyRing.secretKey.extractPrivateKey(decryptor)
        return secretKeyRing
    }


    fun decrypt(privateKey: String, password: String, encrypted: String): DecryptResult {
        ByteArrayInputStream(encrypted.toByteArray()).use {
            PGPUtil.getDecoderStream(it)
        }.use { inputStream ->
            return if (inputStream is ArmoredInputStream && inputStream.isClearText) {
                clearSignDecryptResult(inputStream)
            } else {
                encryptedDecryptResult(inputStream, privateKey, password)
            }
        }
    }

    private fun encryptedDecryptResult(inputStream: InputStream?, privateKey: String, password: String): DecryptResult {
        val privateKeyRing = getSecretKeyRingFromString(privateKey, password)
        val encryptedDataKeyId = arrayListOf<Long>()
        var factory = PGPObjectFactory(inputStream, bcKeyFingerprintCalculator)
            .let {
                val obj = it.nextObject()
                when (obj) {
                    is PGPEncryptedDataList -> obj
                    else -> it.nextObject() as PGPEncryptedDataList
                }
            }.let {
                it.encryptedDataObjects.iterator()
            }.let {
                var privKey: PGPPrivateKey? = null
                var encryptedData: PGPPublicKeyEncryptedData? = null
                while (it.hasNext()) {
                    val data = it.next() as PGPPublicKeyEncryptedData
                    encryptedDataKeyId.add(data.keyID)
                    if (privKey == null) {
                        encryptedData = data
                        privKey = OpenPGPUtils.getMasterPrivateKey(privateKeyRing, encryptedData.keyID, password.toCharArray())
                    }
                }
                encryptedData?.getDataStream(BcPublicKeyDataDecryptorFactory(privKey))
            }?.use { clear ->
                PGPObjectFactory(clear, bcKeyFingerprintCalculator)
            }
        var onePassSignatureList: PGPOnePassSignatureList? = null
        var signatureList: PGPSignatureList? = null
        var result: String? = null
        var time: Date? = null
        if (factory != null) {
            var dataObj = factory.nextObject()
            while (dataObj != null) {
                if (dataObj is PGPCompressedData) {
                    factory = JcaSkipMarkerPGPObjectFactory(dataObj.dataStream)
                }
                if (dataObj is PGPOnePassSignatureList) {
                    onePassSignatureList = dataObj
                }
                if (dataObj is PGPSignatureList) {
                    signatureList = dataObj
                }
                if (dataObj is PGPLiteralData) {
                    time = dataObj.modificationTime
                    result = OpenPGPUtils.extractDataFromPgpLiteralData(dataObj)
                }
                dataObj = factory?.nextObject()
            }
        }

        return DecryptResult(
            result = result ?: "",
            time = time,
            hasSignature = onePassSignatureList != null || signatureList != null,
            signatureData = SignatureData(
                onePassSignatureList, signatureList, result
                    ?: ""
            ),
            includedKeys = encryptedDataKeyId
        )
    }

    private fun clearSignDecryptResult(inputStream: ArmoredInputStream): DecryptResult {
        val result: String
        run {
            // read cleartext
            val out = ByteArrayOutputStream()


            val lineOut = ByteArrayOutputStream()
            var lookAhead = TextUtils.readInputLine(lineOut, inputStream)
            val lineSep = TextUtils.getLineSeparator()

            var line = lineOut.toByteArray()
            out.write(line, 0, TextUtils.getLengthWithoutSeparator(line))
            out.write(lineSep)

            while (lookAhead != -1 && inputStream.isClearText) {
                lookAhead = TextUtils.readInputLine(lineOut, lookAhead, inputStream)
                line = lineOut.toByteArray()
                out.write(line, 0, TextUtils.getLengthWithoutSeparator(line))
                out.write(lineSep)
            }

            out.close()
            result = out.toString().removeSuffix(String(TextUtils.getLineSeparator()))
        }

        val factory = JcaSkipMarkerPGPObjectFactory(inputStream)
        var signatureList: PGPSignatureList? = null
        var dataObj = factory.nextObject()
        while (dataObj != null) {
            if (dataObj is PGPSignatureList) {
                signatureList = dataObj
            }
            dataObj = factory.nextObject()
        }
        return DecryptResult(
            result = result,
            hasSignature = signatureList != null,
            signatureData = SignatureData(signatureList = signatureList, message = result)
        )
    }

    fun encrypt(encryptParameter: EncryptParameter): String {
        val enableEncrypt = encryptParameter.publicKey.any()
        val bytesOutput = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(BufferedOutputStream(bytesOutput, 1 shl 16))
        header.forEach { head ->
            armoredOutputStream.setHeader(head.key, head.value)
        }
        val messageBytes = encryptParameter.message.toByteArray()
        val signatureGenerator: PGPSignatureGenerator?
        var signatureHashAlgorithm = 0
        if (encryptParameter.enableSignature) {
            val privateKeyRing = getSecretKeyRingFromString(encryptParameter.privateKey, encryptParameter.password)
            val signKey = OpenPGPUtils.getSignPrivateKey(privateKeyRing)
            signatureHashAlgorithm = signKey.publicKey.algorithm
            val pgpPrivKey = signKey
                .extractPrivateKey(
                    JcePBESecretKeyDecryptorBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(encryptParameter.password.toCharArray())
                )
            signatureGenerator = PGPSignatureGenerator(
                BcPGPContentSignerBuilder(
                    signatureHashAlgorithm,
                    HashAlgorithmTags.SHA512
                )
            ).apply {
                init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey)
            }
            val date = Date()
            PGPSignatureSubpacketGenerator().apply {
                //TODO: get primary user id
                setSignerUserID(false, signKey.publicKey.userIDs.next())
                setSignatureCreationTime(false, date)
                signatureGenerator.setHashedSubpackets(generate())
            }
        } else {
            signatureGenerator = null
        }
        if (enableEncrypt) {
            val encryptedDataGenerator = JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).apply {
                setWithIntegrityPacket(true)
                setProvider(BouncyCastleProvider.PROVIDER_NAME)
            }.let {
                PGPEncryptedDataGenerator(it)
            }.also {
                encryptParameter.publicKey.map { OpenPGPUtils.getSubKeyPublicKey(getPublicKeyRingFromString(it)) }.forEach { key ->
                    it.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))
                }
            }
            val encryptedOutput = encryptedDataGenerator.open(armoredOutputStream, ByteArray(1 shl 16))

            val compressedDataGenerator: PGPCompressedDataGenerator?
            val bcpgOutputStream = if (encryptParameter.compressionAlgorithm == CompressionAlgorithmTags.UNCOMPRESSED) {
                compressedDataGenerator = null
                BCPGOutputStream(encryptedOutput)
            } else {
                compressedDataGenerator = PGPCompressedDataGenerator(encryptParameter.compressionAlgorithm)
                BCPGOutputStream(compressedDataGenerator.open(encryptedOutput))
            }
            if (signatureGenerator != null) {
                signatureGenerator.generateOnePassVersion(false).encode(bcpgOutputStream)
            }
            val literalDataGenerator = PGPLiteralDataGenerator()
            val literalDataGeneratorOutput = literalDataGenerator.open(
                bcpgOutputStream,
                PGPLiteralData.UTF8,
                PGPLiteralData.CONSOLE,
                Date(),
                ByteArray(1 shl 16)
            )
            literalDataGeneratorOutput.write(messageBytes)
            if (encryptParameter.enableSignature) {
                signatureGenerator?.update(messageBytes)
            }
            //MUST be closed here!!!!
            literalDataGenerator.close()

            if (encryptParameter.enableSignature) {
                signatureGenerator?.generate()?.encode(literalDataGeneratorOutput)
            }

            bcpgOutputStream.close()
            compressedDataGenerator?.close()
            encryptedOutput.close()
            encryptedDataGenerator.close()
        } else if (encryptParameter.enableSignature) {
            // cleartext signature
            armoredOutputStream.beginClearText(signatureHashAlgorithm)
            armoredOutputStream.write(messageBytes)
            signatureGenerator?.update(messageBytes)
            armoredOutputStream.write(TextUtils.getLineSeparator())
            signatureGenerator?.update(TextUtils.getLineSeparator())
            armoredOutputStream.endClearText()
            BCPGOutputStream(armoredOutputStream).use {
                signatureGenerator?.generate()?.encode(it)
            }
        }
        //Close everything we created
        armoredOutputStream.close()
        bytesOutput.close()

        return bytesOutput.toString()
    }



    fun verify(signatureData: SignatureData, publicKey: List<String>): VerifyResult {
        return if (signatureData.onePassSignatureList == null || signatureData.signatureList == null) {
            if (signatureData.signatureList != null) {
                verifyClearTextSignResult(publicKey, signatureData, signatureData.signatureList)
            } else {
                VerifyResult(VerifyStatus.NO_SIGNATURE)
            }
        } else {
            verifyOnePassSignResult(
                publicKey,
                signatureData.onePassSignatureList,
                signatureData,
                signatureData.signatureList
            )
        }
    }

    private fun verifyClearTextSignResult(
        publicKey: List<String>,
        signatureData: SignatureData,
        signatureList: PGPSignatureList
    ): VerifyResult {
        val pubkeys = publicKey.map { Pair(OpenPGPUtils.getMasterPublicKeyFromKeyRing(getPublicKeyRingFromString(it)), it) }
        val knownKeySignature = signatureList.filter {
            pubkeys.any { key ->
                key.first != null && key.first!!.keyID == it.keyID
            }
        }
        if (knownKeySignature.any()) {
            val availableSignature = knownKeySignature.first()
            val availableKeys = pubkeys.filter { it.first != null && it.first!!.keyID == availableSignature.keyID }
            val availableKey = availableKeys.first()
            availableSignature.init(
                JcaPGPContentVerifierBuilderProvider().setProvider(BouncyCastleProvider.PROVIDER_NAME),
                availableKey.first
            )
            availableSignature.update(signatureData.message.toByteArray())
            availableSignature.update(TextUtils.getLineSeparator())
            val index = signatureList.indexOf(availableSignature)
            return if (signatureList.size() < index) {
                VerifyResult(VerifyStatus.NO_SIGNATURE)
            } else {
                val signature = signatureList[signatureList.size() - 1 - index]
                val isVerified = availableSignature.verify()
                if (isVerified) {
                    VerifyResult(
                        VerifyStatus.SIGNATURE_OK,
                        availableKey.second,
                        keyID = availableKey.first?.keyID ?: signature.keyID
                    )
                } else {
                    VerifyResult(VerifyStatus.SIGNATURE_BAD, keyID = signature.keyID)
                }
            }
        } else if (signatureList.any()) {
            return VerifyResult(VerifyStatus.UNKNOWN_PUBLIC_KEY, keyID = signatureList.first().keyID)
        }
        return VerifyResult(VerifyStatus.NO_SIGNATURE)
    }


    private fun verifyOnePassSignResult(
        publicKey: List<String>,
        onePassSignatureList: PGPOnePassSignatureList,
        signatureData: SignatureData,
        signatureList: PGPSignatureList
    ): VerifyResult {
        val pubkeys = publicKey.map { Pair(OpenPGPUtils.getMasterPublicKeyFromKeyRing(getPublicKeyRingFromString(it)), it) }
        val knownKeySignature = onePassSignatureList.filter {
            pubkeys.any { key ->
                key.first != null && key.first!!.keyID == it.keyID
            }
        }
        if (knownKeySignature.any()) {
            //Known public key
            val availableSignature = knownKeySignature.first()
            val availableKeys = pubkeys.filter { it.first != null && it.first!!.keyID == availableSignature.keyID }
            val availableKey = availableKeys.first()
            availableSignature.init(
                JcaPGPContentVerifierBuilderProvider().setProvider(BouncyCastleProvider.PROVIDER_NAME),
                availableKey.first
            )
            availableSignature.update(signatureData.message.toByteArray())
            val index = onePassSignatureList.indexOf(availableSignature)
            return if (signatureList.size() < index) {
                VerifyResult(VerifyStatus.NO_SIGNATURE)
            } else {
                val signature = signatureList[signatureList.size() - 1 - index]
                val isVerified = availableSignature.verify(signature)
                if (isVerified) {
                    VerifyResult(
                        VerifyStatus.SIGNATURE_OK,
                        availableKey.second,
                        keyID = availableKey.first?.keyID ?: signature.keyID
                    )
                } else {
                    VerifyResult(VerifyStatus.SIGNATURE_BAD, keyID = signature.keyID)
                }
            }
        } else if (onePassSignatureList.any()) {
            //Unknown public key
            return VerifyResult(VerifyStatus.UNKNOWN_PUBLIC_KEY, keyID = onePassSignatureList.first().keyID)
        }
        return VerifyResult(VerifyStatus.NO_SIGNATURE)
    }

}

