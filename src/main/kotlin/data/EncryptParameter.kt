package moe.tlaster.kotlinpgp.data

import org.bouncycastle.bcpg.CompressionAlgorithmTags

data class EncryptParameter(
    val message: String,
    val publicKey: List<PublicKeyData> = emptyList(),
    val enableSignature: Boolean = false,
    val privateKey: String = "",
    val password: String = "",
    val compressionAlgorithm: Int = CompressionAlgorithmTags.ZIP,
    val messageOriginatingFileName: String = ""
)

data class PublicKeyData(
    val key: String,
    val isHidden: Boolean = false
)

data class PrivateKeyData(
    val key: String,
    val password: String
)
