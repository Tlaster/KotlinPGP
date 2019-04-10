package moe.tlaster.kotlinpgp.data

import org.bouncycastle.bcpg.CompressionAlgorithmTags

data class EncryptParameter(
    val message: String,
    val publicKey: List<String> = emptyList(),
    val enableSignature: Boolean = false,
    val privateKey: String = "",
    val password: String = "",
    val compressionAlgorithm: Int = CompressionAlgorithmTags.ZIP
)