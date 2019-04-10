package moe.tlaster.kotlinpgp.data

import java.util.*

data class DecryptResult(
    val result: String,
    val time: Date? = null,
    val hasSignature: Boolean = false,
    val signatureData: SignatureData,
    val includedKeys: List<Long> = emptyList()
)