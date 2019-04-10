package moe.tlaster.kotlinpgp.data

data class VerifyResult(
    val verifyStatus: VerifyStatus,
    val publicKey: String = "",
    val keyID: Long = 0
)