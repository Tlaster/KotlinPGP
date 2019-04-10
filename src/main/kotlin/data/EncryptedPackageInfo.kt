package moe.tlaster.kotlinpgp.data

data class EncryptedPackageInfo(
    val isClearSign: Boolean = false,
    val containKeys: List<Long> = emptyList()
)