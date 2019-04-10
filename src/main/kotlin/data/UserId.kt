package moe.tlaster.kotlinpgp.data

internal data class UserId(
    val name: String?,
    val email: String?,
    val comment: String? = null
)