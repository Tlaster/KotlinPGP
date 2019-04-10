package moe.tlaster.kotlinpgp.data

data class GenerateKeyPairParameter(
    val name: String,
    val email: String,
    val password: String = "",
    val strength: Int = 3072
)