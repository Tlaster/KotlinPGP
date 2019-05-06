package moe.tlaster.kotlinpgp.data

data class KeyData(
    val strength: Int = 3072,
    val algorithm: Algorithm = Algorithm.RSA,
    val curve: Curve? = null
)

data class GenerateKeyData(
    val name: String,
    val email: String,
    val password: String = "",
    val masterKey: KeyData = KeyData(),
    val subKey: KeyData = KeyData()
)

enum class Algorithm {
    RSA, DSA, ELGAMAL, ECDSA, ECDH, EDDSA
}

// All curves defined in the standard
// http://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269
enum class Curve {
    NIST_P256, NIST_P384, NIST_P521, Secp256k1

    // these are supported by gpg, but they are not in rfc6637 and not supported by BouncyCastle yet
    // (adding support would be trivial though -> JcaPGPKeyConverter.java:190)
    // BRAINPOOL_P256, BRAINPOOL_P384, BRAINPOOL_P512
}