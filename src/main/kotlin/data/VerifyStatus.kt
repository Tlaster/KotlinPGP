package moe.tlaster.kotlinpgp.data

enum class VerifyStatus {
    NO_SIGNATURE,
    SIGNATURE_BAD,
    SIGNATURE_OK,
    UNKNOWN_PUBLIC_KEY,
}