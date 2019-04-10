package moe.tlaster.kotlinpgp.data

import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPSignatureList

data class SignatureData(
    val onePassSignatureList: PGPOnePassSignatureList? = null,
    val signatureList: PGPSignatureList? = null,
    val message: String
)