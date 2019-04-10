package moe.tlaster.kotlinpgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPKeyRing
import java.io.ByteArrayOutputStream


fun PGPKeyRing.exportToString(): String {
    return ByteArrayOutputStream().use {
        ArmoredOutputStream(it).use { armoredStreamPkr ->
            encode(armoredStreamPkr)
        }
        it.toString()
    }
}

val String.isPGPMessage
    get() =
        (this.startsWith("-----BEGIN PGP MESSAGE-----")
                && this.endsWith("-----END PGP MESSAGE-----"))
                || (this.startsWith("-----BEGIN PGP SIGNED MESSAGE-----")
                && this.endsWith("-----END PGP SIGNATURE-----"))


val String.isPGPPublicKey
    get() = this.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----") && this.endsWith("-----END PGP PUBLIC KEY BLOCK-----")

val String.isPGPPrivateKey
    get() = this.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----") && this.endsWith("-----END PGP PRIVATE KEY BLOCK-----")
