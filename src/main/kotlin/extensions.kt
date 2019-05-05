package moe.tlaster.kotlinpgp

import moe.tlaster.kotlinpgp.utils.UserIdUtils
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import java.io.ByteArrayOutputStream

fun PGPKeyRing.exportToString(): String {
    return ByteArrayOutputStream().use {
        ArmoredOutputStream(it).use { armoredStreamPkr ->
            KotlinPGP.header.forEach { head ->
                armoredStreamPkr.setHeader(head.key, head.value)
            }
            encode(armoredStreamPkr)
        }
        it.toString()
    }
}

val String.isPGPMessage
    get() = (this.trim().startsWith("-----BEGIN PGP MESSAGE-----")
            && this.trim().endsWith("-----END PGP MESSAGE-----"))
            || (this.trim().startsWith("-----BEGIN PGP SIGNED MESSAGE-----")
            && this.trim().endsWith("-----END PGP SIGNATURE-----"))


val String.isPGPPublicKey
    get() = this.trim().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----") && this.trim().endsWith("-----END PGP PUBLIC KEY BLOCK-----")

val String.isPGPPrivateKey
    get() = this.trim().startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----") && this.trim().endsWith("-----END PGP PRIVATE KEY BLOCK-----")

val PGPPublicKey.name
    get() = if (userIDs.hasNext()) {
        UserIdUtils.splitUserId(userIDs.next()).name
    } else {
        ""
    }

val PGPPublicKey.email
    get() = if (userIDs.hasNext()) {
        UserIdUtils.splitUserId(userIDs.next()).email
    } else {
        ""
    }

fun PGPKeyRing.extractPublicKeyRing(): PGPPublicKeyRing {
    val it = publicKeys
    return ByteArrayOutputStream().use { stream ->
        while (it.hasNext()) {
            stream.write(it.next().encoded)
        }
        PGPPublicKeyRing(stream.toByteArray(), JcaKeyFingerprintCalculator())
    }
}
