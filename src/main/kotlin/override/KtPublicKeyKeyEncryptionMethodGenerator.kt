package moe.tlaster.kotlinpgp.override

import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.bcpg.PacketTags
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream

class KtHiddenPublicKeyKeyEncryptionMethodGenerator(private val key: PGPPublicKey?) : BcPublicKeyKeyEncryptionMethodGenerator(key) {
    override fun generate(encAlgorithm: Int, sessionInfo: ByteArray?): ContainedPacket {
        return PublicKeyEncSessionPacket(
            0,
            key!!.algorithm,
            processSessionInfo(encryptSessionInfo(key, sessionInfo))
        )
    }
}
