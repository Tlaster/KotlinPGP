package moe.tlaster.kotlinpgp

import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.InputStream

internal class JcaSkipMarkerPGPObjectFactory(`in`: InputStream) : JcaPGPObjectFactory(`in`) {
    override fun nextObject(): Any? {
        var o = super.nextObject()
        while (o is PGPMarker) {
            o = super.nextObject()
        }
        return o
    }
}