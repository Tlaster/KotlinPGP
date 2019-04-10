package moe.tlaster.kotlinpgp.utils

import java.io.ByteArrayOutputStream
import java.io.InputStream

internal object TextUtils {
    fun readPastEOL(bOut: ByteArrayOutputStream, lastCh: Int, fIn: InputStream): Int {
        var lookAhead = fIn.read()

        if (lastCh == '\r'.toInt() && lookAhead == '\n'.toInt()) {
            bOut.write(lookAhead)
            lookAhead = fIn.read()
        }

        return lookAhead
    }

    fun getLengthWithoutSeparator(line: ByteArray): Int {
        var end = line.size - 1

        while (end >= 0 && isLineEnding(line[end])) {
            end--
        }

        return end + 1
    }

    fun isLineEnding(b: Byte): Boolean {
        return b == '\r'.toByte() || b == '\n'.toByte()
    }

    fun getLineSeparator(): ByteArray {
        val nl = System.getProperty("line.separator")
        return nl!!.toByteArray()
    }

    fun readInputLine(bOut: ByteArrayOutputStream, fIn: InputStream): Int {
        bOut.reset()

        var lookAhead = -1
        var ch: Int

        while (fIn.read().let { ch = it; ch >= 0 }) {
            bOut.write(ch)
            if (ch == '\r'.toInt() || ch == '\n'.toInt()) {
                lookAhead = readPastEOL(bOut, ch, fIn)
                break
            }
        }

        return lookAhead
    }

    fun readInputLine(bOut: ByteArrayOutputStream, lookAhead: Int, fIn: InputStream): Int {
        var lookAhead = lookAhead
        bOut.reset()

        var ch = lookAhead

        do {
            bOut.write(ch)
            if (ch == '\r'.toInt() || ch == '\n'.toInt()) {
                lookAhead = readPastEOL(bOut, ch, fIn)
                break
            }
        } while (fIn.read().let { ch = it; ch >= 0 })

        if (ch < 0) {
            lookAhead = -1
        }

        return lookAhead
    }

}