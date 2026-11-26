package com.biantivirus.security.core

import java.io.InputStream
import kotlin.math.ln

object EntropyCalculator {

    private val LOG_2 = ln(2.0)

    fun calculateEntropy(inputStream: InputStream, maxBytesToAnalyze: Int = 1024 * 1024): Double {
        val frequencies = LongArray(256)
        val buffer = ByteArray(32 * 1024)
        var totalBytesRead = 0L

        var bytesRead: Int
        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            val toProcess = if (totalBytesRead + bytesRead > maxBytesToAnalyze) {
                (maxBytesToAnalyze - totalBytesRead).toInt()
            } else {
                bytesRead
            }

            for (i in 0 until toProcess) {
                val byteVal = buffer[i].toInt() and 0xFF
                frequencies[byteVal]++
            }
            totalBytesRead += toProcess

            if (totalBytesRead >= maxBytesToAnalyze) {
                break
            }
        }

        if (totalBytesRead == 0L) {
            return 0.0
        }

        var entropy = 0.0
        for (count in frequencies) {
            if (count > 0) {
                val p = count.toDouble() / totalBytesRead
                entropy -= p * (ln(p) / LOG_2)
            }
        }

        return (entropy * 1000.0).toLong() / 1000.0 // Round to 3 decimal places
    }

    fun calculateEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0

        val frequencies = LongArray(256)
        for (b in bytes) {
            frequencies[b.toInt() and 0xFF]++
        }

        val total = bytes.size.toDouble()
        var entropy = 0.0
        for (count in frequencies) {
            if (count > 0) {
                val p = count.toDouble() / total
                entropy -= p * (ln(p) / LOG_2)
            }
        }

        return (entropy * 1000.0).toLong() / 1000.0
    }
}
