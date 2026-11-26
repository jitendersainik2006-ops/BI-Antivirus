package com.biantivirus.security

import com.biantivirus.security.core.EntropyCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class EntropyCalculatorTest {

    @Test
    fun testEmptyBytesZeroEntropy() {
        val stream = ByteArrayInputStream(byteArrayOf())
        val entropy = EntropyCalculator.calculateEntropy(stream)
        assertEquals(0.0, entropy, 0.001)
    }

    @Test
    fun testSingleRepeatedByteLowEntropy() {
        val bytes = ByteArray(1024) { 0x41.toByte() } // All 'A's
        val entropy = EntropyCalculator.calculateEntropy(bytes)
        assertEquals(0.0, entropy, 0.001)
    }

    @Test
    fun testUniformByteDistributionHighEntropy() {
        // Uniform distribution across all 256 bytes yields maximum Shannon entropy of 8.0
        val bytes = ByteArray(256 * 16) { (it % 256).toByte() }
        val entropy = EntropyCalculator.calculateEntropy(bytes)
        assertTrue("Uniform distribution entropy should be near 8.0, got: $entropy", entropy >= 7.99)
    }
}
