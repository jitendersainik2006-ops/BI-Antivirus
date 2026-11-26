package com.biantivirus.security

import com.biantivirus.security.core.HeuristicEngine
import com.biantivirus.security.model.ThreatSeverity
import org.junit.Assert.*
import org.junit.Test

class HeuristicEngineTest {

    @Test
    fun testCleanFileIsClean() {
        val verdict = HeuristicEngine.evaluate(
            fileName = "report.pdf",
            fileSize = 1024,
            entropy = 4.5,
            sampleBytes = "Normal PDF document content".toByteArray()
        )

        assertFalse("Clean document must not be flagged suspicious", verdict.isSuspicious)
        assertTrue(verdict.matchedRules.isEmpty())
        assertEquals(ThreatSeverity.NONE, verdict.severity)
    }

    @Test
    fun testSuspiciousDoubleExtensionFlagged() {
        val verdict = HeuristicEngine.evaluate(
            fileName = "invoice_2026.pdf.apk",
            fileSize = 2048,
            entropy = 5.0,
            sampleBytes = null
        )

        assertTrue("Double extension .pdf.apk must be flagged suspicious", verdict.isSuspicious)
        assertTrue(verdict.matchedRules.any { it.contains("HEUR:SUSPICIOUS_DOUBLE_EXTENSION") })
        assertEquals(ThreatSeverity.MEDIUM, verdict.severity)
    }

    @Test
    fun testHighEntropyFlagged() {
        val verdict = HeuristicEngine.evaluate(
            fileName = "packed_payload.bin",
            fileSize = 8192,
            entropy = 7.85,
            sampleBytes = null
        )

        assertTrue("High entropy >= 7.2 must be flagged suspicious", verdict.isSuspicious)
        assertTrue(verdict.matchedRules.any { it.contains("HEUR:HIGH_SHANNON_ENTROPY") })
    }

    @Test
    fun testEicarPatternRecognized() {
        val eicarPattern = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
        val verdict = HeuristicEngine.evaluate(
            fileName = "eicar.txt",
            fileSize = eicarPattern.length.toLong(),
            entropy = 4.2,
            sampleBytes = eicarPattern.toByteArray()
        )

        assertTrue(verdict.isSuspicious)
        assertTrue(verdict.matchedRules.any { it.contains("HEUR:EICAR_PATTERN_DETECTED") })
        assertEquals(ThreatSeverity.CRITICAL, verdict.severity)
    }
}
