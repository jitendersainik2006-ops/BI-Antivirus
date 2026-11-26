package com.biantivirus.security

import com.biantivirus.security.core.SignatureDatabase
import com.biantivirus.security.model.ThreatSeverity
import com.biantivirus.security.model.ThreatSignature
import org.junit.Assert.*
import org.junit.Test

class SignatureDatabaseTest {

    @Test
    fun testBuiltInEicarSignatureFound() {
        val db = SignatureDatabase()
        val eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

        val found = db.findBySha256(eicarSha256)
        assertNotNull("EICAR signature must be found in database", found)
        assertEquals("EICAR-Standard-AV-Test-File", found?.name)
        assertEquals("TestVirus", found?.family)
        assertEquals(ThreatSeverity.CRITICAL, found?.severity)
    }

    @Test
    fun testCaseInsensitiveHashLookup() {
        val db = SignatureDatabase()
        val upperSha = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"

        val found = db.findBySha256(upperSha)
        assertNotNull("Uppercase hash search must match case-insensitively", found)
    }

    @Test
    fun testUnknownHashReturnsNull() {
        val db = SignatureDatabase()
        val cleanSha = "0000000000000000000000000000000000000000000000000000000000000000"

        val found = db.findBySha256(cleanSha)
        assertNull("Unknown hash should return null", found)
    }

    @Test
    fun testDynamicSignatureAddition() {
        val db = SignatureDatabase()
        val custom = ThreatSignature(
            id = "SIG-CUSTOM-01",
            name = "Test.Custom.Threat",
            family = "Trojan",
            severity = ThreatSeverity.HIGH,
            sha256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            md5 = "11223344556677889900aabbccddeeff",
            description = "Custom test signature"
        )
        db.addSignature(custom)

        val found = db.findBySha256(custom.sha256)
        assertNotNull(found)
        assertEquals("Test.Custom.Threat", found?.name)
    }
}
