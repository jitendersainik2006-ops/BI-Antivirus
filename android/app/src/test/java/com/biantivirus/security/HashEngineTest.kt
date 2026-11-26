package com.biantivirus.security

import com.biantivirus.security.core.HashEngine
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class HashEngineTest {

    @Test
    fun testEmptyBytesHash() {
        val stream = ByteArrayInputStream(byteArrayOf())
        val result = HashEngine.calculateHashes(stream)

        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result.sha256)
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", result.md5)
        assertEquals(0L, result.bytesProcessed)
    }

    @Test
    fun testEicarHashMatchesStandard() {
        val eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
        val stream = ByteArrayInputStream(eicarString.toByteArray(Charsets.US_ASCII))
        val result = HashEngine.calculateHashes(stream)

        assertEquals("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", result.sha256)
        assertEquals("44d88612fea8a8f36de82e1278abb02f", result.md5)
    }
}
