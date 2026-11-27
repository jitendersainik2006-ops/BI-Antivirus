package com.biantivirus.security

import com.biantivirus.security.core.OEMBackgroundManager
import com.biantivirus.security.core.OEMType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OEMBackgroundManagerTest {

    private val manager = OEMBackgroundManager(context = null)

    @Test
    fun testDetectOEMReturnsNonNull() {
        val oem = manager.detectOEM()
        assertNotNull(oem)
    }

    @Test
    fun testBackgroundStatusGeneratesGuidance() {
        val status = manager.getBackgroundStatus()
        assertNotNull(status.manufacturer)
        assertNotNull(status.model)
        assertNotNull(status.killRiskLevel)
        assertTrue(status.stepByStepInstructions.isNotEmpty())
        assertTrue(status.actionLabel.isNotEmpty())
    }

    @Test
    fun testOEMTypesEnumValues() {
        val types = OEMType.values()
        assertTrue(types.contains(OEMType.SAMSUNG))
        assertTrue(types.contains(OEMType.XIAOMI))
        assertTrue(types.contains(OEMType.VIVO_IQOO))
        assertTrue(types.contains(OEMType.OPPO_REALME_ONEPLUS))
        assertTrue(types.contains(OEMType.GOOGLE_PIXEL))
        assertTrue(types.contains(OEMType.GENERIC))
    }
}
