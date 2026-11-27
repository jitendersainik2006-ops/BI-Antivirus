package com.biantivirus.security

import android.app.Application
import com.biantivirus.security.core.AppScannerEngine
import com.biantivirus.security.core.QuarantineManager
import com.biantivirus.security.core.ScannerEngine
import com.biantivirus.security.core.SignatureDatabase
import com.biantivirus.security.storage.PreferencesManager
import com.biantivirus.security.storage.ScanHistoryDatabase

class BIAntivirusApp : Application() {

    lateinit var signatureDatabase: SignatureDatabase
        private set

    lateinit var scannerEngine: ScannerEngine
        private set

    lateinit var appScannerEngine: AppScannerEngine
        private set

    lateinit var quarantineManager: QuarantineManager
        private set

    lateinit var historyDatabase: ScanHistoryDatabase
        private set

    lateinit var preferencesManager: PreferencesManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        preferencesManager = PreferencesManager(this)
        historyDatabase = ScanHistoryDatabase(this)
        quarantineManager = QuarantineManager(this)

        signatureDatabase = SignatureDatabase(this)
        signatureDatabase.loadSignatures()

        scannerEngine = ScannerEngine(
            signatureDb = signatureDatabase,
            quarantineManager = quarantineManager,
            historyDb = historyDatabase
        )

        appScannerEngine = AppScannerEngine(
            context = this,
            signatureDb = signatureDatabase,
            historyDb = historyDatabase
        )
    }

    companion object {
        lateinit var instance: BIAntivirusApp
            private set
    }
}
