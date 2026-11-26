package com.biantivirus.security.storage

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity

class ScanHistoryDatabase(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        private const val DATABASE_NAME = "bi_antivirus_history.db"
        private const val DATABASE_VERSION = 1

        private const val TABLE_HISTORY = "scan_history"
        private const val COL_ID = "id"
        private const val COL_SCAN_ID = "scan_id"
        private const val COL_TIMESTAMP = "timestamp"
        private const val COL_FILE_NAME = "file_name"
        private const val COL_FILE_PATH = "file_path"
        private const val COL_FILE_SIZE = "file_size"
        private const val COL_SHA256 = "sha256"
        private const val COL_VERDICT = "verdict"
        private const val COL_THREAT_NAME = "threat_name"
        private const val COL_SEVERITY = "severity"
    }

    override fun onCreate(db: SQLiteDatabase) {
        val createSql = """
            CREATE TABLE $TABLE_HISTORY (
                $COL_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COL_SCAN_ID TEXT UNIQUE,
                $COL_TIMESTAMP INTEGER,
                $COL_FILE_NAME TEXT,
                $COL_FILE_PATH TEXT,
                $COL_FILE_SIZE INTEGER,
                $COL_SHA256 TEXT,
                $COL_VERDICT TEXT,
                $COL_THREAT_NAME TEXT,
                $COL_SEVERITY TEXT
            )
        """.trimIndent()
        db.execSQL(createSql)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_HISTORY")
        onCreate(db)
    }

    fun recordScan(result: ScanResult): Long {
        val db = writableDatabase
        val values = ContentValues().apply {
            put(COL_SCAN_ID, result.scanId)
            put(COL_TIMESTAMP, result.timestamp)
            put(COL_FILE_NAME, result.fileName)
            put(COL_FILE_PATH, result.filePath)
            put(COL_FILE_SIZE, result.fileSize)
            put(COL_SHA256, result.sha256)
            put(COL_VERDICT, result.verdict.name)
            put(COL_THREAT_NAME, result.threatName ?: "")
            put(COL_SEVERITY, result.severity.name)
        }
        return db.insertWithOnConflict(TABLE_HISTORY, null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun getRecentScans(limit: Int = 50): List<ScanResult> {
        val list = mutableListOf<ScanResult>()
        val db = readableDatabase
        val cursor = db.query(
            TABLE_HISTORY,
            null,
            null,
            null,
            null,
            null,
            "$COL_TIMESTAMP DESC",
            limit.toString()
        )

        cursor.use { c ->
            while (c.moveToNext()) {
                val scanId = c.getString(c.getColumnIndexOrThrow(COL_SCAN_ID))
                val timestamp = c.getLong(c.getColumnIndexOrThrow(COL_TIMESTAMP))
                val fileName = c.getString(c.getColumnIndexOrThrow(COL_FILE_NAME))
                val filePath = c.getString(c.getColumnIndexOrThrow(COL_FILE_PATH))
                val fileSize = c.getLong(c.getColumnIndexOrThrow(COL_FILE_SIZE))
                val sha256 = c.getString(c.getColumnIndexOrThrow(COL_SHA256))
                val verdictStr = c.getString(c.getColumnIndexOrThrow(COL_VERDICT))
                val threatName = c.getString(c.getColumnIndexOrThrow(COL_THREAT_NAME))
                val severityStr = c.getString(c.getColumnIndexOrThrow(COL_SEVERITY))

                val verdict = try { ScanVerdict.valueOf(verdictStr) } catch (e: Exception) { ScanVerdict.CLEAN }
                val severity = try { ThreatSeverity.valueOf(severityStr) } catch (e: Exception) { ThreatSeverity.NONE }

                list.add(
                    ScanResult(
                        scanId = scanId,
                        timestamp = timestamp,
                        fileName = fileName,
                        filePath = filePath,
                        fileSize = fileSize,
                        sha256 = sha256,
                        md5 = "",
                        entropy = 0.0,
                        verdict = verdict,
                        threatName = threatName.ifBlank { null },
                        severity = severity
                    )
                )
            }
        }
        return list
    }

    fun clearHistory() {
        writableDatabase.delete(TABLE_HISTORY, null, null)
    }
}
