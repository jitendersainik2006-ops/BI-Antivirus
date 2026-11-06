"""
BI Antivirus - Authenticode & Digital Signature Verifier
Uses native Windows WinTrust APIs (wintrust.dll) via ctypes to verify digital signatures
and binary provenance without third-party dependencies or external network queries.
Validates whether executables, DLLs, and drivers are legitimately signed by trusted vendors.
"""

import os
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Dict, Any, Optional

# WinTrust API Constants
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0
WTD_SAFER_FLAG = 0x00000100

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
CERT_E_UNTRUSTEDROOT = 0x800B0109
TRUST_E_BAD_DIGEST = 0x80096010
ERROR_SUCCESS = 0

# Action GUID for generic Authenticode verification:
# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class AuthenticodeVerifier:
    """Authenticode digital signature verifier using Windows Crypto/WinTrust API."""

    @staticmethod
    def is_windows() -> bool:
        return os.name == "nt"

    @classmethod
    def verify_file_signature(cls, file_path: Path) -> Dict[str, Any]:
        """
        Verify the digital signature of a Windows PE file (exe, dll, sys).
        Returns:
            Dict containing:
            - is_signed (bool)
            - is_trusted (bool)
            - status (str: "TRUSTED", "UNSIGNED", "UNTRUSTED_ROOT", "BAD_DIGEST", "DISTRUSTED", "ERROR")
            - status_code (int)
            - description (str)
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            return {
                "file_path": str(path),
                "is_signed": False,
                "is_trusted": False,
                "status": "FILE_NOT_FOUND",
                "status_code": -1,
                "description": "File does not exist",
            }

        if not cls.is_windows():
            return {
                "file_path": str(path),
                "is_signed": False,
                "is_trusted": False,
                "status": "NON_WINDOWS",
                "status_code": 0,
                "description": "Authenticode verification is only supported on Windows OS",
            }

        try:
            wintrust = ctypes.windll.wintrust
            WinVerifyTrust = wintrust.WinVerifyTrust
            WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
            WinVerifyTrust.restype = wintypes.LONG
        except Exception as e:
            return {
                "file_path": str(path),
                "is_signed": False,
                "is_trusted": False,
                "status": "API_UNAVAILABLE",
                "status_code": -1,
                "description": f"WinTrust API unavailable: {e}",
            }

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = str(path)
        file_info.hFile = None
        file_info.pgKnownSubject = None

        win_data = WINTRUST_DATA()
        win_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        win_data.pPolicyCallbackData = None
        win_data.pSIPClientData = None
        win_data.dwUIChoice = WTD_UI_NONE
        win_data.fdwRevocationChecks = WTD_REVOKE_NONE
        win_data.dwUnionChoice = WTD_CHOICE_FILE
        win_data.pFile = ctypes.pointer(file_info)
        win_data.dwStateAction = WTD_STATEACTION_IGNORE
        win_data.hWVTStateData = None
        win_data.pwszURLReference = None
        win_data.dwProvFlags = WTD_SAFER_FLAG
        win_data.dwUIContext = 0
        win_data.pSignatureSettings = None

        guid = WINTRUST_ACTION_GENERIC_VERIFY_V2
        l_status = WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(win_data))

        # Convert signed 32-bit to unsigned hex
        u_status = l_status & 0xFFFFFFFF

        if u_status == ERROR_SUCCESS:
            return {
                "file_path": str(path),
                "is_signed": True,
                "is_trusted": True,
                "status": "TRUSTED",
                "status_code": 0,
                "description": "Valid digital signature verified by a trusted root certificate.",
            }
        elif u_status == TRUST_E_NOSIGNATURE:
            return {
                "file_path": str(path),
                "is_signed": False,
                "is_trusted": False,
                "status": "UNSIGNED",
                "status_code": u_status,
                "description": "File is not digitally signed.",
            }
        elif u_status == CERT_E_UNTRUSTEDROOT:
            return {
                "file_path": str(path),
                "is_signed": True,
                "is_trusted": False,
                "status": "UNTRUSTED_ROOT",
                "status_code": u_status,
                "description": "Signature chain was issued by an untrusted or self-signed root authority.",
            }
        elif u_status == TRUST_E_BAD_DIGEST:
            return {
                "file_path": str(path),
                "is_signed": True,
                "is_trusted": False,
                "status": "TAMPERED_DIGEST",
                "status_code": u_status,
                "description": "File hash does not match signature digest (file was altered/tampered).",
            }
        elif u_status == TRUST_E_EXPLICIT_DISTRUST:
            return {
                "file_path": str(path),
                "is_signed": True,
                "is_trusted": False,
                "status": "EXPLICITLY_DISTRUSTED",
                "status_code": u_status,
                "description": "Certificate has been explicitly revoked or distrusted by the administrator.",
            }
        else:
            return {
                "file_path": str(path),
                "is_signed": True,
                "is_trusted": False,
                "status": "UNVERIFIED",
                "status_code": u_status,
                "description": f"Signature could not be verified (WinTrust code: 0x{u_status:08X}).",
            }


def verify_authenticode(file_path: Path) -> Dict[str, Any]:
    """Convenience helper function for AuthenticodeVerifier.verify_file_signature."""
    return AuthenticodeVerifier.verify_file_signature(file_path)

