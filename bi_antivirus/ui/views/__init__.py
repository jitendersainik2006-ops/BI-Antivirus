"""UI View modules for BI Antivirus."""

from bi_antivirus.ui.views.overview_view import OverviewView
from bi_antivirus.ui.views.scan_view import ScanView
from bi_antivirus.ui.views.quarantine_view import QuarantineView
from bi_antivirus.ui.views.history_view import HistoryView
from bi_antivirus.ui.views.protection_view import ProtectionView
from bi_antivirus.ui.views.firewall_view import FirewallView
from bi_antivirus.ui.views.automation_view import AutomationView
from bi_antivirus.ui.views.settings_view import SettingsView
from bi_antivirus.ui.views.reports_view import ReportsView
from bi_antivirus.ui.views.edr_view import EDRView
from bi_antivirus.ui.views.patch_view import PatchView
from bi_antivirus.ui.views.pe_view import PEClassifierView
from bi_antivirus.ui.views.fleet_view import FleetView

__all__ = [
    "OverviewView",
    "ScanView",
    "QuarantineView",
    "HistoryView",
    "ProtectionView",
    "FirewallView",
    "AutomationView",
    "SettingsView",
    "ReportsView",
    "EDRView",
    "PatchView",
    "PEClassifierView",
    "FleetView",
]
