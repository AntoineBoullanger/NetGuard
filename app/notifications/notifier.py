from PySide6.QtWidgets import QSystemTrayIcon, QMenu, QApplication, QStyle
from PySide6.QtGui import QIcon
from PySide6.QtCore import QObject
from pathlib import Path


class NetGuardNotifier(QObject):
    """Gère les notifications de sécurité de NetGuard."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.tray = QSystemTrayIcon(self)

        # Utilise l'icône par défaut de l'application si elle existe.
        icon_path = Path(__file__).resolve().parent.parent / "assets" / "netguard.ico"
        icon = QIcon(str(icon_path))
        self.tray.setIcon(icon)

        self.tray.setToolTip("NetGuard - Surveillance réseau")

        self.menu = QMenu()
        self.menu.addAction("NetGuard est actif")
        self.tray.setContextMenu(self.menu)

        self.enabled = True

        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def notify(self, title: str, message: str, severity: str = "WARNING"):
        """Affiche une notification de sécurité."""

        if not self.enabled:
            return

        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        if severity.upper() == "HIGH":
            icon = QSystemTrayIcon.MessageIcon.Critical
        elif severity.upper() == "INFO":
            icon = QSystemTrayIcon.MessageIcon.Information
        else:
            icon = QSystemTrayIcon.MessageIcon.Warning

        self.tray.showMessage(
            title,
            message,
            icon,
            5000,
        )

    def set_enabled(self, enabled: bool):
        """Active ou désactive les notifications."""

        self.enabled = enabled