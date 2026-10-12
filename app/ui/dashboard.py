import sys

import psutil

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from app.network.monitor import (
    get_network_stats,
    get_network_connections,
)


class NetGuardDashboard(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetGuard | Network Security")
        self.resize(1200, 760)

        self.monitoring = False
        self.previous_stats = None

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_dashboard)

        self.setup_ui()
        self.refresh_dashboard()

    def setup_ui(self):

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # MENU LATERAL

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 25, 20, 20)

        logo = QLabel("NETGUARD")
        logo.setObjectName("logo")

        subtitle = QLabel("NETWORK SECURITY")
        subtitle.setObjectName("subtitle")

        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(40)

        menu_items = [
            "Dashboard",
            "Network Connections",
            "Security Alerts",
            "Settings",
        ]

        for item in menu_items:
            button = QPushButton(item)
            button.setObjectName("menuButton")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            sidebar_layout.addWidget(button)

        sidebar_layout.addStretch()

        version = QLabel("NETGUARD v0.1.0")
        version.setObjectName("version")
        sidebar_layout.addWidget(version)

        # CONTENU PRINCIPAL

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(30, 25, 30, 25)
        content_layout.setSpacing(20)

        header_layout = QHBoxLayout()

        title = QLabel("Network Dashboard")
        title.setObjectName("pageTitle")

        self.status_label = QLabel("● STOPPED")
        self.status_label.setObjectName("status")

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)

        content_layout.addLayout(header_layout)

        description = QLabel(
            "Monitor your network activity in real time."
        )
        description.setObjectName("description")

        content_layout.addWidget(description)

        # CARTES STATISTIQUES

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)

        self.connections_value = QLabel("0")
        self.sent_value = QLabel("0 B")
        self.received_value = QLabel("0 B")

        cards = [
            ("ACTIVE CONNECTIONS", self.connections_value),
            ("DATA SENT", self.sent_value),
            ("DATA RECEIVED", self.received_value),
        ]

        for title_text, value_label in cards:

            card = QFrame()
            card.setObjectName("statCard")

            card_layout = QVBoxLayout(card)

            card_title = QLabel(title_text)
            card_title.setObjectName("cardTitle")

            value_label.setObjectName("cardValue")

            card_layout.addWidget(card_title)
            card_layout.addSpacing(10)
            card_layout.addWidget(value_label)

            cards_layout.addWidget(card)

        content_layout.addLayout(cards_layout)

        # COMMANDES

        controls_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setObjectName("secondaryButton")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_monitoring)

        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addStretch()

        content_layout.addLayout(controls_layout)

        # TABLEAU DES CONNEXIONS

        table_title = QLabel("Network Connections")
        table_title.setObjectName("sectionTitle")

        content_layout.addWidget(table_title)

        self.table = QTableWidget()
        self.table.setColumnCount(5)

        self.table.setHorizontalHeaderLabels([
            "Protocol",
            "Local Address",
            "Remote Address",
            "Status",
            "Process ID",
        ])

        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.table.setAlternatingRowColors(True)

        self.table.verticalHeader().setVisible(False)

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.table.setMinimumHeight(300)

        content_layout.addWidget(self.table)

        # ASSEMBLAGE

        main_layout.addWidget(sidebar)
        main_layout.addWidget(content, 1)

        self.apply_styles()

    def apply_styles(self):

        self.setStyleSheet("""
            QMainWindow {
                background-color: #0b1120;
            }

            QWidget {
                color: #e2e8f0;
                font-family: Segoe UI;
                font-size: 13px;
            }

            #sidebar {
                background-color: #111827;
                border-right: 1px solid #263244;
            }

            #logo {
                font-size: 25px;
                font-weight: bold;
                color: #38bdf8;
            }

            #subtitle {
                color: #94a3b8;
                font-size: 10px;
                letter-spacing: 2px;
            }

            #version {
                color: #64748b;
                font-size: 11px;
            }

            QPushButton#menuButton {
                background-color: transparent;
                color: #cbd5e1;
                text-align: left;
                padding: 12px;
                border: none;
                border-radius: 6px;
            }

            QPushButton#menuButton:hover {
                background-color: #1e293b;
                color: #38bdf8;
            }

            #pageTitle {
                font-size: 27px;
                font-weight: bold;
                color: #f8fafc;
            }

            #description {
                color: #94a3b8;
            }

            #status {
                color: #fbbf24;
                font-weight: bold;
            }

            #statCard {
                background-color: #151f30;
                border: 1px solid #263244;
                border-radius: 10px;
                padding: 10px;
            }

            #cardTitle {
                color: #94a3b8;
                font-size: 11px;
                font-weight: bold;
            }

            #cardValue {
                color: #38bdf8;
                font-size: 25px;
                font-weight: bold;
            }

            #sectionTitle {
                color: #f8fafc;
                font-size: 17px;
                font-weight: bold;
            }

            QPushButton#primaryButton {
                background-color: #0284c7;
                color: white;
                padding: 11px 18px;
                border: none;
                border-radius: 6px;
                font-weight: bold;
            }

            QPushButton#primaryButton:hover {
                background-color: #0369a1;
            }

            QPushButton#primaryButton:disabled {
                background-color: #334155;
                color: #94a3b8;
            }

            QPushButton#secondaryButton {
                background-color: #1e293b;
                color: #e2e8f0;
                padding: 11px 18px;
                border: 1px solid #334155;
                border-radius: 6px;
            }

            QPushButton#secondaryButton:hover {
                background-color: #334155;
            }

            QPushButton#secondaryButton:disabled {
                color: #64748b;
            }

            QTableWidget {
                background-color: #111827;
                alternate-background-color: #172235;
                border: 1px solid #263244;
                border-radius: 8px;
                gridline-color: #263244;
                selection-background-color: #164e63;
            }

            QHeaderView::section {
                background-color: #1e293b;
                color: #94a3b8;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)

    @staticmethod
    def format_bytes(value):

        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(value)

        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.1f} {unit}"

            size /= 1024

    def refresh_dashboard(self):

        stats = get_network_stats()
        connections = get_network_connections()

        self.connections_value.setText(str(len(connections)))

        self.sent_value.setText(
            self.format_bytes(stats["bytes_sent"])
        )

        self.received_value.setText(
            self.format_bytes(stats["bytes_received"])
        )

        self.table.setRowCount(len(connections))

        for row, connection in enumerate(connections):

            values = [
                connection["protocol"],
                connection["local_address"] or "-",
                connection["remote_address"] or "-",
                connection["status"] or "-",
                str(connection["pid"] or "-"),
            ]

            for column, value in enumerate(values):

                self.table.setItem(
                    row,
                    column,
                    QTableWidgetItem(value),
                )

        if self.monitoring:
            self.status_label.setText("● MONITORING")

    def start_monitoring(self):

        self.monitoring = True
        self.previous_stats = psutil.net_io_counters()

        self.status_label.setText("● MONITORING")

        self.timer.start(2000)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.refresh_dashboard()

    def stop_monitoring(self):

        self.monitoring = False
        self.timer.stop()

        self.status_label.setText("● STOPPED")

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)


def main():

    app = QApplication(sys.argv)

    window = NetGuardDashboard()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()