import sys
import time
from collections import deque

import psutil

from PySide6.QtCore import Qt, QTimer
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

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from app.network.monitor import (
    get_network_stats,
    get_network_connections,
)


class NetGuardDashboard(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetGuard | Network Security")
        self.resize(1400, 850)
        self.setMinimumSize(1000, 650)

        self.monitoring = False
        self.previous_stats = None
        self.last_sample_time = None

        self.download_speed = 0.0
        self.upload_speed = 0.0

        self.download_history = deque(maxlen=30)
        self.upload_history = deque(maxlen=30)
        self.time_history = deque(maxlen=30)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.refresh_dashboard)

        self.setup_ui()
        self.refresh_dashboard()

    # --------------------------------------------------
    # INTERFACE
    # --------------------------------------------------

    def setup_ui(self):

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # SIDEBAR

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(235)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 25, 20, 20)
        sidebar_layout.setSpacing(18)

        logo = QLabel("NETGUARD")
        logo.setObjectName("logo")

        subtitle = QLabel("N E T W O R K   S E C U R I T Y")
        subtitle.setObjectName("sidebarSubtitle")

        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(35)

        for item in [
            "Dashboard",
            "Network Connections",
            "Security Alerts",
            "Settings",
        ]:
            label = QLabel(item)
            label.setObjectName("sidebarItem")
            sidebar_layout.addWidget(label)

        sidebar_layout.addStretch()

        version = QLabel("NETGUARD v0.1.0")
        version.setObjectName("version")
        sidebar_layout.addWidget(version)

        main_layout.addWidget(sidebar)

        # MAIN CONTENT

        content = QWidget()
        content.setObjectName("content")

        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 15, 20, 10)
        content_layout.setSpacing(10)

        main_layout.addWidget(content, 1)

        # HEADER

        header_layout = QHBoxLayout()

        title = QLabel("Network Dashboard")
        title.setObjectName("pageTitle")

        self.status_label = QLabel("● STOPPED")
        self.status_label.setObjectName("statusLabel")

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)

        content_layout.addLayout(header_layout)

        description = QLabel(
            "Monitor your network activity in real time."
        )
        description.setObjectName("description")

        content_layout.addWidget(description)

        # STATISTICS CARDS

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.connections_value = QLabel("0")
        self.sent_value = QLabel("0 B")
        self.received_value = QLabel("0 B")
        self.download_value = QLabel("0 KB/s")
        self.upload_value = QLabel("0 KB/s")

        cards = [
            ("ACTIVE CONNECTIONS", self.connections_value),
            ("DATA SENT", self.sent_value),
            ("DATA RECEIVED", self.received_value),
            ("DOWNLOAD SPEED", self.download_value),
            ("UPLOAD SPEED", self.upload_value),
        ]

        for title_text, value_label in cards:

            card = QFrame()
            card.setObjectName("statCard")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 12, 12, 12)
            card_layout.setSpacing(6)

            card_title = QLabel(title_text)
            card_title.setObjectName("cardTitle")

            value_label.setObjectName("cardValue")

            card_layout.addWidget(card_title)
            card_layout.addWidget(value_label)

            cards_layout.addWidget(card)

        content_layout.addLayout(cards_layout)

        # MONITORING BUTTONS

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("startButton")
        self.start_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)

        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_layout.addStretch()

        content_layout.addLayout(buttons_layout)

        # CONNECTIONS TITLE

        connections_title = QLabel("Network Connections")
        connections_title.setObjectName("sectionTitle")

        content_layout.addWidget(connections_title)

        # CONNECTIONS TABLE

        self.table = QTableWidget()

        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Protocol",
            "Local Address",
            "Remote Address",
            "Status",
            "Process ID",
        ])

        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(25)

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.table.setMaximumHeight(230)
        self.table.setMinimumHeight(130)

        content_layout.addWidget(self.table)

        # NETWORK TRAFFIC GRAPH

        self.figure = Figure(figsize=(8, 2.5))
        self.figure.patch.set_facecolor("#111827")

        self.canvas = FigureCanvasQTAgg(self.figure)
        self.canvas.setMinimumHeight(150)

        self.ax = self.figure.add_subplot(111)

        self.ax.set_facecolor("#111827")
        self.ax.set_title(
            "Network Traffic",
            color="#f8fafc",
            pad=8,
        )
        self.ax.set_xlabel(
            "Recent samples",
            color="#94a3b8",
        )
        self.ax.set_ylabel(
            "KB/s",
            color="#94a3b8",
        )
        self.ax.tick_params(colors="#94a3b8")
        self.ax.grid(True, alpha=0.2)

        content_layout.addWidget(self.canvas, 1)

        self.apply_styles()

    # --------------------------------------------------
    # STYLES
    # --------------------------------------------------

    def apply_styles(self):

        self.setStyleSheet("""
            QMainWindow {
                background-color: #0b1120;
            }

            QWidget#content {
                background-color: #0b1120;
            }

            QFrame#sidebar {
                background-color: #111827;
                border-right: 1px solid #273449;
            }

            QLabel#logo {
                color: #38bdf8;
                font-size: 25px;
                font-weight: bold;
            }

            QLabel#sidebarSubtitle {
                color: #94a3b8;
                font-size: 10px;
            }

            QLabel#sidebarItem {
                color: #dbeafe;
                font-size: 13px;
                padding: 8px 0;
            }

            QLabel#version {
                color: #64748b;
                font-size: 10px;
            }

            QLabel#pageTitle {
                color: #f8fafc;
                font-size: 27px;
                font-weight: bold;
            }

            QLabel#description {
                color: #94a3b8;
                font-size: 13px;
                padding-bottom: 2px;
            }

            QLabel#statusLabel {
                color: #fbbf24;
                font-weight: bold;
            }

            QFrame#statCard {
                background-color: #162133;
                border: 1px solid #273449;
                border-radius: 10px;
            }

            QLabel#cardTitle {
                color: #94a3b8;
                font-size: 10px;
                font-weight: bold;
            }

            QLabel#cardValue {
                color: #38bdf8;
                font-size: 19px;
                font-weight: bold;
            }

            QLabel#sectionTitle {
                color: #f8fafc;
                font-size: 17px;
                font-weight: bold;
                padding-top: 2px;
            }

            QTableWidget {
                background-color: #111827;
                alternate-background-color: #192538;
                color: #e2e8f0;
                border: 1px solid #273449;
                gridline-color: #273449;
                selection-background-color: #164e63;
                selection-color: #ffffff;
            }

            QHeaderView::section {
                background-color: #1e293b;
                color: #94a3b8;
                padding: 8px;
                border: none;
                font-weight: bold;
            }

            QPushButton {
                padding: 10px 16px;
                border-radius: 6px;
                font-size: 12px;
            }

            QPushButton#startButton {
                background-color: #0284c7;
                color: white;
                font-weight: bold;
                border: none;
            }

            QPushButton#startButton:hover {
                background-color: #0369a1;
            }

            QPushButton#stopButton {
                background-color: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
            }

            QPushButton:disabled {
                color: #64748b;
                background-color: #263449;
            }
        """)

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------

    @staticmethod
    def format_bytes(size):

        value = float(size)

        for unit in ["B", "KB", "MB", "GB", "TB"]:

            if value < 1024 or unit == "TB":
                if unit == "B":
                    return f"{value:.0f} {unit}"
                return f"{value:.1f} {unit}"

            value /= 1024

    # --------------------------------------------------
    # REFRESH DASHBOARD
    # --------------------------------------------------

    def refresh_dashboard(self):

        stats = get_network_stats()
        connections = get_network_connections()

        current_time = time.monotonic()
        current_counters = psutil.net_io_counters()

        if (
            self.monitoring
            and self.previous_stats is not None
            and self.last_sample_time is not None
            and current_counters is not None
        ):

            elapsed = current_time - self.last_sample_time

            if elapsed > 0:

                sent_delta = max(
                    0,
                    current_counters.bytes_sent
                    - self.previous_stats.bytes_sent,
                )

                received_delta = max(
                    0,
                    current_counters.bytes_recv
                    - self.previous_stats.bytes_recv,
                )

                self.upload_speed = sent_delta / elapsed / 1024
                self.download_speed = received_delta / elapsed / 1024

        if current_counters is not None:
            self.previous_stats = current_counters

        self.last_sample_time = current_time

        self.connections_value.setText(str(len(connections)))

        self.sent_value.setText(
            self.format_bytes(stats["bytes_sent"])
        )

        self.received_value.setText(
            self.format_bytes(stats["bytes_received"])
        )

        self.download_value.setText(
            f"{self.download_speed:.1f} KB/s"
        )

        self.upload_value.setText(
            f"{self.upload_speed:.1f} KB/s"
        )

        # UPDATE CONNECTION TABLE

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

        # UPDATE GRAPH

        if self.monitoring:
            self.download_history.append(self.download_speed)
            self.upload_history.append(self.upload_speed)

            if not hasattr(self, "sample_count"):
                self.sample_count = 0

            self.sample_count += 1
            self.time_history.append(self.sample_count)

            if len(self.time_history) > 30:
                self.time_history.popleft()

        self.ax.clear()
        self.ax.set_facecolor("#111827")

        self.ax.plot(
            list(self.time_history),
            list(self.download_history),
            label="Download",
        )

        self.ax.plot(
            list(self.time_history),
            list(self.upload_history),
            label="Upload",
        )

        self.ax.set_title(
            "Network Traffic",
            color="#f8fafc",
            pad=8,
        )

        self.ax.set_xlabel(
            "Recent samples",
            color="#94a3b8",
        )

        self.ax.set_ylabel(
            "KB/s",
            color="#94a3b8",
        )

        self.ax.tick_params(colors="#94a3b8")
        self.ax.grid(True, alpha=0.2)

        max_speed = max(
            max(self.download_history, default=0),
            max(self.upload_history, default=0),
        )

        self.ax.set_ylim(
            0,
            max(10, max_speed * 1.2),
        )

        self.ax.legend()
        self.figure.tight_layout()
        self.canvas.draw()

        if self.monitoring:
            self.status_label.setText("● MONITORING")
        else:
            self.status_label.setText("● STOPPED")

    # --------------------------------------------------
    # START MONITORING
    # --------------------------------------------------

    def start_monitoring(self):

        self.monitoring = True

        self.previous_stats = psutil.net_io_counters()
        self.last_sample_time = None

        self.download_speed = 0.0
        self.upload_speed = 0.0

        self.download_history.clear()
        self.upload_history.clear()
        self.time_history.clear()
        self.sample_count = 0

        self.status_label.setText("● MONITORING")

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.refresh_dashboard()
        self.timer.start()

    # --------------------------------------------------
    # STOP MONITORING
    # --------------------------------------------------

    def stop_monitoring(self):

        self.timer.stop()
        self.monitoring = False

        self.status_label.setText("● STOPPED")

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        self.refresh_dashboard()


def main():

    app = QApplication(sys.argv)

    window = NetGuardDashboard()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()