import sys
import time
from collections import deque

import psutil

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QLineEdit, QComboBox
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDateEdit,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from app.network.monitor import (
    get_network_stats,
    get_network_connections,
)
from app.detection.rules import detect_suspicious_connections
from app.storage.database import (
    initialize_database,
    save_alert,
    get_recent_alerts,
    delete_alert,
)

class NetGuardDashboard(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetGuard | Network Security")
        self.resize(1400, 850)
        self.setMinimumSize(1050, 700)

        self.monitoring = False
        self.previous_stats = None
        self.last_sample_time = None

        self.download_speed = 0.0
        self.upload_speed = 0.0

        self.download_history = deque(maxlen=30)
        self.upload_history = deque(maxlen=30)
        self.time_history = deque(maxlen=30)
        self.sample_count = 0

        self.refresh_interval = 2000

        self.nav_buttons = {}
        self.page_titles = {
            "Dashboard": "Network Dashboard",
            "Network Connections": "Network Connections",
            "Security Alerts": "Security Alerts",
            "Settings": "Settings",
        }

        self.timer = QTimer(self)
        self.timer.setInterval(self.refresh_interval)
        self.timer.timeout.connect(self.refresh_dashboard)

        self.saved_alert_keys = set()
        initialize_database()

        self.setup_ui()
        self.refresh_dashboard()
        self.switch_page("Dashboard")

    # ==================================================
    # INTERFACE
    # ==================================================

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ---------------- SIDEBAR ----------------

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(235)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(18, 25, 18, 20)
        sidebar_layout.setSpacing(12)

        logo = QLabel("NETGUARD")
        logo.setObjectName("logo")

        subtitle = QLabel("NETWORK SECURITY")
        subtitle.setObjectName("sidebarSubtitle")

        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(28)

        navigation_items = [
            "Dashboard",
            "Network Connections",
            "Security Alerts",
            "Settings",
        ]

        for item in navigation_items:
            button = QPushButton(item)
            button.setObjectName("navButton")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setCheckable(True)
            button.clicked.connect(
                lambda checked=False, page=item: self.switch_page(page)
            )

            sidebar_layout.addWidget(button)
            self.nav_buttons[item] = button

        sidebar_layout.addStretch()

        version = QLabel("NETGUARD v0.1.0")
        version.setObjectName("version")
        sidebar_layout.addWidget(version)

        main_layout.addWidget(sidebar)

        # ---------------- MAIN AREA ----------------

        main_area = QWidget()
        main_area.setObjectName("mainArea")

        main_area_layout = QVBoxLayout(main_area)
        main_area_layout.setContentsMargins(25, 20, 25, 20)
        main_area_layout.setSpacing(15)

        # Shared header

        header_layout = QHBoxLayout()

        self.page_title = QLabel("Network Dashboard")
        self.page_title.setObjectName("pageTitle")

        self.status_label = QLabel("● STOPPED")
        self.status_label.setObjectName("statusLabel")

        header_layout.addWidget(self.page_title)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)

        main_area_layout.addLayout(header_layout)

        self.page_description = QLabel(
            "Monitor your network activity in real time."
        )
        self.page_description.setObjectName("description")

        main_area_layout.addWidget(self.page_description)

        # Page container

        self.pages = QStackedWidget()
        self.pages.setObjectName("pages")

        self.dashboard_page = self.create_dashboard_page()
        self.connections_page = self.create_connections_page()
        self.alerts_page = self.create_alerts_page()
        self.settings_page = self.create_settings_page()

        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.connections_page)
        self.pages.addWidget(self.alerts_page)
        self.pages.addWidget(self.settings_page)

        main_area_layout.addWidget(self.pages, 1)
        main_layout.addWidget(main_area, 1)

        self.apply_styles()

    # ==================================================
    # DASHBOARD PAGE
    # ==================================================

    def create_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 5, 0, 0)
        layout.setSpacing(15)

        # Statistics cards

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
            card_layout.setContentsMargins(12, 14, 12, 14)
            card_layout.setSpacing(10)

            card_title = QLabel(title_text)
            card_title.setObjectName("cardTitle")
            card_title.setWordWrap(True)

            value_label.setObjectName("cardValue")

            card_layout.addWidget(card_title)
            card_layout.addWidget(value_label)

            cards_layout.addWidget(card)

        layout.addLayout(cards_layout)

        # Monitoring controls

        controls_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("startButton")
        self.start_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)

        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        # Traffic graph

        graph_frame = QFrame()
        graph_frame.setObjectName("panel")

        graph_layout = QVBoxLayout(graph_frame)
        graph_layout.setContentsMargins(15, 12, 15, 12)

        graph_title = QLabel("Network Traffic")
        graph_title.setObjectName("sectionTitle")
        graph_layout.addWidget(graph_title)

        self.figure = Figure(figsize=(8, 4))
        self.figure.patch.set_facecolor("#111827")

        self.canvas = FigureCanvasQTAgg(self.figure)
        self.canvas.setMinimumHeight(250)

        self.ax = self.figure.add_subplot(111)
        self.configure_graph()

        graph_layout.addWidget(self.canvas)

        layout.addWidget(graph_frame, 1)

        # Recent alerts summary

        summary_title = QLabel("Security Overview")
        summary_title.setObjectName("sectionTitle")
        layout.addWidget(summary_title)

        self.alert_summary = QLabel(
            "No security alerts have been analyzed yet."
        )
        self.alert_summary.setObjectName("summaryLabel")
        self.alert_summary.setWordWrap(True)

        layout.addWidget(self.alert_summary)

        return page

    # ==================================================
    # CONNECTIONS PAGE
    # ==================================================

    def create_connections_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 5, 0, 0)
        layout.setSpacing(12)

        description = QLabel(
            "Detailed view of the network connections visible to NetGuard."
        )
        description.setObjectName("description")
        description.setWordWrap(True)

        layout.addWidget(description)
        
        

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Process Name",
            "Protocol",
            "Local Address",
            "Remote Address",
            "Status",
            "PID",
        ])
        self.table.setSortingEnabled(True)

        self.configure_table(self.table)
        layout.addWidget(self.table)

        self.connection_count_label = QLabel("0 connections")
        self.connection_count_label.setObjectName("summaryLabel")
        layout.addWidget(self.connection_count_label)

        return page

    # ==================================================
    # SECURITY ALERTS PAGE
    # ==================================================

    def create_alerts_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 5, 0, 0)
        layout.setSpacing(12)

        description = QLabel(
            "Connections matching the configured detection rules. "
            "An alert is an indication to investigate, not proof of an attack."
        )
        description.setObjectName("description")
        description.setWordWrap(True)

        layout.addWidget(description)
        
        # Alert actions
        actions_layout = QHBoxLayout()

        test_button = QPushButton("Simulate Test Alert")
        test_button.setObjectName("startButton")
        test_button.clicked.connect(self.simulate_test_alert)

        self.delete_alert_button = QPushButton("Delete Selected Alert")
        self.delete_alert_button.setObjectName("stopButton")
        self.delete_alert_button.clicked.connect(self.delete_selected_alert)

        actions_layout.addWidget(test_button)
        actions_layout.addWidget(self.delete_alert_button)
        
        export_button = QPushButton("Export Alerts to CSV")
        export_button.clicked.connect(self.export_alerts_to_csv)
        actions_layout.addWidget(export_button)
        actions_layout.addStretch()

        layout.addLayout(actions_layout)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems([
            "All severities",
            "INFO",
            "WARNING",
            "HIGH",
        ])
        self.severity_filter.currentTextChanged.connect(
            self.refresh_alerts_from_database
        )

        layout.addWidget(self.severity_filter)
        
        self.alert_search = QLineEdit()
        self.alert_search.setPlaceholderText(
            "Search by IP address, detection rule or message..."
        )
        self.alert_search.textChanged.connect(
            self.refresh_alerts_from_database
        )

        layout.addWidget(self.alert_search)

       

        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(4)
        self.alerts_table.cellDoubleClicked.connect(self.show_alert_details)
        self.alerts_table.setHorizontalHeaderLabels([
            "Time",
            "Severity",
            "Detection Rule",
            "Details",
        ])

        self.configure_table(self.alerts_table)
        layout.addWidget(self.alerts_table)

        self.alert_count_label = QLabel("0 alerts")
        self.alert_count_label.setObjectName("summaryLabel")
        layout.addWidget(self.alert_count_label)

        return page

    # ==================================================
    # SETTINGS PAGE
    # ==================================================

    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 5, 0, 0)
        layout.setSpacing(18)

        title = QLabel("Monitoring Settings")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        description = QLabel(
            "Configure how often NetGuard refreshes network information."
        )
        description.setObjectName("description")
        description.setWordWrap(True)
        layout.addWidget(description)

        settings_panel = QFrame()
        settings_panel.setObjectName("panel")

        settings_layout = QVBoxLayout(settings_panel)
        settings_layout.setContentsMargins(20, 20, 20, 20)
        settings_layout.setSpacing(15)

        interval_label = QLabel("Refresh interval")
        interval_label.setObjectName("settingLabel")
        settings_layout.addWidget(interval_label)

        self.interval_combo = QComboBox()
        self.interval_combo.addItem("1 second", 1000)
        self.interval_combo.addItem("2 seconds", 2000)
        self.interval_combo.addItem("5 seconds", 5000)
        self.interval_combo.addItem("10 seconds", 10000)
        self.interval_combo.setCurrentIndex(1)

        settings_layout.addWidget(self.interval_combo)

        save_button = QPushButton("Apply Settings")
        save_button.setObjectName("startButton")
        save_button.clicked.connect(self.apply_settings)

        settings_layout.addWidget(save_button)
        settings_layout.addStretch()

        layout.addWidget(settings_panel)
        layout.addStretch()

        return page

    # ==================================================
    # NAVIGATION
    # ==================================================

    def switch_page(self, page_name):
        page_indexes = {
            "Dashboard": 0,
            "Network Connections": 1,
            "Security Alerts": 2,
            "Settings": 3,
        }

        if page_name not in page_indexes:
            return

        self.pages.setCurrentIndex(page_indexes[page_name])
        self.page_title.setText(self.page_titles[page_name])

        descriptions = {
            "Dashboard": "Monitor your network activity in real time.",
            "Network Connections": "Inspect visible TCP and UDP connections.",
            "Security Alerts": "Review connections flagged by detection rules.",
            "Settings": "Configure NetGuard monitoring preferences.",
        }

        self.page_description.setText(descriptions[page_name])

        for name, button in self.nav_buttons.items():
            button.setChecked(name == page_name)

    # ==================================================
    # TABLE CONFIGURATION
    # ==================================================

    @staticmethod
    def configure_table(table):
        table.setAlternatingRowColors(True)
        table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(32)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

    # ==================================================
    # GRAPH
    # ==================================================

    def configure_graph(self):
        self.ax.set_facecolor("#111827")
        self.ax.set_title(
            "Network Traffic",
            color="#f8fafc",
            pad=10,
        )
        self.ax.set_xlabel("Recent samples", color="#94a3b8")
        self.ax.set_ylabel("KB/s", color="#94a3b8")
        self.ax.tick_params(colors="#94a3b8")
        self.ax.grid(True, alpha=0.2)

    # ==================================================
    # STYLES
    # ==================================================

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0b1120;
            }

            QWidget#mainArea {
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
                letter-spacing: 2px;
            }

            QLabel#version {
                color: #64748b;
                font-size: 10px;
            }

            QPushButton#navButton {
                background-color: transparent;
                color: #cbd5e1;
                border: none;
                border-radius: 7px;
                text-align: left;
                padding: 13px 12px;
                font-size: 13px;
            }

            QPushButton#navButton:hover {
                background-color: #1e293b;
                color: #f8fafc;
            }

            QPushButton#navButton:checked {
                background-color: #075985;
                color: #ffffff;
                font-weight: bold;
                border-left: 3px solid #38bdf8;
            }

            QLabel#pageTitle {
                color: #f8fafc;
                font-size: 27px;
                font-weight: bold;
            }

            QLabel#description {
                color: #94a3b8;
                font-size: 13px;
            }

            QLabel#statusLabel {
                color: #fbbf24;
                font-weight: bold;
                padding: 8px;
            }

            QFrame#statCard, QFrame#panel {
                background-color: #162133;
                border: 1px solid #273449;
                border-radius: 9px;
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
            }

            QLabel#summaryLabel {
                color: #94a3b8;
                padding: 5px;
            }

            QLabel#settingLabel {
                color: #e2e8f0;
                font-size: 14px;
                font-weight: bold;
            }

            QComboBox {
                background-color: #111827;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 9px;
                min-width: 180px;
            }

            QComboBox QAbstractItemView {
                background-color: #111827;
                color: #e2e8f0;
                selection-background-color: #075985;
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
                padding: 9px;
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

            QPushButton#stopButton:hover {
                background-color: #334155;
            }

            QPushButton:disabled {
                color: #64748b;
                background-color: #263449;
            }
        """)

    # ==================================================
    # HELPERS
    # ==================================================

    @staticmethod
    def format_bytes(size):
        value = float(size)

        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if value < 1024 or unit == "TB":
                if unit == "B":
                    return f"{value:.0f} {unit}"
                return f"{value:.1f} {unit}"

            value /= 1024

        return "0 B"

    # ==================================================
    # REFRESH NETWORK DATA
    # ==================================================

    def refresh_dashboard(self):
        stats = get_network_stats()
        connections = get_network_connections()

        self.refresh_connections(connections)
        self.refresh_alerts(connections)

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

        if self.monitoring:
            self.download_history.append(self.download_speed)
            self.upload_history.append(self.upload_speed)
            self.sample_count += 1
            self.time_history.append(self.sample_count)

        self.update_graph()

        if self.monitoring:
            self.status_label.setText("● MONITORING")
        else:
            self.status_label.setText("● STOPPED")

        self.start_button.setEnabled(not self.monitoring)
        self.stop_button.setEnabled(self.monitoring)

    def refresh_connections(self, connections):
        """Refresh the connections table with process information."""
        import psutil

        self.table.setRowCount(len(connections))

        for row, connection in enumerate(connections):
            pid = connection.get("pid")
            process_name = "Unknown"

            if pid:
                try:
                    process_name = psutil.Process(int(pid)).name()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                    ValueError,
                    TypeError,
                ):
                    process_name = "Unavailable"

            values = [
                process_name,
                connection.get("protocol") or "-",
                connection.get("local_address") or "-",
                connection.get("remote_address") or "-",
                connection.get("status") or "-",
                str(pid or "-"),
            ]

            for column, value in enumerate(values):
                self.table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

        self.connection_count_label.setText(
            f"{len(connections)} connections"
        )

    def simulate_test_alert(self):
        """Create a simulated alert to test the Security Alerts interface."""
        from datetime import datetime

        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "WARNING",
            "rule": "TEST - Sensitive remote port",
            "message": (
                "Simulated alert: a connection to remote port 23 "
                "(Telnet) was detected."
            ),
            "connection": {
                "protocol": "TCP",
                "local_address": "192.168.1.10:51500",
                "remote_address": "203.0.113.10:23",
                "status": "ESTABLISHED",
                "pid": 1234,
            },
        }

        save_alert(alert)
        self.refresh_alerts_from_database()

        QMessageBox.information(
            self,
            "Test alert created",
            "The simulated alert has been saved to the database.",
        )
    
    def delete_selected_alert(self):
        row = self.alerts_table.currentRow()

        if row < 0:
            QMessageBox.warning(
                self,
                "No alert selected",
                "Select an alert before deleting it.",
            )
            return

        id_item = self.alerts_table.item(row, 0)

        if id_item is None or id_item.data(Qt.ItemDataRole.UserRole) is None:
            QMessageBox.warning(
                self,
                "Unable to delete",
                "The selected alert has no database ID.",
            )
            return

        alert_id = id_item.data(Qt.ItemDataRole.UserRole)

        answer = QMessageBox.question(
            self,
            "Confirm deletion",
            "Are you sure you want to permanently delete this alert?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        if delete_alert(alert_id):
            self.refresh_alerts_from_database()

            QMessageBox.information(
                self,
                "Alert deleted",
                "The alert has been deleted successfully.",
            )
        else:
            QMessageBox.warning(
                self,
                "Deletion failed",
                "The alert could not be found in the database.",
            )
        
    def show_alert_details(self, row, column):
        """Display detailed information about a selected alert."""
        from PySide6.QtWidgets import QDialog, QFormLayout

        timestamp_item = self.alerts_table.item(row, 0)

        if timestamp_item is None:
            return

        alert_id = timestamp_item.data(Qt.ItemDataRole.UserRole)

        if alert_id is None:
            return

        alerts = get_recent_alerts()
        alert = next(
            (item for item in alerts if item.get("id") == alert_id),
            None,
        )

        if alert is None:
            QMessageBox.warning(
                self,
                "Alert not found",
                "This alert no longer exists in the database.",
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Alert Details")
        dialog.resize(550, 300)

        details_layout = QFormLayout(dialog)

        details_layout.addRow(
            "ID:",
            QLabel(str(alert.get("id", ""))),
        )
        details_layout.addRow(
            "Timestamp:",
            QLabel(str(alert.get("timestamp", ""))),
        )
        details_layout.addRow(
            "Severity:",
            QLabel(str(alert.get("severity", ""))),
        )
        details_layout.addRow(
            "Detection Rule:",
            QLabel(str(alert.get("rule", ""))),
        )
        details_layout.addRow(
            "Message:",
            QLabel(str(alert.get("message", ""))),
        )
        details_layout.addRow(
            "Remote Address:",
            QLabel(str(alert.get("remote_address") or "Unknown")),
        )
        # Retrieve process information
        import psutil

        pid = alert.get("pid")
        process_name = "Unavailable"
        process_path = "Unavailable"

        if pid:
            try:
                process = psutil.Process(int(pid))

                try:
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Access denied or process ended"

                try:
                    process_path = process.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_path = "Path unavailable"

            except (ValueError, TypeError):
                process_name = "Invalid PID"
                process_path = "Unavailable"
            except psutil.NoSuchProcess:
                process_name = "Process no longer exists"
                process_path = "Unavailable"
            except psutil.AccessDenied:
                process_name = "Access denied"
                process_path = "Access denied"
        else:
            process_name = "No PID recorded"

        details_layout.addRow(
            "Process Name:",
            QLabel(process_name),
        )

        details_layout.addRow(
            "Process ID (PID):",
            QLabel(str(pid) if pid else "Unknown"),
        )

        details_layout.addRow(
            "Executable Path:",
            QLabel(process_path),
        )

        dialog.exec()   
            
    def export_alerts_to_csv(self):
        """Export saved alerts to a CSV file."""
        import csv

        from PySide6.QtWidgets import QFileDialog, QMessageBox

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Security Alerts",
            "netguard_alerts.csv",
            "CSV Files (*.csv)",
        )

        if not file_path:
            return

        alerts = get_recent_alerts()

        selected_severity = self.severity_filter.currentText()
        search_text = self.alert_search.text().strip().lower()

        if selected_severity != "All severities":
            alerts = [
                alert for alert in alerts
                if alert.get("severity", "").upper() == selected_severity
            ]

        if search_text:
            alerts = [
                alert for alert in alerts
                if search_text in str(alert.get("remote_address") or "").lower()
                or search_text in str(alert.get("rule") or "").lower()
                or search_text in str(alert.get("message") or "").lower()
            ]

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as csv_file:
                writer = csv.writer(csv_file, delimiter=";")

                writer.writerow([
                    "ID",
                    "Timestamp",
                    "Severity",
                    "Detection Rule",
                    "Message",
                    "Remote Address",
                    "PID",
                ])

                for alert in alerts:
                    writer.writerow([
                        alert.get("id", ""),
                        alert.get("timestamp", ""),
                        alert.get("severity", ""),
                        alert.get("rule", ""),
                        alert.get("message", ""),
                        alert.get("remote_address", ""),
                        alert.get("pid", ""),
                    ])

            QMessageBox.information(
                self,
                "Export successful",
                f"{len(alerts)} alert(s) exported to:\n{file_path}",
            )

        except OSError as error:
            QMessageBox.critical(
                self,
                "Export failed",
                f"Could not export alerts:\n{error}",
            )
    
    def refresh_alerts_from_database(self):
        """Display saved alerts using severity and text filters."""
        alerts = get_recent_alerts()

        # Filter by severity
        selected_severity = self.severity_filter.currentText()

        if selected_severity != "All severities":
            alerts = [
                alert for alert in alerts
                if alert.get("severity", "").upper() == selected_severity
            ]

        # Filter by search text
        search_text = self.alert_search.text().strip().lower()

        if search_text:
            alerts = [
                alert for alert in alerts
                if search_text in str(alert.get("remote_address") or "").lower()
                or search_text in str(alert.get("rule") or "").lower()
                or search_text in str(alert.get("message") or "").lower()
            ]

        # Display filtered alerts
        self.alerts_table.setRowCount(len(alerts))

        for row, alert in enumerate(alerts):
            details = alert.get("message", "")
            remote_address = alert.get("remote_address")

            if remote_address:
                details += f" | Remote: {remote_address}"

            values = [
                alert.get("timestamp", ""),
                alert.get("severity", ""),
                alert.get("rule", ""),
                details,
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))

                if column == 0:
                    item.setData(
                        Qt.ItemDataRole.UserRole,
                        alert["id"],
                    )

                if column == 1:
                    severity = str(alert.get("severity", "")).upper()

                    if severity == "WARNING":
                        item.setForeground(Qt.GlobalColor.yellow)
                    elif severity == "HIGH":
                        item.setForeground(Qt.GlobalColor.red)

                self.alerts_table.setItem(row, column, item)

        self.alert_count_label.setText(
            f"{len(alerts)} alerts displayed"
        )
    
    def refresh_alerts(self, connections):
        """Detect alerts and avoid saving duplicates."""

        alerts = detect_suspicious_connections(connections)

        for alert in alerts:
            connection = alert.get("connection", {})

            alert_key = (
                alert.get("rule"),
                connection.get("local_address"),
                connection.get("remote_address"),
                connection.get("pid"),
            )

            if alert_key not in self.saved_alert_keys:
                save_alert(alert)
                self.saved_alert_keys.add(alert_key)

        self.refresh_alerts_from_database()

        if not alerts:
            self.alert_summary.setText(
                "No connections currently match the detection rules."
            )
        else:
            self.alert_summary.setText(
                f"{len(alerts)} connection alert(s) require review. "
                "Open Security Alerts for details."
            )

    def update_graph(self):
        self.ax.clear()
        self.configure_graph()

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

        max_speed = max(
            max(self.download_history, default=0),
            max(self.upload_history, default=0),
        )

        self.ax.set_ylim(0, max(10, max_speed * 1.2))
        self.ax.legend(facecolor="#111827", labelcolor="#e2e8f0")

        self.figure.tight_layout()
        self.canvas.draw()

    # ==================================================
    # SETTINGS
    # ==================================================

    def apply_settings(self):
        interval = self.interval_combo.currentData()

        if not isinstance(interval, int):
            QMessageBox.warning(
                self,
                "Invalid setting",
                "Please select a valid refresh interval.",
            )
            return

        self.refresh_interval = interval
        self.timer.setInterval(interval)

        QMessageBox.information(
            self,
            "Settings applied",
            f"Refresh interval set to {interval // 1000} second(s).",
        )

    # ==================================================
    # MONITORING CONTROLS
    # ==================================================

    def start_monitoring(self):
        if self.monitoring:
            return

        self.monitoring = True
        self.previous_stats = psutil.net_io_counters()
        self.last_sample_time = time.monotonic()

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

    def stop_monitoring(self):
        self.timer.stop()
        self.monitoring = False

        self.download_speed = 0.0
        self.upload_speed = 0.0

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