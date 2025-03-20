from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                           QComboBox, QTextEdit, QTabWidget, QProgressBar,
                           QTableWidget, QTableWidgetItem, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor
import sys
from network_security_tool import NetworkSecurityTool
import threading
import asyncio
import nest_asyncio
import traceback

# Windows'ta asyncio event loop'u için gerekli
nest_asyncio.apply()

class ScanWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, target, interface, scan_type):
        super().__init__()
        self.target = target
        self.interface = interface
        self.scan_type = scan_type
        self.tool = NetworkSecurityTool()

    def run(self):
        try:
            self.log.emit(f"Starting {self.scan_type} scan on {self.target}...")
            self.progress.emit(10)

            # Asenkron fonksiyonu çalıştır
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self.progress.emit(30)
            self.log.emit("Performing network scan...")
            
            results = loop.run_until_complete(self.tool.run_scan(self.target, self.interface, self.scan_type))
            
            self.progress.emit(70)
            self.log.emit("Scan completed successfully")
            
            loop.close()
            
            self.progress.emit(100)
            self.finished.emit(results)
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}\n{traceback.format_exc()}"
            self.log.emit(error_msg)
            self.error.emit(error_msg)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Security Tool")
        self.setMinimumSize(1200, 800)
        self.setup_ui()

    def setup_ui(self):
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Üst bilgi çubuğu
        info_bar = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        info_bar.addWidget(self.status_label)
        layout.addLayout(info_bar)

        # Tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Network Scan Tab
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)

        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP or network (e.g., 192.168.1.0/24)")
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_input)
        scan_layout.addLayout(target_layout)

        # Interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_interfaces())
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        scan_layout.addLayout(interface_layout)

        # Scan options
        options_layout = QHBoxLayout()
        self.deep_scan = QPushButton("Deep Scan")
        self.quick_scan = QPushButton("Quick Scan")
        self.vuln_scan = QPushButton("Vulnerability Scan")
        options_layout.addWidget(self.deep_scan)
        options_layout.addWidget(self.quick_scan)
        options_layout.addWidget(self.vuln_scan)
        scan_layout.addLayout(options_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        scan_layout.addWidget(self.progress_bar)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["IP", "Status", "Open Ports", "Vulnerabilities"])
        scan_layout.addWidget(self.results_table)

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        scan_layout.addWidget(self.log_area)

        # Add scan tab
        tabs.addTab(scan_tab, "Network Scan")

        # Traffic Monitor Tab
        monitor_tab = QWidget()
        monitor_layout = QVBoxLayout(monitor_tab)
        
        # Traffic table
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(4)
        self.traffic_table.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "Size"])
        monitor_layout.addWidget(self.traffic_table)

        # Traffic controls
        traffic_controls = QHBoxLayout()
        self.start_monitor = QPushButton("Start Monitoring")
        self.stop_monitor = QPushButton("Stop Monitoring")
        traffic_controls.addWidget(self.start_monitor)
        traffic_controls.addWidget(self.stop_monitor)
        monitor_layout.addLayout(traffic_controls)

        # Add monitor tab
        tabs.addTab(monitor_tab, "Traffic Monitor")

        # Connect signals
        self.deep_scan.clicked.connect(lambda: self.start_scan("deep"))
        self.quick_scan.clicked.connect(lambda: self.start_scan("quick"))
        self.vuln_scan.clicked.connect(lambda: self.start_scan("vuln"))
        self.start_monitor.clicked.connect(self.start_traffic_monitor)
        self.stop_monitor.clicked.connect(self.stop_traffic_monitor)

    def get_interfaces(self):
        try:
            from netifaces import interfaces
            return interfaces()
        except Exception as e:
            self.log_message(f"Error getting interfaces: {str(e)}")
            return ["No interfaces found"]

    def start_scan(self, scan_type):
        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return

        interface = self.interface_combo.currentText()
        self.status_label.setText("Scanning...")
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        self.log_area.clear()

        self.scan_worker = ScanWorker(target, interface, scan_type)
        self.scan_worker.finished.connect(self.scan_completed)
        self.scan_worker.progress.connect(self.update_progress)
        self.scan_worker.log.connect(self.log_message)
        self.scan_worker.error.connect(self.scan_error)
        self.scan_worker.start()

    def scan_completed(self, results):
        self.status_label.setText("Scan completed")
        self.progress_bar.setValue(100)
        self.update_results_table(results)
        self.log_message("Scan completed successfully")

    def scan_error(self, error_msg):
        self.status_label.setText("Scan failed")
        self.progress_bar.setValue(0)
        QMessageBox.critical(self, "Error", f"Scan failed: {error_msg}")
        self.log_message(f"Error: {error_msg}")

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def log_message(self, message):
        self.log_area.append(message)

    def update_results_table(self, results):
        self.results_table.setRowCount(len(results))
        for i, (ip, data) in enumerate(results.items()):
            self.results_table.setItem(i, 0, QTableWidgetItem(ip))
            self.results_table.setItem(i, 1, QTableWidgetItem(data.get('status', 'Unknown')))
            self.results_table.setItem(i, 2, QTableWidgetItem(str(data.get('open_ports', []))))
            self.results_table.setItem(i, 3, QTableWidgetItem(str(data.get('vulnerabilities', []))))

    def start_traffic_monitor(self):
        self.status_label.setText("Monitoring traffic...")
        # Start traffic monitoring thread

    def stop_traffic_monitor(self):
        self.status_label.setText("Traffic monitoring stopped")
        # Stop traffic monitoring thread

def main():
    app = QApplication(sys.argv)
    
    # Set dark theme
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 