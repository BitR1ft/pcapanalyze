"""
Main GUI window for PCAP Analyzer
Implements the three-pane layout similar to Wireshark
"""
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QSplitter, QMenuBar, QMenu, QAction,
                             QFileDialog, QMessageBox, QStatusBar, QTabWidget,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel,
                             QTreeWidget, QTreeWidgetItem, QProgressBar, QPushButton,
                             QLineEdit, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parser import PCAPParser
from core.dissector import PacketDissector
from core.file_extractor import FileExtractor
from core.text_extractor import TextExtractor
from core.statistics import StatisticsGenerator
from utils.logger import logger
from utils.filters import PacketFilter
from utils.exporters import Exporter, ReportGenerator
from utils.ctf_utils import CTFUtils

class AnalysisThread(QThread):
    """Background thread for packet analysis"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, filename):
        super().__init__()
        self.filename = filename
    
    def run(self):
        try:
            self.progress.emit(10, "Loading PCAP file...")
            
            # Parse file
            parser = PCAPParser(self.filename)
            if not parser.load_file():
                self.error.emit("Failed to load PCAP file")
                return
            
            packets = parser.get_packets()
            file_info = parser.get_file_info()
            
            self.progress.emit(30, f"Analyzing {len(packets)} packets...")
            
            self.progress.emit(50, "Generating statistics...")
            
            # Generate statistics
            stats_gen = StatisticsGenerator()
            stats = stats_gen.generate_statistics(packets)
            
            self.progress.emit(70, "Extracting files...")
            
            # Extract files
            extractor = FileExtractor()
            extracted_files = extractor.extract_files(packets)
            
            self.progress.emit(90, "Extracting text and payloads...")
            
            # Extract text content
            text_extractor = TextExtractor()
            text_data = text_extractor.extract_all_text(packets)
            
            self.progress.emit(100, "Analysis complete!")
            
            # Return all results
            results = {
                'parser': parser,
                'packets': packets,
                'file_info': file_info,
                'statistics': stats,
                'extracted_files': extracted_files,
                'text_data': text_data,
                'text_extractor': text_extractor
            }
            
            self.finished.emit(results)
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            self.error.emit(str(e))

class PCAPAnalyzerGUI(QMainWindow):
    """Main GUI window"""
    
    def __init__(self):
        super().__init__()
        self.current_file = None
        self.packets = []
        self.statistics = {}
        self.extracted_files = []
        self.text_data = {}
        self.text_extractor = None
        self.parser = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle('PCAP/PCAPNG Analyzer - Network Traffic Analysis Tool')
        self.setGeometry(100, 100, 1400, 900)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # Create toolbar
        toolbar_layout = QHBoxLayout()
        
        # File open button
        open_btn = QPushButton('Open PCAP File')
        open_btn.clicked.connect(self.open_file)
        toolbar_layout.addWidget(open_btn)
        
        # Filter input
        toolbar_layout.addWidget(QLabel('Filter:'))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText('e.g., TCP, 192.168.1.1, port 80')
        toolbar_layout.addWidget(self.filter_input)
        
        filter_btn = QPushButton('Apply Filter')
        filter_btn.clicked.connect(self.apply_filter)
        toolbar_layout.addWidget(filter_btn)
        
        clear_filter_btn = QPushButton('Clear Filter')
        clear_filter_btn.clicked.connect(self.clear_filter)
        toolbar_layout.addWidget(clear_filter_btn)
        
        toolbar_layout.addStretch()
        main_layout.addLayout(toolbar_layout)
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Packets tab (main three-pane view)
        self.packets_tab = self.create_packets_tab()
        self.tabs.addTab(self.packets_tab, "Packets")
        
        # Statistics tab
        self.statistics_tab = self.create_statistics_tab()
        self.tabs.addTab(self.statistics_tab, "Statistics")
        
        # Extracted Files tab
        self.files_tab = self.create_files_tab()
        self.tabs.addTab(self.files_tab, "Extracted Files")
        
        # Text/Payloads tab
        self.text_tab = self.create_text_tab()
        self.tabs.addTab(self.text_tab, "Text & Payloads")
        
        # CTF Utilities tab
        self.ctf_tab = self.create_ctf_tab()
        self.tabs.addTab(self.ctf_tab, "CTF Utilities")
        
        # Decoder tab
        self.decoder_tab = self.create_decoder_tab()
        self.tabs.addTab(self.decoder_tab, "Decoder/Encoder")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready')
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        open_action = QAction('Open PCAP File...', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        export_menu = file_menu.addMenu('Export')
        
        export_packets_action = QAction('Export Packets to CSV', self)
        export_packets_action.triggered.connect(self.export_packets)
        export_menu.addAction(export_packets_action)
        
        export_stats_action = QAction('Export Statistics to CSV', self)
        export_stats_action.triggered.connect(self.export_statistics)
        export_menu.addAction(export_stats_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu('Analysis')
        
        report_action = QAction('Generate Report', self)
        report_action.triggered.connect(self.generate_report)
        analysis_menu.addAction(report_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_packets_tab(self):
        """Create the main packets view with three panes"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Create splitter for three panes
        splitter = QSplitter(Qt.Vertical)
        
        # Top pane: Packet list
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SingleSelection)
        self.packet_table.itemSelectionChanged.connect(self.on_packet_selected)
        splitter.addWidget(self.packet_table)
        
        # Middle pane: Packet details
        self.packet_details = QTreeWidget()
        self.packet_details.setHeaderLabels(['Field', 'Value'])
        splitter.addWidget(self.packet_details)
        
        # Bottom pane: Hex view
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont('Courier', 9))
        splitter.addWidget(self.hex_view)
        
        # Set splitter sizes
        splitter.setSizes([300, 200, 150])
        
        layout.addWidget(splitter)
        return widget
    
    def create_statistics_tab(self):
        """Create statistics view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.statistics_text = QTextEdit()
        self.statistics_text.setReadOnly(True)
        layout.addWidget(self.statistics_text)
        
        return widget
    
    def create_files_tab(self):
        """Create extracted files view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(5)
        self.files_table.setHorizontalHeaderLabels(['Filename', 'Size', 'Source', 'Content Type', 'Path'])
        layout.addWidget(self.files_table)
        
        return widget
    
    def create_text_tab(self):
        """Create text and payloads view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel('Search:'))
        self.text_search_input = QLineEdit()
        self.text_search_input.setPlaceholderText('Enter text to search in all payloads...')
        search_layout.addWidget(self.text_search_input)
        
        text_search_btn = QPushButton('Search Text')
        text_search_btn.clicked.connect(self.search_text)
        search_layout.addWidget(text_search_btn)
        
        regex_search_btn = QPushButton('Search Regex')
        regex_search_btn.clicked.connect(self.search_regex)
        search_layout.addWidget(regex_search_btn)
        
        layout.addLayout(search_layout)
        
        # Text display area
        self.text_display = QTextEdit()
        self.text_display.setReadOnly(True)
        self.text_display.setFont(QFont('Courier', 9))
        layout.addWidget(self.text_display)
        
        # Statistics
        self.text_stats_label = QLabel('No text data loaded')
        layout.addWidget(self.text_stats_label)
        
        return widget
    
    def create_ctf_tab(self):
        """Create CTF utilities view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        
        find_flags_btn = QPushButton('Find Flags')
        find_flags_btn.clicked.connect(self.find_flags)
        buttons_layout.addWidget(find_flags_btn)
        
        extract_urls_btn = QPushButton('Extract URLs')
        extract_urls_btn.clicked.connect(self.extract_urls)
        buttons_layout.addWidget(extract_urls_btn)
        
        extract_emails_btn = QPushButton('Extract Emails')
        extract_emails_btn.clicked.connect(self.extract_emails)
        buttons_layout.addWidget(extract_emails_btn)
        
        show_creds_btn = QPushButton('Show Credentials')
        show_creds_btn.clicked.connect(self.show_credentials)
        buttons_layout.addWidget(show_creds_btn)
        
        show_strings_btn = QPushButton('Show All Strings')
        show_strings_btn.clicked.connect(self.show_strings)
        buttons_layout.addWidget(show_strings_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # Results display
        self.ctf_results = QTextEdit()
        self.ctf_results.setReadOnly(True)
        self.ctf_results.setFont(QFont('Courier', 9))
        layout.addWidget(self.ctf_results)
        
        return widget
    
    def create_decoder_tab(self):
        """Create decoder/encoder utilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Input area
        input_layout = QVBoxLayout()
        input_layout.addWidget(QLabel('Input Text:'))
        self.decoder_input = QTextEdit()
        self.decoder_input.setMaximumHeight(100)
        input_layout.addWidget(self.decoder_input)
        layout.addLayout(input_layout)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        decode_b64_btn = QPushButton('Decode Base64')
        decode_b64_btn.clicked.connect(lambda: self.apply_decoder('base64_decode'))
        buttons_layout.addWidget(decode_b64_btn)
        
        encode_b64_btn = QPushButton('Encode Base64')
        encode_b64_btn.clicked.connect(lambda: self.apply_decoder('base64_encode'))
        buttons_layout.addWidget(encode_b64_btn)
        
        decode_hex_btn = QPushButton('Decode Hex')
        decode_hex_btn.clicked.connect(lambda: self.apply_decoder('hex_decode'))
        buttons_layout.addWidget(decode_hex_btn)
        
        encode_hex_btn = QPushButton('Encode Hex')
        encode_hex_btn.clicked.connect(lambda: self.apply_decoder('hex_encode'))
        buttons_layout.addWidget(encode_hex_btn)
        
        rot13_btn = QPushButton('ROT13')
        rot13_btn.clicked.connect(lambda: self.apply_decoder('rot13'))
        buttons_layout.addWidget(rot13_btn)
        
        smart_decode_btn = QPushButton('Smart Decode')
        smart_decode_btn.clicked.connect(lambda: self.apply_decoder('smart'))
        buttons_layout.addWidget(smart_decode_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # XOR section
        xor_layout = QHBoxLayout()
        xor_layout.addWidget(QLabel('XOR Single Byte:'))
        xor_btn = QPushButton('Try All Keys')
        xor_btn.clicked.connect(self.xor_single_byte_analysis)
        xor_layout.addWidget(xor_btn)
        xor_layout.addStretch()
        layout.addLayout(xor_layout)
        
        # Output area
        output_layout = QVBoxLayout()
        output_layout.addWidget(QLabel('Output:'))
        self.decoder_output = QTextEdit()
        self.decoder_output.setReadOnly(True)
        self.decoder_output.setFont(QFont('Courier', 9))
        output_layout.addWidget(self.decoder_output)
        layout.addLayout(output_layout)
        
        return widget
    
    def open_file(self):
        """Open a PCAP file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, 
            'Open PCAP File', 
            '', 
            'PCAP Files (*.pcap *.pcapng *.cap);;All Files (*.*)'
        )
        
        if filename:
            self.load_file(filename)
    
    def load_file(self, filename):
        """Load and analyze a PCAP file"""
        self.current_file = filename
        self.status_bar.showMessage(f'Loading {os.path.basename(filename)}...')
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Start analysis in background thread
        self.analysis_thread = AnalysisThread(filename)
        self.analysis_thread.progress.connect(self.on_analysis_progress)
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.start()
    
    def on_analysis_progress(self, value, message):
        """Handle analysis progress updates"""
        self.progress_bar.setValue(value)
        self.status_bar.showMessage(message)
    
    def on_analysis_finished(self, results):
        """Handle analysis completion"""
        self.parser = results['parser']
        self.packets = results['packets']
        self.statistics = results['statistics']
        self.extracted_files = results['extracted_files']
        self.text_data = results.get('text_data', {})
        self.text_extractor = results.get('text_extractor')
        
        # Update all views
        self.update_packet_list()
        self.update_statistics_view()
        self.update_files_view()
        self.update_text_view()
        
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage(f'Loaded {len(self.packets)} packets from {os.path.basename(self.current_file)}')
    
    def on_analysis_error(self, error_message):
        """Handle analysis errors"""
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage('Error loading file')
        QMessageBox.critical(self, 'Error', f'Failed to load file:\n{error_message}')
    
    def update_packet_list(self):
        """Update the packet list table"""
        self.packet_table.setRowCount(len(self.packets))
        
        for i, pkt in enumerate(self.packets):
            summary = self.parser.get_packet_summary(i)
            
            self.packet_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.packet_table.setItem(i, 1, QTableWidgetItem(f"{summary.get('time', 0):.6f}"))
            self.packet_table.setItem(i, 2, QTableWidgetItem(summary.get('src_ip', summary.get('src_mac', ''))))
            self.packet_table.setItem(i, 3, QTableWidgetItem(summary.get('dst_ip', summary.get('dst_mac', ''))))
            self.packet_table.setItem(i, 4, QTableWidgetItem(summary.get('transport', 'N/A')))
            self.packet_table.setItem(i, 5, QTableWidgetItem(str(summary.get('length', 0))))
            self.packet_table.setItem(i, 6, QTableWidgetItem(summary.get('summary', '')))
        
        self.packet_table.resizeColumnsToContents()
    
    def update_statistics_view(self):
        """Update statistics view"""
        text = "NETWORK TRAFFIC STATISTICS\n"
        text += "=" * 80 + "\n\n"
        
        if 'general' in self.statistics:
            text += "General Statistics:\n"
            text += "-" * 80 + "\n"
            for key, value in self.statistics['general'].items():
                text += f"{key}: {value}\n"
            text += "\n"
        
        if 'protocols' in self.statistics:
            text += "Protocol Distribution:\n"
            text += "-" * 80 + "\n"
            for proto, data in self.statistics['protocols'].items():
                if isinstance(data, dict):
                    text += f"{proto}: {data.get('packets', 0)} packets ({data.get('packet_percentage', 0):.2f}%)\n"
            text += "\n"
        
        if 'top_talkers' in self.statistics and self.statistics['top_talkers']:
            text += "Top 10 Talkers:\n"
            text += "-" * 80 + "\n"
            for i, talker in enumerate(self.statistics['top_talkers'][:10], 1):
                text += f"{i}. {talker['ip']}: {talker['total_bytes']:,} bytes\n"
            text += "\n"
        
        self.statistics_text.setText(text)
    
    def update_files_view(self):
        """Update extracted files table"""
        self.files_table.setRowCount(len(self.extracted_files))
        
        for i, file_info in enumerate(self.extracted_files):
            self.files_table.setItem(i, 0, QTableWidgetItem(file_info['filename']))
            self.files_table.setItem(i, 1, QTableWidgetItem(str(file_info['size'])))
            self.files_table.setItem(i, 2, QTableWidgetItem(file_info['source']))
            self.files_table.setItem(i, 3, QTableWidgetItem(file_info.get('content_type', 'N/A')))
            self.files_table.setItem(i, 4, QTableWidgetItem(file_info['filepath']))
        
        self.files_table.resizeColumnsToContents()
    
    def on_packet_selected(self):
        """Handle packet selection"""
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        if row < len(self.packets):
            pkt = self.packets[row]
            
            # Update packet details
            self.packet_details.clear()
            dissection = PacketDissector.dissect_packet(pkt)
            
            for layer in dissection['layers']:
                layer_item = QTreeWidgetItem([layer['name'], ''])
                for field_name, field_value in layer['fields'].items():
                    field_item = QTreeWidgetItem([field_name, str(field_value)])
                    layer_item.addChild(field_item)
                self.packet_details.addTopLevelItem(layer_item)
                layer_item.setExpanded(True)
            
            # Update hex view
            hex_text = self.format_hex_dump(bytes(pkt))
            self.hex_view.setText(hex_text)
    
    def format_hex_dump(self, data):
        """Format bytes as hex dump"""
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f'{i:04x}  {hex_part:<48}  {ascii_part}')
        return '\n'.join(hex_lines)
    
    def apply_filter(self):
        """Apply filter to packet list"""
        filter_text = self.filter_input.text().strip()
        if not filter_text or not self.packets:
            return
        
        # Simple filtering - can be enhanced
        for row in range(self.packet_table.rowCount()):
            show_row = False
            for col in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, col)
                if item and filter_text.lower() in item.text().lower():
                    show_row = True
                    break
            self.packet_table.setRowHidden(row, not show_row)
    
    def clear_filter(self):
        """Clear packet filter"""
        self.filter_input.clear()
        for row in range(self.packet_table.rowCount()):
            self.packet_table.setRowHidden(row, False)
    
    def export_packets(self):
        """Export packets to CSV"""
        if not self.packets:
            QMessageBox.warning(self, 'Warning', 'No packets loaded')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Packets', '', 'CSV Files (*.csv)')
        if filename:
            Exporter.export_packets_to_csv(self.packets, filename)
            QMessageBox.information(self, 'Success', f'Packets exported to {filename}')
    
    def export_statistics(self):
        """Export statistics to CSV"""
        if not self.statistics:
            QMessageBox.warning(self, 'Warning', 'No statistics available')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Statistics', '', 'CSV Files (*.csv)')
        if filename:
            Exporter.export_statistics_to_csv(self.statistics, filename)
            QMessageBox.information(self, 'Success', f'Statistics exported to {filename}')
    
    def generate_report(self):
        """Generate analysis report"""
        if not self.packets:
            QMessageBox.warning(self, 'Warning', 'No packets loaded')
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            'Generate Report', 
            '', 
            'HTML Files (*.html);;Text Files (*.txt)'
        )
        
        if filename:
            if filename.endswith('.html'):
                ReportGenerator.generate_html_report(self.statistics, filename)
            else:
                ReportGenerator.generate_text_report(self.statistics, filename)
            
            QMessageBox.information(self, 'Success', f'Report generated: {filename}')
    
    def update_text_view(self):
        """Update text and payloads view"""
        if not self.text_data:
            self.text_display.setText("No text data available")
            return
        
        # Show all extracted text
        text_output = "=== EXTRACTED TEXT FROM ALL PACKETS ===\n\n"
        
        for item in self.text_data.get('text_packets', [])[:100]:  # Limit to first 100 for performance
            text_output += f"Packet #{item['packet_num']} - {item['protocol']}\n"
            text_output += f"Source: {item['source']} -> Destination: {item['destination']}\n"
            text_output += f"{'-' * 80}\n"
            text_output += f"{item['text'][:500]}\n"  # Show first 500 chars
            if len(item['text']) > 500:
                text_output += f"... (truncated, total length: {len(item['text'])} chars)\n"
            text_output += f"\n{'=' * 80}\n\n"
        
        if len(self.text_data.get('text_packets', [])) > 100:
            text_output += f"\n... and {len(self.text_data.get('text_packets', [])) - 100} more packets with text\n"
        
        self.text_display.setText(text_output)
        
        # Update statistics
        if self.text_extractor:
            stats = self.text_extractor.get_statistics()
            stats_text = f"Text Packets: {stats['total_text_packets']} | "
            stats_text += f"Unique Strings: {stats['unique_strings']} | "
            stats_text += f"Credentials Found: {stats['credentials_found']}"
            self.text_stats_label.setText(stats_text)
    
    def search_text(self):
        """Search for text in payloads"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        query = self.text_search_input.text().strip()
        if not query:
            QMessageBox.warning(self, 'Warning', 'Please enter a search term')
            return
        
        results = self.text_extractor.search_text(query)
        
        output = f"=== SEARCH RESULTS FOR: '{query}' ===\n\n"
        output += f"Found {len(results)} matches\n\n"
        
        for result in results:
            output += f"Packet #{result['packet_num']} - {result['protocol']}\n"
            output += f"Source: {result['source']} -> Destination: {result['destination']}\n"
            output += f"Context: ...{result['context']}...\n"
            output += f"{'-' * 80}\n\n"
        
        self.text_display.setText(output)
    
    def search_regex(self):
        """Search using regex pattern"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        pattern = self.text_search_input.text().strip()
        if not pattern:
            QMessageBox.warning(self, 'Warning', 'Please enter a regex pattern')
            return
        
        try:
            results = self.text_extractor.search_regex(pattern)
            
            output = f"=== REGEX SEARCH RESULTS FOR: '{pattern}' ===\n\n"
            output += f"Found {len(results)} matches\n\n"
            
            for result in results:
                output += f"Packet #{result['packet_num']} - {result['protocol']}\n"
                output += f"Match: {result['match']}\n"
                output += f"Context: ...{result['context']}...\n"
                output += f"{'-' * 80}\n\n"
            
            self.text_display.setText(output)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Invalid regex pattern: {e}')
    
    def find_flags(self):
        """Find CTF flags"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        flags = self.text_extractor.find_flags()
        
        output = "=== CTF FLAGS FOUND ===\n\n"
        output += f"Found {len(flags)} potential flags\n\n"
        
        for flag in flags:
            output += f"Packet #{flag['packet_num']} - {flag['protocol']}\n"
            output += f"Flag: {flag['match']}\n"
            output += f"Context: ...{flag['context']}...\n"
            output += f"{'-' * 80}\n\n"
        
        if not flags:
            output += "No flags found. Try searching manually.\n"
        
        self.ctf_results.setText(output)
    
    def extract_urls(self):
        """Extract URLs from text"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        urls = self.text_extractor.extract_urls()
        
        output = "=== EXTRACTED URLs ===\n\n"
        output += f"Found {len(urls)} URLs\n\n"
        
        for url in urls:
            output += f"Packet #{url['packet_num']}: {url['match']}\n"
        
        if not urls:
            output += "No URLs found.\n"
        
        self.ctf_results.setText(output)
    
    def extract_emails(self):
        """Extract email addresses"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        emails = self.text_extractor.extract_emails()
        
        output = "=== EXTRACTED EMAIL ADDRESSES ===\n\n"
        output += f"Found {len(emails)} email addresses\n\n"
        
        for email in emails:
            output += f"Packet #{email['packet_num']}: {email['match']}\n"
        
        if not emails:
            output += "No email addresses found.\n"
        
        self.ctf_results.setText(output)
    
    def show_credentials(self):
        """Show extracted credentials"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        creds = self.text_data.get('credentials', [])
        
        output = "=== EXTRACTED CREDENTIALS ===\n\n"
        output += f"Found {len(creds)} potential credentials\n\n"
        
        for cred in creds:
            output += f"Packet #{cred['packet_num']}\n"
            output += f"Type: {cred['type']}\n"
            output += f"Value: {cred['value']}\n"
            if 'decoded' in cred:
                output += f"Decoded: {cred['decoded']}\n"
            output += f"{'-' * 80}\n\n"
        
        if not creds:
            output += "No credentials found.\n"
        
        self.ctf_results.setText(output)
    
    def show_strings(self):
        """Show all extracted strings"""
        if not self.text_extractor:
            QMessageBox.warning(self, 'Warning', 'No text data available')
            return
        
        strings = self.text_data.get('unique_strings', [])
        
        output = "=== ALL EXTRACTED STRINGS ===\n\n"
        output += f"Found {len(strings)} unique strings (min length: 4)\n\n"
        
        for string in strings[:1000]:  # Limit to first 1000
            output += f"{string}\n"
        
        if len(strings) > 1000:
            output += f"\n... and {len(strings) - 1000} more strings\n"
        
        if not strings:
            output += "No strings found.\n"
        
        self.ctf_results.setText(output)
    
    def apply_decoder(self, method: str):
        """Apply decoder/encoder to input text"""
        input_text = self.decoder_input.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, 'Warning', 'Please enter text to decode/encode')
            return
        
        output = ""
        
        try:
            if method == 'base64_decode':
                result = CTFUtils.decode_base64(input_text)
                output = f"Base64 Decoded:\n{result if result else 'Failed to decode'}"
            
            elif method == 'base64_encode':
                result = CTFUtils.encode_base64(input_text)
                output = f"Base64 Encoded:\n{result}"
            
            elif method == 'hex_decode':
                result = CTFUtils.decode_hex(input_text)
                output = f"Hex Decoded:\n{result if result else 'Failed to decode'}"
            
            elif method == 'hex_encode':
                result = CTFUtils.encode_hex(input_text)
                output = f"Hex Encoded:\n{result}"
            
            elif method == 'rot13':
                result = CTFUtils.rot13(input_text)
                output = f"ROT13:\n{result}"
            
            elif method == 'smart':
                results = CTFUtils.smart_decode(input_text)
                output = "=== SMART DECODE RESULTS ===\n\n"
                if results:
                    for encoding, decoded in results.items():
                        output += f"{encoding.upper()}:\n{decoded}\n\n{'-' * 60}\n\n"
                else:
                    output += "No successful decodings found.\n"
            
            self.decoder_output.setText(output)
        
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Decoding error: {e}')
    
    def xor_single_byte_analysis(self):
        """Perform single-byte XOR analysis"""
        input_text = self.decoder_input.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, 'Warning', 'Please enter hex data to analyze')
            return
        
        try:
            # Try to interpret as hex first
            try:
                data = bytes.fromhex(input_text.replace(' ', ''))
            except ValueError:
                # If not hex, use as raw bytes
                data = input_text.encode('utf-8')
            
            results = CTFUtils.xor_single_byte(data)
            
            output = "=== SINGLE-BYTE XOR ANALYSIS ===\n\n"
            output += f"Found {len(results)} potential results:\n\n"
            
            for i, result in enumerate(results[:20], 1):  # Show top 20
                output += f"Result {i} - Key: {result['key']} ({result['key_char']}), "
                output += f"Printable: {result['printable_ratio']:.2%}\n"
                output += f"{result['result'][:200]}\n"  # Show first 200 chars
                if len(result['result']) > 200:
                    output += f"... (truncated)\n"
                output += f"\n{'-' * 60}\n\n"
            
            if not results:
                output += "No valid results found. Make sure input is valid hex data.\n"
            
            self.decoder_output.setText(output)
        
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'XOR analysis error: {e}')
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            'About PCAP Analyzer',
            'PCAP/PCAPNG File Analyzer\n\n'
            'A comprehensive network traffic analysis tool\n'
            'with graphical user interface.\n\n'
            'Version 1.0.0\n\n'
            'Final Year Computer Networks Project'
        )

def launch_gui():
    """Launch the GUI application"""
    app = QApplication(sys.argv)
    window = PCAPAnalyzerGUI()
    window.show()
    return app.exec_()

if __name__ == '__main__':
    sys.exit(launch_gui())
