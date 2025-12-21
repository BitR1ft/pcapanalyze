#!/usr/bin/env python3
"""
PCAP/PCAPNG File Analyzer
Main application entry point
"""
import sys
import argparse
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.parser import PCAPParser
from core.dissector import PacketDissector
from core.file_extractor import FileExtractor
from core.statistics import StatisticsGenerator
from utils.logger import logger
from utils.exporters import Exporter, ReportGenerator

def analyze_pcap_file(filename: str, options: dict):
    """Analyze a PCAP file with given options"""
    logger.info(f"Starting analysis of {filename}")
    
    # Parse file
    parser = PCAPParser(filename)
    if not parser.load_file():
        logger.error("Failed to load PCAP file")
        return False
    
    packets = parser.get_packets()
    file_info = parser.get_file_info()
    
    logger.info(f"Loaded {len(packets)} packets from {file_info['format']} file")
    
    # Generate statistics
    stats_gen = StatisticsGenerator()
    stats = stats_gen.generate_statistics(packets)
    
    # Extract files if requested
    extracted_files = []
    if options.get('extract_files'):
        extractor = FileExtractor(options.get('extract_dir', 'extracted_files'))
        extracted_files = extractor.extract_files(packets)
        logger.info(f"Extracted {len(extracted_files)} files")
    
    # Export results
    if options.get('export_stats'):
        Exporter.export_statistics_to_csv(stats, options['export_stats'])
        logger.info(f"Exported statistics to {options['export_stats']}")
    
    if options.get('export_packets'):
        Exporter.export_packets_to_csv(packets, options['export_packets'])
        logger.info(f"Exported packets to {options['export_packets']}")
    
    # Generate report if requested
    if options.get('generate_report'):
        report_file = options['generate_report']
        if report_file.endswith('.html'):
            ReportGenerator.generate_html_report(stats, report_file)
        else:
            ReportGenerator.generate_text_report(stats, report_file)
        logger.info(f"Generated report: {report_file}")
    
    # Print summary
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    print(f"File: {file_info['filename']}")
    print(f"Format: {file_info['format']}")
    print(f"Total Packets: {stats['general']['total_packets']}")
    print(f"Total Bytes: {stats['general']['total_bytes']:,}")
    print(f"Duration: {stats['general']['duration_seconds']:.2f} seconds")
    if extracted_files:
        print(f"Files Extracted: {len(extracted_files)}")
    print("=" * 80 + "\n")
    
    return True

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='PCAP/PCAPNG File Analyzer - Comprehensive Network Traffic Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Launch GUI
  python pcap_analyzer.py
  
  # Analyze a file from command line
  python pcap_analyzer.py -f capture.pcap
  
  # Extract files
  python pcap_analyzer.py -f capture.pcap --extract-files
  
  # Generate comprehensive report
  python pcap_analyzer.py -f capture.pcap --report analysis_report.html
  
  # Export statistics
  python pcap_analyzer.py -f capture.pcap --export-stats stats.csv
        """
    )
    
    parser.add_argument('-f', '--file', help='PCAP/PCAPNG file to analyze')
    parser.add_argument('--gui', action='store_true', help='Launch GUI mode (default if no file specified)')
    parser.add_argument('--extract-files', action='store_true', help='Extract embedded files from traffic')
    parser.add_argument('--extract-dir', default='extracted_files', help='Directory for extracted files')
    parser.add_argument('--export-stats', help='Export statistics to CSV file')
    parser.add_argument('--export-packets', help='Export packet list to CSV file')
    parser.add_argument('--report', help='Generate analysis report (HTML or TXT)')
    
    args = parser.parse_args()
    
    # If no file specified or --gui flag, launch GUI
    if not args.file or args.gui:
        try:
            from gui.main_window import launch_gui
            logger.info("Launching GUI mode")
            return launch_gui()
        except ImportError as e:
            logger.error(f"Failed to import GUI module: {e}")
            print("Error: GUI modules not available. Please install PyQt5:")
            print("  pip install PyQt5")
            return 1
        except Exception as e:
            logger.error(f"Error launching GUI: {e}")
            print(f"Error launching GUI: {e}")
            return 1
    
    # Command-line mode
    options = {
        'extract_files': args.extract_files,
        'extract_dir': args.extract_dir,
        'export_stats': args.export_stats,
        'export_packets': args.export_packets,
        'generate_report': args.report
    }
    
    try:
        success = analyze_pcap_file(args.file, options)
        return 0 if success else 1
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
