"""
Export utilities for saving analysis results
"""
import csv
import json
from typing import List, Dict, Any
from datetime import datetime
import os

class Exporter:
    """Export analysis results to various formats"""
    
    @staticmethod
    def export_to_csv(data: List[Dict], filename: str, fieldnames: List[str] = None):
        """Export data to CSV file"""
        if not data:
            return False
        
        if fieldnames is None:
            fieldnames = list(data[0].keys())
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            return True
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
    
    @staticmethod
    def export_to_json(data: Any, filename: str, pretty=True):
        """Export data to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                if pretty:
                    json.dump(data, jsonfile, indent=2, default=str)
                else:
                    json.dump(data, jsonfile, default=str)
            return True
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False
    
    @staticmethod
    def export_packets_to_csv(packets: List, filename: str):
        """Export packet list to CSV"""
        packet_data = []
        
        for i, pkt in enumerate(packets):
            row = {
                'No': i + 1,
                'Time': pkt.time if hasattr(pkt, 'time') else '',
                'Length': len(pkt),
                'Protocol': pkt.sprintf('%IP.proto%') if hasattr(pkt, 'IP') else 'N/A',
                'Source': pkt.sprintf('%IP.src%') if hasattr(pkt, 'IP') else pkt.sprintf('%Ether.src%') if hasattr(pkt, 'Ether') else '',
                'Destination': pkt.sprintf('%IP.dst%') if hasattr(pkt, 'IP') else pkt.sprintf('%Ether.dst%') if hasattr(pkt, 'Ether') else '',
                'Info': pkt.summary()
            }
            packet_data.append(row)
        
        return Exporter.export_to_csv(packet_data, filename)
    
    @staticmethod
    def export_connections_to_csv(connections: List[Dict], filename: str):
        """Export connection data to CSV"""
        return Exporter.export_to_csv(connections, filename)
    
    @staticmethod
    def export_statistics_to_csv(stats: Dict, filename: str):
        """Export statistics to CSV"""
        stats_list = []
        for key, value in stats.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    stats_list.append({
                        'Category': key,
                        'Item': sub_key,
                        'Value': sub_value
                    })
            else:
                stats_list.append({
                    'Category': key,
                    'Item': '',
                    'Value': value
                })
        
        return Exporter.export_to_csv(stats_list, filename)
    
    @staticmethod
    def export_filtered_pcap(packets: List, filename: str):
        """Export filtered packets to a new PCAP file"""
        try:
            from scapy.all import wrpcap
            wrpcap(filename, packets)
            return True
        except Exception as e:
            print(f"Error exporting filtered PCAP: {e}")
            return False

class ReportGenerator:
    """Generate analysis reports"""
    
    @staticmethod
    def generate_text_report(stats: Dict, connections: List[Dict], filename: str):
        """Generate a text report"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("PCAP ANALYSIS REPORT\n")
                f.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
                f.write("=" * 80 + "\n\n")
                
                # Statistics section
                f.write("STATISTICS\n")
                f.write("-" * 80 + "\n")
                for key, value in stats.items():
                    if isinstance(value, dict):
                        f.write(f"\n{key}:\n")
                        for sub_key, sub_value in value.items():
                            f.write(f"  {sub_key}: {sub_value}\n")
                    else:
                        f.write(f"{key}: {value}\n")
                
                # Connections section
                f.write("\n\nCONNECTIONS\n")
                f.write("-" * 80 + "\n")
                for i, conn in enumerate(connections[:50], 1):  # Top 50 connections
                    f.write(f"\nConnection {i}:\n")
                    for key, value in conn.items():
                        f.write(f"  {key}: {value}\n")
                
                f.write("\n" + "=" * 80 + "\n")
            
            return True
        except Exception as e:
            print(f"Error generating text report: {e}")
            return False
    
    @staticmethod
    def generate_html_report(stats: Dict, connections: List[Dict], filename: str):
        """Generate an HTML report"""
        try:
            html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .metadata {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>PCAP Analysis Report</h1>
    <p class="metadata">Generated: {timestamp}</p>
    
    <h2>Statistics</h2>
    <table>
        <tr><th>Category</th><th>Item</th><th>Value</th></tr>
        {stats_rows}
    </table>
    
    <h2>Connections (Top 50)</h2>
    <table>
        <tr>{conn_headers}</tr>
        {conn_rows}
    </table>
</body>
</html>
"""
            # Generate statistics rows
            stats_rows = ""
            for key, value in stats.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        stats_rows += f"<tr><td>{key}</td><td>{sub_key}</td><td>{sub_value}</td></tr>\n"
                else:
                    stats_rows += f"<tr><td>{key}</td><td></td><td>{value}</td></tr>\n"
            
            # Generate connection headers and rows
            if connections:
                conn_headers = "".join([f"<th>{key}</th>" for key in connections[0].keys()])
                conn_rows = ""
                for conn in connections[:50]:
                    row = "<tr>" + "".join([f"<td>{value}</td>" for value in conn.values()]) + "</tr>\n"
                    conn_rows += row
            else:
                conn_headers = "<th>No Data</th>"
                conn_rows = "<tr><td>No connections found</td></tr>"
            
            # Fill in the template
            html_content = html_content.format(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                stats_rows=stats_rows,
                conn_headers=conn_headers,
                conn_rows=conn_rows
            )
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return False
