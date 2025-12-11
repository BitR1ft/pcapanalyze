"""
File extraction module
Extracts embedded files from network traffic (HTTP, FTP, SMTP, etc.)
"""
import os
import re
from typing import List, Dict, Any
from scapy.all import TCP, Raw
from utils.logger import logger

class FileExtractor:
    """Extract files from packet captures"""
    
    def __init__(self, output_dir: str = "extracted_files"):
        self.output_dir = output_dir
        self.extracted_files = []
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def extract_files(self, packets: List) -> List[Dict[str, Any]]:
        """Extract all files from packet list"""
        logger.info("Extracting files from packets...")
        
        self.extracted_files = []
        
        # Extract HTTP files
        self.extracted_files.extend(self._extract_http_files(packets))
        
        # Extract FTP files
        self.extracted_files.extend(self._extract_ftp_files(packets))
        
        # Extract SMTP attachments
        self.extracted_files.extend(self._extract_smtp_files(packets))
        
        logger.info(f"Extracted {len(self.extracted_files)} files")
        return self.extracted_files
    
    def _extract_http_files(self, packets: List) -> List[Dict[str, Any]]:
        """Extract files from HTTP traffic"""
        files = []
        http_sessions = self._reconstruct_http_sessions(packets)
        
        for session in http_sessions:
            if session.get('has_body', False):
                file_info = self._save_http_file(session)
                if file_info:
                    files.append(file_info)
        
        return files
    
    def _reconstruct_http_sessions(self, packets: List) -> List[Dict[str, Any]]:
        """Reconstruct HTTP sessions from packets"""
        sessions = []
        current_request = None
        current_response = None
        
        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            
            payload = bytes(pkt[Raw]).decode('utf-8', errors='replace')
            
            # HTTP Request
            if any(method in payload[:50] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ']):
                if current_request and current_response:
                    sessions.append({
                        'request': current_request,
                        'response': current_response
                    })
                
                current_request = self._parse_http_request(payload, pkt)
                current_response = None
            
            # HTTP Response
            elif payload.startswith('HTTP/'):
                current_response = self._parse_http_response(payload, pkt)
                
                if current_request and current_response:
                    session = {
                        'request': current_request,
                        'response': current_response,
                        'has_body': len(current_response.get('body', b'')) > 0
                    }
                    sessions.append(session)
                    current_request = None
                    current_response = None
        
        return sessions
    
    def _parse_http_request(self, payload: str, pkt) -> Dict[str, Any]:
        """Parse HTTP request"""
        lines = payload.split('\r\n')
        first_line = lines[0].split(' ')
        
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            elif line == '':
                break
        
        return {
            'method': first_line[0] if len(first_line) > 0 else '',
            'uri': first_line[1] if len(first_line) > 1 else '',
            'version': first_line[2] if len(first_line) > 2 else '',
            'headers': headers,
            'time': float(pkt.time) if hasattr(pkt, 'time') else 0
        }
    
    def _parse_http_response(self, payload: str, pkt) -> Dict[str, Any]:
        """Parse HTTP response"""
        parts = payload.split('\r\n\r\n', 1)
        header_part = parts[0]
        body = parts[1].encode('utf-8', errors='replace') if len(parts) > 1 else b''
        
        lines = header_part.split('\r\n')
        status_line = lines[0].split(' ', 2)
        
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return {
            'version': status_line[0] if len(status_line) > 0 else '',
            'status_code': status_line[1] if len(status_line) > 1 else '',
            'status_msg': status_line[2] if len(status_line) > 2 else '',
            'headers': headers,
            'body': body,
            'time': float(pkt.time) if hasattr(pkt, 'time') else 0
        }
    
    def _save_http_file(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Save HTTP response body as a file"""
        try:
            response = session['response']
            request = session['request']
            
            # Get filename from URI or Content-Disposition
            filename = self._extract_filename(request.get('uri', ''), 
                                            response.get('headers', {}))
            
            if not filename:
                # Generate filename based on content type
                content_type = response.get('headers', {}).get('Content-Type', 'unknown')
                ext = self._get_extension_from_content_type(content_type)
                filename = f"http_file_{len(self.extracted_files) + 1}{ext}"
            
            # Save file
            filepath = os.path.join(self.output_dir, filename)
            
            # Avoid overwriting
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filepath = os.path.join(self.output_dir, f"{name}_{counter}{ext}")
                counter += 1
            
            with open(filepath, 'wb') as f:
                f.write(response['body'])
            
            return {
                'filename': os.path.basename(filepath),
                'filepath': filepath,
                'size': len(response['body']),
                'source': 'HTTP',
                'content_type': response.get('headers', {}).get('Content-Type', 'unknown'),
                'uri': request.get('uri', ''),
                'time': response.get('time', 0)
            }
        
        except Exception as e:
            logger.error(f"Error saving HTTP file: {e}")
            return None
    
    def _extract_filename(self, uri: str, headers: Dict[str, str]) -> str:
        """Extract filename from URI or headers"""
        # Try Content-Disposition header
        if 'Content-Disposition' in headers:
            match = re.search(r'filename="?([^"]+)"?', headers['Content-Disposition'])
            if match:
                return match.group(1)
        
        # Try URI
        if uri:
            # Remove query parameters
            uri_path = uri.split('?')[0]
            # Get last part of path
            filename = uri_path.split('/')[-1]
            if filename and '.' in filename:
                return filename
        
        return None
    
    def _get_extension_from_content_type(self, content_type: str) -> str:
        """Get file extension from content type"""
        type_map = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/bmp': '.bmp',
            'image/svg+xml': '.svg',
            'text/html': '.html',
            'text/css': '.css',
            'text/javascript': '.js',
            'application/javascript': '.js',
            'application/json': '.json',
            'application/xml': '.xml',
            'application/pdf': '.pdf',
            'application/zip': '.zip',
            'application/x-zip-compressed': '.zip',
            'application/octet-stream': '.bin',
            'text/plain': '.txt'
        }
        
        content_type_lower = content_type.lower().split(';')[0].strip()
        return type_map.get(content_type_lower, '.dat')
    
    def _extract_ftp_files(self, packets: List) -> List[Dict[str, Any]]:
        """Extract files from FTP traffic"""
        # FTP data is typically on port 20 or negotiated port
        # This is a simplified implementation
        files = []
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                # Check for FTP-DATA port
                if pkt[TCP].sport == 20 or pkt[TCP].dport == 20:
                    
                    data = bytes(pkt[Raw])
                    if len(data) > 100:  # Minimum size threshold
                        filename = f"ftp_file_{len(files) + 1}.dat"
                        filepath = os.path.join(self.output_dir, filename)
                        
                        try:
                            with open(filepath, 'wb') as f:
                                f.write(data)
                            
                            files.append({
                                'filename': filename,
                                'filepath': filepath,
                                'size': len(data),
                                'source': 'FTP',
                                'time': float(pkt.time) if hasattr(pkt, 'time') else 0
                            })
                        except Exception as e:
                            logger.error(f"Error saving FTP file: {e}")
        
        return files
    
    def _extract_smtp_files(self, packets: List) -> List[Dict[str, Any]]:
        """Extract attachments from SMTP traffic"""
        # Simplified SMTP attachment extraction
        files = []
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                if pkt[TCP].dport == 25 or pkt[TCP].sport == 25:
                    
                    payload = bytes(pkt[Raw]).decode('utf-8', errors='replace')
                    
                    # Look for base64 encoded attachments
                    if 'Content-Transfer-Encoding: base64' in payload:
                        # This is simplified - real implementation would need proper MIME parsing
                        pass
        
        return files
    
    def get_extracted_files(self) -> List[Dict[str, Any]]:
        """Get list of extracted files"""
        return self.extracted_files
