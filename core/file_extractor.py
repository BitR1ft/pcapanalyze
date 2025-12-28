"""
File extraction module
Extracts embedded files from network traffic (HTTP, FTP, SMTP, etc.)
Enhanced with better performance and additional features
"""
import os
import re
import hashlib
from typing import List, Dict, Any, Set
from scapy.all import TCP, Raw
from utils.logger import logger

class FileExtractor:
    """Extract files from packet captures with enhanced performance"""
    
    def __init__(self, output_dir: str = "extracted_files"):
        self.output_dir = output_dir
        self.extracted_files = []
        self.file_hashes: Set[str] = set()  # Track duplicates
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def extract_files(self, packets: List) -> List[Dict[str, Any]]:
        """Extract all files from packet list with optimizations"""
        logger.info("Extracting files from packets...")
        
        self.extracted_files = []
        self.file_hashes = set()
        
        # Extract HTTP files (optimized)
        self.extracted_files.extend(self._extract_http_files(packets))
        
        # Extract FTP files
        self.extracted_files.extend(self._extract_ftp_files(packets))
        
        # Extract SMTP attachments
        self.extracted_files.extend(self._extract_smtp_files(packets))
        
        logger.info(f"Extracted {len(self.extracted_files)} files")
        return self.extracted_files
    
    def _calculate_hash(self, data: bytes) -> str:
        """Calculate SHA256 hash of data for duplicate detection"""
        return hashlib.sha256(data).hexdigest()
    
    def _is_duplicate(self, data: bytes) -> bool:
        """Check if file content is a duplicate"""
        file_hash = self._calculate_hash(data)
        if file_hash in self.file_hashes:
            return True
        self.file_hashes.add(file_hash)
        return False
    
    def _extract_http_files(self, packets: List) -> List[Dict[str, Any]]:
        """Extract files from HTTP traffic with improved session reconstruction"""
        files = []
        http_sessions = self._reconstruct_http_sessions(packets)
        
        for session in http_sessions:
            if session.get('has_body', False) and len(session['response'].get('body', b'')) > 0:
                # Skip duplicates
                body = session['response']['body']
                if not self._is_duplicate(body):
                    file_info = self._save_http_file(session)
                    if file_info:
                        files.append(file_info)
        
        return files
    
    def _reconstruct_http_sessions(self, packets: List) -> List[Dict[str, Any]]:
        """Reconstruct HTTP sessions from packets with better buffering"""
        sessions = []
        current_request = None
        response_buffer = {}  # Buffer for multi-packet responses
        
        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            
            try:
                payload = bytes(pkt[Raw]).decode('utf-8', errors='replace')
            except:
                continue
            
            # HTTP Request
            if any(method in payload[:50] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ']):
                if current_request:
                    # Save previous session if exists
                    if current_request.get('stream_id') in response_buffer:
                        response = response_buffer[current_request['stream_id']]
                        sessions.append({
                            'request': current_request,
                            'response': response,
                            'has_body': len(response.get('body', b'')) > 0
                        })
                        del response_buffer[current_request['stream_id']]
                
                current_request = self._parse_http_request(payload, pkt)
                # Create stream identifier
                if pkt.haslayer(TCP):
                    stream_id = f"{pkt.IP.src}:{pkt.TCP.sport}-{pkt.IP.dst}:{pkt.TCP.dport}"
                    current_request['stream_id'] = stream_id
            
            # HTTP Response
            elif payload.startswith('HTTP/'):
                response = self._parse_http_response(payload, pkt)
                
                if current_request:
                    stream_id = current_request.get('stream_id')
                    if stream_id:
                        # Check if this is a continuation or new response
                        if stream_id not in response_buffer:
                            response_buffer[stream_id] = response
                        else:
                            # Append body if continuation
                            response_buffer[stream_id]['body'] += response.get('body', b'')
                        
                        # Check if response is complete (heuristic)
                        content_length = response.get('headers', {}).get('Content-Length')
                        if content_length:
                            try:
                                expected_len = int(content_length)
                                actual_len = len(response_buffer[stream_id]['body'])
                                if actual_len >= expected_len:
                                    # Response complete
                                    sessions.append({
                                        'request': current_request,
                                        'response': response_buffer[stream_id],
                                        'has_body': len(response_buffer[stream_id]['body']) > 0
                                    })
                                    del response_buffer[stream_id]
                                    current_request = None
                            except:
                                pass
        
        # Flush remaining buffered responses
        for stream_id, response in response_buffer.items():
            # Try to find matching request
            sessions.append({
                'request': current_request if current_request and current_request.get('stream_id') == stream_id else {},
                'response': response,
                'has_body': len(response.get('body', b'')) > 0
            })
        
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
        """Save HTTP response body as a file with enhanced metadata"""
        try:
            response = session['response']
            request = session['request']
            body = response['body']
            
            # Skip empty files
            if len(body) == 0:
                return None
            
            # Get filename from URI or Content-Disposition
            filename = self._extract_filename(request.get('uri', ''), 
                                            response.get('headers', {}))
            
            if not filename:
                # Generate filename based on content type
                content_type = response.get('headers', {}).get('Content-Type', 'unknown')
                ext = self._get_extension_from_content_type(content_type)
                filename = f"http_file_{len(self.extracted_files) + 1}{ext}"
            
            # Sanitize filename
            filename = self._sanitize_filename(filename)
            
            # Save file
            filepath = os.path.join(self.output_dir, filename)
            
            # Avoid overwriting
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filepath = os.path.join(self.output_dir, f"{name}_{counter}{ext}")
                counter += 1
            
            with open(filepath, 'wb') as f:
                f.write(body)
            
            # Calculate file hashes for verification
            md5_hash = hashlib.md5(body).hexdigest()
            sha256_hash = self._calculate_hash(body)
            
            return {
                'filename': os.path.basename(filepath),
                'filepath': filepath,
                'size': len(body),
                'source': 'HTTP',
                'content_type': response.get('headers', {}).get('Content-Type', 'unknown'),
                'uri': request.get('uri', ''),
                'time': response.get('time', 0),
                'md5': md5_hash,
                'sha256': sha256_hash,
                'status_code': response.get('status_code', ''),
                'method': request.get('method', '')
            }
        
        except Exception as e:
            logger.error(f"Error saving HTTP file: {e}")
            return None
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to remove dangerous characters"""
        # Remove path separators and dangerous characters including shell metacharacters
        dangerous_chars = ['/', '\\', '..', '\x00', '<', '>', ':', '"', '|', '?', '*', 
                          ';', '&', '$', '`', '(', ')', '[', ']', '{', '}', '\n', '\r']
        sanitized = filename
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Limit length
        if len(sanitized) > 200:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:190] + ext
        
        return sanitized
        return sanitized
    
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
