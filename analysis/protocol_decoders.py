"""
Protocol-specific decoders for advanced analysis
"""
from typing import Dict, Any, List
from utils.logger import logger

class ProtocolDecoders:
    """Advanced protocol-specific decoders"""
    
    @staticmethod
    def decode_http(packet) -> Dict[str, Any]:
        """Decode HTTP protocol details"""
        if not hasattr(packet, 'Raw'):
            return {}
        
        payload = bytes(packet['Raw']).decode('utf-8', errors='ignore')
        http_data = {}
        
        try:
            lines = payload.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse request/response line
            first_line = lines[0]
            
            if first_line.startswith('HTTP/'):
                # HTTP Response
                parts = first_line.split(' ', 2)
                http_data['type'] = 'response'
                http_data['version'] = parts[0] if len(parts) > 0 else ''
                http_data['status_code'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                http_data['reason'] = parts[2] if len(parts) > 2 else ''
            elif any(first_line.startswith(m) for m in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']):
                # HTTP Request
                parts = first_line.split(' ')
                http_data['type'] = 'request'
                http_data['method'] = parts[0] if len(parts) > 0 else ''
                http_data['uri'] = parts[1] if len(parts) > 1 else ''
                http_data['version'] = parts[2] if len(parts) > 2 else ''
            else:
                return {}
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            http_data['headers'] = headers
            
            # Get body if present
            if body_start < len(lines):
                http_data['body'] = '\r\n'.join(lines[body_start:])
            
            return http_data
            
        except Exception as e:
            logger.error(f"Error decoding HTTP: {e}")
            return {}
    
    @staticmethod
    def decode_tls(packet) -> Dict[str, Any]:
        """Decode TLS handshake information (without decryption)"""
        tls_data = {}
        
        if not hasattr(packet, 'Raw'):
            return {}
        
        try:
            raw_data = bytes(packet['Raw'])
            
            # TLS record starts with content type (1 byte)
            if len(raw_data) < 5:
                return {}
            
            content_type = raw_data[0]
            version = (raw_data[1], raw_data[2])
            length = (raw_data[3] << 8) | raw_data[4]
            
            content_types = {
                20: 'ChangeCipherSpec',
                21: 'Alert',
                22: 'Handshake',
                23: 'ApplicationData'
            }
            
            tls_data['content_type'] = content_types.get(content_type, f'Unknown({content_type})')
            tls_data['version'] = f"{version[0]}.{version[1]}"
            tls_data['length'] = length
            
            # If it's a handshake, try to get handshake type
            if content_type == 22 and len(raw_data) > 5:
                handshake_type = raw_data[5]
                handshake_types = {
                    1: 'ClientHello',
                    2: 'ServerHello',
                    11: 'Certificate',
                    12: 'ServerKeyExchange',
                    13: 'CertificateRequest',
                    14: 'ServerHelloDone',
                    16: 'ClientKeyExchange',
                    20: 'Finished'
                }
                tls_data['handshake_type'] = handshake_types.get(handshake_type, f'Unknown({handshake_type})')
            
            return tls_data
            
        except Exception as e:
            logger.error(f"Error decoding TLS: {e}")
            return {}
    
    @staticmethod
    def decode_ftp(packet) -> Dict[str, Any]:
        """Decode FTP protocol"""
        if not hasattr(packet, 'Raw'):
            return {}
        
        payload = bytes(packet['Raw']).decode('utf-8', errors='ignore').strip()
        ftp_data = {}
        
        try:
            # FTP responses start with 3-digit code
            if len(payload) >= 3 and payload[:3].isdigit():
                ftp_data['type'] = 'response'
                ftp_data['code'] = int(payload[:3])
                ftp_data['message'] = payload[4:] if len(payload) > 4 else ''
            else:
                # FTP command
                parts = payload.split(' ', 1)
                ftp_data['type'] = 'command'
                ftp_data['command'] = parts[0].upper()
                ftp_data['arguments'] = parts[1] if len(parts) > 1 else ''
            
            return ftp_data
            
        except Exception as e:
            logger.error(f"Error decoding FTP: {e}")
            return {}
    
    @staticmethod
    def decode_smtp(packet) -> Dict[str, Any]:
        """Decode SMTP protocol"""
        if not hasattr(packet, 'Raw'):
            return {}
        
        payload = bytes(packet['Raw']).decode('utf-8', errors='ignore').strip()
        smtp_data = {}
        
        try:
            # SMTP responses start with 3-digit code
            if len(payload) >= 3 and payload[:3].isdigit():
                smtp_data['type'] = 'response'
                smtp_data['code'] = int(payload[:3])
                smtp_data['message'] = payload[4:] if len(payload) > 4 else ''
            else:
                # SMTP command
                parts = payload.split(' ', 1)
                smtp_data['type'] = 'command'
                smtp_data['command'] = parts[0].upper()
                smtp_data['arguments'] = parts[1] if len(parts) > 1 else ''
            
            return smtp_data
            
        except Exception as e:
            logger.error(f"Error decoding SMTP: {e}")
            return {}
    
    @staticmethod
    def decode_dhcp(packet) -> Dict[str, Any]:
        """Decode DHCP protocol"""
        dhcp_data = {}
        
        if hasattr(packet, 'BOOTP'):
            bootp = packet['BOOTP']
            dhcp_data['op'] = 'Request' if bootp.op == 1 else 'Reply'
            dhcp_data['client_mac'] = bootp.chaddr if hasattr(bootp, 'chaddr') else ''
            dhcp_data['client_ip'] = bootp.ciaddr if hasattr(bootp, 'ciaddr') else '0.0.0.0'
            dhcp_data['your_ip'] = bootp.yiaddr if hasattr(bootp, 'yiaddr') else '0.0.0.0'
            dhcp_data['server_ip'] = bootp.siaddr if hasattr(bootp, 'siaddr') else '0.0.0.0'
        
        if hasattr(packet, 'DHCP'):
            # DHCP options would be here
            dhcp_data['has_options'] = True
        
        return dhcp_data
    
    @staticmethod
    def decode_sip(packet) -> Dict[str, Any]:
        """Decode SIP (Session Initiation Protocol)"""
        if not hasattr(packet, 'Raw'):
            return {}
        
        payload = bytes(packet['Raw']).decode('utf-8', errors='ignore')
        sip_data = {}
        
        try:
            lines = payload.split('\r\n')
            
            if not lines:
                return {}
            
            first_line = lines[0]
            
            # SIP Request
            if any(first_line.startswith(m) for m in ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER']):
                parts = first_line.split(' ')
                sip_data['type'] = 'request'
                sip_data['method'] = parts[0]
                sip_data['uri'] = parts[1] if len(parts) > 1 else ''
            # SIP Response
            elif first_line.startswith('SIP/'):
                parts = first_line.split(' ', 2)
                sip_data['type'] = 'response'
                sip_data['version'] = parts[0]
                sip_data['status_code'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                sip_data['reason'] = parts[2] if len(parts) > 2 else ''
            
            # Parse important headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            sip_data['headers'] = headers
            
            return sip_data
            
        except Exception as e:
            logger.error(f"Error decoding SIP: {e}")
            return {}
