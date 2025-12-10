"""
Text and payload extraction module
Extracts all text content and payloads from packets for searching and analysis
Particularly useful for CTF challenges
"""
import re
import base64
import binascii
from typing import List, Dict, Any, Set
from collections import defaultdict
from scapy.all import IP, TCP, UDP, Raw
from utils.logger import logger


class TextExtractor:
    """Extract text and payloads from packets"""
    
    def __init__(self):
        self.all_text = []
        self.payloads = []
        self.strings = set()
        self.credentials = []
        
    def extract_all_text(self, packets: List) -> Dict[str, Any]:
        """Extract all text content from packets"""
        logger.info("Extracting text content from packets...")
        
        self.all_text = []
        self.payloads = []
        self.strings = set()
        self.credentials = []
        
        for i, pkt in enumerate(packets):
            # Extract raw payload
            if pkt.haslayer(Raw):
                try:
                    payload = bytes(pkt[Raw])
                    
                    # Store raw payload info
                    payload_info = {
                        'packet_num': i + 1,
                        'raw_bytes': payload,
                        'hex': payload.hex(),
                        'length': len(payload)
                    }
                    
                    # Try to decode as text
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        if text.strip():
                            payload_info['text'] = text
                            self.all_text.append({
                                'packet_num': i + 1,
                                'text': text,
                                'source': self._get_packet_source(pkt),
                                'destination': self._get_packet_destination(pkt),
                                'protocol': self._get_protocol(pkt)
                            })
                            
                            # Extract printable strings
                            strings = self._extract_strings(payload)
                            self.strings.update(strings)
                            
                    except Exception:
                        pass
                    
                    # Try ASCII decode as fallback
                    try:
                        text = payload.decode('ascii', errors='ignore')
                        if text.strip() and 'text' not in payload_info:
                            payload_info['text'] = text
                    except Exception:
                        pass
                    
                    self.payloads.append(payload_info)
                    
                    # Look for credentials
                    self._extract_credentials(payload, i + 1)
                    
                except Exception as e:
                    logger.debug(f"Error extracting from packet {i}: {e}")
        
        logger.info(f"Extracted {len(self.all_text)} text packets, {len(self.strings)} unique strings")
        
        return {
            'text_packets': self.all_text,
            'all_payloads': self.payloads,
            'unique_strings': sorted(list(self.strings)),
            'credentials': self.credentials
        }
    
    def _get_packet_source(self, pkt) -> str:
        """Get source address from packet"""
        if pkt.haslayer(IP):
            src = pkt[IP].src
            if pkt.haslayer(TCP):
                return f"{src}:{pkt[TCP].sport}"
            elif pkt.haslayer(UDP):
                return f"{src}:{pkt[UDP].sport}"
            return src
        return "Unknown"
    
    def _get_packet_destination(self, pkt) -> str:
        """Get destination address from packet"""
        if pkt.haslayer(IP):
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                return f"{dst}:{pkt[TCP].dport}"
            elif pkt.haslayer(UDP):
                return f"{dst}:{pkt[UDP].dport}"
            return dst
        return "Unknown"
    
    def _get_protocol(self, pkt) -> str:
        """Get protocol from packet"""
        protocols = []
        if pkt.haslayer(IP):
            protocols.append('IP')
        if pkt.haslayer(TCP):
            protocols.append('TCP')
        elif pkt.haslayer(UDP):
            protocols.append('UDP')
        # HTTP and DNS don't have dedicated Scapy layers in basic import
        return '/'.join(protocols) if protocols else 'Unknown'
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> Set[str]:
        """Extract printable strings from bytes"""
        strings = set()
        current_string = []
        
        for byte in data:
            # Check if byte is printable ASCII
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.add(''.join(current_string))
                current_string = []
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.add(''.join(current_string))
        
        return strings
    
    def _extract_credentials(self, payload: bytes, packet_num: int):
        """Extract potential credentials from payload"""
        try:
            text = payload.decode('utf-8', errors='ignore').lower()
            
            # Look for common credential patterns
            patterns = {
                'basic_auth': r'authorization:\s*basic\s+([a-zA-Z0-9+/=]+)',
                'password': r'(?:password|passwd|pwd)[=:\s]+([^\s&]+)',
                'username': r'(?:username|user|login)[=:\s]+([^\s&]+)',
                'api_key': r'(?:api[_-]?key|apikey)[=:\s]+([^\s&]+)',
                'token': r'(?:token|bearer)[=:\s]+([^\s&]+)',
            }
            
            for cred_type, pattern in patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    cred_info = {
                        'packet_num': packet_num,
                        'type': cred_type,
                        'value': match
                    }
                    
                    # Try to decode base64 for basic auth
                    if cred_type == 'basic_auth':
                        try:
                            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                            cred_info['decoded'] = decoded
                        except Exception:
                            pass
                    
                    self.credentials.append(cred_info)
        
        except Exception as e:
            logger.debug(f"Error extracting credentials: {e}")
    
    def search_text(self, query: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search for text in all extracted content"""
        results = []
        
        if not case_sensitive:
            query = query.lower()
        
        for item in self.all_text:
            text = item['text']
            if not case_sensitive:
                text = text.lower()
            
            if query in text:
                # Find all occurrences
                start = 0
                while True:
                    index = text.find(query, start)
                    if index == -1:
                        break
                    
                    # Get context around the match
                    context_start = max(0, index - 50)
                    context_end = min(len(text), index + len(query) + 50)
                    context = text[context_start:context_end]
                    
                    results.append({
                        'packet_num': item['packet_num'],
                        'source': item['source'],
                        'destination': item['destination'],
                        'protocol': item['protocol'],
                        'match_index': index,
                        'context': context,
                        'full_text': item['text']
                    })
                    
                    start = index + 1
        
        return results
    
    def search_regex(self, pattern: str) -> List[Dict[str, Any]]:
        """Search using regex pattern"""
        results = []
        
        try:
            regex = re.compile(pattern)
            
            for item in self.all_text:
                matches = regex.finditer(item['text'])
                for match in matches:
                    results.append({
                        'packet_num': item['packet_num'],
                        'source': item['source'],
                        'destination': item['destination'],
                        'protocol': item['protocol'],
                        'match': match.group(0),
                        'groups': match.groups(),
                        'context': item['text'][max(0, match.start()-50):min(len(item['text']), match.end()+50)]
                    })
        
        except Exception as e:
            logger.error(f"Regex error: {e}")
        
        return results
    
    def find_flags(self, flag_patterns: List[str] = None) -> List[Dict[str, Any]]:
        """Find CTF flags in text"""
        if flag_patterns is None:
            # Default CTF flag patterns
            flag_patterns = [
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'[a-f0-9]{32}',  # MD5 hash
                r'[a-f0-9]{40}',  # SHA1 hash
                r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
            ]
        
        flags = []
        
        for pattern in flag_patterns:
            results = self.search_regex(pattern)
            flags.extend(results)
        
        return flags
    
    def extract_urls(self) -> List[Dict[str, Any]]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return self.search_regex(url_pattern)
    
    def extract_emails(self) -> List[Dict[str, Any]]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return self.search_regex(email_pattern)
    
    def extract_ips(self) -> List[Dict[str, Any]]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return self.search_regex(ip_pattern)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about extracted text"""
        total_chars = sum(len(item['text']) for item in self.all_text)
        
        return {
            'total_text_packets': len(self.all_text),
            'total_payloads': len(self.payloads),
            'unique_strings': len(self.strings),
            'total_characters': total_chars,
            'credentials_found': len(self.credentials),
            'urls_found': len(self.extract_urls()),
            'emails_found': len(self.extract_emails()),
        }
