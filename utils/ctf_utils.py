"""
CTF Utilities Module
Provides encoding/decoding and analysis utilities for CTF challenges
"""
import base64
import binascii
import string
import math
import urllib.parse
from typing import List, Dict, Any, Optional


class CTFUtils:
    """Utility functions for CTF challenge analysis"""
    
    @staticmethod
    def decode_base64(data: str) -> Optional[str]:
        """Decode base64 string"""
        try:
            # Remove whitespace and newlines
            data = data.replace(' ', '').replace('\n', '').replace('\r', '')
            decoded = base64.b64decode(data)
            # Try to decode as UTF-8
            return decoded.decode('utf-8', errors='replace')
        except Exception:
            return None
    
    @staticmethod
    def encode_base64(data: str) -> str:
        """Encode string to base64"""
        try:
            return base64.b64encode(data.encode('utf-8')).decode('utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def decode_hex(data: str) -> Optional[str]:
        """Decode hexadecimal string"""
        try:
            # Remove common separators
            data = data.replace(' ', '').replace(':', '').replace('-', '')
            decoded = bytes.fromhex(data)
            return decoded.decode('utf-8', errors='replace')
        except Exception:
            return None
    
    @staticmethod
    def encode_hex(data: str) -> str:
        """Encode string to hexadecimal"""
        try:
            return data.encode('utf-8').hex()
        except Exception:
            return ""
    
    @staticmethod
    def decode_url(data: str) -> str:
        """Decode URL-encoded string"""
        try:
            return urllib.parse.unquote(data)
        except Exception:
            return data
    
    @staticmethod
    def encode_url(data: str) -> str:
        """Encode string to URL encoding"""
        try:
            return urllib.parse.quote(data)
        except Exception:
            return data
    
    @staticmethod
    def rot13(data: str) -> str:
        """Apply ROT13 cipher"""
        return data.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))
    
    @staticmethod
    def caesar_cipher(data: str, shift: int) -> str:
        """Apply Caesar cipher with given shift"""
        result = []
        for char in data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def xor_decrypt(data: bytes, key: bytes) -> bytes:
        """XOR decrypt data with key"""
        if not key:
            return data
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)
    
    @staticmethod
    def xor_single_byte(data: bytes) -> List[Dict[str, Any]]:
        """Try all single-byte XOR keys and return results"""
        results = []
        for key in range(256):
            decrypted = bytes([b ^ key for b in data])
            try:
                text = decrypted.decode('utf-8', errors='ignore')
                # Check if result contains mostly printable characters
                if len(text) > 0:
                    printable_ratio = sum(c in string.printable for c in text) / len(text)
                    if printable_ratio > 0.8:  # At least 80% printable
                        results.append({
                            'key': key,
                            'key_char': chr(key) if 32 <= key < 127 else f'\\x{key:02x}',
                            'result': text,
                            'printable_ratio': printable_ratio
                        })
            except Exception:
                pass
        
        # Sort by printable ratio
        results.sort(key=lambda x: x['printable_ratio'], reverse=True)
        return results
    
    @staticmethod
    def find_repeating_xor_key(data: bytes, key_length: int) -> bytes:
        """Try to find repeating XOR key of given length"""
        # This is a simplified implementation
        # Real cryptanalysis would use frequency analysis
        key = bytearray()
        for i in range(key_length):
            bytes_at_position = data[i::key_length]
            # Try all possible bytes and pick the one that gives most printable chars
            best_byte = 0
            best_score = 0
            for b in range(256):
                decrypted = bytes([byte ^ b for byte in bytes_at_position])
                try:
                    text = decrypted.decode('utf-8', errors='ignore')
                    score = sum(c in string.printable for c in text)
                    if score > best_score:
                        best_score = score
                        best_byte = b
                except Exception:
                    pass
            key.append(best_byte)
        return bytes(key)
    
    @staticmethod
    def analyze_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequencies.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def detect_encoding(data: str) -> List[str]:
        """Detect possible encodings of data"""
        encodings = []
        
        # Check for base64
        try:
            cleaned = data.replace(' ', '').replace('\n', '')
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in cleaned):
                if base64.b64decode(cleaned):
                    encodings.append('base64')
        except Exception:
            pass
        
        # Check for hex
        try:
            cleaned = data.replace(' ', '').replace(':', '').replace('-', '')
            if all(c in '0123456789abcdefABCDEF' for c in cleaned):
                bytes.fromhex(cleaned)
                encodings.append('hex')
        except Exception:
            pass
        
        # Check for URL encoding
        if '%' in data:
            encodings.append('url')
        
        return encodings
    
    @staticmethod
    def extract_printable_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data"""
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        # Don't forget last string
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    @staticmethod
    def smart_decode(data: str) -> Dict[str, Any]:
        """Try multiple decoding methods and return all successful results"""
        results = {}
        
        # Try base64
        b64_result = CTFUtils.decode_base64(data)
        if b64_result and b64_result != data:
            results['base64'] = b64_result
        
        # Try hex
        hex_result = CTFUtils.decode_hex(data)
        if hex_result and hex_result != data:
            results['hex'] = hex_result
        
        # Try URL decode
        url_result = CTFUtils.decode_url(data)
        if url_result != data:
            results['url'] = url_result
        
        # Try ROT13
        rot13_result = CTFUtils.rot13(data)
        if rot13_result != data:
            results['rot13'] = rot13_result
        
        # Try various Caesar shifts
        for shift in [1, 3, 13, 25]:
            caesar_result = CTFUtils.caesar_cipher(data, shift)
            if caesar_result != data:
                results[f'caesar_{shift}'] = caesar_result
        
        return results
    
    @staticmethod
    def analyze_http_traffic(packets: List) -> Dict[str, Any]:
        """Analyze HTTP traffic for interesting patterns"""
        from scapy.all import Raw, TCP
        
        http_requests = []
        http_responses = []
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
                
                # HTTP Request
                if any(method in payload[:20] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                    http_requests.append({
                        'payload': payload,
                        'packet': pkt
                    })
                
                # HTTP Response
                elif payload.startswith('HTTP/'):
                    http_responses.append({
                        'payload': payload,
                        'packet': pkt
                    })
        
        return {
            'requests': http_requests,
            'responses': http_responses,
            'total_requests': len(http_requests),
            'total_responses': len(http_responses)
        }
    
    @staticmethod
    def reconstruct_tcp_stream(packets: List, src_ip: str, src_port: int, 
                                dst_ip: str, dst_port: int) -> bytes:
        """Reconstruct TCP stream between two endpoints"""
        from scapy.all import IP, TCP, Raw
        
        stream_data = bytearray()
        
        for pkt in packets:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            
            # Check if packet belongs to this stream
            if ((pkt[IP].src == src_ip and pkt[TCP].sport == src_port and
                 pkt[IP].dst == dst_ip and pkt[TCP].dport == dst_port) or
                (pkt[IP].src == dst_ip and pkt[TCP].sport == dst_port and
                 pkt[IP].dst == src_ip and pkt[TCP].dport == src_port)):
                
                stream_data.extend(bytes(pkt[Raw]))
        
        return bytes(stream_data)
