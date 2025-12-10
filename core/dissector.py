"""
Packet dissection module
Provides layer-by-layer analysis of network packets
"""
from scapy.all import *
from typing import Dict, List, Any

class PacketDissector:
    """Dissect packets layer by layer"""
    
    @staticmethod
    def dissect_packet(packet) -> Dict[str, Any]:
        """Dissect a packet into layers"""
        layers = []
        layer_dict = {}
        
        # Get all layers
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            
            layer_name = layer.name
            layer_info = PacketDissector._dissect_layer(layer)
            layers.append({
                'name': layer_name,
                'fields': layer_info
            })
            layer_dict[layer_name] = layer_info
            counter += 1
        
        return {
            'layers': layers,
            'layer_dict': layer_dict,
            'summary': packet.summary()
        }
    
    @staticmethod
    def _dissect_layer(layer) -> Dict[str, Any]:
        """Extract fields from a specific layer"""
        fields = {}
        
        # Get all fields in the layer
        for field in layer.fields_desc:
            field_name = field.name
            field_value = layer.getfieldval(field_name)
            
            # Format the value appropriately
            if isinstance(field_value, bytes):
                field_value = field_value.hex()
            elif hasattr(field_value, '__iter__') and not isinstance(field_value, str):
                field_value = str(field_value)
            
            fields[field_name] = field_value
        
        return fields
    
    @staticmethod
    def get_ethernet_info(packet) -> Dict[str, Any]:
        """Extract Ethernet layer information"""
        if not hasattr(packet, 'Ether'):
            return {}
        
        eth = packet['Ether']
        return {
            'src_mac': eth.src,
            'dst_mac': eth.dst,
            'type': eth.type,
            'type_name': eth.sprintf('%Ether.type%')
        }
    
    @staticmethod
    def get_ip_info(packet) -> Dict[str, Any]:
        """Extract IP layer information"""
        if not hasattr(packet, 'IP'):
            return {}
        
        ip = packet['IP']
        return {
            'version': ip.version,
            'ihl': ip.ihl,
            'tos': ip.tos,
            'len': ip.len,
            'id': ip.id,
            'flags': ip.flags,
            'frag': ip.frag,
            'ttl': ip.ttl,
            'proto': ip.proto,
            'proto_name': ip.sprintf('%IP.proto%'),
            'src': ip.src,
            'dst': ip.dst,
            'chksum': ip.chksum
        }
    
    @staticmethod
    def get_tcp_info(packet) -> Dict[str, Any]:
        """Extract TCP layer information"""
        if not hasattr(packet, 'TCP'):
            return {}
        
        tcp = packet['TCP']
        flags = {
            'FIN': bool(tcp.flags & 0x01),
            'SYN': bool(tcp.flags & 0x02),
            'RST': bool(tcp.flags & 0x04),
            'PSH': bool(tcp.flags & 0x08),
            'ACK': bool(tcp.flags & 0x10),
            'URG': bool(tcp.flags & 0x20),
            'ECE': bool(tcp.flags & 0x40),
            'CWR': bool(tcp.flags & 0x80)
        }
        
        return {
            'sport': tcp.sport,
            'dport': tcp.dport,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'dataofs': tcp.dataofs,
            'reserved': tcp.reserved,
            'flags': flags,
            'flags_value': tcp.flags,
            'window': tcp.window,
            'chksum': tcp.chksum,
            'urgptr': tcp.urgptr,
            'options': tcp.options
        }
    
    @staticmethod
    def get_udp_info(packet) -> Dict[str, Any]:
        """Extract UDP layer information"""
        if not hasattr(packet, 'UDP'):
            return {}
        
        udp = packet['UDP']
        return {
            'sport': udp.sport,
            'dport': udp.dport,
            'len': udp.len,
            'chksum': udp.chksum
        }
    
    @staticmethod
    def get_icmp_info(packet) -> Dict[str, Any]:
        """Extract ICMP layer information"""
        if not hasattr(packet, 'ICMP'):
            return {}
        
        icmp = packet['ICMP']
        return {
            'type': icmp.type,
            'code': icmp.code,
            'chksum': icmp.chksum,
            'id': icmp.id if hasattr(icmp, 'id') else None,
            'seq': icmp.seq if hasattr(icmp, 'seq') else None
        }
    
    @staticmethod
    def get_dns_info(packet) -> Dict[str, Any]:
        """Extract DNS layer information"""
        if not hasattr(packet, 'DNS'):
            return {}
        
        dns = packet['DNS']
        queries = []
        answers = []
        
        # Parse queries
        if dns.qd:
            for i in range(dns.qdcount):
                if dns.qd:
                    q = dns.qd if not isinstance(dns.qd, list) else dns.qd[i] if i < len(dns.qd) else None
                    if q:
                        queries.append({
                            'qname': q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                            'qtype': q.qtype,
                            'qclass': q.qclass
                        })
        
        # Parse answers
        if dns.an:
            for i in range(dns.ancount):
                if dns.an:
                    a = dns.an if not isinstance(dns.an, list) else dns.an[i] if i < len(dns.an) else None
                    if a:
                        answers.append({
                            'rrname': a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname),
                            'type': a.type,
                            'rdata': str(a.rdata)
                        })
        
        return {
            'id': dns.id,
            'qr': dns.qr,
            'opcode': dns.opcode,
            'aa': dns.aa,
            'tc': dns.tc,
            'rd': dns.rd,
            'ra': dns.ra,
            'z': dns.z,
            'rcode': dns.rcode,
            'qdcount': dns.qdcount,
            'ancount': dns.ancount,
            'nscount': dns.nscount,
            'arcount': dns.arcount,
            'queries': queries,
            'answers': answers
        }
    
    @staticmethod
    def get_http_info(packet) -> Dict[str, Any]:
        """Extract HTTP layer information"""
        http_info = {}
        
        if hasattr(packet, 'Raw'):
            payload = bytes(packet['Raw']).decode('utf-8', errors='ignore')
            
            # Check if it's HTTP
            if payload.startswith('HTTP/') or any(method in payload[:50] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                lines = payload.split('\r\n')
                
                # Parse first line
                if lines:
                    first_line = lines[0]
                    http_info['first_line'] = first_line
                    
                    # Request or Response
                    if first_line.startswith('HTTP/'):
                        parts = first_line.split(' ', 2)
                        http_info['type'] = 'response'
                        http_info['version'] = parts[0] if len(parts) > 0 else ''
                        http_info['status_code'] = parts[1] if len(parts) > 1 else ''
                        http_info['status_msg'] = parts[2] if len(parts) > 2 else ''
                    else:
                        parts = first_line.split(' ')
                        http_info['type'] = 'request'
                        http_info['method'] = parts[0] if len(parts) > 0 else ''
                        http_info['uri'] = parts[1] if len(parts) > 1 else ''
                        http_info['version'] = parts[2] if len(parts) > 2 else ''
                
                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                    elif line == '':
                        break
                
                http_info['headers'] = headers
        
        return http_info
    
    @staticmethod
    def get_payload(packet) -> Dict[str, Any]:
        """Extract payload information"""
        if not hasattr(packet, 'Raw'):
            return {}
        
        raw_data = bytes(packet['Raw'])
        
        return {
            'length': len(raw_data),
            'hex': raw_data.hex(),
            'ascii': raw_data.decode('utf-8', errors='ignore'),
            'raw': raw_data
        }
