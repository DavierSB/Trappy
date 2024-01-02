import random
from struct import pack, unpack
import socket
import utils

class Packet:
    def __init__(self):
                
        self.source_ip = '127.0.0.1'
        self.dest_ip = '127.0.0.1'
        
        self.ip_version = 4
        self.ip_ihl = 5
        self.ip_tos = 0
        self.ip_total_len = 40 # 20 bytes por la cabecera ip y 20 bytes por la cabezera tcp
        self.ip_identification = 0 # Ni idea de como llenarlo
        self.ip_flags = 0
        self.ip_frg_off = 0
        self.ip_ttl = 255
        self.ip_protocol = socket.IPPROTO_TCP
        self.ip_checksum = 0
        self.ip_source_host = socket.inet_aton(self.source_ip)
        self.ip_dest_host = socket.inet_aton(self.dest_ip)
        
        self.ip_header = self.build_ip_header()
        
        self.tcp_source_port = 0
        self.tcp_dest_port = 0
        self.tcp_seq_num = random.randint(2**32)
        self.tcp_ack_num = 0        
        self.tcp_offset_res = 5
        # self.tcp_flag_syn = 0
        # self.tcp_flag_ack = 0
        # self.tcp_flag_rst = 0
        # self.tcp_flag_psh = 0
        # self.tcp_flag_urg = 0
        # self.tcp_flag_fin = 0        
        self.tcp_flags = 2        
        self.tcp_window = 2**16
        self.tcp_checksum = 0
        self.tcp_urg_ptr = 0
        
        self.tcp_header = self.build_tcp_header()
        
        self.data = b'\x00\x00'
    
    def get_ip_header(self, ip_header_packet):
        self.ip_header = ip_header_packet
        (
            self.ip_version, 
            self.ip_ihl, 
            self.ip_tos,
            self.ip_total_len,
            self.ip_identification,
            self.ip_flags,
            self.ip_frg_off,
            self.ip_ttl,
            self.ip_protocol,
            self.ip_checksum,
            self.ip_source_host,
            self.ip_dest_host
        ) = unpack('!BBHHHBBH4s4s', self.ip_header)
        
    def get_tcp_header(self, tcp_header_packet):
        self.tcp_header = tcp_header_packet
        (
            self.tcp_source_port,
            self.tcp_dest_port,
            self.tcp_seq_num,
            self.tcp_ack_num,
            self.tcp_offset_res,
            self.tcp_flags,
            self.tcp_window,
            self.tcp_checksum,
            self.tcp_urg_ptr
        ) = unpack('!HHLLBBHHH', self.tcp_header)
    
    def get(self, packet_from_raw):
        self.get_ip_header(packet_from_raw[:20])
        self.get_tcp_header(packet_from_raw[20:40])
        self.data = packet_from_raw[40:]
    
    def build_tcp_header(self):
        tcp_header = pack(
            "!HHLLBBHHH",
            self.tcp_source_port,
            self.tcp_dest_port,
            self.tcp_seq_num,
            self.tcp_ack_num,
            self.tcp_offset_res,
            self.tcp_flags,
            self.tcp_window,
            self.tcp_checksum,
            self.tcp_urg_ptr,
        )
        return tcp_header
    
    def build_ip_header(self):
        ip_header = pack(
            '!BBHHHBBH4s4s',
            self.ip_version >> 4 + self.ip_ihl,
            self.ip_tos,
            self.ip_total_len,
            self.ip_identification,
            self.ip_flags >> 13 + self.ip_frg_off,
            self.ip_ttl,
            self.ip_protocol,
            self.ip_checksum,
            self.ip_source_host,
            self.ip_dest_host
        )
        return ip_header

    def build(self):
        
        self.update(tcp_check=0)
        tcp_header = self.build_tcp_header()
        checksum = utils.make_checksum(tcp_header + self.data)
        self.update(tcp_check=checksum)
        self.tcp_header = self.build_tcp_header()
        
        self.update(ip_checksum=0)
        ip_header = self.build_ip_header()
        checksum = utils.make_checksum(ip_header)
        self.update(ip_checksum=checksum)
        self.ip_header = self.build_ip_header()
        
        return ip_header + tcp_header + self.data

    def update(self, 
        tcp_source_port = None,
        tcp_dest_port = None,
        tcp_seq_num = None,
        tcp_ack_num = None,
        tcp_offset_res = None,        
        tcp_flags = None,
        tcp_window = None,
        tcp_check = None,
        tcp_urg_ptr = None,
        
        source_ip = None,
        dest_ip = None,
        
        ip_version = None,
        ip_ihl = None,
        ip_tos = None,
        ip_total_len = None,
        ip_identification = None,
        ip_flags = None,
        ip_frg_off = None,
        ip_ttl = None,
        ip_protocol = None,
        ip_checksum = None,
        
        data = None
        ):
        
        if (source_ip != None): 
            self.source_ip = source_ip
            self.ip_source_host = socket.inet_aton(self.source_ip)
        if (dest_ip != None): 
            self.dest_ip = dest_ip
            self.ip_dest_host = socket.inet_aton(self.dest_ip)
        if (ip_version != None): self.ip_version = ip_version
        if (ip_ihl != None): self.ip_ihl = ip_ihl
        if (ip_tos != None): self.ip_tos = ip_tos
        if (ip_total_len != None): self.ip_total_len = ip_total_len
        if (ip_identification != None): self.ip_identification = ip_identification
        if (ip_flags != None): self.ip_flags = ip_flags
        if (ip_frg_off != None): self.ip_frg_off = ip_frg_off
        if (ip_ttl != None): self.ip_ttl = ip_ttl
        if (ip_protocol != None): self.ip_protocol = ip_protocol
        if (ip_checksum != None): self.ip_checksum = ip_checksum
        self.ip_header = self.build_ip_header()
        
        if (tcp_source_port != None): self.tcp_source_port = tcp_source_port
        if (tcp_dest_port != None): self.tcp_dest_port = tcp_dest_port
        if (tcp_seq_num != None): self.tcp_seq_num = tcp_seq_num
        if (tcp_ack_num != None): self.tcp_ack_num = tcp_ack_num
        if (tcp_offset_res != None): self.tcp_offset_res = tcp_offset_res
        if (tcp_flags != None): self.tcp_flags = tcp_flags
        if (tcp_window != None): self.tcp_window = tcp_window
        if (tcp_check != None): self.tcp_checksum = tcp_check
        if (tcp_urg_ptr != None): self.tcp_urg_ptr = tcp_urg_ptr
        
        if (data != None): self.data = data
        self.tcp_header = self.build_tcp_header()

    def corrupted(self):
        tcp_checksum = self.tcp_checksum
        ip_checksum = self.ip_checksum
        self.update(ip_checksum=0, tcp_check=0)
        corrupted_tcp_checksum = utils.make_checksum(self.tcp_header + self.data) != tcp_checksum
        corrupted_ip_checksum = utils.make_checksum(self.ip_header) != ip_checksum
        self.tcp_checksum = tcp_checksum
        self.ip_checksum = ip_checksum
        return corrupted_ip_checksum or corrupted_tcp_checksum