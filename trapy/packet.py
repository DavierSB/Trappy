from struct import pack, unpack
import socket
import utils

class Packet:
    def __init__(self):
        self.tcp_source_port = None
        self.tcp_dest_port = None
        self.tcp_seq_num = None
        self.tcp_ack_num = None
        
        self.tcp_offset_res = 80
        
        # self.tcp_flag_syn = 0
        # self.tcp_flag_ack = 0
        # self.tcp_flag_rst = 0
        # self.tcp_flag_psh = 0
        # self.tcp_flag_urg = 0
        # self.tcp_flag_fin = 0
        
        # self._tcp_flags = 0
        
        self.tcp_flags = 0
        
        self.tcp_window = 28944
        self.tcp_check = None
        self.tcp_urg_ptr = 0
        
        self._ip_check = None
        self.ip_source_host = None
        self.ip_dest_host = None
        
        #el header checksum ni idea de como hacerlo
        self._ip_header = [60, 0, 40, 43981, 0, 64, 6] 
        
        self.data = b'\x00\x00'
    
    def get(self, packet_from_raw):
        self.ip_header = unpack("!BBHHHBBH4s4s", packet_from_raw[0:20]) 
        
        self._ip_check = self._ip_header[7]
        self.source_host = self.ip_header[8]
        self.dest_host = self.ip_header[9]
        
        self.tcp_source_port, self.tcp_dest_port, self.tcp_seq_num, self.tcp_ack_num, self.tcp_offset_res, self.tcp_flags, self.tcp_window, self.tcp_check, self.tcp_urg_ptr, = unpack("!HHLLBBHHH", packet_from_raw[20:40])
        
        self.data = packet_from_raw[40:]
    
    def _refresh(self):
        if (len(self._ip_header)==10):
            self._ip_header[8] = socket.inet_aton(self.ip_source_host)
            self._ip_header[9] = socket.inet_aton(self.ip_dest_host)

        # self._tcp_flags = (
        #     self.tcp_fin
        #     + (self.tcp_syn << 1)
        #     + (self.tcp_rst << 2)
        #     + (self.tcp_psh << 3)
        #     + (self.tcp_ack << 4)
        #     + (self.tcp_urg << 5)
        # )
    
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
            self.tcp_check,
            self.tcp_urg_ptr,
        )
        return tcp_header
    
    def build_ip_header(self):
        ip_header = pack(
            "!BBHHHBBH4s4s", 
            self._ip_header[0],
            self._ip_header[1],
            self._ip_header[2],
            self._ip_header[3],
            self._ip_header[4],
            self._ip_header[5],
            self._ip_header[6],
            self._ip_check,
            self.ip_source_host.encode(),
            self.ip_dest_host.encode(),
        )
        return ip_header

    def build(self):
        self._refresh()
        
        self.update(tcp_check=0)
        tcp_header = self.build_tcp_header()
        checksum = utils.make_checksum(tcp_header + self.data)
        self.update(tcp_check=checksum)
        tcp_header = self.build_tcp_header()
        
        self.update(_ip_check=0)
        ip_header = self.build_ip_header()
        checksum = utils.make_checksum(ip_header)
        self.update(_ip_check=checksum)
        ip_header = self.build_ip_header()
        
        return ip_header + tcp_header + self.data

    def update(self, 
        tcp_source_port = None,
        tcp_dest_port = None,
        tcp_seq_num = None,
        tcp_ack_num = None,
        tcp_offset_res = None,        
        tcp_flags = 0,
        tcp_window = None,
        tcp_check = None,
        tcp_urg_ptr = None,
        
        _ip_check = None,
        ip_source_host = None,
        ip_dest_host = None,

        data = None
        ):
        if (tcp_source_port != None): self.tcp_source_port = tcp_source_port
        if (tcp_dest_port != None): self.tcp_dest_port = tcp_dest_port
        if (tcp_seq_num != None): self.tcp_seq_num = tcp_seq_num
        if (tcp_ack_num != None): self.tcp_ack_num = tcp_ack_num
        if (tcp_offset_res != None): self.tcp_offset_res = tcp_offset_res
        if (tcp_flags != 0): self.tcp_flags = tcp_flags
        if (tcp_window != None): self.tcp_window = tcp_window
        if (tcp_check != None): self.tcp_check = tcp_check
        if (tcp_urg_ptr != None): self.tcp_urg_ptr = tcp_urg_ptr
        
        if (_ip_check != None): self._ip_check = _ip_check
        if (ip_source_host != None): self.ip_source_host = ip_source_host
        if (ip_dest_host != None): self.ip_dest_host = ip_dest_host
        
        if (data != None): self.data = data

    def corrupted(self):
        checksum = self.tcp_check
        self.update(tcp_check=0)
        tcp_header = self.build_tcp_header()
        self.tcp_check = utils.make_checksum(tcp_header)
        if (self.tcp_check == checksum): return True
        else:
            self.tcp_check = checksum
            return False