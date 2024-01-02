from struct import pack, unpack
import socket

def parse_address(address):
    host, port = address.split(':')

    if host == '':
        host = 'localhost'

    return host, int(port)

def make_checksum(data):
    words = [data[i:i+2] for i in range(0, len(data), 2)]
    checksum = 0
    for word in words:
        value = int.from_bytes(word, 'big')
        checksum += value
    return ~checksum&0xffff

def get_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0)) 
    port = sock.getsockname()[1]
    sock.close()
    return port

def fragment_data(data: bytes, max_data_size: int):
    fragmented_data = []
    fd_size = 0
    while fd_size < len(data):
        next_position = min(fd_size + max_data_size, len(data))
        fragmented_data.append(data[fd_size:next_position])
        fd_size = next_position
    return fragmented_data

def trim(buffer, length):
    return fragment_data(buffer,length)[0] 
