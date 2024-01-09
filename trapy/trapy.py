from conn import Conn
from tcp import *
from utils import *

def listen(address: str) -> Conn:
    host, port = parse_address(address)
    conn = Conn()
    conn.bind(host, port)
    return conn

def accept(conn) -> Conn:
    receive_sync(conn)
    finish_handshake(conn)
    return conn

def dial(address) -> Conn:
    host, port = parse_address(address)
    conn = Conn()
    conn.bind() #Lo ubico en un puerto libre
    conn.set_destination(host, port)
    send_sync(conn)
    send_confirmation(conn)
    return conn

def send(conn: Conn, data: bytes) -> int:
    if conn.isClosed:
        raise ConnException("La conexion esta cerrada")
    chunks = create_data_queue(data, MAX_DATA_SIZE)
    window = our_queue.queue()
    sent_data = 0
    last_received = conn.seq_num #last_received by the destination
    print("BEGGINING TRANSMISSION")
    while(not(chunks.empty()) or not(window.empty())):
        fill_window(conn, window, chunks)
        ack_packet = wait_packet_with_condition(conn, has_ack_flag, MAXIMUM_WAIT_BEFORE_RESEND)
        while (last_received < ack_packet.tcp_ack_num):
            sent_data = sent_data + len(window.pop()[0])
            last_received = last_received + 1
        if is_fin(conn, ack_packet):
            print("FIN ORDER RECEIVED")
            break
        resend_timeout_packages(conn, window)
    send_confirmation(conn, "FIN") #El segundo parametro es pijeria para imprimir lindo
    return sent_data

#Notemos que si deja de recibir un paquete, ahi mismo no procesa los siguientes, para preservar el orden
def recv(conn: Conn, length: int) -> bytes:
    if conn.isClosed:
        raise ConnException("La conexion esta cerrada")
    buffer = b''
    timer = Chronometer()
    keep_going = True
    packet = None
    while keep_going:
        timer.start(MAXIMUM_WAIT_BEFORE_ACK)
        for i in range(0, N_CHUNKS_PER_ACK):
            if ((i > 0) or (packet == None)):
                packet = wait_packet_with_condition(conn, is_expected_data, timer.time_left())
            if packet is not None:
                buffer = buffer + packet.data
                if (is_fin(conn, packet) or (len(buffer) > length)):
                    if(len(buffer) > length):
                        print("RECQUIRED AMOUNT OF DATA HAS BEEN READ")
                    else:
                        print("LAST PACKET OF SENDER RECEIVED, WITHOUT COMPLETE RECQUIRED AMOUNT OF DATA")
                    keep_going = False
                    break
            break #Caso en el q se agoto el timer
        packet = next_data(conn, not(keep_going))
        if not keep_going:
            print("FIN CONFIRMATION RECEIVED")
    return trim(buffer, length)

def close(conn: Conn):
    conn.close()
    print("CONNECTION CLOSED")