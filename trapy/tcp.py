from conn import *
from aux_flags_functions import *
from utils import fragment_data
import our_queue

#Parametros
MAX_DATA_SIZE = 512
N_CHUNKS_PER_ACK = 2
N_CHUNKS_PER_WINDOW = 4
MAXIMUM_WAIT_BEFORE_ACK = 1
MAXIMUM_WAIT_BEFORE_RESEND = 1

#Handshaking
def receive_sync(conn : Conn):
    print("WAITING SYNC")
    sync_packet = wait_packet_with_condition(conn, is_sync, 30, unknwn_source = True)#espero medio minuto
    if sync_packet is None:
        raise ConnException("Nunca llego el SYNC")
    conn.seq_num = randint(1, 1000)
    conn.set_destination(sync_packet.source_ip, sync_packet.tcp_source_port)
    print("RECEIVED SYNC")

def finish_handshake(conn: Conn):
    sync_ack_packet = create_packet_for_send(conn, sync= True, ack= True)
    send_till_its_received(conn, sync_ack_packet, is_ack)
    print("FINISHED HANDSHAKE")

def send_sync(conn : Conn):
    conn.seq_num = randint(1, 1000)
    sync_packet = create_packet_for_send(conn, sync= True)
    print("SYNC SENDED")
    ack_packet = send_till_its_received(conn, sync_packet, is_sync_ack, 30)#Espero medio minuto
    print("SYNC RECEIVED")
    if ack_packet is None:
        raise ConnException("Nunca llego el SYNC_ACK")

def send_confirmation(conn : Conn, type_of_confirmation = "SYNC"):
    conf_packet = create_packet_for_send(conn, ack= True)
    print(type_of_confirmation + " CONFIRMATION SENDED")
    send_many_times(conn, conf_packet)
    conn.seq_num = conn.seq_num + 1 #No recibiremos un ACK a la confirmacion, pero debemos actuar como si lo hubieramos recibido
    conn.ack_num = conn.ack_num + 1 #No recibiremos un ACK a la confirmacion, pero debemos actuar como si lo hubieramos recibido


#Transmission
def create_data_queue(data : bytes, max_data_size):
    chunks = fragment_data(data, max_data_size)
    cola = our_queue.queue()
    for chunk in chunks:
        cola.push(chunk)
    return cola

def fill_window(conn : Conn, window : our_queue.queue, chunks : our_queue.queue):
    if chunks.empty():
        return
    while (window.size() < N_CHUNKS_PER_WINDOW) and not(chunks.empty()):
        packet = create_packet_for_send(conn, chunks.peek(), (chunks.size() == 1))
        data = packet.build()
        chunks.pop()
        if(chunks.size() == 1):
            print("LAST PACKET SENT")
        conn.send(data)
        conn.seq_num = conn.seq_num + 1
        timer = Chronometer()
        timer.start(MAXIMUM_WAIT_BEFORE_RESEND)
        window.push((data, timer))

#Esta funcion manda el ack correspondiente y espera al sgte fragmento de data
def next_data(conn : Conn, fin_was_received):
    ack_packet = create_packet(conn)
    if fin_was_received:
        ack_packet.tcp_flags = 17 #ACK + FIN
    else:
        ack_packet.tcp_flags = 16 #ACK
    return send_till_its_received(conn, ack_packet, is_expected_data)

def resend_timeout_packages(conn : Conn, window : our_queue.queue):
    for i in range(0, min(N_CHUNKS_PER_WINDOW, window.size())):
        tuple = window.peek(i)
        if tuple[1].timeout():
            conn.send(tuple[0])
            timer = Chronometer()
            window.edit(i, (tuple[0], timer.start(MAXIMUM_WAIT_BEFORE_RESEND)))


#Global Utils
def send_till_its_received(conn : Conn, packet : Packet, cond = always, timeout = None):
    data = packet.build()
    timer = None
    idx = 0
    if timeout is not None:
        timer = Chronometer()
        timer.start(timeout)
    while True:
        if timeout is None:
            idx = idx + 1
        if ((idx == 10) or ((timeout is not None) and timer.timeout())):
            break
        conn.send(data)
        ack_packet = wait_packet_with_condition(conn, cond)
        if ack_packet is not None:
            return ack_packet
    raise ConnException("Paquete nunca fue recibido")

def send_many_times(conn : Conn, packet : Packet):
    data = packet.build()
    for i in range(0, 20):
        conn.send(data)

def wait_packet_with_condition(conn : Conn, cond = always, timeout = 5, unknwn_source = False): #Q tiempo ponemos default el timeout?
    timer = Chronometer()
    timer.start(timeout)
    while True:
        packet = conn.recv(unknwn_source= unknwn_source)[0]
        if (packet is None) or not(cond(conn, packet)):
            if timer.timeout():
                return None
            continue
        conn.ack_num = packet.tcp_seq_num + 1 #Decidimos no sumar la longitud del paquete, sino siempre sumar 1
        conn.seq_num = packet.tcp_ack_num
        return packet

def create_packet_for_send(conn : Conn, data = b'', fin = False, sync = False, ack = False):
    packet = create_packet(conn)
    packet.data = data
    packet.tcp_flags = 0
    if fin:
        packet.tcp_flags = packet.tcp_flags + 1
    if sync:
        packet.tcp_flags = packet.tcp_flags + 2
    if ack:
        packet.tcp_flags = packet.tcp_flags + 16
    return packet

def create_packet(conn : Conn):
    packet = Packet()
    packet.update(
        dest_ip= conn.dest_host,
        source_ip= conn.source_host,
        tcp_dest_port= conn.dest_port,
        tcp_source_port = conn.source_port,
        tcp_seq_num= conn.seq_num,
        tcp_ack_num= conn.ack_num,
    )
    return packet