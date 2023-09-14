#!/usr/bin/python3.10

import sys
import socket
import struct
import threading
import random
import time
from datetime import datetime
from datetime import timedelta
import os
import signal
from time import sleep

# Constants
REGISTER_REQ = 0x00
REGISTER_ACK = 0x02
REGISTER_NACK = 0x04
REGISTER_REJ = 0x06
ERROR = 0x0F
ALIVE_INF = 0x10
ALIVE_ACK = 0x12
ALIVE_NACK = 0x14
ALIVE_REJ = 0x16

DISCONNECTED = 0xA0
WAIT_DB_CHECK = 0xA4
REGISTERED = 0xA6
SEND_ALIVE = 0xA8

SEND_FILE = 0x20
SEND_DATA = 0x22
SEND_ACK = 0x24
SEND_REJ = 0x28
SEND_END = 0x2A

GET_FILE = 0x30
GET_DATA = 0x32
GET_ACK = 0x34
GET_REJ = 0x38
GET_END = 0x3A

TCP_BYTES_LENGTH = 178

# TCP configuration
MAX_TCP_TIME = 3              # w
MAX_ALIVES_NOT_RECEIVED = 3   # s
MAX_NOT_RECEIVED_WHILE_RG = 2 # j
TIME_BETWEEN_ALIVES = 2       # r


# define SEND_FILE (unsigned char) 0x20
# define SEND_DATA (unsigned char) 0x22
# define SEND_ACK (unsigned char) 0x24
# define SEND_END (unsigned char) 0x2A

# define GET_FILE (unsigned char) 0x30
# define GET_DATA (unsigned char) 0x32
# define GET_ACK (unsigned char) 0x34
# define GET_END (unsigned char) 0x3A

# Global variables
conf_file = "server.cfg"
authorized_clients = "equips.dat"
debug = False
file_d = None
udp_socket = None
tcp_socket = None
clients = []

class File_data():
    def __init__(self):
        self.id = None
        self.mac = None
        self.udp_port = None
        self.tcp_port = None
    
    def __str__(self):
        return f"Id: {self.id}\nMac: {self.mac}\nUdp port: {self.udp_port}\nTcp port: {self.tcp_port}"

class Package():
    def __init__(self):
        self.type = None
        self.id = None
        self.mac = None
        self.rand_num = None
        self.data = None
    
    def __str__(self):
        return f"Type: {self.type}\nId: {self.id}\nMac: {self.mac}\nRand_num: {self.rand_num}\nData: {self.data}"

class Client():
    def __init__(self):
        self.id = None
        self.ip = None
        self.mac = None
        self.rand_num = None
        self.state = None
        self.tcp_socket = None
        self.tcp_data_received = False
        self.tcp_end_received = False
        self.timeout_exceeded = False
        self.alive_received = False
    
    def __str__(self):
        return (f"Id: {self.id}\nIp: {self.ip}\nMac: {self.mac}\nRand_num: {self.rand_num}\nState: {self.state}\nTcp socket: {self.tcp_socket}\n" + 
            f"Tcp data received: {self.tcp_data_received}\nTcp end received: {self.tcp_end_received}\nTimeout exceeded: {self.timeout_exceeded}" +
            f"Alive received: {self.alive_received}")

def string_of(state):
    if state == DISCONNECTED:
        return "DISCONNECTED"
    elif state == WAIT_DB_CHECK:
        return "WAIT_DB_CHECK"
    elif state == REGISTERED:
        return "REGISTERED"
    elif state == SEND_ALIVE:
        return "SEND_ALIVE"
    else:
        return "UNKNOWN"

def change_state(client, state):
    client.state = state
    print_message(f"Client {client.id} change to state {string_of(state)}")

def print_message(message):
    current_time = time.strftime("[%T]", time.localtime(time.time()))
    print(f"{str(current_time)}:  =>  {message}")

def error_message(message, finalize_program = True):
    print_message(f"ERROR: {message}")
    if finalize_program:
        exit(1)

def debug_message(message):
    print_message(f"DEBUG: {message}")

def print_accepted_clients():
    print("\nACCEPTED CLIENTS TABLE:")
    print("NAME\t|MAC\t\t|STATE\t\t|IP\t\t|RANDOM NUMBER")
    print("--------|---------------|---------------|---------------|-------------")

    for client in clients:
        init = f"{client.id}\t|{client.mac}\t|{string_of(client.state)}\t|"
        if client.state == DISCONNECTED:
            print(init + "---------------|-------------")
        else:
            print(init + f"{client.ip}\t|{client.rand_num}")

def manage_command_line():
    try:
        while True:
            command = sys.stdin.readline().split('\n')[0]
            if command == "quit":
                os.kill(os.getpid(), signal.SIGINT)
            elif command == "list":
                print_accepted_clients()
            else:
                print_message("Incorrect command. The valid commands are:\n" +
                              "\t\t- list\n" +
                              "\t\t- quit\n")
    except:
        return

def write_send_data(client, file):
    while not client.timeut_exceeded:
        pck = receive_tcp_package(client.tcp_socket)

def send_tcp_package(send_pck, sock):
    sock.sendall(send_pck)

    pck = struct.unpack(f'B7s13s7s150s', send_pck)

    if debug:
        debug_message("Package sent:\n" +
                      f"\t\t\tType: {pck[0]}\n" +
                      f"\t\t\tId: " + str({pck[1].decode('utf-8').split("\x00")[0]}) + "\n" +
                      f"\t\t\tMac: " + str({pck[2].decode('utf-8').split("\x00")[0]}) + "\n" +
                      f"\t\t\tRandom number: " + str({pck[3].decode('utf-8').split("\x00")[0]}) + "\n"  +
                      f"\t\t\tData: " + str({pck[4].decode('utf-8').split("\x00")[0]}) + "\n") 


def control_send_time(client):
    max_time = datetime.now() + timedelta(seconds=MAX_TCP_TIME)
    while datetime.now() < max_time and not client.tcp_end_received:
        if client.tcp_data_received:
            max_time = datetime.now() + timedelta(seconds=MAX_TCP_TIME)
            client.tcp_data_received = False
        if client.tcp_end_received:
            exit(0)
    if not client.tcp_end_received:
        print_message(f"Package not received in {MAX_TCP_TIME} seconds")
        client.timeout_exceeded = True
    return

def validate_client(client, pck, sock, ip):
    if client.mac != pck.mac:
        # Case not allowed client
        error_message(f"Send file rejected,\n\t\t\tId: {pck.id}\n\t\t\tMac: {pck.mac}\n\t\t\tNot allowed", False)
        if client != None:
            change_state(client, DISCONNECTED)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, "The id and mac received are not allowed")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False
    if client.state == DISCONNECTED:
        # Case disconnected client
        error_message(f"Send file rejected, client is disconnected", False)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, "The id and mac received are not allowed")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False
    if client.rand_num != pck.rand_num or client.ip != ip:
        # Case random number or ip incorrect
        if client.rand_num != pck.rand_num:
            problem = "random number"
        else:
            problem = "ip"
        error_message(f"Send file rejected, client's {problem} is incorrect", False)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, f"The {problem} received is not correct")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False

    tokens = pck.data.split(",")

    if client.tcp_socket != None:
        # This client is already doing a configuration file operation
        error_message(f"The client {client.id} is already doing a configuration file operation", False)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, f"There already exist a configuration file operation")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False

    if len(tokens) != 2:
        # Data field is incorrect
        error_message(f"Received data field is not correct", False)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, f"Data field incorrect")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False

    tokens = pck.data.split(",")

    if client.tcp_socket != None:
        # This client is already doing a configuration file operation
        error_message(f"The client {client.id} is already doing a configuration file operation", False)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, f"There already exist a configuration file operation")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False

    if len(tokens) != 2:
        # Data field is incorrect
        error_message(f"Received data field is not correct", False)
        rej_pck = build_regular_package_tcp(SEND_REJ, client, f"Data field incorrect")
        send_tcp_package(rej_pck, sock)
        sleep(MAX_TCP_TIME)
        sock.close()
        return False
    return True

def serve_get_file(pck, sock, ip):
    client = get_client(pck.id)
    if client == None:
        return
    lock = threading.Lock()
    lock.acquire()

    # Validate client
    if not validate_client(client, pck, sock, ip):
        lock.release()
        return

    # All correct
    client.tcp_socket = sock
    print_message(f"get-cfg command with the client {client.id} accepted")
    file = f"{client.id}.cfg"
    ack_pck = build_regular_package_tcp(GET_ACK, client, file)
    send_tcp_package(ack_pck, client.tcp_socket)
    file = open(file, "r")

    thread = threading.Thread(target=control_send_time, args=(client,))
    thread.daemon = True
    thread.start()

    lines = file.readlines()

    # Send GET_DATA
    for line in lines:
        pck = build_regular_package_tcp(GET_DATA, client, line)
        if client.timeout_exceeded:
            break
        send_tcp_package(pck, client.tcp_socket)
        client.tcp_data_received = True
    
    # Send GET_END
    pck = build_regular_package_tcp(GET_END, client, "")
    if not client.timeout_exceeded:
        send_tcp_package(pck, client.tcp_socket)
        print_message("File successfully sent")
        client.tcp_end_received = True
        client.tcp_data_received = False
        sock.close()
        client.tcp_socket = None

def serve_send_file(pck, sock, ip):
    client = get_client(pck.id)
    if client == None:
        return
    lock = threading.Lock()
    lock.acquire()

    # Validate client
    if not validate_client(client, pck, sock, ip):
        lock.release()
        return

    # All correct
    client.tcp_socket = sock
    print_message(f"send-cfg command with the client {client.id} accepted")
    file = f"{client.id}.cfg"
    ack_pck = build_regular_package_tcp(SEND_ACK, client, file)
    send_tcp_package(ack_pck, client.tcp_socket)
    file = open(file, "w")

    thread = threading.Thread(target=control_send_time, args=(client,))
    thread.daemon = True
    thread.start()

    while not client.timeout_exceeded:
        pck = receive_tcp_package(client.tcp_socket)

        if client.timeout_exceeded:
            lock.release()
            rej_pck = build_regular_package_tcp(SEND_REJ, client, f"Data field incorrect")
            send_tcp_package(rej_pck, sock)
            sock.close()
            return
        
        if pck.type == SEND_END:
            print_message("File successfully received")
            client.tcp_end_received = True
            client.tcp_data_received = False
            sock.close()
            client.tcp_socket = None
            break
        elif pck.type == SEND_DATA:
            client.tcp_data_received = True
            file.write(pck.data)
        else:
            error_message(f"TYPE: {hex(pck.type)}")
            error_message("Incorrect package type received", False)

def treat_tcp_connection(pck, sock, ip):
    type = pck.type

    if type == SEND_FILE:
        serve_send_file(pck, sock, ip)
    elif type == GET_FILE:
        serve_get_file(pck, sock, ip)

def receive_tcp_package(sock):
    pck = Package()
    recv_pck = sock.recv(TCP_BYTES_LENGTH)

    recv_pck = struct.unpack('B7s13s7s150s', recv_pck)

    pck.type = recv_pck[0]
    pck.id = recv_pck[1].split(b"\x00")[0].decode()
    pck.mac = recv_pck[2].split(b"\x00")[0].decode()
    pck.rand_num = recv_pck[3].split(b"\x00")[0].decode()
    pck.data = recv_pck[4].split(b"\x00")[0].decode()

    if debug:
        debug_message(f"{str(pck)}\n")
    
    return pck

def tcp_loop():
    while True:
        sock, (ip, port) = tcp_socket.accept() 
        pck = receive_tcp_package(sock)

        # Create thread to serve tcp connection
        thread = threading.Thread(target=treat_tcp_connection, args=(pck, sock, ip))
        thread.daemon = True
        thread.start()

def build_regular_package_tcp(type, client, data):
    pck = struct.pack("B7s13s7s150s", type, file_d.id.encode(), file_d.mac.encode(), client.rand_num.encode(), data.encode())
    return pck

def build_regular_package(type, client, data):
    pck = struct.pack("B7s13s7s50s", type, file_d.id.encode(), file_d.mac.encode(), client.rand_num.encode(), data.encode())
    return pck

def build_reg_ack_package(data):
    rand_num = str(random.randint(1,999999))
    while len(rand_num) < 6:
        rand_num = "0" + rand_num
    pck = struct.pack("B7s13s7s50s", REGISTER_ACK, file_d.id.encode(), file_d.mac.encode(), rand_num.encode(), data.encode())
    return pck, rand_num

def build_void_package(type, data):
    pck = struct.pack("B7s13s7s50s", type, b"", b"000000000000", b"000000", data.encode())
    return pck

def build_client(id, ip, rand_num, state):
    client = get_client(id)
    client.ip = ip
    client.rand_num = rand_num
    client.state = state

def new_client(id, mac):
    client = Client()
    client.id = id
    client.mac = mac
    client.state = DISCONNECTED
    return client

def get_client(id):
    for client in clients:
        if client.id == id:
            return client
    return None

def check_random_number_in_reg(client, pck):
    if client.state is not WAIT_DB_CHECK:
        return client.rand_num == pck.rand_num
    else:
        return pck.rand_num == "000000"

def control_alive_time_while_registered(client):
    max_time = datetime.now() + timedelta(seconds = MAX_ALIVES_NOT_RECEIVED * TIME_BETWEEN_ALIVES)
    while(client.state == SEND_ALIVE):
        if client.alive_received:
            max_time = datetime.now() + timedelta(seconds = MAX_ALIVES_NOT_RECEIVED * TIME_BETWEEN_ALIVES)
            client.alive_received = False
        elif datetime.now() > max_time:
            change_state(client, DISCONNECTED)

def control_registered_alive_time(client):
    max_time = datetime.now() + timedelta(seconds = MAX_NOT_RECEIVED_WHILE_RG * TIME_BETWEEN_ALIVES)
    while(client.state == REGISTERED):
        if client.alive_received:
            max_time = datetime.now() + timedelta(seconds = MAX_NOT_RECEIVED_WHILE_RG * TIME_BETWEEN_ALIVES)
        elif datetime.now() > max_time:
            change_state(client, DISCONNECTED)

def control_alive_time(client):
    max_time = datetime.now() + timedelta(seconds = MAX_ALIVES_NOT_RECEIVED * TIME_BETWEEN_ALIVES)
    while(client.state == SEND_ALIVE):
        if client.alive_received:
            max_time = datetime.now() + timedelta(seconds = MAX_ALIVES_NOT_RECEIVED * TIME_BETWEEN_ALIVES)
            client.alive_received = False
        elif datetime.now() > max_time:
            change_state(client, DISCONNECTED)

def treat_udp_package(pck, client_ip, udp_port):
    if pck.type == REGISTER_REQ:
        client = get_client(pck.id)
        if client != None and client.state == DISCONNECTED:
            change_state(client, WAIT_DB_CHECK)
        if client == None or client.mac != pck.mac:
            # Not authorized client
            pck = build_void_package(REGISTER_REJ, "The id and mac received are not allowed")
            udp_socket.sendto(pck, (client_ip, udp_port))
        elif not check_random_number_in_reg(client, pck):
            # Random number incorrect
            pck = build_void_package(REGISTER_NACK, "The random number received is not correct")
            udp_socket.sendto(pck, (client_ip, udp_port))
        elif (client.state == REGISTERED or client.state == SEND_ALIVE) and (pck.mac != client.mac or client_ip != client.ip):
            # Client data incrrect
            pck = build_void_package(REGISTER_NACK, "The data of the client is incorrect")
            udp_socket.sendto(pck, (client_ip, udp_port))
        else:
            # All correct
            send_pck, rand_num = build_reg_ack_package(file_d.tcp_port)
            build_client(pck.id, client_ip, rand_num, client.state)
            udp_socket.sendto(send_pck, (client_ip, udp_port))
            if client.state != REGISTERED:
                change_state(client, REGISTERED)
            thread = threading.Thread(target = control_registered_alive_time, args=(client,))
            thread.daemon = True
            thread.start()
    elif pck.type == ALIVE_INF:
        client = get_client(pck.id)
        if client == None or client.mac != pck.mac:
            # Not authorized client
            pck = build_void_package(ALIVE_REJ, "The id and mac received are not allowed")
            udp_socket.sendto(pck, (client_ip, udp_port))
        elif pck.rand_num != client.rand_num:
            # Random number incorrect
            pck = build_void_package(ALIVE_NACK, "The random number received is not correct")
            udp_socket.sendto(pck, (client_ip, udp_port))
        elif client_ip != client.ip:
            # Ip incrrect
            pck = build_void_package(ALIVE_NACK, "The ip of the client is incorrect")
            udp_socket.sendto(pck, (client_ip, udp_port))
        else:
            # All correct
            send_pck = build_regular_package(ALIVE_ACK, client, "")
            udp_socket.sendto(send_pck, (client_ip, udp_port))
            client.alive_received = True
            if client.state == REGISTERED:
                change_state(client, SEND_ALIVE)
                thread = threading.Thread(target = control_alive_time, args=(client,))
                thread.daemon = True
                thread.start()
    else:
        error_message(f"The package type received is not correct", False)

def receive_udp_package():
    pck = Package()
    recv_pck, (client_ip_addr, udp_port) = udp_socket.recvfrom(78)
    recv_pck = struct.unpack('B7s13s7s50s', recv_pck)

    pck.type = recv_pck[0]
    pck.id = recv_pck[1].split(b"\x00")[0].decode()
    pck.mac = recv_pck[2].split(b"\x00")[0].decode()
    pck.rand_num = recv_pck[3].split(b"\x00")[0].decode()
    pck.data = recv_pck[4].split(b"\x00")[0].decode()
    
    if debug:
        debug_message("Package received:\n" +
                      f"\t\t\tType: {pck.type}\n" +
                      f"\t\t\tId: {pck.id}\n" +
                      f"\t\t\tMac: {pck.mac}\n" +
                      f"\t\t\tRandom number: {pck.rand_num}\n"  +
                      f"\t\t\tData: {pck.data}\n") 
    return pck, client_ip_addr, udp_port

def udp_loop():
    while True:
        received_package, client_ip_addr, udp_port = receive_udp_package()

        thread = threading.Thread(target = treat_udp_package, args=(received_package, client_ip_addr, udp_port))
        thread.daemon = True
        thread.start()

def init_loop():
    # Serve tcp communications
    thread = threading.Thread(target = tcp_loop)
    thread.daemon = True
    thread.start()

    # Serve udp communications
    udp_loop()

def setup_sockets():
    try:
        # Setup udp socket
        global udp_socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(("", int(file_d.udp_port)))

        # Setup tcp socket
        global tcp_socket
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Permitir conectarse a un puerto ocupado????
        tcp_socket.bind(("", int(file_d.tcp_port)))
        tcp_socket.listen(5)
    except socket.error as e:
        error_message(f"Bind failed: {e}")

def read_accepted_clients():
    try:
        file = open(authorized_clients)
        lines = file.readlines()
        for line in lines:
            tokens = line.split(' ')
            if len(tokens) != 2:
                error_message(f'Line "{line[:-1]}" is not a valid format')
            clients.append(new_client(tokens[0], tokens[1][:-1]))
    except:
        error_message(f"Couldn't open the '{authorized_clients}' file")

def read_server_data():
    try:
        global file_d
        file_d = File_data()
        file = open(conf_file)
        lines = file.readlines()
        for line in lines:
            tokens = line.split(' ')
            if tokens[0] == 'Id':
                file_d.id = tokens[1][:-1]
            elif tokens[0] == 'MAC':
                file_d.mac = tokens[1][:-1]
            elif tokens[0] == 'UDP-port':
                file_d.udp_port = tokens[1][:-1]
            elif tokens[0] == 'TCP-port':
                file_d.tcp_port = tokens[1][:-1]
    except:
        error_message(f"Couldn't open the '{conf_file}' file")

def read_files():
    read_server_data()
    read_accepted_clients()

def read_arguments():
    read_conf_file = False
    read_auth_clients_file = False
    args = sys.argv[1:]
    global conf_file
    global authorized_clients

    for arg in args:
        if read_conf_file:
            conf_file = arg
            read_conf_file = False
            continue
        if read_auth_clients_file:
            authorized_clients = arg
            read_auth_clients_file = False
            continue
        if arg == "-d":
            global debug
            debug = True
        elif arg == "-c":
            read_conf_file = True
        elif arg == "-u":
            read_auth_clients_file = True
        else:
            error_message(f'The argument "{arg}" is not a valid argument for server')
    
    if read_conf_file:
        error_message("You have to specify the name of the file after '-c'")
    if read_auth_clients_file:
        error_message("You have to specify the name of the file after '-u'")

if __name__ == "__main__":
    try:
        read_arguments()
        read_files()
        
        thread = threading.Thread(target = manage_command_line)
        thread.daemon = True
        thread.start()

        setup_sockets()
        init_loop()
    except(SystemExit, KeyboardInterrupt):
        pass