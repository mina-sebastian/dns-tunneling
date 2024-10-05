import copy
import select
import socket
import threading
from scapy.all import DNS, DNSRR
import base64
import os
from threading import Lock

lock1 = Lock()
lock2 = Lock()
lock3 = Lock()

# DNS server configuration
DNS_SERVER_IP = '0.0.0.0'
DNS_SERVER_PORT = 53
CLOUDFLARE_DNS_IP = "1.1.1.1"
CLOUDFLARE_DNS_PORT = 53


DOMAIN_SUFF_FTRANSFER = 'ftransfer.tunel.yourdomain.org.'
DOMAIN_SUFF_PROX = 'prox.tunel.yourdomain.org.'

prox_connections = {}
prox_buffer_send = {}
prox_buffer_recv = {}

# create the UDP socket
server_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
server_udp.bind((DNS_SERVER_IP, DNS_SERVER_PORT))

def forward_query(query):
    # create a new UDP socket to send it to Cloudflare's DNS 😇
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP) as forward_udp:
        forward_udp.sendto(query, (CLOUDFLARE_DNS_IP, CLOUDFLARE_DNS_PORT))
        # receive the response from Cloudflare's DNS
        response, _ = forward_udp.recvfrom(65535)
    return response

def encode_file_to_txt_records(filename):
    if not os.path.exists(filename):
        return None
    # read the file content
    with open(filename, 'rb') as file:
        file_content = file.read()
    # encode the content in base32
    encoded_content = base64.b32encode(file_content).decode()
    max_record_size = 255  # maximum size for a DNS TXT record
    # split the encoded content into fragments of the maximum size
    txt_records = [encoded_content[i:i + max_record_size] for i in range(0, len(encoded_content), max_record_size)]
    return txt_records

# GENERAL DNS HANDLER
def handle_dns_query(packet):
    dns = packet.getlayer(DNS)
    if dns and dns.opcode == 0:  # DNS request
        qname = dns.qd.qname.decode()

        # if the domain name ends with the file transfer suffix
        if qname.endswith(DOMAIN_SUFF_FTRANSFER):
            return handle_file_transfer_query(qname, dns, packet)
        # if the domain name ends with the proxy suffix
        elif qname.endswith(DOMAIN_SUFF_PROX):
            return handle_prox_query(qname, dns, packet)
        else:
            # forward the DNS request to Cloudflare's DNS so Google doesn't steal our data 😡
            return forward_query(bytes(packet))
    return None

# FILE HANDLER
def handle_file_transfer_query(qname, dns, packet):
    query_part = qname.replace('.' + DOMAIN_SUFF_FTRANSFER, '')  # the file transfer suffix is removed from the domain name
    n, filename = query_part.split(',', 1)  # split the query by "," into the number and filename
    n = int(n)
    txt_records = encode_file_to_txt_records(filename)  # encode the file into TXT records
    
    if txt_records:
        if n == -1:  # if n is -1, request the total number of available windows
            total_windows = len(txt_records)
            return build_dns_response(dns, packet, total_windows)
        elif n < len(txt_records):  # otherwise, return the n-th window
            return build_dns_response(dns, packet, txt_records[n])
        else:
            return build_dns_error_response(dns, packet, 3)  # NXDOMAIN
    return build_dns_error_response(dns, packet, 3)  # NXDOMAIN

# PROXY HANDLER
def handle_prox_query(qname: str, dns, packet):
    print("-------------------------------------------")
    print("resolving for", qname)
    query_part = qname.replace('.' + DOMAIN_SUFF_PROX, '')

    if query_part.startswith("recv"):  # check if the site wants to send us data
        parts = query_part.split('.')
        thread_index = parts[1]
        n = int(parts[2])
        return handle_prox_recv(thread_index, n, dns, packet)

    parts = query_part.split(".")

    thread_index = parts[0]
    total = int(parts[1])

    final = False
    if total != 1:
        for i in range(2, len(parts), 2):  # build the packet from the received pieces
            indx = int(parts[i])
            print(thread_index, "FOR", indx, parts[i+1])
            if indx == 0:
                with lock2:
                    prox_buffer_send[thread_index] = parts[i+1]
            else:
                with lock2:
                    prox_buffer_send[thread_index] += parts[i+1]
            
            if indx+1 == total:
                final = True
    else:
        final = True
        with lock2:
            prox_buffer_send[thread_index] = parts[3]

    if not final:  # if it hasn't finished sending packets, tell it to continue
        return handle_continue(thread_index, dns, packet)

    query_part = base64.b32decode(prox_buffer_send[thread_index])

    if final:
        with lock2:
            del prox_buffer_send[thread_index]
    try:
        query_part1 = query_part.decode('utf-8')

        if query_part1.startswith("CONNECT"):  # connection request from the browser
            return handle_prox_connect(thread_index, query_part1, dns, packet)
        else:
            return handle_prox_send(thread_index, query_part, dns, packet)  # decoded message is HTTP
    except:
        return handle_prox_send(thread_index, query_part, dns, packet)

# Continuation handler
def handle_continue(thread_index, dns, packet):
    # received all pieces from thread_index
    return build_dns_response(dns, packet, "CONTINUE")

# Proxy connection handler
def handle_prox_connect(thread_index, query_part, dns, packet):
    target = query_part.split(' ')[1]
    addr, port = target.split(':')
    port = int(port)
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((addr, port))
    with lock1:
        prox_connections[thread_index] = remote_socket
    print(thread_index, "Successfully connected to:", addr, port)
    return build_dns_response(dns, packet, "CONNECTED")

# Receive handler for proxy
def handle_prox_recv(thread_index, n, dns, packet):
    if n == -1:  # if n is -1, read from SOCKS5 server and send required window count
        remote_socket = prox_connections.get(thread_index)

        if remote_socket:
            data = remote_socket.recv(131072)
            if data:
                print(f"{thread_index} RECEIVED DATA FROM SITE {len(data)}")
                encoded_data = base64.b32encode(data).decode('utf-8')
                with lock3:
                    prox_buffer_recv[thread_index] = [encoded_data[i:i + 255] for i in range(0, len(encoded_data), 255)]

                return build_dns_response(dns, packet, len(prox_buffer_recv[thread_index]))
            return build_dns_response(dns, packet, "")
    else:  # if n is not -1, request the n-th piece of the packet
        data = prox_buffer_recv.get(thread_index)
        if data:
            if n < len(data):
                newD = copy.deepcopy(data[n])
                if n+1 == len(data):
                    with lock3:
                        del prox_buffer_recv[thread_index]
                return build_dns_response(dns, packet, newD)
            else:
                return build_dns_error_response(dns, packet, 3)
    return build_dns_error_response(dns, packet, 3)  # NXDOMAIN

# Send handler for proxy
def handle_prox_send(thread_index, data, dns, packet):
    remote_socket = prox_connections.get(thread_index)
    print(thread_index, "Sending data bytes...")
    if remote_socket:
        print(f"{thread_index} SENT DATA {len(data)}")
        remote_socket.sendall(data)
        return build_dns_response(dns, packet, "SENT")
    return build_dns_error_response(dns, packet, 3)  # NXDOMAIN

# DNS RESPONSE HANDLERS
def build_dns_response(dns, packet, rdata):
    answer = DNSRR(rrname=dns.qd.qname, type='TXT', ttl=3600, rdata=str(rdata))
    return DNS(
        id=packet[DNS].id,  # DNS response must have the same ID as the current request
        qr=1,  # 1 for response, 0 for query
        aa=1,  # authoritative response
        rcode=0,  # 0, no error
        qd=packet.qd,  # the initial request
        an=answer  # response object
    )

def build_dns_error_response(dns, packet, rcode):
    return DNS(
        id=packet[DNS].id,  # DNS response must have the same ID as the current request
        qr=1,  # 1 for response, 0 for query
        aa=0,  # non-authoritative response
        rcode=rcode,  # error code
        qd=packet.qd  # the initial request
    )
