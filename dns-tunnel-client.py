import socket
import threading
import select
import logging
import dns.resolver
import dns.query
import dns.message
import base64
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the address and port for the proxy server
PROXY_HOST = '192.168.0.149'
PROXY_PORT = 1080

ns_domain = 'ns1.yourdomain.org'
DNS_TUNNEL_DOMAIN = 'prox.tunel.yourdomain.org'

active_thread = {}
lock = threading.Lock()


def resolve_ns(ns_domain):  # resolve the domain
    resolver = dns.resolver.Resolver()
    response = resolver.resolve(ns_domain, 'A')
    return response[0].to_text()

def dns_query(ns_ip, query_domain):
    try:
        query = dns.message.make_query(query_domain, dns.rdatatype.TXT)
        response = dns.query.udp(query, ns_ip, timeout=30)
        if response.answer:
            for answer in response.answer:
                for item in answer.items:
                    return item.to_text().strip('"')
    except Exception as e:
        logging.error(f"Couldn't make the DNS query: {e}")
    return None

def dns_send_data(thread_index, ns_ip, data):
    max_label_size = 63  # maximum label size for DNS
    max_url_length = 250  # maximum URL length
    encoded_data = base64.b32encode(data).decode('utf-8')
    # logging.info(f"{thread_index} Encoded data: {encoded_data}")

    # split data into chunks of max_label_size
    chunks = [encoded_data[i:i + max_label_size] for i in range(0, len(encoded_data), max_label_size)]
    total_chunks = len(chunks)

    responses = []
    current_query = f"{thread_index}.{total_chunks}"

    for index, chunk in enumerate(chunks):
        potential_query = f"{current_query}.{index}.{chunk}"
        if len(potential_query) + len(DNS_TUNNEL_DOMAIN) + 1 > max_url_length:  # added +1 for the "." in the URL
            current_query += f".{DNS_TUNNEL_DOMAIN}"
            response = dns_query(ns_ip, current_query)
            if response:
                responses.append(response)
            else:
                return None
            # reset for the next set of chunks
            current_query = f"{thread_index}.{total_chunks}.{index}.{chunk}"
        else:
            current_query = potential_query

    # send remaining packet chunks
    if current_query:
        current_query += f".{DNS_TUNNEL_DOMAIN}"
        response = dns_query(ns_ip, current_query)
        if response:
            responses.append(response)
        else:
            return None

    return ''.join(responses)

def dns_receive_data(thread_index, ns_ip):
    query_domain = f"recv.{thread_index}.-1.{DNS_TUNNEL_DOMAIN}"
    response = dns_query(ns_ip, query_domain)
    
    while not response:  # keep requesting response until received
        response = dns_query(ns_ip, query_domain)
    
    response = int(response)
    resp = ""
    for i in range(response):
        query_domain = f"recv.{thread_index}.{i}.{DNS_TUNNEL_DOMAIN}"
        response = dns_query(ns_ip, query_domain)
        # logging.info(f"RECCCCCCC {response}")
        
        while not response:
            response = dns_query(ns_ip, query_domain)
        
        if response:
            resp += response

    if resp:
        # logging.info(f"RECCCCCCC {resp}")
        return base64.b32decode(resp)
    else:
        logging.info(f"{thread_index} NO RESPONSE {resp}")
    return b''

def handle_client(client_socket, thread_index):
    ns_ip = resolve_ns(ns_domain)
    logging.info(f"Server {DNS_TUNNEL_DOMAIN} with IP {ns_ip}")
    try:
        # configure the client socket to use SOCKS5
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_socket.settimeout(10)

        # read the client's initial request
        client_socket.recv(262)
        client_socket.sendall(b"\x05\x00")

        # receive the client's connection request
        data = client_socket.recv(4)
        if data[1] != 1:
            client_socket.close()
            return

        # read the address type
        addr_type = data[3]

        # read the destination address
        if addr_type == 1:  # IPv4
            addr = socket.inet_ntoa(client_socket.recv(4))
        elif addr_type == 3:  # domain name
            addr_len = client_socket.recv(1)[0]
            addr = client_socket.recv(addr_len).decode('utf-8')
        elif addr_type == 4:  # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, client_socket.recv(16))

        # read the destination port
        port = int.from_bytes(client_socket.recv(2), 'big')

        # connect to the destination address through the DNS tunnel
        resp = dns_send_data(thread_index, ns_ip, f"CONNECT {addr}:{port}".encode('utf-8'))
        while not resp:
            resp = dns_send_data(thread_index, ns_ip, f"CONNECT {addr}:{port}".encode('utf-8'))

        if resp != "CONNECTED":
            logging.error(f"Connection failed! Response: {resp}")
            client_socket.close()
            return
        
        logging.info(f"{thread_index} Connected! Response: {resp}")

        # send success message back to the client
        client_socket.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (1080).to_bytes(2, 'big'))

        # start forwarding data between client and remote server through the DNS tunnel
        start_forwarding_threads(thread_index, client_socket, ns_ip)

    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        client_socket.close()

def start_forwarding_threads(thread_index, client_socket, ns_ip):
    # add the thread to the dictionary of active threads

    # create separate threads to read from both the client and the server faster
    client_to_server_thread = threading.Thread(target=client_to_server, args=(thread_index, client_socket, ns_ip))
    server_to_client_thread = threading.Thread(target=server_to_client, args=(thread_index, client_socket, ns_ip))

    with lock:
        active_thread[thread_index] = True

    client_to_server_thread.start()
    server_to_client_thread.start()

    client_to_server_thread.join()
    server_to_client_thread.join()

    logging.info(f"{thread_index} Connection closed.")

def client_to_server(thread_index, client_socket, ns_ip):
    try:
        while active_thread.get(thread_index, True):
            readable, _, _ = select.select([client_socket], [], [])  # check if the client wants to write

            if client_socket in readable:
                data = client_socket.recv(131072)
                logging.error(f"{thread_index} Received data from the client: {len(data)}")
                if not data:
                    with lock:
                        active_thread[thread_index] = False
                    break
                dns_send_data(thread_index, ns_ip, data)  # take what the client wrote and send it to DNS

    except Exception as e:
        logging.error(f"{thread_index} Error while forwarding data from client to server: {e}")
        with lock:
            active_thread[thread_index] = False
    finally:
        client_socket.close()


def server_to_client(thread_index, client_socket, ns_ip):  # read from server through MANY DNS requests
    try:
        while active_thread.get(thread_index, True):
            logging.info(f"{thread_index} Waiting for data from the server...")
            try:
                response_data = dns_receive_data(thread_index, ns_ip)
            except Exception as e:
                logging.info(f"{thread_index} No data received from the DNS server. {e}")
                response_data = None

            if response_data:
                logging.error(f"{thread_index} Received data from DNS: {len(response_data)}")
                client_socket.sendall(response_data)
    except Exception as e:
        logging.error(f"{thread_index} Error while forwarding data from server to client: {e}")
        with lock:
            active_thread[thread_index] = False
    finally:
        client_socket.close()

if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((PROXY_HOST, PROXY_PORT))
    server_socket.listen(5)
    logging.info(f"Listening on {PROXY_HOST}:{PROXY_PORT}")

    thread_index = 0
    try:
        while True:
            client_socket, addr = server_socket.accept()
            # add time to unique thread index
            now = int(time.time())
            logging.info(f"{thread_index}={now} Accepted connection from {addr}")

            client_handler = threading.Thread(target=handle_client, args=(client_socket, f'{thread_index}={now}', ))
            thread_index += 1
            client_handler.start()
    except KeyboardInterrupt:
        logging.info("Stopping the server.")
    finally:
        server_socket.close()
