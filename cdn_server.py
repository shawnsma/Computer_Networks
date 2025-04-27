#!/usr/bin/env python3

import socket
import ssl
import threading
import argparse
import re
import os
import sys
import time
from queue import Queue
from urllib.parse import urlparse, unquote

class ConnectionPool:
    def __init__(self, max_conn=10):
        self.pool = Queue(maxsize=max_conn)
        self.lock = threading.Lock()
        self.active_connections = 0
    
    def get_connection(self, origin_domain, origin_addr, origin_port):
        try:
            conn = self.pool.get(block=False)
            try:
                conn.settimeout(0.1)
                conn.send(b'')
                conn.settimeout(None)
                return conn
            except:
                return self.create_new_connection(origin_domain, origin_addr, origin_port)
        except:
            return self.create_new_connection(origin_domain, origin_addr, origin_port) 

    def create_new_connection(self, origin_domain, origin_addr, origin_port):
        with self.lock:
            self.active_connections += 1
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                   server_hostname=origin_domain)
        conn.connect((origin_addr, origin_port))
        return conn
    
    def release_connection(self, conn):
        try:
            self.pool.put(conn, block=False)
        except:
            try:
                conn.close()
            except:
                pass
            with self.lock:
                self.active_connections -= 1

class Cache:
    def __init__(self, max_size=100):
        self.cache = {}
        self.lock = threading.Lock()
        self.max_size = max_size
    
    def get(self, key):
        with self.lock:
            return self.cache.get(key)
    
    def put(self, key, value):
        with self.lock:
            if len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
            self.cache[key] = value
    
    def cacheable(self, path, headers):
        cache_control = headers.get('Cache-Control', '')
        if 'no-store' in cache_control.lower() or 'private' in cache_control.lower():
            return False
        
        if path == '/' or path == '':
            return True
            
        cacheable_extensions = ['.html', '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico']
        for extension in cacheable_extensions:
            if path.lower().endswith(extension):
                return True
                
        return False

def parse_headers(header_data):
    headers = {}
    for line in header_data.split('\r\n'):
        if not line or ':' not in line:
            continue
        key, value = line.split(':', 1)
        headers[key.strip()] = value.strip()
    return headers

def extract_content_length(headers):
    try:
        return int(headers.get('Content-Length', 0))
    except ValueError:
        return 0

def normalize_path(path):
    return path.split('?')[0]

def handle_client(client_socket, client_address, origin_domain, origin_addr, origin_port, conn_pool, cache):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="certs/cdn_cert.pem", keyfile="certs/cdn_key.pem")
        client_secure = context.wrap_socket(client_socket, server_side=True)

        request_data = b''
        while b'\r\n\r\n' not in request_data:
            chunk = client_secure.recv(4096)
            if not chunk:
                break
            request_data += chunk
        
        if not request_data:
            return
        
        request_text = request_data.decode('utf-8')
        request_lines = request_text.split('\r\n')
        request_line = request_lines[0]
        match = re.match(r'([A-Z]+)\s+(.*)\s+HTTP/\d\.\d', request_line)
        if not match:
            return
        
        method, path = match.groups()
        host_header = next((line for line in request_lines if line.startswith('Host:')), f'Host: {origin_domain}')
        host = host_header.split(':', 1)[1].strip()
        
        if method != 'GET':
            origin_conn = conn_pool.get_connection(origin_domain, origin_addr, origin_port)
            modified_request = request_data.replace(b'Connection: close', b'Connection: keep-alive')
            if b'Connection:' not in modified_request:
                modified_request = modified_request.replace(b'\r\n\r\n', b'\r\nConnection: keep-alive\r\n\r\n')
            
            origin_conn.sendall(modified_request)
            
            response_data = b''
            while True:
                chunk = origin_conn.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                
            client_secure.sendall(response_data)
            conn_pool.release_connection(origin_conn)
            return
        
        normalized_path = normalize_path(path)
        cache_key = normalized_path
        
        cached_content = cache.get(cache_key)
        if cached_content:
            client_secure.sendall(cached_content)
            
            response_lines = cached_content.split(b'\r\n')
            status_line = response_lines[0].decode('utf-8')
            status_parts = status_line.split(' ')
            status_code = status_parts[1] if len(status_parts) > 1 else '000'
            
            headers_section = cached_content.split(b'\r\n\r\n')[0].decode('utf-8')
            headers = parse_headers(headers_section)
            content_length = extract_content_length(headers)
            
            print(f"{client_address[0]}\t{request_line}\t{host}\t{status_code}\t{content_length}")
            return
        
        modified_request = request_text
        modified_request = re.sub(r'Connection:.*\r\n', '', modified_request)
        if '\r\n\r\n' in modified_request:
            modified_request = modified_request.replace('\r\n\r\n', '\r\nConnection: keep-alive\r\n\r\n')
        
        origin_conn = conn_pool.get_connection(origin_domain, origin_addr, origin_port)
        origin_conn.sendall(modified_request.encode('utf-8'))
        
        response_data = b''
        headers_data = b''
        body_data = b''
        headers_received = False
        
        while not headers_received:
            chunk = origin_conn.recv(4096)
            if not chunk:
                break
            
            response_data += chunk
            if b'\r\n\r\n' in response_data:
                headers_data, body_data = response_data.split(b'\r\n\r\n', 1)
                headers_received = True
        
        if not headers_received:
            origin_conn.close()
            with conn_pool.lock:
                conn_pool.active_connections -= 1
            return
        
        headers_text = headers_data.decode('utf-8')
        headers = parse_headers(headers_text)
        content_length = extract_content_length(headers)
        
        response_lines = headers_text.split('\r\n')
        status_line = response_lines[0] if response_lines else "HTTP/1.1 000 Unknown"
        status_parts = status_line.split(' ')
        status_code = status_parts[1] if len(status_parts) > 1 else '000'
        
        current_body_length = len(body_data)
        
        client_secure.sendall(headers_data + b'\r\n\r\n')
        client_secure.sendall(body_data)
        
        while current_body_length < content_length:
            chunk = origin_conn.recv(4096)
            if not chunk:
                break
            
            client_secure.sendall(chunk)
            body_data += chunk
            current_body_length += len(chunk)
        
        full_response = headers_data + b'\r\n\r\n' + body_data
        
        if cache.cacheable(normalized_path, headers):
            cache.put(cache_key, full_response)
        
        conn_pool.release_connection(origin_conn)
        
        print(f"{client_address[0]}\t{request_line}\t{host}\t{status_code}\t{content_length}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description='CDN Edge Server')
    parser.add_argument('-p', '--port', type=int, help='Port')
    parser.add_argument('-d', '--origin-domain', help='Origin server domain')
    parser.add_argument('--cdn-port', type=int, help='CDN port')
    parser.add_argument('--origin-addr', help='Origin server address')
    parser.add_argument('--origin-port', type=int, default=443, help='Origin server port')
    args = parser.parse_args()
    
    port = args.port if args.port else args.cdn_port
    origin_domain = args.origin_domain
    origin_addr = args.origin_addr if args.origin_addr else origin_domain
    origin_port = args.origin_port
    
    conn_pool = ConnectionPool(max_conn=20)
    cache = Cache(max_size=100)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(100)
    
    print(f"CDN server listening on port {port}, forwarding to {origin_domain}")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, origin_domain, origin_addr, origin_port, conn_pool, cache)
            )
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()