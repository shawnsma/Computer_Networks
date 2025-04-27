#!/usr/bin/env python3
import socket
import sys 
import argparse
import json
import ssl

def parseargs():
    parser = argparse.ArgumentParser(usage = './client [-p port] [-s] hostname NetID')

    parser.add_argument('-p', type = int, dest = 'port')
    parser.add_argument('-s', action = 'store_true')
    parser.add_argument('hostname')
    parser.add_argument('netid')

    try:
        args = parser.parse_args()
        
        if args.port is None:
            if args.s:
                args.port = 49153
            else:
                args.port = 49152
    
        return {'port': args.port, 'flag': args.s, 'hostname': args.hostname, 'netid': args.netid}
    
    except argparse.ArgumentError:
        parser.print_usage()
        sys.exit(1)

def recieve_message(socket):
    message = ""
    while True:
        chunck = socket.recv(1024).decode('ascii')
        message += chunck

        if '\n' in message:
            message = message.strip()
            if message:
                try:
                    return json.loads(message)
                except json.JSONDecodeError as e:
                    # print(f"Invalid JSON received: {message}")
                    # print(f"JSON decode error: {e}")
                    return None

Wry_data = {"type": "WRY"}
Wry = json.dumps(Wry_data) + "\n"

if __name__ == "__main__":
    # Parse Inputs
    try:
        args = parseargs()
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    
    # Get host IP (technically only need to recieve once)
    try:
        host_ip = socket.gethostbyname(args['hostname'])
    except socket.gaierror:
        print("Error resolving host")
        sys.exit(1)

    # Create socket connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host_ip, args['port']))
    if args['flag']:
        try:
            context = ssl.create_default_context()
            s = context.wrap_socket(s, server_hostname=args['hostname'])
        except socket.error as err: 
            print("socket creation failed with error %s" %(err))
            sys.exit(1)

    # Send Hi message
    Hi_data = {"type": "HI", "netid": args['netid']}
    Hi = json.dumps(Hi_data) + "\n"
    s.send(Hi.encode('ascii'))
    # print(Hi)

    # Recieve AYE message
    while True:
        message = recieve_message(s)
        # print(message)
        if message:
            if message["type"] == "AYE" and isinstance(message["min"], int) and isinstance(message["max"], int) and message["max"] >= message["min"]:
                low = message["min"]
                high = message["max"]
                break
        else:
            s.send(Wry.encode('ascii'))
    
    
    # Send TRY messages
    while low <= high:
        mid = low + (high - low) // 2
        Try_data = {"type": "TRY", "guess": mid}
        Try = json.dumps(Try_data) + "\n"
        s.send(Try.encode('ascii'))
        # print(Try)

        message = recieve_message(s)
        # print(message)

        while True:
            if message:
                if message["type"] == "NIGH":
                    if message["hint"] == "too low":
                        low = mid + 1
                    elif message["hint"] == "too high":
                        high = mid - 1
                    else:
                        s.send(Wry.encode('ascii'))
                    break

                elif message["type"] == "BYE":
                    flag = message["flag"]
                    s.close()
                    print(flag)
                    sys.exit(0)

                else:
                    s.send(Wry.encode('ascii'))
                    # print(Wry)
                    message = recieve_message(s)
                    # print(message)

            else:
                s.send(Wry.encode('ascii'))
                # print(Wry)
                message = recieve_message(s)
                # print(message)
                