# 2c.SIMULATING ARP /RARP PROTOCOLS
## AIM
To write a python program for simulating ARP protocols using TCP.
## ALGORITHM:
## Client:
1. Start the program
2. Using socket connection is established between client and server.
3. Get the IP address to be converted into MAC address.
4. Send this IP address to server.
5. Server returns the MAC address to client.
## Server:
1. Start the program
2. Accept the socket which is created by the client.
3. Server maintains the table in which IP and corresponding MAC addresses are
stored.
4. Read the IP address which is send by the client.
5. Map the IP address with its MAC address and return the MAC address to client.
P
## PROGRAM - ARP
```
import socket
import threading

HOST = '127.0.0.1'
PORT = 50000
ip_to_mac = {
    "192.168.1.2": "AA:BB:CC:11:22:33",
    "192.168.1.3": "AA:BB:CC:44:55:66",
    "10.0.0.4":"DE:AD:BE:EF:00:01",
}
mac_to_ip = {mac: ip for ip, mac in ip_to_mac.items()}

def handle_client(conn, addr):
    with conn:
        print(f"[+] Connection from {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            try:
                msg = data.decode().strip()
            except Exception:
                conn.sendall(b"ERROR: invalid encoding\n")
                continue

            # Expected messages: "ARP:192.168.1.2" or "RARP:AA:BB:CC:11:22:33"
            if msg.upper().startswith("ARP:"):
                ip = msg[4:].strip()
                mac = ip_to_mac.get(ip)
                if mac:
                    response = f"MAC:{mac}\n"
                else:
                    response = "NOTFOUND\n"
            elif msg.upper().startswith("RARP:"):
                mac = msg[5:].strip()
                ip = mac_to_ip.get(mac.upper(), mac_to_ip.get(mac.lower()))
                if ip:
                    response = f"IP:{ip}\n"
                else:
                    response = "NOTFOUND\n"
            else:
                response = "ERROR: Unknown command. Use ARP:<ip> or RARP:<mac>\n"

            conn.sendall(response.encode())

        print(f"[-] Connection closed {addr}")

def run_server():
    print(f"Starting ARP/RARP server on {HOST}:{PORT}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        srv.close()

if __name__ == "__main__":
    run_server()
```

## OUPUT - ARP

<img width="409" height="45" alt="Screenshot 2025-10-03 074728" src="https://github.com/user-attachments/assets/7969d995-7e1a-4268-849e-5ab9ffa79ff7" />

<img width="520" height="96" alt="Screenshot 2025-10-03 074734" src="https://github.com/user-attachments/assets/0858becf-be50-416e-8020-c1ecdd2f6537" />

## PROGRAM - RARP
```
import socket

HOST = '127.0.0.1'
PORT = 50000

def query_server(message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall((message + "\n").encode())
        resp = s.recv(1024).decode().strip()
        return resp

def interactive():
    print("ARP/RARP client.")
    print("Send requests in these formats:")
    print("  ARP:<ip>    e.g. ARP:192.168.1.2")
    print("  RARP:<mac>  e.g. RARP:AA:BB:CC:11:22:33")
    print("Type 'exit' to quit.\n")

    while True:
        line = input("Enter request: ").strip()
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            break
        try:
            resp = query_server(line)
            print("Server response:", resp)
        except ConnectionRefusedError:
            print("Could not connect to server. Make sure the server is running.")
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    interactive()
```
## OUPUT -RARP

<img width="406" height="47" alt="Screenshot 2025-10-03 074739" src="https://github.com/user-attachments/assets/bba33105-ac6a-4f19-966d-53116ba81804" />

## RESULT
Thus, the python program for simulating ARP protocols using TCP was successfully 
executed.
