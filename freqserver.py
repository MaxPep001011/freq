# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.73"



import os
import socket
import threading
import struct
import json
import signal
import sys
import time

serverName = "SERVER"

def timestamp():
    return "[" + time.strftime("%H:%M:%S") + "]"
def send_client_list(clients: dict):
    """
    Sends the current list of connected client fingerprints to all clients
    """
    client_idents = list(clients.keys())
    data = json.dumps(client_idents).encode("utf-8")
    header = {"sender": serverName}
    for ident, conn in clients.items():
        try:
            # Pack as msg_type 0x03 for client pull client side
            packed = pack_message(0x03, header, ident, data)
            conn.sendall(packed)
        except Exception as e:
            print(f"{timestamp()}[!] Failed to send client list to {ident}: {e}")
def pack_message(msg_type: int, header: dict, recipient: str, data: bytes) -> bytes:
    header_json = json.dumps(header).encode("utf-8")
    recipient_bytes = recipient.encode("utf-8")
    return (
        struct.pack(">B", msg_type) +
        struct.pack(">I", len(header_json)) + header_json +
        struct.pack(">I", len(recipient_bytes)) + recipient_bytes +
        struct.pack(">Q", len(data)) + data
    )
def recv_exact(sock, n: int) -> bytes:
    buffer = b''
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        buffer += chunk
    return buffer
def recv_frame(sock) -> bytes:
    """
    Receive one full message frame with 64-bit data length support
    """
    prefix = recv_exact(sock, 1 + 4)
    msg_type = struct.unpack(">B", prefix[:1])[0]
    header_len = struct.unpack(">I", prefix[1:])[0]

    header_bytes = recv_exact(sock, header_len)
    header = json.loads(header_bytes.decode("utf-8"))

    recip_len_bytes = recv_exact(sock, 4)
    recip_len = struct.unpack(">I", recip_len_bytes)[0]
    recip_bytes = recv_exact(sock, recip_len)
    recipient = recip_bytes.decode("utf-8")

    data_len_bytes = recv_exact(sock, 8)
    data_len = struct.unpack(">Q", data_len_bytes)[0]
    
    #Load everything into ram (for now dont send large messages)
    data = recv_exact(sock, data_len)

    raw = (
        prefix +
        header_bytes +
        recip_len_bytes + recip_bytes +
        data_len_bytes + data
    )

    return raw, msg_type, header, recipient, data
def client_handler(conn, addr, clients):
    try:
        #Join message must carry ident in header["ident"]
        raw, msg_type, header, recipient, data = recv_frame(conn)
        ident = header.get("sender")
        if not ident:
            print(f"{timestamp()}[-] {addr} missing ident, closing")
            conn.close()
            return
        elif ident == serverName:
            print(f"{timestamp()}[-] {addr} ident not allowed to be 'SERVER', closing")
            conn.close()
            return
        clients[ident] = conn
        print(f"{timestamp()}[+] {ident} connected from {addr}")
        print(f"{timestamp()}[i] {len(clients)} clients")
        #Send updated client list to all clients (bc someone joined)
        send_client_list(clients)

        #Forward all subsequent frames unchanged
        while True:
            frame = recv_frame(conn)

            if not frame:
                print(f"{timestamp()}[-] '{ident}' closed connection {addr}")
                break

            raw, msg_type, header, recipient, data = frame

            newestident = header.get("sender")
            if newestident != ident:
                #switch entry
                if ident in clients and clients[ident] == conn:
                    del clients[ident]
                clients[newestident] = conn
                ident = newestident

                send_client_list(clients)
            if recipient in clients:
                clients[recipient].sendall(raw)
                print(f"{timestamp()}[+] Routed '{ident}' --> '{recipient}'")

    except ConnectionError:
        print(f"{timestamp()}[-] {addr} disconnected")
    except Exception as e:
        print(f"{timestamp()}[!] Error with {addr}: {e}")
    finally:
        conn.close()
        for k, v in list(clients.items()):
            if v == conn:
                del clients[k]
                #send updated client list to all clients (bc someone joined)
                send_client_list(clients)
                print(f"{timestamp()}[i] {len(clients)} clients")


def main():
    print(f"***   FR3Qserver(v{ptversion})   ***\n")
    ip = input("[?] Bind IP [default 0.0.0.0]:").strip() or "0.0.0.0"
    try:
        lport = int(input("[?] Bind port [default 80]:").strip() or "80")
    except ValueError:
        lport = 80
    try:
        pport = int(input("[?] Service port [default 80]:").strip() or "80")
    except ValueError:
        pport = 80
    forwarded = input("[?] Already forwarded onion service in torrc? (y/N): ").lower().strip()
    if forwarded != "y":
        print("\n[+] Add/uncomment the following lines to your torrc and save:")
        print(" - Normal Linux: edit /etc/tor/torrc")
        print(f"    HiddenServiceDir /var/lib/tor/hidden_service/")
        print(f"    HiddenServicePort {pport} {ip}:{lport}")
        print(f"     - Adjust firewall to allow incoming connections at {ip}:{lport}")
        print("     - Then restart tor:")
        print("         sudo systemctl restart tor")
        print(" - Whonix (Qubes): edit /usr/local/etc/torrc.d/50_user.conf (in gatewayVM)")
        print(f"    HiddenServiceDir /var/lib/tor/hidden_service/")
        print(f"    HiddenServicePort {pport} 'whonix-workstation-ip':{lport}")
        print("     - Also edit firewall in the workstation (thisVM) and add the following")
        print(f"         EXTERNAL_OPEN_PORTS+=\" {lport} \"")
        print("     - Restart the firewall:")
        print("         sudo whonix_firewall")
        print("     - Then restart tor (in gatewayVM):")
        print("         sudo systemctl restart tor")
        input("--- PRESS ENTER WHEN COMPLETE AND TOR HAS RESTARTED ---")

    clients = {}
    print(f"{timestamp()}[+] Server init...")
    print("              - Starting listener...")

    def cleanup_message():
        print("\n[!] REMINDER:")
        print(f" - Delete the HiddenServiceDir (/var/lib/tor/hidden_service/)")
        print("   so a new onion address is generated next time.")
        print(" - Reset firewall rules.")
        print(" - Comment out or remove the HiddenServicePort lines you added to torrc.")
        print(" - Restart Tor after cleanup to restore normal behavior.\n")
        input("--- PRESS ENTER TO EXIT ---")

    # Handle Ctrl+C clean exit
    def handle_exit(sig, frame):
        print(f"\n{timestamp()}[+] Closing server...")
        server.close()
        print(f"{timestamp()}[+] Server closed")
        cleanup_message()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, lport))
    server.listen()
    print(f"              + Listening on {ip}:{lport}")
    print(f"\n{timestamp()}[+] Server started, url found at /var/lib/tor/hidden_service/hostname")

    

    while True:
        conn, addr = server.accept()
        threading.Thread(target=client_handler, args=(conn, addr, clients), daemon=True).start()

if __name__ == "__main__":
    main()
