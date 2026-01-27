from gclass import Profile, State
import fcrypto
import fui

import socket
import threading
from typing import Tuple
import struct
import json
import shutil
import re
import os


### Raw datastream
def recv_exact(sock, n):
    """ Reads <n> bytes out of <sock> """
    buffer = b''
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            return None #Connection closed
        buffer += chunk
    return buffer

def pack_message(msg_type: int, header: dict, recipient: str, data: bytes) -> bytes:
    header_json = json.dumps(header).encode("utf-8")
    recipient_bytes = recipient.encode("utf-8")
    return (
        struct.pack(">B", msg_type) +
        struct.pack(">I", len(header_json)) + header_json +
        struct.pack(">I", len(recipient_bytes)) + recipient_bytes +
        struct.pack(">Q", len(data)) + data
    )

def unpack_message(sock: socket.socket, profile: Profile, serverNN: str) -> Tuple[int, dict, str, bytes]:
    raw_type = recv_exact(sock, 1)
    if not raw_type: raise ConnectionError("Lost connection")
    msg_type = struct.unpack(">B", raw_type)[0]

    raw_h_len = recv_exact(sock, 4)
    header_len = struct.unpack(">I", raw_h_len)[0]
    header = json.loads(recv_exact(sock, header_len).decode("utf-8"))
    sender = header.get("sender", "Unknown")

    raw_r_len = recv_exact(sock, 4)
    recipient_len = struct.unpack(">I", raw_r_len)[0]
    recipient = recv_exact(sock, recipient_len).decode("utf-8")

    raw_d_len = recv_exact(sock, 8)
    data_len = struct.unpack(">Q", raw_d_len)[0]
    allowed = False
    if msg_type == 0x01:
        allowed = determine_accept_action("m", sender, profile)
    elif msg_type == 0x02:
        allowed = determine_accept_action("f", sender, profile)
    elif msg_type == 0x03:
        #allowed = sender == serverNN
        allowed = True
    
    #total, used, free = shutil.disk_usage(".") 
    #has_disk_space = free > (data_len + (100 * 1024 * 1024)) #100MB padding

    #Check profile.maxMsgLen
    data = b""
    if allowed and data_len <= profile.maxMsgLen:
        #MEM_LIMIT = 10*1024*1024 #10MB
        #eventually force large messages into tmpfiles and check hasDiskSpace above
        chunks = []
        bytes_received = 0
        while bytes_received < data_len:
            #Read 64kb at a time
            chunk = sock.recv(min(data_len - bytes_received, 65536))
            if not chunk: raise ConnectionError("Socket closed during transfer")
            chunks.append(chunk)
            bytes_received += len(chunk)
        data = b"".join(chunks)
    else:
        #Drain message
        remaining = data_len
        while remaining > 0:
            #Read into buffer to discard
            chunk = sock.recv(min(remaining, 65536))
            if not chunk: break
            remaining -= len(chunk)
    return msg_type, header, recipient, data

### Startup
def start_listener(sock, room_name: str, profile: Profile, state: State):
    """
    Starts a separate thread to listen to incoming messages.
    """
    t = threading.Thread(target=handle_incoming, args=(sock, room_name, profile, state), daemon=True)
    t.start()
    return t

### Handler
def handle_incoming(sock, room_name: str, profile: Profile, state: State):
    """
    Continuously read messages from a socket and dispatch to the correct handler.
    #Guide:
    #0x01 = message
    #0x02 = file transfer
    #0x03 = Client list
    """
    while state.currentRoom == room_name:
        try:
            msg_type, header, recipient, data = unpack_message(sock, profile, state.serverNN)
            if data:
                #Ignore messages not for this client
                #if recipient != profile.fingerprint:
                    #continue
                if msg_type == 0x01:
                    #Standard text message
                    receive_signed_message(data, header, profile, state.screenBuffer)
                elif msg_type == 0x02:
                    #File transfer (need room name for sorting)
                    receive_signed_file(data, header, room_name, profile, state.screenBuffer)
                elif msg_type == 0x03:
                    #Client list from server
                    handle_client_list(data, header, profile, state)
                else:
                    #fui.printBuff(f"[!] Unknown message type {msg_type} received", state.screenBuffer) ignore for now
                    continue
                fui.updateScreen(state.screenBuffer, state.connStatus, profile.nickname, room_name, True)
        except ConnectionError:
            fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, fui.get_identity_color(profile.fingerprint, state.server_peers, profile))}] Left", state.screenBuffer)
            fui.printBuffCmt("[-] Connection closed", state.screenBuffer)
            state.server_peers = []
            state.connStatus = False
            state.currentRoom = ""
            break
        except Exception as e:
            fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'cyan')}] Left: {e}", state.screenBuffer)
            break
    fui.updateScreen(state.screenBuffer, state.connStatus, profile.nickname, room_name, True)

### Handles and transmitters
#0x01 (messages)
def send_message(sock, msg: str, recipient: str, senderfp: str, arg):
    if "DM" in arg:
        header = {"sender": senderfp, "DM": "YES"}
    if "UE" in arg:
        #UE SHOULD ONLY BE DM
        header = {"sender": senderfp, "DM": "YES", "UE":"YES"}
        #header = {"sender": "A7F983289F26F629F742A35338B2FAD8B4F7E6A9", "DM": "YES", "UE":"YES"}
    if arg == "":
        header = {"sender": senderfp}
        #header = {"sender": "A7F983289F26F629F742A35338B2FAD8B4F7E6A9"}

    if "UE" in arg:
        #dont encrypt just encode
        encrypted = msg.encode()
    else:
        encrypted = fcrypto.gpg_sign_and_encrypt(msg.encode(), recipient, senderfp)
    
    packed = pack_message(0x01, header, recipient, encrypted)
    sock.sendall(packed)

def receive_signed_message(data: bytes, header: dict, profile: Profile, screenBuffer):
    sender = header.get("sender", "Unknown") #fingerprint
    isDM = header.get("DM") == "YES"
    isUE = header.get("UE") == "YES"
    try:
        #Get subtypes
        typestr = ""
        if not isUE:
            decrypted_bytes, signer_fp = fcrypto.gpg_decrypt_and_verify(data)
            if signer_fp:
                if not determine_accept_action("msg", signer_fp, profile):
                    #Signature present (gpg decrypted) but blocked by policy
                    return
            if decrypted_bytes:
                #No signature but decrypted
                decrypted_text = decrypted_bytes.decode()
                message_body = fcrypto.extract_signed_text(decrypted_text)
        else:
            message_body = data.decode()
            typestr += f"[{fui.color('UE','orange')}]"
            isDM = True
        if isDM:
            typestr += f"[{fui.color('DM','purple')}]"
        #Notify
        alias_match = None
        if signer_fp:
            #Signed
            for alias, fps in profile.aliases.items():
                if signer_fp in fps:
                    alias_match = alias
                    break
            if sender == signer_fp:
                #Sig match
                if alias_match:
                    #Known + trusted signer
                    fui.printBuff(f"{fui.timestamp()}{typestr}[{fui.color(alias_match, 'green')}]:{message_body}", screenBuffer)
                else:
                    #Signed but unknown key (for allow in firewall)
                    fui.printBuff(f"{fui.timestamp()}{typestr}[{fui.color(sender[:8] + '..', 'blue')}]:{message_body}", screenBuffer)
            else:
                #Sig mismatch (sig fp != claimed fp)
                if alias_match:
                    fui.printBuff(f"{fui.timestamp()}{typestr}{fui.color('[!]', 'orange')}[\"{fui.color(alias_match, 'yellow')}\"]:{message_body}", screenBuffer)
                else:
                    fui.printBuff(f"{fui.timestamp()}{typestr}{fui.color('[!]', 'orange')}[\"{fui.color(sender[:8] + '..', 'yellow')}\"]:{message_body}", screenBuffer)
                fui.printBuff(fui.color(f"[!] Signed by different key:", "orange") + signer_fp, screenBuffer)
        else:
            #Not signed
            alias_match = None
            for alias, fps in profile.aliases.items():
                if sender in fps:
                    alias_match = alias
                    break
            if isUE:
                #Unencrypted
                if alias_match:
                    fui.printBuff(f"{fui.timestamp()}{typestr}[\"{fui.color(alias_match, 'orange')}\"]:{fui.color(message_body, 'yellow')}", screenBuffer)
                else:
                    fui.printBuff(f"{fui.timestamp()}{typestr}[\"{fui.color(sender[:8] + '..', 'orange')}\"]:{fui.color(message_body, 'yellow')}", screenBuffer)
            elif message_body:
                #No signature found (or not signed)
                if alias_match:
                    fui.printBuff(f"{fui.timestamp()}{typestr}{fui.color('[!]', 'orange')}[\"{fui.color(alias_match, 'yellow')}\"]:{message_body}", screenBuffer)
                else:
                    fui.printBuff(f"{fui.timestamp()}{typestr}{fui.color('[!]', 'orange')}[\"{fui.color(sender[:8] + '..', 'yellow')}\"]:{message_body}", screenBuffer)
                fui.printBuff(fui.color("[!] Could not verify sender", "orange"), screenBuffer)
            else:
                #Could not decrypt
                if alias_match:
                    fui.printBuff(f"{fui.timestamp()}{typestr}[\"{fui.color(alias_match, 'yellow')}\"] {fui.color('<Could not decrypt>', 'orange')}", screenBuffer)
                else:
                    fui.printBuff(f"{fui.timestamp()}{typestr}[\"{fui.color(sender[:8] + '..', 'yellow')}\"] {fui.color('<Could not decrypt>', 'orange')}", screenBuffer)
    except Exception as e:
        #Misc gpg errors
        fui.printBuff(f"{fui.timestamp()}[\"{fui.color(sender, 'yellow')}\"]{fui.color(f'[!] <Message decryption error>: {e}', 'red')}", screenBuffer)

#0x02 (files)
def send_file(sock, filepath: str, recipient: str, senderfp: str, arg, screenBuffer):
    try:
        isdir = False
        if os.path.isdir(filepath):
            isdir = True
            zipname = filepath.rstrip("/") + ".zip"
            with zipfile.ZipFile(zipname, 'w', zipfile.ZIP_DEFLATED) as z:
                for root, dirs, files in os.walk(filepath):
                    for file in files:
                        z.write(os.path.join(root, file), arcname=os.path.relpath(os.path.join(root, file), filepath))
            filepath = zipname  #overwrite with .zip path

        filename = os.path.basename(filepath.rstrip(os.sep))

        with open(filepath, 'rb') as f:
            raw_data = f.read()

        if "DM" in arg:
            header = {"sender": senderfp,"filename": filename , "DM": "YES", "FP": senderfp}
        if "UE" in arg:
            header = {"sender": senderfp,"filename": filename , "DM": "YES", "FP": senderfp,"UE":"YES"}
        if arg == "":
            header = {"sender": senderfp,"filename": filename , "FP": senderfp}

        if "UE" not in arg:
            encrypted = fcrypto.gpg_sign_and_encrypt_binary(raw_data, recipient, senderfp)
        else:
            #dont encrypt
            encrypted = raw_data
        packed = pack_message(0x02, header, recipient, encrypted)
        sock.sendall(packed)
        if isdir:
            try:
                os.remove(zipname)
            except FileNotFoundError:
                pass
    except Exception as e:
        fui.printBuffCmt(f"[-] Error sending file: {e}", screenBuffer)

def receive_signed_file(data: bytes, header: dict, room_name: str, profile: Profile, screenBuffer):

    def get_unique_filename(base_path: str, name: str) -> str:
        """Returns a filename that does not exist in the base_path by appending _1, _2, etc."""
        name_no_ext, ext = os.path.splitext(name)
        candidate = name
        i = 1
        while os.path.exists(os.path.join(base_path, candidate)):
            candidate = f"{name_no_ext}_{i}{ext}"
            i += 1
        return candidate

    #Prohibits path traversal attacks (i think)
    def sanitize_filename(filename: str) -> str:
        return os.path.basename(filename.replace("\\", "/"))

    filename = sanitize_filename(header.get("filename", "unnamed.dat"))
    sender = header.get("sender", "Unknown")

    homedir = os.path.expanduser("~")
    homeddir = os.path.join(homedir, "Downloads")
    if profile.defDdir != "":
        if os.path.exists(profile.defDdir):
            log_path = profile.defDdir
        else:
            fui.printBuffCmt(f"[-] Cannot find '{profile.defDdir}', defaulting", screenBuffer)
            log_path = os.path.join(homeddir, room_name)
    else:
        log_path = os.path.join(homeddir, room_name)
    os.makedirs(log_path, exist_ok=True)

    #Generate safe filename if exists
    filename = get_unique_filename(log_path, filename)
    dec_path = os.path.join(log_path, filename)
    isDM = header.get("DM") == "YES"
    typestr = ""
    if isDM:
        typestr += f"[{fui.color('DM','purple')}]"

    try:
        decrypted_data, signer_fp = fcrypto.gpg_decrypt_and_verify_binary(data)

        #Early reject if signature present but not accepted
        if signer_fp is not None and not determine_accept_action("file", signer_fp, profile):
            #(f"{fui.timestamp()}[!] Rejected file '{filename}' from {sender} (untrusted key {signer_fp})")
            return

        acceptedFile = False

        if signer_fp:
            #Try resolve alias by fingerprint
            alias_match = None
            for alias, fps in profile.aliases.items():
                if signer_fp in fps:
                    alias_match = alias
                    break

            if alias_match:
                #Known + trusted signer
                fui.printBuff(f"{fui.timestamp()}{typestr}[{fui.color(alias_match, 'green')}] Sent file '{filename}'", screenBuffer)

                #Auto-accept (replace with prompt if needed)
                acceptedFile = True
                with open(dec_path, 'wb') as df:
                    df.write(decrypted_data)
                fui.printBuffCmt(f"[+] Saved '{dec_path}'", screenBuffer)
            else:
                #Signed but unknown key
                fui.printBuff(f"{fui.timestamp()}{typestr}{fui.color(f'[!]{signer_fp[:8]}...[!]', 'red')}[\"{fui.color(sender, 'yellow')}\"] Sent file '{filename}'", screenBuffer)
        else:
            #No signature
            fui.printBuff(f"{fui.timestamp()}{typestr}{fui.color('[!]NO SIG[!]', 'red')}[\"{fui.color(sender, 'yellow')}\"] Sent file '{filename}'", screenBuffer)
    except Exception as e:
        fui.printBuff(f"{fui.timestamp()}{typestr}[\"{fui.color(sender, 'yellow')}\"]{fui.color(f'[!] <File decryption error>: {e}', 'red')}", screenBuffer)
    if not acceptedFile and os.path.exists(dec_path):
            os.remove(dec_path)

#0x03 (server)
def handle_client_list(data: bytes, header: dict, profile: Profile, state: State):
    """
    Receives a list of online fingerprints from the server and updates global server_peers.
    Also generates join/leave notifications for peers entering or leaving.
    """
    try:
        decoded = json.loads(data.decode())
        prev_peers = set(state.server_peers) if state.server_peers else set()

        #Normalize into list of strings (fps)
        if isinstance(decoded, dict):
            new_peers = set(map(str, decoded.keys()))
        elif isinstance(decoded, list):
            new_peers = set(map(str, decoded))
        else:
            raise ValueError()

        #Compare
        joined = new_peers - prev_peers
        left = prev_peers - new_peers

        state.server_peers = list(new_peers)

        def display_peer(fp):
            """Return display name for a fingerprint (alias or raw)."""
            if fp == profile.fingerprint:
                return profile.nickname
            for name, fps in profile.aliases.items():
                if fp in fps:
                    return name
            return fp

        for fp in sorted(joined):
            display = display_peer(fp)
            color = fui.get_identity_color(fp, state.server_peers, profile)
            fui.printBuff(f"{fui.timestamp()}[{fui.color(display, color)}] Joined", state.screenBuffer)
        for fp in sorted(left):
            display = display_peer(fp)
            color = fui.get_identity_color(fp, state.server_peers, profile)
            fui.printBuff(f"{fui.timestamp()}[{fui.color(display, color)}] Left", state.screenBuffer)
    except Exception as e:
        state.server_peers = []
        fui.printBuffCmt(f"[!] Failed to parse client list:{e}", state.screenBuffer)



### ONION connections
def connect_to_onion_server(host: str, port: int, proxy: str, pport: int) -> socket.socket:
    """
    Connect to a Tor hidden service through the local SOCKS5 proxy.
    """
    if not is_tor_running(proxy, pport):
        raise ConnectionError(f"SOCKS5 proxy not reachable at {proxy}:{pport}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((proxy, pport))

    #SOCKS5 handshake
    sock.sendall(b"\x05\x01\x00")  #VER NMETHODS METHODS
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        raise ConnectionError("SOCKS5 proxy refused connection")

    #Request connection to destination (host:port)
    host_bytes = host.encode("utf-8")
    port_bytes = struct.pack(">H", port)
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port_bytes
    sock.sendall(req)
    resp = sock.recv(10)
    if len(resp) < 2 or resp[1] != 0x00:
        raise ConnectionError(f"SOCKS5 failed to connect to {host}:{port}")

    return sock

def is_tor_running(proxy: str,pport: int) -> bool:
    """
    Checks if Tor is running, guarantees the connection is closed 
    using the 'with' statement, and performs a SOCKS handshake check.
    """
    try:
        with socket.create_connection((proxy, pport), timeout=2) as s:
            #SOCKS Handshake Request
            s.sendall(b'\x05\x01\x00') 
            #Receive SOCKS Resp
            response = s.recv(2)
            #Successful SOCKS5 'No Auth'
            return response == b'\x05\x00'
            
    except (OSError, ConnectionRefusedError, socket.timeout, socket.error):
        return False

### Policy checker
def determine_accept_action(mtype: str, fingerprint: str, profile: Profile) -> bool:
    """ returns boolean based on file/msg policy mtype in ['m''f']"""
    if not fingerprint:
        return False

    if mtype.lower() in ["file","f"]:
        if profile.filePolicy == "allow":
            return fingerprint not in profile.fileBlacklist
        elif profile.filePolicy == "whitelist":
            return fingerprint in profile.fileWhitelist
        else:
            return False
    else:
        if profile.msgPolicy == "allow":
            return fingerprint not in profile.msgBlacklist
        elif profile.msgPolicy == "whitelist":
            return fingerprint in profile.msgWhitelist
        else:
            return False









