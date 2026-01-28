from fclass import State, Profile
import fcrypto
import fconn
import fui

import os
import sys
import json
import socket

def room_list(profile: Profile, state: State):
    fui.printBuff(fui.style(f"ROOMS ({len(profile.rooms)}):","bold"), state.screenBuffer)
    pad = "      "
    if not profile.rooms:
        fui.printBuffCmt(pad + "- NONE", state.screenBuffer)
        return
    for name, url in profile.rooms:
        marker = "-"
        color = "clear"
        if name == state.currentRoom:
            marker = "-"
            if state.connStatus:
                color = "blue"
        fui.printBuff(pad + fui.color(f" {marker} " + name,color), state.screenBuffer)
def room_info(profile: Profile, state: State, rname):
    if not rname:
        fui.printBuffCmt("[-] Not in a room", state.screenBuffer)
        return
    for name, url in profile.rooms:
        if name == rname:
            fui.printBuff(fui.style(f"INFO for {fui.color(rname,'blue')}:","bold"), state.screenBuffer)
            fui.printBuff(f"    \033[90mURL: {fui.color(url,'purple')}", state.screenBuffer)
            if state.connStatus:
                whoHere(profile, state)
            else:
                fui.printBuff("         " + fui.color("DISCONNECTED","red"), state.screenBuffer)
            return
    fui.printBuffCmt(f"[-] '{rname}' not found", state.screenBuffer)
def room_set(rname, profile: Profile, state: State):
    #checks nn capability
    if fcrypto.check_gpg_key(profile.fingerprint) != 2:
        fui.printBuffCmt(f"[-] No valid fingerprint set, set with 'fp <fingerprint>'", state.screenBuffer)
        return

    if state.currentRoom == rname:
        fui.printBuffCmt(f"[-] Already in '{rname}'", state.screenBuffer)
        return
    state.connStatus = False
    fui.printBuffCmt(f"[+] Connecting to {fui.color(rname,'blue') + fui.color('...','gray')}", state.screenBuffer)
    fui.updateScreen(state.screenBuffer, state.connStatus, profile.nickname, state.currentRoom, False)
    for name, rurl in profile.rooms:
        if name == rname:
            #Stop previous listener if running
            if state.current_listener_thread and state.current_listener_thread.is_alive():
                try:
                    state.current_sock.close()
                except:
                    pass
                state.current_listener_thread = None
            #Parse host and port from rurl
            try:
                if ":" in rurl:
                    host, port_str = rurl.split(":", 1)
                    port = int(port_str)
                else:
                    host = rurl
                    port = 80  #fallback
            except Exception as e:
                fui.printBuffCmt(f"[-] URL issue '{rurl}': {e}", state.screenBuffer)
                state.currentRoom = None
                return
            #Connect to new room server
            try:
                state.current_sock = fconn.connect_to_onion_server(host, port, profile.torProxyIP, profile.torProxyPort)
            except Exception as e:
                fui.printBuff(fui.color(f"[!] Failed to connect to '{rname}'","red") + f":{e}", state.screenBuffer)
                state.currentRoom = None
                return
            #Start listener thread for this room
            state.currentRoom = rname
            state.current_listener_thread = fconn.start_listener(state.current_sock, rname, profile, state)
            state.connStatus = True
            fconn.send_message(state.current_sock, "JOINMESSAGE", state.serverNN, profile.fingerprint, "UE")
            fui.clearBuff(state.screenBuffer)
            return
    fui.printBuffCmt(f"[-] Room '{rname}' not found.", state.screenBuffer)
def room_leave(profile: Profile, state: State):
    """Leave the current room and close the connection."""
    
    if not state.currentRoom:
        fui.printBuffCmt("[-] Not in any room", state.screenBuffer)
        return
    room2leave = state.currentRoom

    fui.printBuffCmt(f"[+] Leaving {fui.color(room2leave, 'blue')}{fui.color('...','gray')}", state.screenBuffer)
    fui.updateScreen(state.screenBuffer, state.connStatus, profile.nickname, state.currentRoom, True)
    state.currentRoom = ""
    #Stop listener thread
    if state.current_sock:
        try:
            state.current_sock.shutdown(socket.SHUT_RDWR)  # wake up recv()
            state.current_sock.close()
            #fui.printBuffCmt(f" [+] Closed socket", state.screenBuffer)
        except Exception as e:
            fui.printBuffCmt(f"[-] Socket Close Error: {e}", state.screenBuffer)
    #fui.updateScreen(state.screenBuffer, state.connStatus, profile.nickname, state.currentRoom, True)

    if state.current_listener_thread and state.current_listener_thread.is_alive():
        state.current_listener_thread.join(timeout=1.0)
    state.current_listener_thread = None
    #fui.printBuffCmt(f" [+] Closed listener thread", state.screenBuffer)
    state.server_peers = []
    state.current_sock = None
    state.connStatus = False
def room_add(name, url, profile: Profile, state: State):
    for rname, _ in profile.rooms:
        if rname == name:
            fui.printBuffCmt(f"[-] Room '{name}' already exists.", state.screenBuffer)
            return
    profile.rooms.append((name, url))
    fui.printBuffCmt(f"[+] Added room '{name}' @ '{url}'", state.screenBuffer)
def room_remove(nameORurl, profile: Profile, state: State):
    new_rooms = []
    removed = False
    for name, url in profile.rooms:
        if name == nameORurl or url == nameORurl:
            fui.printBuffCmt(f"[+] Removed room '{name}' ({url}).", state.screenBuffer)
            removed = True
            if state.currentRoom == name:
                state.currentRoom = ""
        else:
            new_rooms.append((name, url))
    profile.rooms[:] = new_rooms
    if not removed:
        fui.printBuffCmt(f"[-] Room '{nameORurl}' not found.", state.screenBuffer)

def alias_list(profile, state):
    fui.printBuff(fui.style(f"ALIASES ({len(profile.aliases)}):","bold"), state.screenBuffer)
    pad = "       "
    if not profile.aliases:
        fui.printBuffCmt(pad + "- NONE", state.screenBuffer)
        return

    for alias, fps in profile.aliases.items():
        fui.printBuff(pad + f"- {fui.color(alias, fui.get_identity_color(alias, state.server_peers, profile))} " + fui.color(f"({len(fps)} fps)","gray"), state.screenBuffer)
def alias_info(alias_name: str, profile: Profile, state: State):
    if alias_name not in profile.aliases:
        fui.printBuffCmt(f"[-] No alias found for '{alias_name}'", state.screenBuffer)
        return
    peers_set = set(state.server_peers) if state.server_peers else set()
    fps = profile.aliases[alias_name]
    identColor = fui.get_identity_color(alias_name, state.server_peers, profile)
    fui.printBuff(fui.style(f"INFO for {fui.color(alias_name, identColor)}:","bold"), state.screenBuffer)

    #Show each fingerprint with its color and message/file permissions
    for fp in fps:
        color = fui.get_identity_color(fp, state.server_peers, profile)  # get display color for fingerprint
        gpgStat = fcrypto.check_gpg_key(fp)
        gpgStr = "(no key)"
        if gpgStat > 1:
            #priv + pub
            gpgStr = "(priv + pub)"
        elif gpgStat > 0:
            gpgStr = "(pub)"
        #Determine permissions based on current policies
        if fp in peers_set:
            msg_perm = "\033[92mALLOW\033[0m" if fconn.determine_accept_action("m", fp, profile) else "\033[91mDENY\033[0m"
            file_perm = "\033[92mALLOW\033[0m" if fconn.determine_accept_action("f", fp, profile) else "\033[91mDENY\033[0m"
        else:
            msg_perm = "\033[90mALLOW\033[0m" if fconn.determine_accept_action("m", fp, profile) else "\033[90mDENY\033[0m"
            file_perm = "\033[90mALLOW\033[0m" if fconn.determine_accept_action("f", fp, profile) else "\033[90mDENY\033[0m"        

        fui.printBuff(f"  \033[90mPRINT: {fui.color(fp, color)} {gpgStr}", state.screenBuffer)
        fui.printBuff(f"    \033[90mMSG: {msg_perm}", state.screenBuffer)
        fui.printBuff(f"     \033[90mFT: {file_perm}", state.screenBuffer)
def alias_edit(alias_name: str, property: str, value: str, profile: Profile, state: State):

    if alias_name not in profile.aliases:
        fui.printBuffCmt(f"[-] Alias '{alias_name}' not found", state.screenBuffer)
        return

    if property.lower() in ("name", "nickname","n"):
        #Rename alias
        if value in profile.aliases:
            fui.printBuffCmt(f"[-] Alias name '{value}' already exists, not renaming", state.screenBuffer)
            return
        profile.aliases[value] = profile.aliases.pop(alias_name)
        fui.printBuffCmt(f"[+] Alias '{alias_name}' renamed to '{value}'.", state.screenBuffer)
    elif property.lower() in ("key", "fingerprint", "pubkey","k"):
        #Replace all fingerprints with a single new one
        if fcrypto.check_gpg_key(value) < 1:
            fui.printBuffCmt(f"[-] No key found by gpg for '{value}', not changing", state.screenBuffer)
            return
        if value == profile.fingerprint:
            fui.printBuffCmt(f"[-] Cannot use your own fingerprint", state.screenBuffer)
            return
        #Ensure value not tied to another alias
        for other_alias, fps in profile.aliases.items():
            if other_alias != alias_name and value in fps:
                fui.printBuffCmt(f"[-] Fingerprint '{value}' already assigned to alias '{other_alias}', not changing", state.screenBuffer)
                return

        profile.aliases[alias_name] = [value]
        fui.printBuffCmt(f"[+] Updated key(s) for '{alias_name}' to '{value}'.", state.screenBuffer)
    else:
        fui.printBuffCmt(f"[i] Usage: alias edit {alias_name} name|fingerprint <value>", state.screenBuffer)
def alias_add(alias_name: str, key: str, profile: Profile, state: State):
    if fcrypto.check_gpg_key(key) < 1:
        fui.printBuffCmt(f"[-] No key found by gpg for '{key}', not adding", state.screenBuffer)
        return
    if key == profile.fingerprint:
        fui.printBuffCmt(f"[-] Cannot use your own fingerprint", state.screenBuffer)
        return
    #Ensure key not tied to another alias
    for other_alias, fps in profile.aliases.items():
        if key in fps:
            fui.printBuffCmt(f"[-] Fingerprint '{key}' already belongs to alias '{other_alias}', not adding to '{alias_name}'.", state.screenBuffer)
            return

    if alias_name not in profile.aliases:
        profile.aliases[alias_name] = []

    profile.aliases[alias_name].append(key)
    fui.printBuffCmt(f"[+] Added key '{key}' to alias '{alias_name}'.", state.screenBuffer)
def alias_remove(name_or_key: str, profile: Profile, state: State):
    #Remove whole alias
    if name_or_key in profile.aliases:
        del profile.aliases[name_or_key]
        fui.printBuffCmt(f"[+] Removed alias '{name_or_key}' entirely.", state.screenBuffer)
        return

    #Remove fp
    removed_from = []
    for alias, fps in list(profile.aliases.items()):
        if name_or_key in fps:
            profile.aliases[alias].remove(name_or_key)
            removed_from.append(alias)
            if not profile.aliases[alias]:
                del profile.aliases[alias]

    if removed_from:
        fui.printBuffCmt(f"[+] Removed key '{name_or_key}' from: {', '.join(removed_from)}", state.screenBuffer)
    else:
        fui.printBuffCmt(f"[-] No alias or key '{name_or_key}' found.", state.screenBuffer)

def blockkey(ident: str, profile: Profile, state: State):
    """
    Block a fingerprint or all fingerprints tied to an alias.
    """

    fps = []
    if ident in profile.aliases:
        #alias
        fps = profile.aliases[ident]
        label = ident
    else:
        if len(ident) > 32:
            #prolly fp
            fps = [ident]
            label = ident[:8] + ".."
        else:
            fui.printBuffCmt(f"[-] '{ident}' is not an alias or valid fingerprint", state.screenBuffer)
            return

    for fp in fps:
        profile.msgWhitelist.discard(fp)
        profile.fileWhitelist.discard(fp)
        profile.msgBlacklist.add(fp)
        profile.fileBlacklist.add(fp)

    fui.printBuffCmt(f"[+] blocked '{fui.color(label,fui.get_identity_color(label, state.server_peers, profile))}\033[90m' ({len(fps)} keys)", state.screenBuffer)
def unblockkey(ident: str, profile: Profile, state: State):
    """
    Unblock a fingerprint or all fingerprints tied to an alias.
    """

    fps = []
    if ident in profile.aliases:
        fps = profile.aliases[ident]
        label = ident
    else:
        if len(ident) > 32:
            fps = [ident]
            label = ident[:8] + ".."
        else:
            fui.printBuffCmt(f"[-] '{ident}' is not an alias or valid fingerprint", state.screenBuffer)
            return

    removed = False
    for fp in fps:
        if fp in profile.msgBlacklist:
            profile.msgBlacklist.remove(fp)
            removed = True
        if fp in profile.fileBlacklist:
            profile.fileBlacklist.remove(fp)
            removed = True
    if removed:
        fui.printBuffCmt(f"[+] unblocked '{fui.color(label,fui.get_identity_color(label, state.server_peers, profile))}\033[90m' ({len(fps)} keys)", state.screenBuffer)
    else:
        fui.printBuffCmt(f"[-] '{label}' not blocked", state.screenBuffer)

def changeNN(newName, profile: Profile, state: State):
    if "@" not in newName:
        if newName not in profile.aliases.items():
            profile.nickname = newName
        else:
            fui.printBuffCmt("[-] Nickname cannot match alias", state.screenBuffer)
    else:
        fui.printBuffCmt("[-] Nickname cannot have '@'", state.screenBuffer)
def chgfingerprint(newFingerprint, profile: Profile, state: State):
    if fcrypto.check_gpg_key(newFingerprint) == 2:
        profile.fingerprint = newFingerprint
        fui.printBuffCmt(f"[+] Changed primary fingerprint to '{newFingerprint}'", state.screenBuffer)
    else:
        fui.printBuffCmt("[-] Need private & public key to sign/decrypt", state.screenBuffer)

def whoHere(profile: Profile, state: State):
    if not state.connStatus:
        fui.printBuffCmt("[-] Offline", state.screenBuffer)
        return
    online = 1
    if state.server_peers:
        online = len(state.server_peers)
    fui.printBuff(fui.style(f"ONLINE ({online}):","bold"), state.screenBuffer)
    pad = "       "
    fui.printBuff(pad + f"- {fui.color(profile.nickname,'cyan') + fui.color(' (YOU)','gray')}", state.screenBuffer)

    if state.server_peers:
        for fp in state.server_peers:
            if fp == profile.fingerprint:
                continue

            #Resolve name
            alias_name = None
            for name, fps in profile.aliases.items():
                if fp in fps:
                    alias_name = name
                    break

            display = alias_name if alias_name else fp
            status_color = fui.get_identity_color(fp, state.server_peers, profile)
            fui.printBuff(pad + f"- {fui.color(display, status_color)}", state.screenBuffer)

    fui.printBuff("", state.screenBuffer)

def whois(profile: Profile, state: State, fingerprint):
    for alias, fps in profile.aliases.items():
        if fingerprint in fps:
            alias_info(alias, profile, state)
            return
    if len(fingerprint) < 33:
        fui.printBuffCmt(f"[-] '{fingerprint}' is not a valid fingerprint or alias", state.screenBuffer)
    online = fingerprint in state.server_peers
    color = fui.get_identity_color(fingerprint, state.server_peers, profile)
    gpgStat = fcrypto.check_gpg_key(fingerprint)
    gpgStr = "(no key)"
    if gpgStat > 1:
        #priv + pub
        gpgStr = "(priv + pub)"
    elif gpgStat > 0:
        gpgStr = "(pub)"
    #Determine permissions based on current policies
    if online:
        msg_perm = "\033[92mALLOW\033[0m" if fconn.determine_accept_action("m", fingerprint, profile) else "\033[91mDENY\033[0m"
        file_perm = "\033[92mALLOW\033[0m" if fconn.determine_accept_action("f", fingerprint, profile) else "\033[91mDENY\033[0m"
    else:
        msg_perm = "ALLOW" if fconn.determine_accept_action("m", fingerprint, profile) else "DENY"
        file_perm = "ALLOW" if fconn.determine_accept_action("f", fingerprint, profile) else "DENY"
    fui.printBuff(fui.style(f"INFO for {fui.color(fingerprint, color)}:","bold"), state.screenBuffer)
    fui.printBuff(f"  \033[90mPRINT: {fui.color(fingerprint, color)} {gpgStr}", state.screenBuffer)
    fui.printBuff(f"    \033[90mMSG: {msg_perm}", state.screenBuffer)
    fui.printBuff(f"     \033[90mFT: {file_perm}\033[0m", state.screenBuffer)


def buffer_ident(profile: Profile, state: State):
    fpStr = ""
    if profile.fingerprint == "":
        fpStr = "\033[91mNO FINGERPRINT\033[0m"
    else:
        fpStr = profile.fingerprint
    fui.printBuff(f"{fui.style('YOU:','bold')}\n         {fui.color(profile.nickname,'cyan')}\n         {fui.color(fpStr,'cyan')}", state.screenBuffer)

def chgFilePolicy(policy, profile: Profile, state: State):
    if policy in ("allow", "a"):
        profile.filePolicy = "allow"
        color = "green"
    elif policy in ("deny", "d"):
        profile.filePolicy = "deny"
        color = "red"
    elif policy in ("whitelist", "w"):
        profile.filePolicy = "whitelist"
        color = "white"
    else:
        fui.printBuffCmt("[-] Policy options are allow, deny, whitelist", state.screenBuffer)
        return
    fui.printBuffCmt(f"[+] Changed file policy to {fui.color(profile.filePolicy.upper(),color)}", state.screenBuffer)

def chgMsgPolicy(policy, profile: Profile, state: State):
    if policy in ("allow", "a"):
        profile.msgPolicy = "allow"
        color = "green"
    elif policy in ("deny", "d"):
        profile.msgPolicy = "deny"
        color = "red"
    elif policy in ("whitelist", "w"):
        profile.msgPolicy = "whitelist"
        color = "white"
    else:
        fui.printBuffCmt("[-] Policy options are allow, deny, whitelist", state.screenBuffer)
    fui.printBuffCmt(f"[+] Changed message policy to {fui.color(profile.msgPolicy.upper(),color)}", state.screenBuffer)

def chgPolicyLists(msgType, ident, action, profile: Profile, state: State):
    """
    Change whitelist/blacklist policies for message or file transfers.
    
    msgType: "file" or "msg"
    action: "allow" or "deny"
    ident: fingerprint (>32 chars) or alias (resolve to one or more fingerprints)
    """
    if msgType == "file":
        whitelist, blacklist = profile.fileWhitelist, profile.fileBlacklist
    else:
        whitelist, blacklist = profile.msgWhitelist, profile.msgBlacklist
    fps = []
    if len(ident) > 32:  
        #raw fp
        fps = [ident]
    else:
        for name, fprints in profile.aliases.items():
            if name == ident:
                fps.extend(fprints)
    if not fps:
        print(f"[-] No valid fingerprints found for '{ident}'.")
        return
    for fp in fps:
        if action in ("allow","a"):
            if fp in blacklist:
                blacklist.remove(fp)
            if fp not in whitelist:
                whitelist.add(fp)
                fui.printBuffCmt(f"[+] {fp[:8]}.. added to {msgType} whitelist", state.screenBuffer)
            else:
                fui.printBuffCmt(f"[-] {fp[:8]}.. alr on {msgType} whitelist", state.screenBuffer)
        elif action in ("deny","d"):
            if fp in whitelist:
                whitelist.remove(fp)
            if fp not in blacklist:
                blacklist.add(fp)
                fui.printBuffCmt(f"[+] {fp[:8]}.. added to {msgType} blacklist", state.screenBuffer)
            else:
                fui.printBuffCmt(f"[-] {fp[:8]}.. alr on {msgType} blacklist", state.screenBuffer)
        else:
            fui.printBuffCmt(f"[i] Usage: policy {msgType} {ident} allow|deny", state.screenBuffer)
def bufferPolicyInfo(profile: Profile, state: State):
    msgColor = ""
    fileColor = ""
    mspecstr = ""
    fspecstr = ""
    if profile.msgPolicy == "allow":
        msgColor = "green"
        if len(profile.msgBlacklist) > 0:
            mspecstr = f"\033[90m (\033[91m{len(profile.msgBlacklist)}\033[90m)"
    elif profile.msgPolicy == "deny":
        msgColor = "red"
    else:
        msgColor = "white"
        mspecstr = f"\033[90m (\033[92m{len(profile.msgWhitelist)}\033[90m)"

    if profile.filePolicy == "allow":
        fileColor = "green"
        if len(profile.fileBlacklist) > 0:
            fspecstr = f" (\033[91m{len(profile.fileBlacklist)}\033[90m)"
    elif profile.filePolicy == "deny":
        fileColor = "red"
    else:
        fileColor = "white"
        fspecstr = f"\033[90m (\033[92m{len(profile.fileWhitelist)}\033[90m)"
    msgStr = fui.color(profile.msgPolicy.upper(), msgColor)
    fileStr = fui.color(profile.filePolicy.upper(), fileColor)
    if mspecstr:
        msgStr += mspecstr
    if fspecstr:
        fileStr += (fspecstr + "\033[0m")
    fui.printBuff(f"{fui.style('POLICY:','bold')}\n    \033[90mMSG: " + msgStr + "\n     \033[90mFT: " + fileStr, state.screenBuffer)

def chgTorProxy(ipport, profile: Profile, state: State):
    try:
        if ':' not in ipport:
            raise ValueError("VALUE ERROR")
        parts = ipport.split(':')
        ip = parts[0]
        port = parts[1]
        profile.torProxyIP = ip
        profile.torProxyPort = int(port)
        fui.printBuffCmt(f"[+] Changed socks5 proxy to '{ip}:{port}'", state.screenBuffer)
    except ValueError as e:
        #formatting wrong
        fui.printBuffCmt(f"[-] Usage: tor proxy <ip:port> (default: 127.0.0.1:9050)", state.screenBuffer)
    except Exception as e:
        #other error
        fui.printBuffCmt(f"[-] Unexpected error: {e}", state.screenBuffer)
def printTorStat(profile: Profile, state: State):
    fui.printBuff(fui.style("PROXY:","bold"), state.screenBuffer)
    pad = "         "
    fui.printBuff(pad + f"{profile.torProxyIP}:{profile.torProxyPort}", state.screenBuffer)
    if fconn.is_tor_running(profile.torProxyIP, profile.torProxyPort):
        if state.connStatus:
            fui.printBuff(pad + fui.color("CONNECTED","purple"), state.screenBuffer)
        else:
            fui.printBuff(pad + fui.color("REACHABLE","blue"), state.screenBuffer)
    else:
        fui.printBuff(pad + fui.color("UNREACHABLE","red"), state.screenBuffer)

def bufferPolicyList(listType, color, profile: Profile, state: State):
    """
    Print whitelist/blacklist contents for messages or files.
    listType: "file" or "msg"
    color:    "whitelist"/"wl"/"w" or "blacklist"/"blist"/"b"
    """

    #normalize args
    listType = listType.lower()
    color = color.lower()

    if color in ("whitelist", "wl", "w"):
        listName = "Whitelist"
        activeList = profile.fileWhitelist if listType == "file" else profile.msgWhitelist
    elif color in ("blacklist", "blist", "b"):
        listName = "Blacklist"
        activeList = profile.fileBlacklist if listType == "file" else profile.msgBlacklist
    else:
        fui.printBuffCmt(f"[i] Usage: policy file list whitelist|blacklist", state.screenBuffer)
        return

    header = f"{listType.capitalize()} {listName}:"
    fui.printBuff(header, state.screenBuffer)

    if not activeList:
        fui.printBuffCmt("  - NONE", state.screenBuffer)
        return

    for fp in activeList:
        #resolve names
        alias_matches = [alias for alias, fps in profile.aliases.items() if fp in fps]
        if alias_matches:
            alias_str = ",".join(alias_matches)
            ident_str = f"{alias_str}:{fp}"
        else:
            ident_str = fp

        status_color = fui.get_identity_color(fp, state.server_peers, profile)
        fui.printBuff(f"  - {fui.color(ident_str,status_color)}", state.screenBuffer)

###   SETTINGS
#CONFIG FILE FUNCTIONS
def config_path() -> str:
    """Returns the standard path for the config file '~/.config/freq/cfg.json'
     Will create a freq folder in ~/.config/freq
    """
    homedir = os.path.expanduser("~")
    dotConfigDir = os.path.join(homedir, ".config")
    config_dir = os.path.join(dotConfigDir, "freq")
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, "profile.json")

def chgDir(profile: Profile, state: State, Dtype, directory=""):
    if directory == "":
        if Dtype == "d":
            profile.defDdir = ""
            fui.printBuffCmt(f"[+] Using default directory for downloads (~/Downloads/<room>/)", state.screenBuffer)
            return

    if not os.path.isdir(directory):
        fui.printBuffCmt(f"[-] '{directory}' not valid dir", state.screenBuffer)
        return
    if not os.access(directory, os.W_OK):
        fui.printBuffCmt(f"[-] '{directory}' not writeable", state.screenBuffer)
        return

    if Dtype == "d":
        #download
        profile.defDdir = directory
        fui.printBuffCmt(f"[+] Using '{directory}' for downloads", state.screenBuffer)

def save_config(profile: Profile, state: State, filepath: str=""):
    """Saves <profile> state into [<path>]"""
    if not filepath:
        filepath = config_path()
    dir_path = os.path.dirname(filepath)
    if not dir_path:
        fui.printBuffCmt(f"[-] Path '{filepath}' not found", state.screenBuffer)
        return
    config_data = {
        "identity": {
            "nickname": profile.nickname,
            "fingerprint": profile.fingerprint
        },
        "network": {
            "tor_proxy_ip": profile.torProxyIP,
            "tor_proxy_port": profile.torProxyPort
        },
        "rooms": profile.rooms,
        "aliases": profile.aliases,
        "policies": {
            "messages": {
                "policy": profile.msgPolicy,
                "whitelist": list(profile.msgWhitelist),
                "blacklist": list(profile.msgBlacklist)
            },
            "files": {
                "policy": profile.filePolicy,
                "whitelist": list(profile.fileWhitelist),
                "blacklist": list(profile.fileBlacklist)
            }
        },
        "dirs": {
            "download": profile.defDdir
        }
    }

    try:
        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=4)
        fui.printBuffCmt(f"[+] Settings saved to '{filepath}'", state.screenBuffer)
    except Exception as e:
        fui.printBuffCmt(f"[-] Error saving settings: {e}", state.screenBuffer)

def load_config(profile: Profile, state: State, filepath: str=""):
    """Loads settings from the config file at [<filepath>] and populates <profile>"""
    if not filepath:
        filepath = config_path()
    if not os.path.exists(filepath):
        fui.printBuffCmt(f"[-] Config file not found at '{filepath}'", state.screenBuffer)
        fui.printBuffCmt(f"[-] To save settings type 'settings save'", state.screenBuffer)
        return
    fui.printBuffCmt(f"[+] Loading settings from '{filepath}'...", state.screenBuffer)
    if state.connStatus:
        fui.printBuffCmt(f"[+] Dropping connections..", state.screenBuffer)
        room_leave(profile, state)
    try:
        with open(filepath, 'r') as f:
            config_data = json.load(f)

        #Load data w fallback
        identity = config_data.get("identity", {})
        profile.nickname = identity.get("nickname", profile.nickname)
        profile.fingerprint = identity.get("fingerprint", profile.fingerprint)

        network = config_data.get("network", {})
        profile.torProxyIP = network.get("tor_proxy_ip", profile.torProxyIP)
        profile.torProxyPort = network.get("tor_proxy_port", profile.torProxyPort)
        profile.rooms = config_data.get("rooms", profile.rooms)

        new_aliases = config_data.get("aliases", profile.aliases)
        #Rename alias with duplicate name as nickname
        if profile.nickname in new_aliases:
            renamed_key = f"alias_{profile.nickname}"
            new_aliases[renamed_key] = new_aliases.pop(profile.nickname)
            fui.printBuffCmt(f"[-] Alias '{profile.nickname}' renamed to '{renamed_key}'", state.screenBuffer)
        profile.aliases = new_aliases

        policies = config_data.get("policies", {})
        msg_policies = policies.get("messages", {})
        profile.msgPolicy = str(msg_policies.get("policy", profile.msgPolicy))
        profile.msgWhitelist = set(msg_policies.get("whitelist", []))
        profile.msgBlacklist = set(msg_policies.get("blacklist", []))

        file_policies = policies.get("files", {})
        profile.filePolicy = str(file_policies.get("policy", profile.filePolicy))
        profile.fileWhitelist = set(file_policies.get("whitelist", []))
        profile.fileBlacklist = set(file_policies.get("blacklist", []))

        dirs = config_data.get("dirs",{})
        profile.defDdir = str(dirs.get("download", profile.defDdir))

        fui.printBuffCmt(f"[+] Settings loaded from '{filepath}'", state.screenBuffer)

    except json.JSONDecodeError:
        fui.printBuffCmt(f"[-] Could not parse config file at '{filepath}'. Using defaults.", state.screenBuffer)
    except Exception as e:
        fui.printBuffCmt(f"[-] Error loading settings: {e}", state.screenBuffer)

def reset_settings(profile: Profile, state: State):
    fui.printBuffCmt("[+] Resetting settings...", state.screenBuffer)
    if state.connStatus:
        fui.printBuffCmt(f"[+] Dropping connections..", state.screenBuffer)
        room_leave(profile, state)
    blank_p = Profile()
    return blank_p

def buffer_current_settings(profile: Profile, state: State, praw=0):
    if praw:
        config_data = {
        "identity": {
            "nickname": profile.nickname,
            "fingerprint": profile.fingerprint
        },
        "network": {
            "tor_proxy_ip": profile.torProxyIP,
            "tor_proxy_port": profile.torProxyPort
        },
        "rooms": profile.rooms,
        "aliases": profile.aliases,
        "policies": {
            "messages": {
                "policy": profile.msgPolicy,
                "whitelist": list(profile.msgWhitelist),
                "blacklist": list(profile.msgBlacklist)
            },
            "files": {
                "policy": profile.filePolicy,
                "whitelist": list(profile.fileWhitelist),
                "blacklist": list(profile.fileBlacklist)
            }
        },
        "dirs": {
            "download": profile.defDdir,
        }
    }
        fui.printBuff(f"--- ACTIVE ---", state.screenBuffer)
        fui.printBuff(json.dumps(config_data, indent=0), state.screenBuffer)
        fui.printBuff(f"---- EOS -----", state.screenBuffer)
    else:
        fui.printBuff(fui.style("ACTIVE SETTINGS:","bold"), state.screenBuffer)
        buffer_ident(profile, state)
        bufferPolicyInfo(profile, state)
        printTorStat(profile, state)
        room_list(profile, state)
        alias_list(profile, state)

def buffer_file_settings(state: State):
    path = config_path()
    fui.printBuffCmt(f"[+] Parsing '{path}'...", state.screenBuffer)
    #raw only
    if os.path.exists(path):
        with open(path, 'r') as f:
            fui.printBuff("--- Content ---", state.screenBuffer)
            for line in f:
                fui.printBuff(line.strip(), state.screenBuffer)
            fui.printBuff("----- EOF -----", state.screenBuffer)
    else:
        fui.printBuffCmt(f"[-] No settings file exists at {config_path}", state.screenBuffer)

def buffer_version_menu(state: State, version):
    #just print banner for now
    fui.bufferBanner(state.screenBuffer, version)
    fui.printBuffCmt("SRC: " + fui.color("https://github.com/MaxPep001011/freq","blue"), state.screenBuffer)

###   MESSAGING
def send_message_to_aliases(profile: Profile, state: State, raw_msg):
    if state.connStatus:
        #send to all recognized fp
        for alias_name, fps in profile.aliases.items():
            for fpr in fps:
                if fpr in state.server_peers:
                    if fcrypto.check_gpg_key(fpr) > 0:
                        fconn.send_message(state.current_sock, raw_msg, fpr, profile.fingerprint, "")
        fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'cyan')}]:{raw_msg}", state.screenBuffer)
    else:
        fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'gray')}]:{fui.color(raw_msg, 'gray')}", state.screenBuffer)

def send_file_to_aliases(profile: Profile, state: State, raw_path):
    if state.connStatus:
        for alias_name, fps in profile.aliases.items():
            for fpr in fps:
                if fpr in state.server_peers:
                    if fcrypto.check_gpg_key(fpr) > 0:
                        fconn.send_file(state.current_sock, raw_path, fpr, profile.fingerprint, "", state.screenBuffer)
        fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'cyan')}] --> '{raw_path}'", state.screenBuffer)
    else:
        fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'gray')}] --> '{fui.color(raw_path, 'gray')}'", state.screenBuffer)

def send_direct_message_to_alias(profile: Profile, state: State, alias: str, raw_msg: str):
    """
    Send a direct message to a peer. `alias` can be either:
      - a configured alias name (resolved via aliases{}), or
      - a raw fingerprint (direct).
    Can also dm a fingerprint as long as a pubkey is found.
    """
    if state.connStatus:
        target_fps = []

        #alias
        if alias in profile.aliases:
            target_fps = profile.aliases[alias]

        #fp
        elif any(alias in fps for fps in profile.aliases.values()):
            target_fps = [alias]

        if not target_fps:
            if fcrypto.check_gpg_key(alias) > 0:
                #pubkey but no alias
                target_fps.append(alias)
            else:
                fui.printBuffCmt(f"[-] No key found for '{alias}'", state.screenBuffer)
                return

        #send to each fp online
        for fpr in target_fps:
            if fpr not in state.server_peers:
                fui.printBuffCmt(f"[-] '{fpr}' not online", state.screenBuffer)
                continue

            fconn.send_message(state.current_sock, raw_msg, fpr, profile.fingerprint, "DM")
            fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'cyan')}][{fui.color('DM','purple')}>{fui.color(alias,fui.get_identity_color(alias, state.server_peers, profile))}]:{raw_msg}", state.screenBuffer)
            
    else:
        fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'gray')}][{fui.color('DM','gray')}]:{fui.color(raw_msg, 'gray')}", state.screenBuffer)

def send_direct_file_to_alias(profile: Profile, state: State, alias: str, raw_path: str):
    """
    Send a direct file to a peer. `alias` can be either:
      - a configured alias name (resolved via aliases{}), or
      - a raw fingerprint (direct).
    Can also df a fingerprint as long as a pubkey is found.
    """
    if state.connStatus:
        target_fps = []

        #name
        if alias in profile.aliases:
            target_fps = profile.aliases[alias]

        #fp
        elif any(alias in fps for fps in profile.aliases.values()):
            target_fps = [alias]

        if not target_fps:
            if fcrypto.check_gpg_key(alias) > 0:
                #pubkey but no alias
                target_fps.append(alias)
            else:
                fui.printBuffCmt(f"[-] No key found for '{alias}'", state.screenBuffer)
            return

        #send to each fp online
        for fpr in target_fps:
            if fpr not in state.server_peers:
                fui.printBuffCmt(f"[-] '{fpr}' not online", state.screenBuffer)
                continue

            fconn.send_file(state.current_sock, raw_path, fpr, profile.fingerprint, "DM", state.screenBuffer)
            fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'cyan')}][{fui.color('DM','purple')}>{fui.color(alias,fui.get_identity_color(alias, state.server_peers, profile))}] --> '{raw_path}'", state.screenBuffer)
            
    else:
        fui.printBuff(f"{fui.timestamp()}[{fui.color(profile.nickname, 'gray')}][{fui.color('DM','gray')}] --> '{fui.color(raw_path, 'gray')}'", state.screenBuffer)


