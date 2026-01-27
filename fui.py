from fclass import Profile, State
import fcrypto

import readline
import os
import sys
import time

### INPUT
def read_cmd_line():
    """
    Get next command from terminal
    """
    prompt = ""
    try:
        line = input(prompt)
        return line
    except EOFError:
        return None

### BUFFER
def clearBuff(buffer):
    buffer.clear()
def printBuff(bStr, buffer):
    buffer.append(bStr)
def printBuffCmt(bStr, buffer):
    printBuff(color(bStr,"gray"), buffer)

def updateScreen(buffer, connStatus, nickname, currentRoom, DrawPS1):
    """Redraw screen using <buffer>. if DrawPS1=1 then PS1 drawn"""
    #I know every time this is called it will shoot you all the way back down, looking for replacement or ui overhaul

    def printStatusBar(connStatus, currentRoom):
        """ Prints status bar on top of empty terminal """
        try:
            width = os.get_terminal_size().columns
        except OSError:
            width = 80

        stat_bar = color(" FREQ", "green") + ": "
        if connStatus:
            stat_bar += (color("\033[7m Connected ", "green") + color(f" @ {currentRoom}", "blue"))
        elif currentRoom == "":
            stat_bar += (color("\033[7m Disconnected ", "red") + " @ " + color("NONE", "gray"))
        else:
            stat_bar += (color("\033[7m Disconnected ", "red") + " @ " + color(f"{currentRoom}", "blue"))
        print(stat_bar)
        print("\033[90m" + ("~" * width) + "\033[0m")

    #Get current typed input before redraw
    try:
        current_line = readline.get_line_buffer()
    except Exception:
        current_line = ""

    #Cls + redraw buffer
    os.system('cls' if os.name == 'nt' else 'clear')
    printStatusBar(connStatus, currentRoom)
    if buffer:
        print("\n".join(buffer))
    if DrawPS1:
        #Redraw prompt + typed text
        atfreqStr = ""
        if connStatus:
            atfreqStr += color("@","purple")
        else:
            atfreqStr += color("@","red")
        atfreqStr += color("freq","green")
        print(f"{color(nickname,'cyan')}{atfreqStr} >> ", end="", flush=True)
        sys.stdout.write(current_line)
        sys.stdout.flush()

### STYLING
def timestamp():
    """ ret '[HH:MM:SS]' """
    return "[" + color(time.strftime("%H:%M:%S"),"gray") + "]"
#BANNER
    #  ______   ______    ______   ______        
    # /_____/\ /_____/\  /_____/\ /_____/\       
    # \::::_\/_\:::_ \ \ \:::_:\ \\:::_ \ \      
    #  \:\/___/\\:(_) ) )_  /_\:\ \\:\ \ \ \_    
    #   \:::._\/ \: __ `\ \ \::_:\ \\:\ \ /_ \   
    #    \:\ \    \ \ `\ \ \/___\:\ '\:\_-  \ \  
    #     \_\/     \_\/ \_\/\______/  \___|\_\_/ 
def bufferBanner(buffer, version=""):
    """ Prints ascii banner, lack of version => no version printed """
    printBuff(r"  ______   ______    " + color("______","green") + r"   ______        ", buffer)
    printBuff(r" /_____/\ /_____/\  " + color("/_____/\\","green") + r" /_____/\       ", buffer)
    printBuff(r" \::::_\/_\:::_ \ \ " + color("\:::_:\ \\","green") + r"\:::_ \ \      ", buffer)
    printBuff(r"  \:\/___/\\:(_) ) )_  " + color("/_\:\ \\","green") +r"\:\ \ \ \_   ", buffer)
    printBuff(r"   \:::._\/ \: __ `\ \ "+color("\::_:\ \\","green")+r"\:\ \ /_ \  ", buffer)
    printBuff("    \:\ \    \ \ `\ \ \\" + color("/___\:\ '", "green")+r"\:\_-  \ \ ", buffer)
    printBuff(r"     \_\/     \_\/ \_\/"+color("\______/","green")+r"  \___|\_\_/", buffer)
    if version:
        printBuff(f"   v{color(version, 'green')}", buffer)

def color(message: str, color: str = None) -> str:
    """ ret escaped str out of the following <color>.lower()
        - red
        - orange
        - yellow
        - green
        - blue
        - purple
        - pink
        - gray
        - cyan
        - white
        - clear
    """
    color_codes = {
        "red": "\033[91m",
        "orange": "\033[38;5;208m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "blue": "\033[94m",
        "purple": "\033[95m",
        "pink": "\033[38;5;198m",
        "gray": "\033[90m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "clear": "\033[0m"
    }
    reset = "\033[0m"
    
    if color and color.lower() in color_codes:
        return f"{color_codes[color.lower()]}{message}{reset}"
    return message

def style(message: str, style: str = None) -> str:
    """ ret escaped str out of the following <style>.lower()
        - bold
        - italic
        - strike
        - dim
        - underline
        - blink
        - reverse
    """
    #Ill use these eventually
    color_codes = {
        "bold": "\033[1m",
        "dim": "\033[2m",
        "italic": "\033[3m",
        "underline": "\033[4m",
        "blink": "\033[5m",
        "reverse": "\033[7m",
        "strike": "\033[9m"
    }
    reset = "\033[0m"
    
    if color and color.lower() in color_codes:
        return f"{color_codes[color.lower()]}{message}{reset}"
    return message

def get_identity_color(ident: str, server_peers, profile: Profile) -> str:
    """
    ret color string
    Guide:
    - You -> "cyan"
    - Blocked + Online -> "purple"
    - Blocked + Offline -> "red"
    - Unblocked:
        - Online + GPG Key -> "green" if alias else "blue"
        - Online + No GPG Key -> "yellow"
        - Offline + GPG Key -> "gray"
        - Offline + No GPG Key -> "orange"
    """
    peers_set = set(server_peers) if server_peers else set()

    def is_blocked_fp(fp: str) -> bool:
        from fconn import determine_accept_action
        return not determine_accept_action("msg", fp, profile)
    #You
    if ident in (profile.fingerprint, profile.nickname):
        return "cyan"
    target_fps = []
    is_alias = False
    #Target fp resolution
    if ident in profile.aliases:
        #alias to fps
        target_fps = profile.aliases[ident]
        is_alias = True
    else:
        #fp
        target_fps = [ident]
        for name, fps in profile.aliases.items():
            if ident in fps:
                #tied to alias
                is_alias = True
                break
    #find active fps
    active_fp = target_fps[0] if target_fps else ident
    for fp in target_fps:
        if fp in peers_set:
            active_fp = fp
            break
    #find indicators
    online = any(fp in peers_set for fp in target_fps)
    blocked = is_blocked_fp(active_fp)
    if online:
        has_key = fcrypto.check_gpg_key(active_fp) > 0
    else:
        has_key = any(fcrypto.check_gpg_key(fp) > 0 for fp in target_fps)
    #Apply color rules
    if blocked:
        return "purple" if online else "red"
    if online:
        if has_key:
            return "green" if is_alias else "blue"
        return "yellow"
    #offline
    return "gray" if has_key else "orange"





