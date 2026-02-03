# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.73"

          #          # LEFT OFF: maxMemLimit (anything above will use tmpfiles for recieving)
    #   #####   #    #  anything above memlimit should be written to a tempfile by unpacker in fconn maybe alter handles to take in optional path
  #####   #   #####  #  add limit mem <> vs limit msg <> and alter method calls to support changes to both and limit check in unpack
    #     #     #    #  add room edit. add profile switcher and maybe encrypt settings
    #           #    #  add bar to show status of sending large files? use fui.writeBuff? also add dir to 'set view active' printout
#BUGS:
#   switching profile after loading full profile prevents being able to connect to socks5 <url:port>
#   
from fclass import Profile, State
import fcrypto
import fcalls
import fconn
import fui

import signal
import sys

activeProfile = Profile()
state = State()

###   MAIN
def main():
    global activeProfile, state
    def handle_exit(sig, frame):
        #Useless for now
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_exit)

    
    fui.clearBuff(state.screenBuffer)
    fcalls.buffer_version_menu(state, ptversion)
    fcalls.load_config(activeProfile, state)
    fui.updateScreen(state.screenBuffer, state.connStatus, activeProfile.nickname, state.currentRoom, True)
    while True:
        line = fui.read_cmd_line()
        if line is None:
            break
        result = parse_command(line)
        if result == "quit":
            break
        #preserves input
        fui.updateScreen(state.screenBuffer, state.connStatus, activeProfile.nickname, state.currentRoom, True)

###   PARSER
def parse_command(line):
    global activeProfile, state

    tokens = line.strip().split()
    if not tokens:
        return

    cmd = tokens[0].lower()
    args = tokens[1:]

    ###   COMMANDS   (Im sorry)

    ### HELP STRINGS
    if True:
        helpstr = fui.style("GENERAL:\n","bold")
        helpstr += "  \033[0mnickname\033[90m(nn) - switches nickname\n     Usage: nickname <nickname>\n"
        helpstr += "  \033[0mfingerprint\033[90m(fp) - sets fingerprint\n     Usage: fingerprint <fingerprint>\n"
        helpstr += "  \033[0mme\033[90m(m) - displays your info\n\n"
        helpstr += "  \033[0malias\033[90m(p) - aliases/contacts\n     Usage: alias list|info|edit|add|remove ...\n"
        helpstr += "  \033[0msettings\033[90m(set) - settings manager\n     Usage: settings save|load|view [<path>|saved|active] [raw]\n"
        helpstr += "  \033[0mbanner\033[90m - prints banner\n"
        helpstr += "  \033[0mclear\033[90m(clr) - clears terminal or n buffer lines (not terminal lines)\n     Usage: clear [<n>]\n"
        helpstr += "  \033[0mquit\033[90m(q) - quits application\n"
        helpstr += "  \033[0mhelp\033[90m(h) - displays help strings\n     Usage: help [all|msg|conn|color|general]"
        helpstr+= "\033[0m"
        

        helpstrColor = fui.style("COLORS:\n","bold")
        helpstrColor += fui.color("  Identity colors will be resolved using the following rules:\n","gray")
        helpstrColor += fui.color("  CYAN - ","cyan") + "client privkey\n"
        helpstrColor += fui.color("  TURQUOISE - ","turquoise") + "privkey, online\n"
        helpstrColor += fui.color("  TEAL - ","teal") + "privkey, offline\n"
        helpstrColor += fui.color("  GREEN  - ","green") + "alias, pubkey, online\n"
        helpstrColor += fui.color("  BLUE  - ","blue") + "pubkey, online\n"
        helpstrColor += fui.color("  GRAY  - ","gray") + "pubkey, offline\n"
        helpstrColor += fui.color("  YELLOW  - ","yellow") + "keyless, online\n"
        helpstrColor += fui.color("  ORANGE  - ","orange") + "keyless, offline\n"
        helpstrColor += fui.color("  PURPLE  - ","purple") + "blocked, online\n"
        helpstrColor += fui.color("  RED  - ","red") + "blocked, offline"
        helpstrColor += "\033[0m"

        helpstrMsg = fui.style("MESSAGING:\n","bold")
        helpstrMsg += "  \033[0msend\033[90m(s) - send message to all aliases in room\n     Usage: send <message>\n"
        helpstrMsg += "  \033[0mfile\033[90m(f) - send file/dir to all aliases in room\n     Usage: file <path>\n"
        helpstrMsg += "  \033[0mdirectmsg\033[90m(dm) - send message to one alias/fingerprint in room\n     Usage: directmsg <identity> <message>\n"
        helpstrMsg += "  \033[0mdirectfile\033[90m(df) - send file to one alias/fingerprint in room\n     Usage: directf <identity> <path>\n"
        helpstrMsg += "  \033[0mpolicy\033[90m(p) - policy editor/viewer\n     Usage: policy message|file|info [<identity>|set|list|verbose] [allow|deny|whitelist]\n"
        helpstrMsg += "  \033[0mblock\033[90m(bl) - block key from messaging\n     Usage: block <ident>\n"
        helpstrMsg += "  \033[0munblock\033[90m(ub) - unblock key for messaging\n     Usage: unblock <ident>\n"
        helpstrMsg += "  \033[0mlimit\033[90m(lim) - set maximum size for files allowed (bytes)\n     Usage: limit <n>[MB|GB]"
        helpstrMsg += "\033[0m"

        helpstrConn = fui.style("CONNECTION:\n","bold")
        helpstrConn += "  \033[0mtor\033[90m(t) - tor proxy mgmt\n     Usage: tor status|proxy [default|<ip:port>]\n"
        helpstrConn += "  \033[0mroom\033[90m(r) - room/server mgmt\n     Usage: room list|info|set|quit|add|remove ...\n"
        helpstrConn += "  \033[0mwho\033[90m - shows connected peers in current room\n"
        helpstrConn += "  \033[0mwhose\033[90m - prints relevant info about a fingerprint\n     Usage: whose <fingerprint>\n"
        helpstrConn += "  \033[0mdirectory\033[90m(dir) - updates default directories\n     Usage: dir download [<directory>]"
        helpstrConn += "\033[0m"

    
    if cmd in ("quit", "q", "exit"):
        fui.printBuffCmt("\n[+] Quitting FR3Q...", state.screenBuffer)
        return "quit"

    elif cmd in ("help","h"):
        if args and args[0].lower() == "color":
            fui.printBuff(helpstrColor, state.screenBuffer)
        elif args and args[0].lower() in ("msg","message","messaging","m","com","communication"):
            fui.printBuff(helpstrMsg, state.screenBuffer)
        elif args and args[0].lower() in ("connection","conn"):
            fui.printBuff(helpstrConn, state.screenBuffer)
        elif args and args[0].lower() in ("all","a"):
            fui.printBuff(helpstrColor, state.screenBuffer)
            fui.printBuff(helpstr, state.screenBuffer)
            fui.printBuff(helpstrMsg, state.screenBuffer)
            fui.printBuff(helpstrConn, state.screenBuffer)
        elif args and args[0].lower() not in ("g", "general", "gen"):
            fui.printBuffCmt("[i] Usage: help [all|msg|conn|color|general]", state.screenBuffer)
        else:
            fui.printBuff(helpstr, state.screenBuffer)
            fui.printBuffCmt("[+] Note: for all commands type 'help all'", state.screenBuffer)

    elif cmd in ("clear","clr"):
        try:
            if args:
                fui.clearBuff(state.screenBuffer, int(args[0]))
            else:
                fui.clearBuff(state.screenBuffer)
        except Exception:
            fui.clearBuff(state.screenBuffer)

    elif cmd in ("room", "r"):
        if args and args[0].lower() in ("list", "l","ls"):
            fcalls.room_list(activeProfile, state)
        elif args and args[0].lower() in ("info", "i"):
            if len(args) > 1:
                fcalls.room_info(activeProfile, state, args[1])
            else:
                fcalls.room_info(activeProfile, state, state.currentRoom)
        elif args and args[0].lower() in ("set", "s"):
            if len(args) > 1:
                fcalls.room_set(args[1], activeProfile, state)
            else:
                fui.printBuffCmt("[i] Usage: room set <name>", state.screenBuffer)
        elif args and args[0].lower() in ("add", "a"):
            if len(args) > 2:
                fcalls.room_add(args[1],args[2], activeProfile, state)
            else:
                fui.printBuffCmt("[i] Usage: room add <name> <url:port>", state.screenBuffer)
        elif args and args[0].lower() in ("remove","r","delete"):
            if len(args) > 1:
                fcalls.room_remove(args[1], activeProfile, state)
            else:
                fui.printBuffCmt("[i] Usage: room remove <name|url:port>", state.screenBuffer)
        elif args and args[0] in ("leave", "exit", "quit", "q"):
            fcalls.room_leave(activeProfile, state)
        else:
            fui.printBuffCmt("[i] Usage: room list|info|set|quit|add|remove ...", state.screenBuffer)

    elif cmd in ("alias", "a"):
        if args and args[0].lower() in ("list","l","ls"):
            fcalls.alias_list(activeProfile, state)
        elif args and args[0].lower() in ("info", "i"):
            if len(args) > 1:
                fcalls.alias_info(args[1], activeProfile, state)
            else:
                fui.printBuffCmt(f"[i] Usage: alias info <name>", state.screenBuffer)
        elif args and args[0].lower() in ("edit","e"):
            if len(args) > 3:
                fcalls.alias_edit(args[1], args[2], args[3], activeProfile, state)
            elif len(args) > 1:
                fui.printBuffCmt(f"[i] Usage: alias edit {args[1]} name|fingerprint <value>", state.screenBuffer)
            else:
                fui.printBuffCmt("[i] Usage: alias edit <name> name|fingerprint <value>", state.screenBuffer)
                #properties, name, key(nickname email), 
        elif args and args[0].lower() in ("add","a"):
            if len(args) > 2:
                fcalls.alias_add(args[1], args[2], activeProfile, state)
            else:
                fui.printBuffCmt("[i] Usage: alias add <name> <fingerprint>", state.screenBuffer)
        elif args and args[0].lower() in ("remove","r"):
            if len(args) > 1:
                fcalls.alias_remove(args[1], activeProfile, state)
            else:
                fui.printBuffCmt("[i] Usage: alias remove <name|fingerprint>", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: alias list|info|edit|add|remove ...", state.screenBuffer)
    
    elif cmd == "who":
        fcalls.whoHere(activeProfile, state)

    elif cmd in ("whose", "whois"):
        if args:
            fcalls.whois(activeProfile, state, args[0])
        else:
            fui.printBuffCmt("[i] Usage: whose <fingerprint>", state.screenBuffer)

    elif cmd in ("send","s"):
        raw_msg = line[len(tokens[0]):].strip()
        if raw_msg:
            fcalls.send_message_to_aliases(activeProfile, state, raw_msg)
        else:
            fui.printBuffCmt("[i] Usage: send <message>", state.screenBuffer)

    elif cmd in ("file","f"):
        raw_path = line[len(tokens[0]):].strip()
        if raw_path:
            fcalls.send_file_to_aliases(activeProfile, state, raw_path)
        else:
            fui.printBuffCmt("[i] Usage: file <path>", state.screenBuffer)

    elif cmd in ("directmessage", "dm", "directmsg"):
        if args:
            if len(args) > 1:
                alias = args[0]
                # everything after alias is the raw message
                raw_msg = " ".join(args[1:])
                fcalls.send_direct_message_to_alias(activeProfile, state, alias, raw_msg)
            else:
                fui.printBuffCmt(f"[i] Usage: directmsg {args[0]} <message>", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: directmsg <ident> <message>", state.screenBuffer)

    elif cmd in ("directfile", "df", "directf"):
        if args:
            if len(args) > 1:
                alias = args[0]
                #everything after alias is the raw message
                path = " ".join(args[1:])
                fcalls.send_direct_file_to_alias(activeProfile, state, alias, path)
            else:
                fui.printBuffCmt(f"[i] Usage: directf {args[0]} <path>", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: directf <ident> <path>", state.screenBuffer)

    elif cmd in ("nickname","nn", "nick"):
        if args:
            fcalls.changeNN(args[0], activeProfile, state)
        else:
            fui.printBuffCmt("[i] Usage: nickname <nickname>", state.screenBuffer)
    
    elif cmd == "banner":
        fui.bufferBanner(state.screenBuffer, ptversion)

    elif cmd in ("block","bl"):
        if args:
            fcalls.blockkey(args[0], activeProfile, state)
        else:
            fui.printBuffCmt("[i] Usage: block <ident>", state.screenBuffer)
    elif cmd in ("unblock","ublock","ub"):
        if args:
            fcalls.unblockkey(args[0], activeProfile, state)
        else:
            fui.printBuffCmt("[i] Usage: unblock <ident>", state.screenBuffer)

    elif cmd in ("fingerprint", "fp","print"):
        if args and (len(args[0]) >= 32):
            fcalls.chgfingerprint(args[0], activeProfile, state)
        elif args:
            fui.printBuffCmt("[-] Not valid fingerprint", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: fingerprint <fingerprint>", state.screenBuffer)

    elif cmd in ("limit","lim"):
        if args:
            fcalls.chgLimit(activeProfile, state, args[0])
        else:
            fui.printBuffCmt("[i] Usage: limit <n>[MB|GB]", state.screenBuffer)

    elif cmd in ("policy", "p"):
        #policy msg <ident> allow
        if not args:
            fui.printBuffCmt("[i] Usage: policy message|file|info [<ident>|set|list] [allow|deny|whitelist]", state.screenBuffer)
            return

        subcmd = args[0].lower()
        #Msg
        if subcmd in ("message", "m", "msg"):
            if len(args) < 2:
                fui.printBuffCmt("[i] Usage: policy msg <ident>|set|list allow|deny|whitelist", state.screenBuffer)
                return
            if args[1] in ("set", "s"):
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy msg set allow|deny|whitelist", state.screenBuffer)
                else:
                    fcalls.chgMsgPolicy(args[2], activeProfile, state)
            elif args[1] in ("list", "l","ls"):
                if len(args) > 2:
                    fcalls.bufferPolicyList("msg",args[2], True, activeProfile, state)
                else:
                    fui.printBuffCmt(f"[i] Usage: policy msg list whitelist|blacklist", state.screenBuffer)
            else:
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy msg <ident> allow|deny", state.screenBuffer)
                else:
                    fcalls.chgPolicyLists("msg", args[1], args[2].lower(), activeProfile, state)
        #File
        elif subcmd in ("file", "f"):
            if len(args) < 2:
                fui.printBuffCmt("[i] Usage: policy file <ident>|set|list allow|deny|whitelist", state.screenBuffer)
                return

            if args[1] in ("set", "s"):
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy file set allow|deny|whitelist", state.screenBuffer)
                else:
                    fcalls.chgFilePolicy(args[2], activeProfile, state)

            elif args[1] in ("list", "l","ls"):
                if len(args) > 2:
                    fcalls.bufferPolicyList("file",args[2], True, activeProfile, state)
                else:
                    fui.printBuffCmt(f"[i] Usage: policy file list whitelist|blacklist", state.screenBuffer)

            else:
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy file <ident> allow|deny", state.screenBuffer)
                else:
                    fcalls.chgPolicyLists("file", args[1], args[2].lower(), activeProfile, state)
        #Info
        elif subcmd in ("info", "i"):
            if len(args) > 1 and args[1] in ("v","verbose"):
                fcalls.bufferPolicyInfo(activeProfile, state, verbose=True)
            else:
                fcalls.bufferPolicyInfo(activeProfile, state)

        else:
            fui.printBuffCmt("[i] Usage: policy message|file|info [<ident>|set|list] [allow|deny|whitelist]", state.screenBuffer)

    elif cmd in ("me", "my", "m", "whoami"):
        fcalls.buffer_ident(activeProfile, state)

    elif cmd in ("tor", "t"):
        if args and args[0].lower() in ("stat","status","sta"):
            fcalls.printTorStat(activeProfile, state)
            return
        elif args and args[0].lower() in ("set","cfg","proxy","p"):
            if len(args) == 2:
                if args[1].lower() in ("default","def","d"):
                    fcalls.chgTorProxy("127.0.0.1:9050", activeProfile, state)
                else:
                    fcalls.chgTorProxy(args[1], activeProfile, state)
            else:
                fui.printBuffCmt(f"[i] Usage: tor proxy default|<ip:port>", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: tor status|proxy [default|<ip:port>]", state.screenBuffer)

    elif cmd in ("settings", "set"):
        if args and args[0].lower() in ("save","s"):
            if len(args) > 1:
                fcalls.save_config(activeProfile, state, args[1])
            else:
                fcalls.save_config(activeProfile, state)
        elif args and args[0].lower() in ("load","l"):
            if len(args) > 1:
                #Load from arg
                fcalls.load_config(activeProfile, state, args[1])
            else:
                #Load from default
                fcalls.load_config(activeProfile, state)
        elif args and args[0].lower() in ("view","v","info","i","list","ls"):
            if len(args) > 1:
                praw = None
                if len(args) > 2 and args[2].lower() in ("raw","r"):
                    praw = True
                if args[1].lower() in ("saved","s"):
                    fcalls.buffer_file_settings(state)
                elif args[1].lower() in ("active","current","a","c"):
                    fcalls.buffer_current_settings(activeProfile, state, praw)
                else:
                    fui.printBuffCmt("[i] Usage: settings view saved|active [raw]", state.screenBuffer)
            else:
                fui.printBuffCmt("[i] Usage: settings view saved|active [raw]", state.screenBuffer)
        elif args and args[0].lower() in ("r", "reset"):
            activeProfile = fcalls.reset_settings(activeProfile, state)
            fui.printBuffCmt("[+] Settings reset to default", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: settings save|load|view|reset [<path>|saved|active] [raw]", state.screenBuffer)

    elif cmd in ("version","ver","build"):
        fcalls.buffer_version_menu(state, ptversion)

    elif cmd in ("directory","dir"):
        if args:
            if args[0].lower() in ("dl","download","d"):
                if len(args) > 1:
                    fcalls.chgDir(activeProfile, state, "d", args[1])
                else:
                    fcalls.chgDir(activeProfile, state, "d")
            else:
                fui.printBuffCmt("[i] Usage: dir download [<directory>]", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: dir download [<directory>]", state.screenBuffer)

    else:
        fui.printBuffCmt(f"[-] Unknown command: {line}\n[i] help for info", state.screenBuffer)

########################################################################################################- ENTRY
if __name__ == "__main__":
    main()
