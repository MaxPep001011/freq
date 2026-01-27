# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.70"



##########################################   TODO/BUGFIXES
## DONE/CHANGELOG:
#   some misc bugs
#   room cmd tooltip
#   title for terminal
#   printout styling consistency
#   settings view src raw ... set v a, set v
#   Fix help tooltips
#   Default download dir and default settings dir
#   Adjust fui.timestamp to HR:MM:SS format
########################################################################################################- CODE BEGIN

from gclass import Profile, State
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

    def handle_exit(sig, frame):
        #Useless for now
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_exit)

    print("\033]0;FR3Q @ NONE\007")
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
        helpstr = "General Commands:\n\n"
        helpstr += " \033[0mnickname\033[90m(nn) - switches nickname\n     Usage: nickname <nickname>\n"
        helpstr += " \033[0mfingerprint\033[90m(fp) - sets fingerprint\n     Usage: fingerprint <fingerprint>\n"
        helpstr += " \033[0mme\033[90m(m) - displays your info\n\n"
        helpstr += " \033[0malias\033[90m(p) - aliases/contacts\n     Usage: alias list|info|edit|add|remove ...\n"
        helpstr += " \033[0msettings\033[90m(set) - settings manager\n     Usage: settings save|load|view [<path>|saved|active] [raw]\n"
        helpstr += " \033[0mbanner\033[90m - prints banner\n"
        helpstr += " \033[0mclear\033[90m(clr) - clears terminal\n"
        helpstr += " \033[0mdirectory\033[90m(dir) - updates default directories\n     Usage: dir download|logs [<directory>]\n"
        helpstr += " \033[0mquit\033[90m(q) - quits application\n"
        helpstr += " \033[0mhelp\033[90m(h) - displays help strings\n     Usage: help [all|msg|conn|color|general]\n"
        helpstr+= "\033[0m"
        

        helpstrColor = "Color guide:\n\n"
        helpstrColor += fui.color(" GREEN  - ","green") + "Online aliases\n"
        helpstrColor += fui.color(" CYAN - ","cyan") + "You\n"
        helpstrColor += fui.color(" BLUE  - ","blue") + "Online fingerprints (have pubkey)\n"
        helpstrColor += fui.color(" PURPLE  - ","purple") + "Online blocked aliases/fingerprints\n"
        helpstrColor += fui.color(" RED  - ","red") + "Offline blocked aliases/fingerprints\n"
        helpstrColor += fui.color(" YELLOW  - ","yellow") + "Online fingerprints (no pubkey)\n"
        helpstrColor += fui.color(" GRAY  - ","gray") + "Offline\n"
        helpstrColor += "\033[0m"

        helpstrMsg = "Messaging Commands:\n\n"
        helpstrMsg += " \033[0msend\033[90m(s) - send message to all aliases in room\n     Usage: send <message>\n"
        helpstrMsg += " \033[0mfile\033[90m(f) - send file/dir to all aliases in room\n     Usage: file <path>\n"
        helpstrMsg += " \033[0mdirectmsg\033[90m(dm) - send message to one alias/fingerprint in room\n     Usage: directmsg <alias|fingerprint> <message>\n"
        helpstrMsg += " \033[0mdirectfile\033[90m(df) - send file to one alias/fingerprint in room\n     Usage: directf <alias|fingerprint> <path>\n"

        helpstrMsg += " \033[0mblock\033[90m(bl) - block key from messaging\n     Usage: block <alias|fingerprint>\n"
        helpstrMsg += " \033[0munblock\033[90m(ub) - unblock key for messaging\n     Usage: unblock <alias|fingerprint>\n"
        helpstrMsg += "\033[0m"

        helpstrConn = "Connection Commands:\n\n"
        helpstrConn += " \033[0mtor\033[90m(t) - tor proxy mgmt\n     Usage: tor status|proxy [default|<ip:port>]\n"
        helpstrConn += " \033[0mroom\033[90m(r) - room/server mgmt\n     Usage: room list|info|set|quit|add|remove ...\n"
        helpstrConn += " \033[0mwho\033[90m - shows connected peers in current room\n"
        helpstrConn += " \033[0mpolicy\033[90m(p) - policy editor/information\n     Usage: policy message|file|info [<alias|fingerprint>|set|list] [allow|deny|whitelist]\n"
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

    elif cmd in ("clear","clr"):
        fui.clearBuff(state.screenBuffer)

    elif cmd in ("room", "r"):
        if args and args[0].lower() in ("list", "l","ls"):
            fcalls.room_list(activeProfile, state)
        elif args and args[0].lower() in ("info", "i"):
            if len(args) > 1:
                fcalls.room_info(activeProfile, state, args[1].lower())
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
        elif args and args[0].lower() in ("remove","r"):
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
            fui.printBuffCmt("[i] Usage: directmsg <alias|fingerprint> <message>", state.screenBuffer)

    elif cmd in ("directfile", "df", "directf"):
        if args:
            if len(args) > 1:
                alias = args[0]
                # everything after alias is the raw message
                path = " ".join(args[1:])
                fcalls.send_direct_file_to_alias(activeProfile, state, alias, path)
            else:
                fui.printBuffCmt(f"[i] Usage: directf {args[0]} <path>", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: directf <alias|fingerprint> <path>", state.screenBuffer)

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
            fui.printBuffCmt("[i] Usage: block <alias|fingerprint>", state.screenBuffer)
    elif cmd in ("unblock","ublock","ub"):
        if args:
            fcalls.unblockkey(args[0], activeProfile, state)
        else:
            fui.printBuffCmt("[i] Usage: unblock <alias|fingerprint>", state.screenBuffer)

    elif cmd in ("fingerprint", "fp"):
        if args and (len(args[0]) >= 32):
            fcalls.chgfingerprint(args[0], activeProfile, state)
        elif args:
            fui.printBuffCmt("[-] Not valid fingerprint", state.screenBuffer)
        else:
            fui.printBuffCmt("[i] Usage: fingerprint <fingerprint>", state.screenBuffer)

    elif cmd in ("policy", "p"):
        # ex. policy msg <alias|fingerprint> allow
        if not args:
            fui.printBuffCmt("[i] Usage: policy message|file|info [<alias|fingerprint>|set|list] [allow|deny|whitelist]", state.screenBuffer)
            return

        subcmd = args[0].lower()
        # --- MESSAGE POLICIES ---
        if subcmd in ("message", "m", "msg"):
            if len(args) < 2:
                fui.printBuffCmt("[i] Usage: policy msg <alias|fingerprint>|set|list allow|deny|whitelist", state.screenBuffer)
                return

            if args[1] in ("set", "s"):
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy msg set allow|deny|whitelist", state.screenBuffer)
                else:
                    fcalls.chgMsgPolicy(args[2], activeProfile, state)

            elif args[1] in ("list", "l","ls"):
                if len(args) > 2:
                    fcalls.bufferPolicyList("msg",args[2], activeProfile, state)
                else:
                    fui.printBuffCmt(f"[i] Usage: policy msg list whitelist|blacklist", state.screenBuffer)

            else:
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy msg <alias|fingerprint> allow|deny", state.screenBuffer)
                else:
                    fcalls.chgPolicyLists("msg", args[1], args[2].lower(), activeProfile, state)
        # --- FILE POLICIES ---
        elif subcmd in ("file", "f"):
            if len(args) < 2:
                fui.printBuffCmt("[i] Usage: policy file <alias|fingerprint>|set|list allow|deny|whitelist", state.screenBuffer)
                return

            if args[1] in ("set", "s"):
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy file set allow|deny|whitelist", state.screenBuffer)
                else:
                    fcalls.chgFilePolicy(args[2], activeProfile, state)

            elif args[1] in ("list", "l","ls"):
                if len(args) > 2:
                    fcalls.bufferPolicyList("file",args[2], activeProfile, state)
                else:
                    fui.printBuffCmt(f"[i] Usage: policy file list whitelist|blacklist", state.screenBuffer)

            else:
                if len(args) < 3:
                    fui.printBuffCmt("[i] Usage: policy file <alias|fingerprint> allow|deny", state.screenBuffer)
                else:
                    fcalls.chgPolicyLists("file", args[1], args[2].lower(), activeProfile, state)

        # --- INFO ---
        elif subcmd in ("info", "i"):
            fcalls.bufferPolicyInfo(activeProfile, state)

        else:
            fui.printBuffCmt("[i] Usage: policy message|file|info [<alias|fingerprint>|set|list] [allow|deny|whitelist]", state.screenBuffer)

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
                fcalls.save_config(activeProfile, state, path=args[1])
            else:
                fcalls.save_config(activeProfile, state)
        elif args and args[0].lower() in ("load","l"):
            # Check if a filepath argument was provided
            if len(args) > 1:
                # Load from the specified file
                fcalls.load_config(activeProfile, state, filepath=args[1])
            else:
                # Load from the default location
                fcalls.load_config(activeProfile, state)
        elif args and args[0].lower() in ("view","v","info","i","list","ls"):
            if len(args) > 1:
                praw = None
                if len(args) > 2 and args[2].lower() in ("raw","r"):
                    praw = True
                if args[1].lower() in ("saved","s"):
                    config_path = fcalls.config_path()
                    fui.printBuffCmt(f"[+] Parsing '{config_path}'...", state.screenBuffer)
                    fcalls.buffer_file_settings(config_path, state)
                elif args[1].lower() in ("active","current","a","c"):
                    fcalls.buffer_current_settings(activeProfile, state, praw)
                else:
                    fui.printBuffCmt("[i] Usage: settings view saved|active [raw]", state.screenBuffer)
            else:
                fui.printBuffCmt("[i] Usage: settings view saved|active [raw]", state.screenBuffer)
        elif args and args[0].lower() in ("r", "reset"):
            fcalls.reset_settings(activeProfile, state)
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
