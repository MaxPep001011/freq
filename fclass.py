from dataclasses import dataclass, field
from typing import List, Dict, Set, Any



@dataclass
class Profile:
    nickname: str = "NOBODY"
    fingerprint: str = ""

    torProxyIP: str = "127.0.0.1"
    torProxyPort: int = 9050

    rooms: List[str] = field(default_factory=list)
    aliases: Dict[str, str] = field(default_factory=dict)

    # Policies
    filePolicy: str = "whitelist"
    msgPolicy: str = "allow"
    maxMsgLen = 1000000000 #(bytes) Default = 1GB

    # Fingerprint Sets
    msgWhitelist: Set[str] = field(default_factory=set)
    msgBlacklist: Set[str] = field(default_factory=set)
    fileWhitelist: Set[str] = field(default_factory=set)
    fileBlacklist: Set[str] = field(default_factory=set)

    defDdir: str = ""

@dataclass
class State:
    screenBuffer = []
    serverNN: str = "SERVER"

    connStatus: bool = False
    listenerRunning: bool = False

    currentRoom: str = "" #Empty => not in a room
    server_peers: List[str] = field(default_factory=list)
    
    #These hold the actual objects (Thread and Socket)
    current_listener_thread: Any = None
    current_sock: Any = None
    
    
