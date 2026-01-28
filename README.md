
FR3Q is a portable encrypted chatroom and filesharing network (only linux right now)

It uses your gpg keyring to encrypt (with recipients pubkey) and sign (with senders priv key) so messages
and files sent can be verified reliably. The client connects to any freqserver set up and running as 
a hidden service (tor) with a onion url:port. The protocol is set up so even a compromised freqserver can only see the 
gpg fingerprint of sender/recipient, when messages are sent, message type, and if it is a file, the filename (for now).

This is the path your message/file takes:

client > enc/signed > relays (3 yours, 3 server) > freqserver > relays (3 server, 3 recipients) > decr/verified > client

Dependencies: python3, tor, gpg
```
To get,

 git clone https://github.com/MaxPep001011/freq.git

 cd ./freq


To get started (client):

  1. Generate your own new pgp key pair to use as your primary signing/decryption key (note fingerprint):

   gpg --full-generate-key

   gpg --list-keys

  2. Export your pubkey and share:

   gpg --export --armor <your_fingerprint> > pubkey.asc

  3. Import other pubkeys:

   gpg --import <path_to_pubkey.asc>

  3. start freq and set your fingerprint:

   python3 ./freq.py

   fp <your_fingerprint>

  4. add a room url and connect:

   room add <room_name> <url.onion:port>

   room set <room_name>


To get started (server):

  1. Start script:

   sudo ./freqserver.py		*If using bind port # < 1024
 
	 OR

   ./freqserver.py		*If using bind port # >= 1024

  2. Input server bind address, bind port, and service port.

  3. Follow prompts to setup and start server.

  4. Find URL and distribute:

   cat /var/lib/tor/hidden_service/hostname
```

