
FR3Q is a small encrypted chat and filesharing messanger (for linux right now)

It uses gpg keyring to securely encrypt (with recipients pubkey) and sign (with senders priv key) so messages
and files sent can be verified reliably. The client connects to any portable freqserver set up and running as 
a hidden service (tor) with a onion url:port. The encryption is set up so even a compromised freqserver can only see the 
gpg fingerprint of sender/recipient, when messages are sent, message type, and if it is a file, the filename (for now).

This is the path your message/file takes to get to an alias:

Your client > enc/signed > relays (3 yours, 3 server) > freqserver > relays (3 server, 3 recipients) > decr/verified > alias client

Required packages:
   Python3 (obviosly)
   Tor
   GPG
To install/run,
   git clone https://
   
   python3 freq.py
   sudo python3 freqserver.py
To get started,
1. generate your own new gpg key pair to use as your primary signing/decryption key. Note the fingerprint.
   gpg --full-generate-key
   gpg --list-keys
2. (optional). Then export your public key and share with people
   gpg --export --armor <your_fingerprint> > pubkey.asc
3. start freq and set your fingerprint
   python3 freq.py
   fp <your_fingerprint>
4. add a room url and connect
   room add <name> <url.onion>
   room set <name>
