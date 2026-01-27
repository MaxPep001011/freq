
import tarfile
import tempfile
from typing import Optional, Tuple
import subprocess
import os

###   SIGNING/ENC/DECR
#for Messages
def gpg_sign_and_encrypt(data: bytes, recipient: str, signer: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f_in:
        f_in.write(data)
        f_in.flush()
        signed_file = f_in.name + ".signed"
        #Sign with <signer> privkey
        subprocess.run([
            "gpg", "--yes", "--batch", "--quiet","--trust-model","always",
            "--local-user", signer,  
            "--output", signed_file,
            "--clearsign", f_in.name
        ], check=True)
        #Encrypt with <recipient> pubkey
        encrypted_file = signed_file + ".gpg"
        subprocess.run([
            "gpg", "--yes", "--batch", "--quiet","--trust-model","always",
            "--encrypt", "--recipient", recipient,
            "--output", encrypted_file,
            signed_file
        ], check=True)
        with open(encrypted_file, 'rb') as ef:
            return ef.read()
def gpg_decrypt_and_verify(data: bytes) -> Tuple[bytes, Optional[str]]:
    try:
        with tempfile.NamedTemporaryFile(delete=False) as enc_file:
            enc_file.write(data)
            enc_file.flush()
            enc_path = enc_file.name
        #Decrypt to tmpfile
        proc = subprocess.run(
            ["gpg", "--yes", "--batch", "--decrypt", enc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        decrypted = proc.stdout
        #Save decrypted file
        with tempfile.NamedTemporaryFile(delete=False) as dec_file:
            dec_file.write(decrypted)
            dec_file.flush()
            dec_path = dec_file.name
        if not dec_path:
            return None, None
        #Verify sig
        verify_proc = subprocess.run(
            ["gpg", "--status-fd=1", "--verify", dec_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        signer_fpr = None
        for line in verify_proc.stdout.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                #[GNUPG:] VALIDSIG <fingerprint> ...
                parts = line.split()
                if len(parts) >= 3:
                    signer_fpr = parts[2]
                    break
        return decrypted, signer_fpr
    finally:
        #Failed
        try:
            if enc_path:
                os.remove(enc_path)
            if dec_path:
                os.remove(dec_path)
        except FileNotFoundError:
            pass
def extract_signed_text(clearsigned: str) -> str:
    """ Extracts cleartext from signed text (for messages) """
    lines = clearsigned.splitlines()
    extracted = []
    capture = False
    for line in lines:
        if line.startswith("-----BEGIN PGP SIGNATURE-----"):
            break
        if capture:
            extracted.append(line)
        if line.startswith("Hash:"):
            capture = True
    return "\n".join(extracted).strip()

#Files (and zipped dirs)
def gpg_sign_and_encrypt_binary(data: bytes, recipient: str, signer: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f_in:
        f_in.write(data)
        f_in.flush()
        in_path = f_in.name
    signed_path = in_path + ".sig"
    enc_path = signed_path + ".gpg"
    #Create detached signature
    subprocess.run([
        "gpg", "--yes", "--batch", "--quiet", "--trust-model","always",
        "--local-user", signer,
        "--output", signed_path,
        "--sign", "--detach-sign", in_path
    ], check=True)
    #Package into .tar for transmission
    tar_path = in_path + ".tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(in_path, arcname="data")
        tar.add(signed_path, arcname="data.sig")
    #Encrypt tarball
    subprocess.run([
        "gpg", "--yes", "--batch", "--quiet","--trust-model","always",
        "--output", enc_path,
        "--encrypt", "--recipient", recipient, tar_path
    ], check=True)
    with open(enc_path, 'rb') as ef:
        return ef.read()
def gpg_decrypt_and_verify_binary(data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    def is_safe_tar(tar, path):
        """ Ret true if unsafe tarball """
        abs_base = os.path.abspath(path)
        for member in tar.getmembers():
            member_path = os.path.abspath(os.path.join(path, member.name))
            if not member_path.startswith(abs_base):
                return False
        return True
    enc_path = dec_tar = data_path = sig_path = None
    try:
        #Load encrypted tarball
        with tempfile.NamedTemporaryFile(delete=False) as f_enc:
            f_enc.write(data)
            f_enc.flush()
            enc_path = f_enc.name
        dec_tar = enc_path + ".tar"
        subprocess.run([
            "gpg", "--yes", "--batch", "--quiet",
            "--output", dec_tar,
            "--decrypt", enc_path
        ], check=True)
        #Extract if safe
        with tarfile.open(dec_tar, "r") as tar:
            if not is_safe_tar(tar, os.path.dirname(dec_tar)):
                raise Exception("Unsafe path in tar archive")
            tar.extractall(path=os.path.dirname(dec_tar))
            data_path = os.path.join(os.path.dirname(dec_tar), "data")
            sig_path = os.path.join(os.path.dirname(dec_tar), "data.sig")
        if not (os.path.exists(data_path) and os.path.exists(sig_path)):
            raise Exception("Missing expected files after tar extraction")
        #Check detatched sig
        verify_proc = subprocess.run(
            ["gpg", "--status-fd=1", "--verify", sig_path, data_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        signer_fpr = None
        for line in verify_proc.stdout.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                if len(parts) >= 3:
                    signer_fpr = parts[2]
                    break
        with open(data_path, "rb") as f:
            file_data = f.read()
        return file_data, signer_fpr
    finally:
        try:
            os.remove(enc_path)
            os.remove(dec_tar)
            os.remove(data_path)
            os.remove(sig_path)
        except FileNotFoundError:
            pass

###   Key status
def check_gpg_key(identifier: str) -> int:
    """
    Check if a GPG key exists for the given fingerprint
    Ret:
    0 = no key found or error
    1 = public key only
    2 = public and private key
    """
    try:
        #Check public
        pub_result = subprocess.run(
            ["gpg", "--list-keys", "--with-colons", identifier],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        has_pub = pub_result.returncode == 0 and "pub:" in pub_result.stdout
        #Check secret
        sec_result = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons", identifier],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        has_sec = sec_result.returncode == 0 and "sec:" in sec_result.stdout

        if has_pub and has_sec:
            return 2
        elif has_pub:
            return 1
        else:
            return 0
    except Exception:
        return 0