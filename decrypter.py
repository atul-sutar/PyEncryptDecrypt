import os
import sys
import warnings
from getpass import getpass

from cryptography.utils import CryptographyDeprecationWarning
from pgpy import PGPKey, PGPMessage

PRIVATE_KEY_PATH = 'pgp_keys/private.asc'
PASSPHRASE = getpass("Enter private key passphrase : ")

INPUT_FILE_PATH = "input_files/encrypted/"
OUTPUT_FILE_PATH = "output_files/decrypted/"

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


def decrypt(file_path, private_key, pass_phrase, input_path, output_path):
    """Decrypt file function from given private key and pass phrase"""

    try:
        msg = PGPMessage()
        emsg = msg.from_file(input_path + file_path)

        privkey, _ = PGPKey.from_file(private_key)

        with privkey.unlock(pass_phrase):
            data = privkey.decrypt(emsg)

            if not data.is_encrypted:
                path = output_path + file_path

                with open(path.replace(".pgp", ""), "wt") as write_file:
                    write_file.write(str(data.message))

                print(f"[+] Decryption successful for file : {os.path.basename(file_path)}")
            else:
                print(f"[-] Unable to decrypt given file : {os.path.basename(file_path)}")

    except Exception as e:
        print(f"[-] Unable to decrypt given file : {os.path.basename(file_path)}")
        print(f"[*] Error : {e}")
        sys.exit(1)


if __name__ == "__main__":
    for file in os.listdir(INPUT_FILE_PATH):
        decrypt(file, PRIVATE_KEY_PATH, PASSPHRASE, INPUT_FILE_PATH, OUTPUT_FILE_PATH)
