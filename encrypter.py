import os
import sys
import warnings

from cryptography.utils import CryptographyDeprecationWarning
from pgpy import PGPKey, PGPMessage

PUBLIC_KEY_PATH = 'pgp_keys/public.asc'

INPUT_FILE_PATH = "input_files/decrypted/"
OUTPUT_FILE_PATH = "output_files/encrypted/"

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


def encrypt(file_name, public_key, input_path, output_path):
    """Encrypt file function from given public key"""

    try:
        pubkey, _ = PGPKey.from_file(public_key)

        msg = PGPMessage.new(input_path + file_name, file=True)
        emsg = pubkey.encrypt(msg)

        with open(output_path + file_name + ".pgp", 'wb') as write_file:
            write_file.write(bytes(emsg))

        print(f"[+] Encryption successful for file : {os.path.basename(file_name)}")

    except Exception as e:
        print(f"[-] Unable to encrypt given file : {os.path.basename(file_name)}")
        print(f"[*] Error : {e}")
        sys.exit(1)


if __name__ == "__main__":
    for file in os.listdir(INPUT_FILE_PATH):
        encrypt(file, PUBLIC_KEY_PATH, INPUT_FILE_PATH, OUTPUT_FILE_PATH)
