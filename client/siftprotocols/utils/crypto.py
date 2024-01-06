import sys, os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

from typing import Union

# RSA constants
RSA_KEY_SIZE = 2048
# TODO: more dynamic?
PASSPHRASE = "1234"
KEY_PATH = "./keys/"
PUBKEY_FILE = "pub.pem"
PRIVKEY_FILE = "priv.pem"

# AES constants
AUTH_TAG_LEN = 12


class SiFT_Crypto_validation_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg


# RSA PUBLIC-PRIVATE KEY
def load_publickey(pubkey_file):
    public_key_path = os.path.join(KEY_PATH, pubkey_file)
    with open(public_key_path, "rb") as f:
        pubkey_str = f.read()
    try:
        return RSA.import_key(pubkey_str)
    except ValueError:
        print("Error: Cannot import public key from file " + public_key_path)
        sys.exit(1)


def load_keypair(privkey_file):
    private_key_path = os.path.join(KEY_PATH, privkey_file)

    with open(private_key_path, "rb") as f:
        keypair_str = f.read()
    try:
        return RSA.import_key(keypair_str, passphrase=PASSPHRASE)
    except ValueError:
        print("Error: Cannot import private key from file " + privkey_file)
        sys.exit(1)


def rsa_enc_symkey(aes_symkey: bytes):
    """Encrypting a given AES symmetric key by a RSA public key

    Args:
        aes_symkey (bytes): AES symmetric key

    Returns:
        bytes: encrypted AES key
    """
    # load the public key from the public key file and
    # create an RSA cipher object
    pubkey = load_publickey(PUBKEY_FILE)
    rsa_cipher = PKCS1_OAEP.new(pubkey)

    # encrypt the AES key with the RSA cipher
    enc_symkey = rsa_cipher.encrypt(aes_symkey)

    return enc_symkey


def rsa_dec_symkey(enc_aes_symkey: bytes):
    """Decrypting a given AES symmetric key by RSA private key

    Args:
        enc_aes_symkey (bytes): encrypted AES symmetric key

    Returns:
        bytes: decrypted AES key
    """

    # load the private key from the private key file and
    # create the RSA cipher object
    keypair = load_keypair(PRIVKEY_FILE)
    rsa_cipher = PKCS1_OAEP.new(keypair)

    # decrypt the AES key and create the AES cipher object
    symkey = rsa_cipher.decrypt(enc_aes_symkey)

    return symkey


def aes_enc_symkey(
    header: bytes, payload: str, aes_symkey: bytes, header_sqn: bytes, header_rnd: bytes
) -> Union[bytes, bytes]:
    nonce = header_sqn + header_rnd
    aes = AES.new(aes_symkey, AES.MODE_GCM, nonce=nonce, mac_len=AUTH_TAG_LEN)
    aes.update(header)
    epd, mac = aes.encrypt_and_digest(payload)

    return epd, mac


def aes_dec_symkey(
    header: bytes,
    encrypted_payload: bytes,
    mac: bytes,
    aes_symkey: bytes,
    header_sqn: bytes,
    header_rnd: bytes,
) -> bytes:
    nonce = header_sqn + header_rnd
    aes = AES.new(aes_symkey, AES.MODE_GCM, nonce=nonce, mac_len=AUTH_TAG_LEN)
    aes.update(header)

    try:
        payload = aes.decrypt_and_verify(encrypted_payload, mac)
    except Exception as e:
        raise SiFT_Crypto_validation_Error("Payload authentication failed")

    return payload
