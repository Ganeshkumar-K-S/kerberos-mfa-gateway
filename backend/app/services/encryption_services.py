import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(data: str, key: bytes) -> str:
    key = key[:32].ljust(32, b'\0')
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()


def decrypt(cipher_text: str, key: bytes) -> str:
    key = key[:32].ljust(32, b'\0')
    cipher = AES.new(key, AES.MODE_ECB)
    decoded = base64.b64decode(cipher_text)
    decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
    return decrypted.decode()