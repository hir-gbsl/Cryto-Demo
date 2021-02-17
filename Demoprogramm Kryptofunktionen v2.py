# Demoprogramm Kryptofunktionen  hir, 10.12.2020

def byte_xor(ba1, ba2):                                         # XOR für List of Bytes
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def convert(s):                                                 # List of Bytes to string (binary encoded)
    str1 = ''
    return(str1.join(s))


# einen Key mit pbkdf2 aus einem Passwort erzeugen

from passlib.hash import pbkdf2_sha256

password = input('Gib den Schlüssel ein: ')

key = pbkdf2_sha256.hash(password, rounds=200000, salt_size=0)
key2 = pbkdf2_sha256.hash(password, rounds=200000, salt_size=0)    # ohne salt gibt es immer das Gleiche

print('ohne Salt')
print('Die ersten zwei abgeleiteten Schlüssel sind nun:', key, key2)

# und mit salt
key = pbkdf2_sha256.hash(password, rounds=200000, salt_size=16)
key2 = pbkdf2_sha256.hash(password, rounds=200000, salt_size=16)
print('mit Salt')
print('Die ersten zwei abgeleiteten Schlüssel sind nun:', key, key2)               # der salt steht im Output


# Neuer: Scrypt statt pbkdf2 (Memory-hard) dazu verwenden
import pyscrypt

salt = b'aa1f2d3f4d23ac44e9c5a6c3d8f9ee8c'
passwd = password.encode('utf-8')

skey = pyscrypt.hash(passwd, salt, N=2048, r=8, p=1, dkLen=32)
print('Scrypt-abgeleiteter Schlüssel:', skey.hex())                          # key ist nicht druckbar, nur als hex

# XOR nur demo
klartext = b'abcdefghijkl01234567890123456789'  # 32 bytes
key = b'bacdefghijkl01234567890123456789'  # 32 bytes

cryptotext = byte_xor(klartext, key)
print('Demo für XOR')
print('Klartext:', klartext, 'key:', key, 'Cryptotext:', cryptotext)       # cryptotext ist nicht druckbar

# und wieder entschlüsseln
klartext = cryptotext  # 32 bytes
decryptotext = byte_xor(klartext, key)
print('Wieder entschlüsselt:', decryptotext)

# XOR mit key aus scrypt
print('und jetzt mit dem scrypt-key')

klartext = 'abcdefghijkl01234567890123456789'  # 32 bytes
key = skey
klartext = klartext.encode('utf-8')

cryptotext = byte_xor(klartext, key)

print('Klartext:', klartext, 'key:', key, 'Cryptotext:', cryptotext)       # cryptotext ist nicht druckbar

# und wieder entschlüsseln

klartext = byte_xor(cryptotext, key)

print('Entschlüsselt:', klartext)
