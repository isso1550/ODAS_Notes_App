from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import tools

KEY_HEX = "e8 fa 13 f0 23 19 1b 5d 45 7f d3 87 5c ed 90 6d "
KEY = bytes.fromhex(KEY_HEX)
IV_HEX = "82 41 26 e6 c5 18 a1 7a e1 81 a8 64 08 ed 87 e1 "
IV = bytes.fromhex(KEY_HEX)

'''
def pad(text, block_size=16):
    return text + b"\x00"*(block_size-len(text) % block_size) 
 
def unpad(text, block_size=16):
#Pobieram końcówkę tekstu o max dł. paddingu -> zamieniam wszystkie bity 0 na puste b"" -> zwracam tekst ucięty o długość usuniętych bitów 0
    return text[:-block_size+1+(len(text[-block_size+1:].replace(b"\x00",b"")))]
'''

def encrypt_note(note_text):
    if(type(note_text) is str):
        note_padded = pad(note_text.encode(),16)
    else:
        note_padded = pad(note_text,16)
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_note = aes.encrypt(note_padded)
    return encrypted_note

def decrypt_note(encrypted_note):
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    note_padded = aes.decrypt(encrypted_note)
    return unpad(note_padded,16)

def get_user_key(password, hash=None):
    if (hash is None):
        hash = tools.hash_password(password)
    salt = hash.split("$")[3]
    user_key = PBKDF2(password.encode(), salt)
    return user_key, hash

def encrypt_note_with_user_password(note_text, user_key):
    if(type(note_text) is str):
        note_padded = pad(note_text.encode(),16)
    else:
        note_padded = pad(note_text,16)
    aes = AES.new(user_key, AES.MODE_CBC, IV)
    encrypted_note = aes.encrypt(note_padded)
    return encrypted_note

def decrypt_note_user_password(encrypted_note, user_key):
    aes = AES.new(user_key, AES.MODE_CBC, IV)
    note_padded = aes.decrypt(encrypted_note)
    return unpad(note_padded,16)

if __name__ == "__main__":
    print("###TEST MODE###")
    f = open("./user_pictures/notepics/default.png",'rb')
    pic = f.read()
    f.close()
    password = "abc"
    c, hash = encrypt_note_with_user_password(pic, password)

    print(pic)
    p = decrypt_note_user_password(c, password,  hash.split("$")[3])
    print(p)
