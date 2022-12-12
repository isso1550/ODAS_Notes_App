from Crypto.Cipher import AES

KEY_HEX = "e8 fa 13 f0 23 19 1b 5d 45 7f d3 87 5c ed 90 6d "
KEY = bytes.fromhex(KEY_HEX)
IV_HEX = "82 41 26 e6 c5 18 a1 7a e1 81 a8 64 08 ed 87 e1 "
IV = bytes.fromhex(KEY_HEX)

def pad(text, block_size=16):
    return text + b"\x00"*(block_size-len(text) % block_size) 
 
def unpad(text, block_size=16):
#Pobieram końcówkę tekstu o max dł. paddingu -> zamieniam wszystkie bity 0 na puste b"" -> zwracam tekst ucięty o długość usuniętych bitów 0
    return text[:-block_size+1+(len(text[-block_size+1:].replace(b"\x00",b"")))]

def encrypt_note(note_text):
    note_padded = pad(note_text.encode())
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_note = aes.encrypt(note_padded)
    return encrypted_note

def decrypt_note(encrypted_note):
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    note_padded = aes.decrypt(encrypted_note)
    return unpad(note_padded).decode()


if __name__ == "__main__":
    print("###TEST MODE###")
    note = b"My super secret message!"
    note = note.decode()
    c = encrypt_note(note)
    m = decrypt_note(c)
    print(m)