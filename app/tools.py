from time import sleep
from passlib.hash import sha256_crypt
import bleach

#wielokrotne hashowanie - ile razy hashować?
MULTIHASH_COUNT = 3
#hashowanie - ile czasu odczekać[s]
HASH_DELAY = 0.5
CLEAN_TAGS = ["h1","h2","h3","abbr", "acronym", "b", "blockquote", "br", "code", "div", "em", "i", "li", "ol", "p", "span", "strong", "table", "td", "tr", "ul"]

#   Przetwarzanie hasła na hash
#   Użyta funkcja jednokierunkowa: sha256 z pakietu passlib.hash
def registerHash(password):
    #pierwszy hash
    hash = sha256_crypt.hash(password, rounds=535000)
    #wykorzystanie soli wygenerowanej losowo przez funkcję sha256_crypt
    salt = hash.split("$")[3]
    #wielokrotne hashowanie
    for i in range(1,MULTIHASH_COUNT):
        hash = sha256_crypt.hash(hash, rounds=535000, salt=salt)
    return hash

def loginHash(password, db_hash):
    salt = db_hash.split("$")[3]
    #pierwszy hash
    hash = sha256_crypt.hash(password, rounds=535000, salt=salt)
    #wielokrotne hashowanie
    for i in range(1,MULTIHASH_COUNT):
        hash = sha256_crypt.hash(hash, rounds=535000, salt=salt)
    #sztuczne opoznienie
    sleep(HASH_DELAY)
    return hash

def cleanText(text):
    return bleach.clean(text, tags=CLEAN_TAGS)

if __name__ == "__main__":
    print("###TEST MODE###")
    print(type(HASH_DELAY))