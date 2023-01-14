from time import sleep
from passlib.hash import sha256_crypt
import bleach
from math import log2
import re

#wielokrotne hashowanie - ile razy hashować?
MULTIHASH_COUNT = 3
#hashowanie - ile czasu odczekać[s]
HASH_DELAY = 0.5
CLEAN_TAGS = ["h1","h2","h3","abbr", "acronym", "b", "blockquote", "br", "code", "div", "em", "i", "li", "ol", "p", "span", "strong", "table", "td", "tr", "ul"]

#   Przetwarzanie hasła na hash
#   Użyta funkcja jednokierunkowa: sha256 z pakietu passlib.hash
def hash_password(password):
    #pierwszy hash
    hash = sha256_crypt.hash(password, rounds=535000)
    #wykorzystanie soli wygenerowanej losowo przez funkcję sha256_crypt
    salt = hash.split("$")[3]
    #wielokrotne hashowanie
    for i in range(1,MULTIHASH_COUNT):
        hash = sha256_crypt.hash(hash, rounds=535000, salt=salt)
    return hash

def hash_password_salt(password, db_hash):
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

def passwordEntropy(password):
    alpha_len = 0
    #Badanie czy hasło zawiera chociaż jeden znak z danego alfabetu: małe litery, duże litery, cyfry, znaki specjalne
    #Znaki specjalne to w tym przypadku to wszystko inne niż 3 wcześniejsze grupy.
    checker = ((r'[a-z]',26), (r'[A-Z]',26), (r'\d', 10), (r'[^a-z^A-Z^\d]', 32))
    for pass_re, count in checker:
        if (re.search(pass_re, password)):
            alpha_len = alpha_len + count
    ent = len(password) * log2(alpha_len)
    #Bardzo krótkie, bardzo proste lub oba jednocześnie
    if (30 >= ent):
        pass_msg = "Password extremely weak"
    
    #Bardzo krótkie lub dość krótkie i brak zróżnicowania w użytych znakach
    elif (50 >= ent > 30):
        pass_msg = "Password is weak"

    #Średniej długości ok.10 znaków z podstawowymi znakami (duze,male,liczby)
    #Średnio-krótkie ok.6-8 znaków z rozmaitym alfabetem
    elif (70 >= ent > 50):
        pass_msg = "Password is ok, but not very strong"

    #Średnio-długie ok.13-15 znaków z podstawowymi znakami (duze,male,liczby)
    #Średniej długości do 13 znaków z rozmaitym alfabetem
    elif (90 >= ent > 70):
        pass_msg = "Password is good"

    #15+ znaków z podstawowymi znakami
    #ok. 15 znaków z rozmaitym alfabetem
    elif (ent > 90):
        pass_msg = "Password is very good"
    return ent, pass_msg

if __name__ == "__main__":
    print("###TEST MODE###")
    print(hash_password("hello"))