# my_secure_app
link github: https://github.com/isso1550/my_secure_app

Planowane technologie:\
szablon - python flask\
baza danych - python sqlite3\
sanityzacja - python bleach\
edytor notatek - python markdown\
autoryzacja i system ról- token JWT (python pyjwt) lub session cookie (python flask_login)\
jakosc hasla - entropia (liczona biorac pod uwage obszernosc uzytego alfabetu), przewidywany czas łamania hasła atakiem bruteforce\
funkcja hashujaca - sha256 z solą losowaną przy rejestracji + wielokrotne hashowanie\
przechowywanie notatek - szyfrowanie AES przez python pycryptodome
