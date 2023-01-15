# Projekt ODAS
link github: https://github.com/isso1550/my_secure_app<br>
W plik README specyfikacja elementów aplikacji, wbudowane dane (do ułatwienia testów) oraz wyjaśnienia dotyczące korzystania. <br>
Samo działanie najważniejszych elementów aplikacji starałem się opisywać komentarzami w kodzie.<br>
Aplikacja uruchamiana przez docker compose.
# Rzeczywista specyfikacja (elementy obowiązkowe):
* Szablon - Flask
* Baza danych - sqlite3
* Sanityzacja - bleach
* Edycja notatek - markdown
* Przechowywanie haseł - wielokrotne hashowanie sha256 z solą losowaną przy rejestracji
* Szyfrowanie - AES w trybie CBC
    * W przypadku szyfrowania hasłem użytkownika hasło przekształcane na klucz funkcją PBKDF2
* Logowanie użytkowników - flask login
* Tymczasowa blokada konta za zbyt dużą ilość prób logowania w krótkim czasie
    * Użytkownik dostaje informacje, że zostało niewiele prób 
    * Użytkownik może odblokować swoje konto przez wiadomość e-mail
* Jakość hasła - entropia wyliczana na podstawie obszerności alfabetu i ilości znaków
    * Odrzucanie rejestracji w przypadku zbyt słabego hasła - definicja jakie hasło jest "za słabe" na podstawie własnego doświadczenia
* Weryfikacja danych od użytkownika - sprawdzanie poprawności przy użyciu wyrażeń regularnych oraz sprawdzanie obecności konkretnych znaków w celu wykrycia konkretnych ataków (np. obecność znaku ' sprawia, że logger rejestruje podejrzaną akcję - możliwą próbę SQL Injection)
* Przekazywanie danych użytkownika, kiedy nie jest zalogowany (na przykład e-mail do resetu hasła) - jwt

## Dodatkowe elementy:
* Logowanie działalności aplikacji do oddzielnej bazy danych przez moduł logger.py (utworzony przeze mnie)
    * Do przeglądania logów trzeba wejść do kontenera i uruchomić plik logger używając python-a (python3 logger.py)
* Wyłączony nagłówek Server
* Możliwość resetu hasła pod adresem /resetPassword

## Dodatkowe informacje:
* Sprawdzanie rzeczywistego formatu pliku przy użyciu biblioteki filetype
* Wczytywanie sekretów przy użyciu dotenv

## Podział na pliki:
* notes_app - główna aplikacja flask
* logger - odpowiada za tworzenie logów podczas działania aplikacji
* login_ban_handler - odpowiada za funkcję blokowania użytkowników po zbyt wielu nieudanych próbach logowania
    * sprawdza ile nieudanych logowań wystąpiło w danym czasie, jeśli więcej niż dozwolone to zwraca informację żeby odrzucić logowanie użytkownika
* notecrypt - odpowiada za szyfrowanie notatek 
* tools - zawiera funkcje do hashowania haseł, obliczania entropii oraz czyszczenia tekstu markdown przy użyciu bleach
* /docker - zawiera pliki konfiguracyjne nginx (nginx.conf oraz default) i klucze, certyfikaty do obsługi https
* .env - zawiera tylko "sekretne" parametry, konfiguracje są w plikach *.py
* /user_pictures/notepics - przechowuje zdjęcia dołączane do notatek
* /user_pictures/temp - służy do tymczasowego zapisywania pliku na czas sprawdzania jego formatu<br>

# Wbudowane dane
* Użytkownicy (username, e-mail, hasło):
    * bob bob@bob.com   bob
    * friend carl@mail.com  hello
* Notatki:
    * Zwykła prywatna notatka użytkownika bob - widoczna tylko dla bob
    * Zwykła publiczna notatka użytkownika admin - widoczna dla wszystkich
    * Szyfrowana publiczna notatka użytkownika bob - widoczna dla wszystkich znających hasło (hasło: parrot)
    * Niepubliczna notatka od użytkownika bob dla użytkownika friend - widoczna tylko dla tej dwójki (/render/4)

# Wyjaśnienia dotyczące działania
* Notatki dla wybranych użytkowników
    * Przy tworzeniu wybrać opcję prywatności "unlisted" i wpisać listę użytkowników mogących ją odczytać oddzielając nazwy przecinkami
    * Dostępna tylko przez link, nie wyświetla się w notatkach odbiorców

