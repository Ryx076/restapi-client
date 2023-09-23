# Protocoale de comunicatie
# Tema 4 - Client Web. Comunicatie cu REST API
## Ismana Mihai Iulian Robert - 321CC

## Clase și structuri principale

- **Command**: O clasă funcțională ce înregistrează o funcție care poate fi apelată mai târziu. Aceasta este folosită pentru a înregistra funcțiile care implementează comenzile.

- **CommandHandler**: Clasă care gestionează comenzile înregistrate, executându-le în funcție de numele comenzii. Realizează o mapare între numele comenzii, metoda HTTP, calea endpoint-ului HTTP și funcția care trebuie executată.

- **InputException**: Excepție care este aruncată atunci când se întâmplă o eroare în timpul citirii datelor de intrare.

- **HTTPResponse**: Structură care conține informațiile relevante despre un răspuns HTTP, inclusiv codul HTTP, corpul răspunsului și header-urile.

- **Client**: Clasă care gestionează comunicarea cu serverul, în principal trimiterea și primirea de mesaje.

- **HTTPRequest**: Clasă care construiește 
un cereri HTTP. Poate înregistra header-uri și adăuga un corp cererii care mai apoi poate fi trimisă la server sub forma unui string.

- **Session**: Clasă care gestionează o sesiune de comunicare cu serverul si care stochează cookie-ul de sesiune si token-ul JWT pentru a fi folosite la cereri ulterioare.

- **loginCommand**, **accountRegisterCommand**, **accessCommand**, **getBooksCommand**, **getBookCommand**, **addBookCommand**: Acestea sunt funcții care implementează diferite comenzi pe care clientul le poate executa.

## Detalii despre funcții și comenzi

- **registerCommand()**: Înregistrează o nouă comandă. Acceptă numele comenzii, funcția care să fie executată, metoda HTTP și calea endpoint-ului HTTP.

- **handleCommand()**: Manipulează o comandă. Aceasta își caută functia asociată și o execută.

- **prompt()**: Funcție template care solicită utilizatorului să introducă o valoare. Aceasta lansează o excepție InputException dacă există o eroare în timpul citirii datelor de intrare.

- **Client::send()**: Trimite un mesaj la server prin socket-ul dat. Mesajul este împachetat într-un buffer și trimis prin socket.

- **Client::receive()**: Primește un răspuns de la server și îl analizează pentru a extrage codul HTTP, header-urile și corpul răspunsului stocate într-o structură HTTPResponse.

- **Client::refreshSocket()**: Închide socket-ul curent și deschide unul nou pentru a evita erori de timeout.

- **Session::sendRequest()**: Trimite o cerere HTTP către server și returnează răspunsul primit.

- loginCommand(), accountRegisterCommand(), accessCommand(), getBooksCommand(), getBookCommand, addBookCommand(): Aceste funcții implementează comenzile din cerinta. Ele interacționează cu utilizatorul, solicită intrările necesare, trimit cereri HTTP la server și afișează răspunsuri în funcție de codul HTTP.

## Comenzi

	handler.registerCommand("login", loginCommand, "POST", "/api/v1/tema/auth/login");
	handler.registerCommand("register", accountRegisterCommand, "POST", "/api/v1/tema/auth/register");
	handler.registerCommand("enter_library", accessCommand, "GET", "/api/v1/tema/library/access");
	handler.registerCommand("get_books", getBooksCommand, "GET", "/api/v1/tema/library/books");
	handler.registerCommand("get_book", getBookCommand, "GET", "/api/v1/tema/library/books/:bookId");
	handler.registerCommand("add_book", addBookCommand, "POST", "/api/v1/tema/library/books");
	handler.registerCommand("delete_book", deleteBookCommand, "DELETE", "/api/v1/tema/library/books/:bookId");
	handler.registerCommand("logout", logoutCommand, "GET", "/api/v1/tema/auth/logout");

### loginCommand(std::string method, std::string path)
#### method = "POST", path = "/api/v1/tema/auth/login"
Această funcție permite utilizatorului să se conecteze la aplicație. Cere utilizatorului să introducă numele de utilizator și parola, care sunt apoi împachetate într-un obiect JSON și trimise ca parte a corpului unui request HTTP. Dacă serverul răspunde cu codul HTTP 200, conectarea a fost reușită și cookie-ul de sesiune este extras din răspuns și stocat pentru a fi folosit la cereri ulterioare. Dacă serverul răspunde cu codul HTTP 400, numele de utilizator sau parola sunt greșite.

### accountRegisterCommand(std::string method, std::string path)
#### method = "POST", path = "/api/v1/tema/auth/register"

Această funcție permite utilizatorului să se înregistreze în aplicație. Cere utilizatorului să introducă numele de utilizator și parola, care sunt apoi împachetate într-un obiect JSON și trimise ca parte a corpului unui request HTTP. Dacă serverul răspunde cu codul HTTP 201, înregistrarea a fost reușită. Dacă serverul răspunde cu codul HTTP 400, numele de utilizator este deja înregistrat.

### accessCommand(std::string method, std::string path)
#### method = "POST", path = "/api/v1/tema/library/access"
Această funcție face o cerere HTTP pentru a obține un token JWT. Dacă serverul răspunde cu codul HTTP 200, accesul este acordat și tokenul este extras din răspuns și stocat pentru a fi folosit la cereri ulterioare. Dacă serverul răspunde cu codul HTTP 401, accesul este refuzat deoarece utilizatorul nu este conectat.

### getBooksCommand(std::string method, std::string path)
#### method = "GET", path = "/api/v1/tema/library/books"

Această funcție face o cerere HTTP pentru a obține lista de cărți. Dacă serverul răspunde cu codul HTTP 200, lista de cărți este afișată. Dacă serverul răspunde cu codul HTTP 403, accesul este refuzat deoarece utilizatorul nu are acces la bibliotecă.

### getBookCommand(std::string method, std::string path)
#### method = "GET", path = "/api/v1/tema/library/books/:bookId"

Această funcție permite utilizatorului să obțină detalii despre o carte specifică. Solicită utilizatorului să introducă un ID de carte, care este apoi înlocuit în calea endpoint-ului HTTP. Dacă serverul răspunde cu codul HTTP 200, detalii despre carte sunt afișate. Dacă serverul răspunde cu codul HTTP 404, cartea nu a fost găsită. Dacă serverul răspunde cu codul HTTP 403, accesul este refuzat deoarece utilizatorul nu are acces la bibliotecă.

### addBookCommand(std::string method, std::string path)
#### method = "POST", path = "/api/v1/tema/library/books"

Această funcție permite utilizatorului să adauge o carte nouă. Solicită utilizatorului să introducă detalii despre carte (titlu, autor, gen, numărul de pagini și editura), care sunt apoi împachetate într-un obiect JSON și trimise ca parte a corpului unui request HTTP. Dacă serverul răspunde cu codul HTTP 200, cartea a fost adăugată cu succes. Dacă serverul răspunde cu codul HTTP 403, accesul este refuzat deoarece utilizatorul nu are acces la bibliotecă.

### deleteBookCommand(std::string method, std::string path)
#### method = "DELETE", path = "/api/v1/tema/library/books/:bookId"

Această funcție permite utilizatorului să șteargă o carte din bibliotecă. Solicită utilizatorului să introducă un ID de carte, care este apoi înlocuit în calea endpoint-ului HTTP. Dacă serverul răspunde cu codul de stare 200, cartea a fost ștearsă cu succes. Dacă serverul răspunde cu codul de stare 404, cartea nu a fost găsită. Dacă serverul răspunde cu codul de stare 403, accesul este refuzat deoarece utilizatorul nu are acces la bibliotecă.

### logoutCommand(std::string method, std::string path)
#### method = "GET", path = "/api/v1/tema/auth/logout"

Această funcție permite utilizatorului să se deconecteze din aplicație. Dacă serverul răspunde cu codul de stare 200, deconectarea a fost reușită. Dacă serverul răspunde cu codul de stare 403, accesul este refuzat deoarece utilizatorul nu este conectat.

## Biblioteci externe folosite

1. https://github.com/nlohmann/json
    - Biblioteca JSON pentru C++
    - Utilizată pentru a împacheta și deșpacheta obiecte JSON
    - .dump() pentru a împacheta un obiect JSON într-un string
    - .parse() pentru a despacheta un string într-un obiect JSON
