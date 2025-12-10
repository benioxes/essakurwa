# mObywatel - Polish ID Card Generator

## Overview
Aplikacja do generowania polskich dowodów osobistych (mObywatel) z systemem autentykacji i kontroli dostępu. Aplikacja jest zbudowana na architekturze full-stack z:
- **Frontend**: HTML/CSS/JS na porcie 5000
- **Backend**: Flask API na porcie 3000
- **Database**: PostgreSQL z zarządzaniem użytkownikami i dokumentami

**Ważne**: Ta aplikacja nie generuje prawdziwych dokumentów i jest wyłącznie do użytku osobistego.

## Architektura

### Frontend (Port 5000)
- `server.py` - Python HTTP server z cache control dla Replit preview
- HTML Pages:
  - `index.html` - Strona startowa (redirect)
  - `login.html` - Logowanie/Rejestracja użytkowników
  - `gen.html` - Generator dowodów (chroniony logowaniem)
  - `id.html` - Podgląd wygenerowanego dowodu
  - `admin.html` - Panel administracyjny (zarządzanie dostępem i przeglądanie dokumentów)

### Backend (Port 3000)
- `app.py` - Flask API z JWT authentication
- **Endpoints**:
  - `POST /api/auth/register` - Rejestracja nowego użytkownika
  - `POST /api/auth/login` - Logowanie (zwraca JWT token)
  - `GET /api/auth/verify` - Weryfikacja tokenu
  - `POST /api/documents/save` - Zapisanie wygenerowanego dokumentu
  - `GET /api/admin/users` - Lista wszystkich użytkowników (admin only)
  - `PUT /api/admin/users/<id>/access` - Kontrola dostępu (admin only)
  - `GET /api/admin/documents` - Historia wszystkich dokumentów (admin only)

### Baza Danych
**Tabele**:
1. `users` - Użytkownicy z polami:
   - `id` - Primary key
   - `username` - Nazwa użytkownika (unikalna)
   - `password` - Hasło (plain text - DO ZAMIANY na bcrypt w produkcji!)
   - `has_access` - Czy ma dostęp do generatora
   - `is_admin` - Czy jest administratorem
   - `created_at` - Data rejestracji

2. `generated_documents` - Wygenerowane dokumenty z polami:
   - `id` - Primary key
   - `user_id` - Foreign key do users
   - `name` - Imię
   - `surname` - Nazwisko
   - `pesel` - Nr PESEL
   - `created_at` - Data wygenerowania
   - `data` - JSON z pełnymi danymi

## Setup i Deployment

### Instalacja
```bash
# Zależności były zainstalowane automatycznie przez uv
pip install flask flask-cors flask-jwt-extended psycopg2-binary python-dotenv
```

### Zmienne Środowiskowe
- `DATABASE_URL` - Połączenie do bazy (automatycznie ustawione przez Replit)
- `JWT_SECRET` - Klucz do JWT tokens (ustawiony na 'mamba-secret-key-super-tajny-2024')

### Workflows
1. **Web Server** - `python3 server.py` (port 5000) - Frontend
2. **Backend API** - `python3 app.py` (port 3000) - API

### Konta Testowe
- **Admin**: username=`admin`, password=`admin123`
  - Ma dostęp do panelu administracyjnego
  - Może nadawać/odbierać dostęp innym użytkownikom

## Przepływ Użytkownika

1. **Rejestracja**: Nowy użytkownik idzie na `/login.html` i się rejestruje
2. **Oczekiwanie**: Po rejestracji czeka na akceptację admina
3. **Logowanie**: Po uzyskaniu dostępu loguje się za pomocą tokenu JWT
4. **Generowanie**: Wchodzi na `/gen.html` i generuje dokument
5. **Zapis**: Dokument jest automatycznie zapisywany w bazie
6. **Podgląd**: Widzi dokument na `/id.html`

## Panel Admina

Admin ma dostęp do:
- **Zarządzanie użytkownikami**:
  - Przegląd listy wszystkich zarejestrowanych użytkowników
  - Nadawanie/odbieranie dostępu do generatora
  - Status: dostęp aktywny/zablokowany

- **Historia dokumentów**:
  - Przegląd wszystkich wygenerowanych dokumentów
  - Informacje o użytkowniku, dacie i danych dokumentu

## Struktura Plików

```
.
├── server.py              # Frontend HTTP server
├── app.py                 # Backend Flask API
├── init_admin.py          # Script do tworzenia admin konta
├── login.html             # Strona logowania
├── gen.html               # Generator (z integracją API)
├── id.html                # Podgląd dowodu
├── admin.html             # Panel administracyjny
├── home.html              # Strona główna
├── assets/                # CSS, JS, images
│   ├── main.css
│   ├── bar.js
│   ├── card.js
│   └── ...
└── functions/             # Backend functions directory
```

## Technologia

- **Frontend Framework**: Pure HTML/CSS/JavaScript
- **Backend Framework**: Flask
- **Database**: PostgreSQL (Neon)
- **Authentication**: JWT (Flask-JWT-Extended)
- **Package Manager**: uv (Python)

## Bezpieczeństwo (TODO w produkcji)

⚠️ **Aktualne problemy**:
- Hasła przechowywane w plain text - NALEŻY ZMIENIĆ NA BCRYPT!
- JWT secret jest hardcoded - powinno być w env var
- CORS ustawiony na wszystko - powinien być ograniczony do konkretnych domenów

## Historia Zmian

### Dec 10, 2024
- ✅ Dodano system jednorazowych tokenów
- ✅ Nowa zakładka "Tokeny" w panelu admina
- ✅ Admin może generować tokeny jednorazowe
- ✅ Strona gen-token.html dla użytkowników z tokenem
- ✅ Token pozwala na wygenerowanie 1 dokumentu bez logowania
- ✅ Tokeny są automatycznie oznaczane jako użyte po generacji

### Nov 25, 2024
- ✅ Ekstrahowanie assets z ZIP
- ✅ Skonfigurowanie frontend server na porcie 5000
- ✅ Dodanie systemu autentykacji (login/register)
- ✅ Stworzenie panelu administracyjnego
- ✅ Backend API z JWT tokens
- ✅ Integracja generatora z API do zapisywania dokumentów
- ✅ Admin account created (admin/admin123)
- ✅ Zmiana nazwy twórcy na "MAMBA"

## URL Dostępu

Po uruchomieniu:
- **Frontend**: https://[REPLIT_DOMAIN]/
- **Backend API**: http://localhost:3000 (internal only)

## Deployment

Aplikacja jest gotowa do wdrożenia na Replit:
- Deployment target: VM
- Run command: `python3 server.py` (frontend) + `python3 app.py` (backend)
- Baza danych: PostgreSQL (Replit Neon)
