# mObywatel - Polish ID Card Generator

## Overview
Application for generating Polish ID cards (mObywatel) with authentication and access control. Built as a full-stack application:
- **Web Application**: Flask on port 5000
- **Database**: PostgreSQL for user and document management

**Note**: This application does not generate real documents and is for personal use only.

## Architecture

### Web Application (Port 5000)
- `app.py` - Flask application serving both frontend and API
- HTML Pages:
  - `admin-login.html` - Admin login page (default landing)
  - `login.html` - User login/registration
  - `gen.html` - Document generator (login protected)
  - `gen-token.html` - Token-based document generator
  - `id.html` - Generated document preview
  - `admin.html` - Admin panel (manage access and view documents)
  - `home.html`, `card.html`, `more.html`, `services.html` - Additional pages

### API Endpoints
- `POST /api/auth/create-user` - Create new user
- `POST /api/auth/login` - Login (returns user data)
- `POST /api/documents/save` - Save generated document
- `POST /api/documents/save-with-token` - Save document using one-time token
- `GET /api/documents/<id>` - Get document by ID
- `GET /api/admin/users` - List all users (admin)
- `PUT /api/admin/users/<id>/access` - Control access (admin)
- `GET /api/admin/documents` - Document history (admin)
- `DELETE /api/admin/documents/<id>` - Delete document (admin)
- `GET /api/admin/tokens` - List tokens (admin)
- `POST /api/admin/tokens/create` - Create tokens (admin)
- `DELETE /api/admin/tokens/<id>` - Delete token (admin)
- `POST /api/token/validate` - Validate one-time token

### Database Tables
1. `users` - User accounts:
   - `id`, `username`, `password`, `email`, `has_access`, `is_admin`, `created_at`

2. `generated_documents` - Generated documents:
   - `id`, `user_id`, `name`, `surname`, `pesel`, `created_at`, `data` (JSON)

3. `tokens` - One-time generation tokens:
   - `id`, `token`, `is_used`, `created_at`, `used_at`, `created_by`

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection (auto-set by Replit)

## Workflow
- **Web Server** - `python app.py` (port 5000)

## Default Admin Account
- Username: `mamba`
- Password: `MangoMango67`

## Deployment
- **Target**: Autoscale
- **Run**: `gunicorn --bind=0.0.0.0:5000 --reuse-port app:app`
- **Database**: PostgreSQL (Replit)

## File Structure
```
.
├── app.py                 # Main Flask application
├── assets/                # CSS, JS, images
├── more_files/            # Additional image assets
├── qr_files/              # QR code related assets
├── scanqr_files/          # QR scanner assets
├── services_files/        # Services page assets
├── showqr_files/          # QR display assets
├── *.html                 # HTML pages
└── requirements.txt       # Python dependencies
```

## Technology
- **Framework**: Flask
- **Database**: PostgreSQL
- **Frontend**: Pure HTML/CSS/JavaScript
