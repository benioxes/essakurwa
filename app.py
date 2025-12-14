#!/usr/bin/env python3
import os
import secrets
import json
import hashlib
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, send_file, send_from_directory, Response, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
import bcrypt

load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
is_production = os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('PRODUCTION')
app.config['SESSION_COOKIE_SECURE'] = bool(is_production)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

CORS(app, origins=['*'], supports_credentials=True)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "blob:", "https://i.imgur.com", "https://res.cloudinary.com", "https://*.cloudinary.com", "https:"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
    'connect-src': "'self'"
}

Talisman(app, 
         content_security_policy=csp,
         force_https=False,
         session_cookie_secure=False)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return password == hashed


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def sanitize_input(value, max_length=255):
    if not value:
        return value
    value = str(value)[:max_length]
    value = re.sub(r'[<>"\';]', '', value)
    return value.strip()


def validate_pesel(pesel):
    if not pesel:
        return True
    pesel = str(pesel)
    return len(pesel) <= 11 and pesel.isdigit()


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_id'):
            return jsonify({'error': 'Unauthorized - Admin access required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/assets/<path:filename>')
def serve_assets(filename):
    try:
        return send_from_directory('assets', filename)
    except Exception as e:
        return jsonify({'error': 'File not found'}), 404


def serve_html(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        response = Response(content, mimetype='text/html; charset=utf-8')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response
    except Exception as e:
        return jsonify({'error': 'Page not found'}), 500


def get_db():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise ValueError("DATABASE_URL not set")
    return psycopg.connect(db_url)


def init_db():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("WARNING: DATABASE_URL not set - skipping database initialization")
        return

    try:
        print(f"Connecting to database...")
        conn = psycopg.connect(db_url)
        cur = conn.cursor()
        print("Connection successful")

        print("Creating users table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                has_access BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')
        print("Users table created/verified")
        
        print("Adding missing columns to users table if needed...")
        try:
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0")
        except:
            pass
        try:
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP")
        except:
            pass
        try:
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE")
        except:
            pass
        conn.commit()
        print("Users table columns verified")

        print("Creating generated_documents table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS generated_documents (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                name VARCHAR(255),
                surname VARCHAR(255),
                pesel VARCHAR(11),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data JSON
            )
        ''')
        
        print("Creating tokens table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                token_hash VARCHAR(64) UNIQUE NOT NULL,
                token_prefix VARCHAR(8),
                is_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                created_by INTEGER REFERENCES users(id),
                expires_at TIMESTAMP
            )
        ''')
        print("Tokens table created/verified")
        
        print("Adding missing columns to tokens table if needed...")
        try:
            cur.execute("ALTER TABLE tokens ADD COLUMN IF NOT EXISTS token_prefix VARCHAR(8)")
        except:
            pass
        try:
            cur.execute("ALTER TABLE tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP")
        except:
            pass
        try:
            cur.execute("ALTER TABLE tokens ADD COLUMN IF NOT EXISTS used_at TIMESTAMP")
        except:
            pass
        try:
            cur.execute("ALTER TABLE tokens ADD COLUMN IF NOT EXISTS created_by INTEGER")
        except:
            pass
        conn.commit()
        print("Tokens table columns verified")
        
        print("Creating doc_access_tokens table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS doc_access_tokens (
                id SERIAL PRIMARY KEY,
                doc_id INTEGER REFERENCES generated_documents(id) ON DELETE CASCADE,
                access_token_hash VARCHAR(64) UNIQUE NOT NULL,
                access_token_prefix VARCHAR(8),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                max_views INTEGER DEFAULT NULL,
                view_count INTEGER DEFAULT 0
            )
        ''')
        
        print("Adding missing columns to doc_access_tokens table if needed...")
        try:
            cur.execute("ALTER TABLE doc_access_tokens ADD COLUMN IF NOT EXISTS access_token_prefix VARCHAR(8)")
        except:
            pass
        try:
            cur.execute("ALTER TABLE doc_access_tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP")
        except:
            pass
        try:
            cur.execute("ALTER TABLE doc_access_tokens ADD COLUMN IF NOT EXISTS max_views INTEGER DEFAULT NULL")
        except:
            pass
        try:
            cur.execute("ALTER TABLE doc_access_tokens ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0")
        except:
            pass
        conn.commit()
        print("Doc access tokens table columns verified")
        
        print("Creating audit_log table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                action VARCHAR(100),
                details TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        print("All tables created/verified")

        admin_password = os.environ.get('ADMIN_PASSWORD', 'MangoMango67')
        hashed_password = hash_password(admin_password)
        force_reset = os.environ.get('FORCE_ADMIN_RESET', '').lower() in ('true', '1', 'yes')
        
        print("Checking for admin user...")
        cur.execute('SELECT id, password FROM users WHERE username = %s', ('mamba',))
        existing = cur.fetchone()
        
        if not existing:
            cur.execute('INSERT INTO users (username, password, has_access, is_admin) VALUES (%s, %s, %s, %s)',
                       ('mamba', hashed_password, True, True))
            conn.commit()
            print("Admin user 'mamba' created with hashed password!")
        elif force_reset:
            cur.execute('UPDATE users SET password = %s, failed_attempts = 0, locked_until = NULL WHERE username = %s', (hashed_password, 'mamba'))
            conn.commit()
            print("Admin password FORCE RESET completed!")
        else:
            stored_hash = existing[1]
            if not stored_hash.startswith('$2'):
                cur.execute('UPDATE users SET password = %s, failed_attempts = 0, locked_until = NULL WHERE username = %s', (hashed_password, 'mamba'))
                conn.commit()
                print("Admin password upgraded to bcrypt hash!")
            elif not verify_password(admin_password, stored_hash):
                cur.execute('UPDATE users SET password = %s, failed_attempts = 0, locked_until = NULL WHERE username = %s', (hashed_password, 'mamba'))
                conn.commit()
                print("Admin password updated from ADMIN_PASSWORD env variable!")
            else:
                print("Admin user 'mamba' already exists with correct password")
        
        cur.close()
        conn.close()
        print("Database initialization completed successfully!")
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        import traceback
        traceback.print_exc()


def log_action(user_id, action, details=None):
    try:
        conn = get_db()
        cur = conn.cursor()
        ip = request.remote_addr or 'unknown'
        cur.execute(
            'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (%s, %s, %s, %s)',
            (user_id, action, details, ip)
        )
        conn.commit()
        cur.close()
        conn.close()
    except:
        pass


@app.route('/')
def index():
    return serve_html('admin-login.html')


@app.route('/admin-login.html')
def admin_login_page():
    return serve_html('admin-login.html')


@app.route('/login.html')
def login_page():
    return serve_html('login.html')


@app.route('/gen.html')
def gen_page():
    return serve_html('gen.html')


@app.route('/id.html')
def id_page():
    return serve_html('id.html')


@app.route('/card-view.html')
def card_view_page():
    return serve_html('card-view.html')


@app.route('/manifest.json')
def manifest():
    try:
        with open('manifest.json', 'r', encoding='utf-8') as f:
            content = f.read()
        response = Response(content, mimetype='application/manifest+json')
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
    except Exception as e:
        return jsonify({'error': 'Not found'}), 404


@app.route('/admin.html')
def admin_page():
    return serve_html('admin.html')


@app.route('/api/auth/create-user', methods=['POST'])
@require_admin
@limiter.limit("10 per hour")
def create_user():
    data = request.get_json()
    username = sanitize_input(data.get('username'), 50)
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        hashed = hash_password(password)
        cur.execute(
            'INSERT INTO users (username, password, has_access) VALUES (%s, %s, %s)',
            (username, hashed, True))
        conn.commit()
        
        log_action(session.get('admin_id'), 'CREATE_USER', f'Created user: {username}')
        
        cur.close()
        conn.close()
        return jsonify({'message': 'User created successfully'}), 201
    except psycopg.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        return jsonify({'error': 'Failed to create user'}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    username = sanitize_input(data.get('username'), 50)
    password = data.get('password')

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        
        if not user:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user.get('locked_until') and user['locked_until'] > datetime.now():
            cur.close()
            conn.close()
            return jsonify({'error': 'Account temporarily locked. Try again later.'}), 429
        
        if not verify_password(password, user['password']):
            cur.execute(
                'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = %s',
                (user['id'],))
            
            if user.get('failed_attempts', 0) >= 4:
                cur.execute(
                    'UPDATE users SET locked_until = %s WHERE id = %s',
                    (datetime.now() + timedelta(minutes=15), user['id']))
            
            conn.commit()
            cur.close()
            conn.close()
            log_action(user['id'], 'LOGIN_FAILED', f'Failed login for: {username}')
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user['has_access']:
            cur.close()
            conn.close()
            return jsonify({'error': 'Access denied. Contact administrator'}), 403

        cur.execute(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s',
            (user['id'],))
        conn.commit()
        
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        if user['is_admin']:
            session['admin_id'] = user['id']
        
        log_action(user['id'], 'LOGIN_SUCCESS', f'User logged in: {username}')
        
        cur.close()
        conn.close()

        return jsonify({
            'user_id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin']
        }), 200
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'User logged out')
    session.clear()
    return jsonify({'message': 'Logged out'}), 200


@app.route('/api/documents/save', methods=['POST'])
@require_auth
@limiter.limit("20 per hour")
def save_document():
    data = request.get_json()
    user_id = session.get('user_id')
    
    name = sanitize_input(data.get('name'), 100)
    surname = sanitize_input(data.get('surname'), 100)
    pesel = sanitize_input(data.get('pesel'), 11)
    
    if not validate_pesel(pesel):
        return jsonify({'error': 'Invalid PESEL format'}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        
        sanitized_data = {k: sanitize_input(v) if isinstance(v, str) else v for k, v in data.items()}
        
        cur.execute(
            '''
            INSERT INTO generated_documents (user_id, name, surname, pesel, data)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        ''',
            (user_id, name, surname, pesel, json.dumps(sanitized_data)))
        doc_id = cur.fetchone()[0]
        
        access_token = secrets.token_urlsafe(48)
        token_hash = hash_token(access_token)
        expires = datetime.now() + timedelta(days=30)
        
        cur.execute(
            '''
            INSERT INTO doc_access_tokens (doc_id, access_token_hash, access_token_prefix, expires_at)
            VALUES (%s, %s, %s, %s)
            ''',
            (doc_id, token_hash, access_token[:8], expires))
        
        conn.commit()
        
        log_action(user_id, 'CREATE_DOCUMENT', f'Created document ID: {doc_id}')
        
        cur.close()
        conn.close()
        return jsonify({'doc_id': doc_id, 'access_token': access_token}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to save document'}), 500


@app.route('/api/documents/access/<access_token>', methods=['GET'])
@limiter.limit("30 per minute")
def get_document_by_token(access_token):
    try:
        token_hash = hash_token(access_token)
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute('''
            SELECT d.*, t.expires_at, t.max_views, t.view_count
            FROM doc_access_tokens t
            JOIN generated_documents d ON t.doc_id = d.id
            WHERE t.access_token_hash = %s OR t.access_token = %s
        ''', (token_hash, access_token))
        
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid or expired link'}), 404
        
        if result['expires_at'] and result['expires_at'] < datetime.now():
            cur.close()
            conn.close()
            return jsonify({'error': 'Link expired'}), 403
        
        if result['max_views'] and result['view_count'] >= result['max_views']:
            cur.close()
            conn.close()
            return jsonify({'error': 'View limit exceeded'}), 403
        
        cur.execute(
            'UPDATE doc_access_tokens SET view_count = view_count + 1 WHERE access_token_hash = %s OR access_token = %s',
            (token_hash, access_token))
        conn.commit()
        
        cur.close()
        conn.close()
        
        data = result['data']
        if isinstance(data, str):
            data = json.loads(data)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve document'}), 500


@app.route('/api/admin/users', methods=['GET'])
@require_admin
def get_users():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        cur.execute(
            'SELECT id, username, has_access, created_at, is_admin FROM users ORDER BY created_at DESC'
        )
        users = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(users), 200
    except Exception as e:
        return jsonify({'error': 'Failed to load users'}), 500


@app.route('/api/admin/users/<int:user_id>/access', methods=['PUT'])
@require_admin
def update_access(user_id):
    data = request.get_json()
    has_access = data.get('has_access')

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        cur.execute('UPDATE users SET has_access = %s WHERE id = %s',
                    (has_access, user_id))
        conn.commit()
        
        log_action(session.get('admin_id'), 'UPDATE_ACCESS', f'User {user_id} access set to {has_access}')
        
        cur.close()
        conn.close()
        return jsonify({'message': 'Access updated'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to update access'}), 500


@app.route('/api/admin/documents', methods=['GET'])
@require_admin
def get_all_documents():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        cur.execute('''
            SELECT d.id, u.username, d.name, d.surname, d.pesel, d.created_at
            FROM generated_documents d
            LEFT JOIN users u ON d.user_id = u.id
            ORDER BY d.created_at DESC
        ''')
        documents = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(documents), 200
    except Exception as e:
        return jsonify({'error': 'Failed to load documents'}), 500


@app.route('/api/admin/documents/<int:doc_id>', methods=['DELETE'])
@require_admin
def delete_document(doc_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM generated_documents WHERE id = %s', (doc_id,))
        conn.commit()
        
        log_action(session.get('admin_id'), 'DELETE_DOCUMENT', f'Deleted document ID: {doc_id}')
        
        cur.close()
        conn.close()
        return jsonify({'message': 'Document deleted'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to delete document'}), 500


@app.route('/api/admin/tokens', methods=['GET'])
@require_admin
def get_tokens():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('''
            SELECT t.id, t.token_prefix, t.is_used, t.created_at, t.used_at, t.expires_at
            FROM tokens t
            ORDER BY t.created_at DESC
        ''')
        tokens = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(tokens), 200
    except Exception as e:
        return jsonify({'error': 'Failed to load tokens'}), 500


@app.route('/api/admin/tokens/create', methods=['POST'])
@require_admin
@limiter.limit("20 per hour")
def create_token():
    try:
        data = request.get_json() or {}
        count = min(int(data.get('count', 1)), 50)
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        created_tokens = []
        expires = datetime.now() + timedelta(days=7)
        
        for _ in range(count):
            token = secrets.token_hex(16)
            token_hash_val = hash_token(token)
            cur.execute(
                'INSERT INTO tokens (token_hash, token_prefix, expires_at) VALUES (%s, %s, %s) RETURNING id',
                (token_hash_val, token[:8], expires))
            result = cur.fetchone()
            created_tokens.append({'id': result['id'], 'token': token})
        
        conn.commit()
        
        log_action(session.get('admin_id'), 'CREATE_TOKENS', f'Created {count} tokens')
        
        cur.close()
        conn.close()
        
        if count == 1:
            return jsonify(created_tokens[0]), 201
        return jsonify({'tokens': created_tokens, 'count': len(created_tokens)}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to create tokens'}), 500


@app.route('/api/admin/tokens/<int:token_id>', methods=['DELETE'])
@require_admin
def delete_token(token_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM tokens WHERE id = %s', (token_id,))
        conn.commit()
        
        log_action(session.get('admin_id'), 'DELETE_TOKEN', f'Deleted token ID: {token_id}')
        
        cur.close()
        conn.close()
        return jsonify({'message': 'Token deleted'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to delete token'}), 500


@app.route('/api/token/validate', methods=['POST'])
@limiter.limit("10 per minute")
def validate_token():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    try:
        token_hash_val = hash_token(token)
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM tokens WHERE token_hash = %s OR token = %s', (token_hash_val, token))
        token_row = cur.fetchone()
        cur.close()
        conn.close()
        
        if not token_row:
            return jsonify({'valid': False, 'error': 'Token not found'}), 404
        
        if token_row['is_used']:
            return jsonify({'valid': False, 'error': 'Token already used'}), 400
        
        if token_row.get('expires_at') and token_row['expires_at'] < datetime.now():
            return jsonify({'valid': False, 'error': 'Token expired'}), 400
        
        return jsonify({'valid': True, 'token_id': token_row['id']}), 200
    except Exception as e:
        return jsonify({'error': 'Validation failed'}), 500


@app.route('/api/documents/save-with-token', methods=['POST'])
@limiter.limit("10 per hour")
def save_document_with_token():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    name = sanitize_input(data.get('name'), 100)
    surname = sanitize_input(data.get('surname'), 100)
    pesel = sanitize_input(data.get('pesel'), 11)
    
    if not validate_pesel(pesel):
        return jsonify({'error': 'Invalid PESEL format'}), 400
    
    try:
        token_hash_val = hash_token(token)
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute('SELECT * FROM tokens WHERE token_hash = %s OR token = %s', (token_hash_val, token))
        token_row = cur.fetchone()
        
        if not token_row:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid token'}), 404
        
        if token_row['is_used']:
            cur.close()
            conn.close()
            return jsonify({'error': 'Token already used'}), 400
        
        if token_row.get('expires_at') and token_row['expires_at'] < datetime.now():
            cur.close()
            conn.close()
            return jsonify({'error': 'Token expired'}), 400
        
        sanitized_data = {k: sanitize_input(v) if isinstance(v, str) else v for k, v in data.items()}
        
        cur.execute(
            '''
            INSERT INTO generated_documents (user_id, name, surname, pesel, data)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            ''',
            (None, name, surname, pesel, json.dumps(sanitized_data)))
        doc_id = cur.fetchone()['id']
        
        access_token = secrets.token_urlsafe(48)
        
        cur.execute(
            '''
            INSERT INTO doc_access_tokens (doc_id, access_token, access_token_hash, access_token_prefix, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ''',
            (doc_id, access_token, hash_token(access_token), access_token[:8], datetime.now() + timedelta(days=30)))
        
        cur.execute(
            'UPDATE tokens SET is_used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = %s',
            (token_row['id'],))
        
        conn.commit()
        
        log_action(None, 'CREATE_DOCUMENT_TOKEN', f'Document {doc_id} created with token')
        
        cur.close()
        conn.close()
        return jsonify({'doc_id': doc_id, 'access_token': access_token}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to save document'}), 500


@app.route('/gen-token.html')
def gen_token_page():
    return serve_html('gen-token.html')


@app.route('/api/admin/documents/<int:doc_id>/access-token', methods=['GET'])
@require_admin
def get_document_access_token(doc_id):
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        access_token = secrets.token_urlsafe(48)
        token_hash = hash_token(access_token)
        expires = datetime.now() + timedelta(days=30)
        
        cur.execute('DELETE FROM doc_access_tokens WHERE doc_id = %s', (doc_id,))
        
        cur.execute(
            'INSERT INTO doc_access_tokens (doc_id, access_token_hash, access_token_prefix, expires_at) VALUES (%s, %s, %s, %s)',
            (doc_id, token_hash, access_token[:8], expires))
        conn.commit()
        
        cur.close()
        conn.close()
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to get access token'}), 500


@app.route('/api/admin/documents/<int:doc_id>', methods=['GET'])
@require_admin
def get_document_for_edit(doc_id):
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute('''
            SELECT id, name, surname, pesel, data FROM generated_documents WHERE id = %s
        ''', (doc_id,))
        doc = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not doc:
            return jsonify({'error': 'Document not found'}), 404
        
        data = doc['data']
        if isinstance(data, str):
            data = json.loads(data)
        
        return jsonify({
            'id': doc['id'],
            'name': doc['name'],
            'surname': doc['surname'],
            'pesel': doc['pesel'],
            'data': data
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to load document'}), 500


@app.route('/api/admin/documents/<int:doc_id>', methods=['PUT'])
@require_admin
def update_document(doc_id):
    data = request.get_json()
    
    name = sanitize_input(data.get('name'), 100)
    surname = sanitize_input(data.get('surname'), 100)
    pesel = sanitize_input(data.get('pesel'), 11)
    
    if not validate_pesel(pesel):
        return jsonify({'error': 'Invalid PESEL format'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        sanitized_data = {k: sanitize_input(v) if isinstance(v, str) else v for k, v in data.items()}
        
        cur.execute('''
            UPDATE generated_documents 
            SET name = %s, surname = %s, pesel = %s, data = %s
            WHERE id = %s
        ''', (name, surname, pesel, json.dumps(sanitized_data), doc_id))
        
        conn.commit()
        
        log_action(session.get('admin_id'), 'UPDATE_DOCUMENT', f'Updated document ID: {doc_id}')
        
        cur.close()
        conn.close()
        return jsonify({'message': 'Document updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to update document'}), 500


@app.route('/home.html')
def home_page():
    return serve_html('home.html')


@app.route('/more.html')
def more_page():
    return serve_html('more.html')


@app.route('/moreid.html')
def moreid_page():
    return serve_html('moreid.html')


@app.route('/pesel.html')
def pesel_page():
    return serve_html('pesel.html')


@app.route('/qr.html')
def qr_page():
    return serve_html('qr.html')


@app.route('/showqr.html')
def showqr_page():
    return serve_html('showqr.html')


@app.route('/scanqr.html')
def scanqr_page():
    return serve_html('scanqr.html')


@app.route('/services.html')
def services_page():
    return serve_html('services.html')


@app.route('/shortcuts.html')
def shortcuts_page():
    return serve_html('shortcuts.html')


@app.route('/card.html')
def card_page():
    return serve_html('card.html')


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Too many requests. Please slow down.'}), 429


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
