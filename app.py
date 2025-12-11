#!/usr/bin/env python3
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_file, send_from_directory, Response
from flask_cors import CORS
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Serve static files from /assets/
@app.route('/assets/<path:filename>')
def serve_assets(filename):
    try:
        return send_from_directory('assets', filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

# Serve HTML files with proper caching headers
def serve_html(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        response = Response(content, mimetype='text/html; charset=utf-8')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    except Exception as e:
        return jsonify({'error': f'Cannot load {filename}: {str(e)}'}), 500


# Database Connection
def get_db():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise ValueError("DATABASE_URL not set")
    return psycopg.connect(db_url)


def init_db():
    """Initialize database with required tables"""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("WARNING: DATABASE_URL not set - skipping database initialization")
        return

    try:
        print(f"Connecting to database...")
        conn = psycopg.connect(db_url)
        cur = conn.cursor()
        print("Connection successful")

        # Users table
        print("Creating users table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                has_access BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE
            )
        ''')
        print("Users table created/verified")

        # Generated documents table
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
        
        # Tokens table for one-time document generation
        print("Creating tokens table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                token VARCHAR(64) UNIQUE NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                created_by INTEGER REFERENCES users(id)
            )
        ''')
        print("Tokens table created/verified")
        
        # Document access tokens table for secure links
        print("Creating doc_access_tokens table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS doc_access_tokens (
                id SERIAL PRIMARY KEY,
                doc_id INTEGER REFERENCES generated_documents(id) ON DELETE CASCADE,
                access_token VARCHAR(128) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                max_views INTEGER DEFAULT NULL,
                view_count INTEGER DEFAULT 0
            )
        ''')
        print("Doc access tokens table created/verified")

        # Seed admin user if not exists
        print("Checking for admin user...")
        try:
            cur.execute('INSERT INTO users (username, password, has_access, is_admin) VALUES (%s, %s, %s, %s)',
                       ('mamba', 'MangoMango67', True, True))
            conn.commit()
            print("✓ Admin user 'mamba' created successfully!")
        except psycopg.IntegrityError:
            print("✓ Admin user 'mamba' already exists")
        
        cur.close()
        conn.close()
        print("✓ Database initialization completed successfully!")
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        import traceback
        traceback.print_exc()


# Serve HTML files with correct MIME types
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
        return jsonify({'error': str(e)}), 404


@app.route('/admin.html')
def admin_page():
    return serve_html('admin.html')


# Force create all tables - visit /api/init-db to initialize
@app.route('/api/init-db', methods=['GET'])
def force_init_db():
    try:
        db_url = os.environ.get('DATABASE_URL')
        if not db_url:
            return jsonify({'error': 'DATABASE_URL not set'}), 500
        
        conn = psycopg.connect(db_url)
        cur = conn.cursor()
        
        # Users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                has_access BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Generated documents table
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
        
        # Tokens table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                token VARCHAR(64) UNIQUE NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                created_by INTEGER REFERENCES users(id)
            )
        ''')
        
        # Doc access tokens table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS doc_access_tokens (
                id SERIAL PRIMARY KEY,
                doc_id INTEGER REFERENCES generated_documents(id) ON DELETE CASCADE,
                access_token VARCHAR(128) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                max_views INTEGER DEFAULT NULL,
                view_count INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        
        # Create admin user
        try:
            cur.execute(
                'INSERT INTO users (username, password, has_access, is_admin) VALUES (%s, %s, %s, %s)',
                ('mamba', 'MangoMango67', True, True))
            conn.commit()
        except:
            pass
        
        cur.close()
        conn.close()
        return jsonify({'message': 'All tables created successfully!', 'tables': ['users', 'generated_documents', 'tokens', 'doc_access_tokens']}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Seed database with admin user
@app.route('/api/seed', methods=['POST'])
def seed():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        # Try to create admin user
        try:
            cur.execute(
                'INSERT INTO users (username, password, has_access, is_admin) VALUES (%s, %s, %s, %s)',
                ('mamba', 'MangoMango67', True, True))
            conn.commit()
            print("Admin user 'mamba' created")
        except psycopg.IntegrityError:
            print("Admin user already exists")
        
        cur.close()
        conn.close()
        return jsonify({'message': 'Database seeded successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Routes
@app.route('/api/auth/create-user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        # Create user with access enabled by default
        cur.execute(
            'INSERT INTO users (username, password, has_access) VALUES (%s, %s, %s)',
            (username, password, True))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'User created successfully'}), 201
    except psycopg.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM users WHERE username = %s', (username, ))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user or user['password'] != password:
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user['has_access']:
            return jsonify({'error':
                            'Access denied. Contact administrator'}), 403

        return jsonify({
            'user_id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin']
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/documents/save', methods=['POST'])
def save_document():
    data = request.get_json()
    user_id = data.get('user_id')

    try:
        conn = get_db()
        cur = conn.cursor()
        import json
        cur.execute(
            '''
            INSERT INTO generated_documents (user_id, name, surname, pesel, data)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        ''',
            (user_id, data.get('name'), data.get('surname'), data.get('pesel'),
             json.dumps(data)))
        doc_id = cur.fetchone()[0]
        
        # Generate secure access token
        access_token = secrets.token_urlsafe(48)
        cur.execute(
            '''
            INSERT INTO doc_access_tokens (doc_id, access_token)
            VALUES (%s, %s)
            ''',
            (doc_id, access_token))
        
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'doc_id': doc_id, 'access_token': access_token}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/documents/access/<access_token>', methods=['GET'])
def get_document_by_token(access_token):
    """Secure document access via encrypted token only"""
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        # Find document by access token
        cur.execute('''
            SELECT d.*, t.expires_at, t.max_views, t.view_count
            FROM doc_access_tokens t
            JOIN generated_documents d ON t.doc_id = d.id
            WHERE t.access_token = %s
        ''', (access_token,))
        
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({'error': 'Nieprawidłowy lub wygasły link'}), 404
        
        # Check expiration
        if result['expires_at'] and result['expires_at'] < datetime.now():
            cur.close()
            conn.close()
            return jsonify({'error': 'Link wygasł'}), 403
        
        # Check view limit
        if result['max_views'] and result['view_count'] >= result['max_views']:
            cur.close()
            conn.close()
            return jsonify({'error': 'Przekroczono limit wyświetleń'}), 403
        
        # Increment view count
        cur.execute(
            'UPDATE doc_access_tokens SET view_count = view_count + 1 WHERE access_token = %s',
            (access_token,))
        conn.commit()
        
        cur.close()
        conn.close()
        
        import json
        data = result['data']
        if isinstance(data, str):
            data = json.loads(data)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users', methods=['GET'])
def get_users():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        cur.execute(
            'SELECT id, username, has_access, created_at FROM users ORDER BY created_at DESC'
        )
        users = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(users), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>/access', methods=['PUT'])
def update_access(user_id):
    data = request.get_json()
    has_access = data.get('has_access')

    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)

        cur.execute('UPDATE users SET has_access = %s WHERE id = %s',
                    (has_access, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Access updated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/documents', methods=['GET'])
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
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM generated_documents WHERE id = %s', (doc_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Document deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


import secrets

@app.route('/api/admin/tokens', methods=['GET'])
def get_tokens():
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('''
            SELECT t.id, t.token, t.is_used, t.created_at, t.used_at
            FROM tokens t
            ORDER BY t.created_at DESC
        ''')
        tokens = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(tokens), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/tokens/create', methods=['POST'])
def create_token():
    try:
        data = request.get_json() or {}
        count = min(int(data.get('count', 1)), 50)
        
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        created_tokens = []
        for _ in range(count):
            token = secrets.token_hex(16)
            cur.execute(
                'INSERT INTO tokens (token) VALUES (%s) RETURNING id, token',
                (token,))
            result = cur.fetchone()
            created_tokens.append({'id': result['id'], 'token': result['token']})
        
        conn.commit()
        cur.close()
        conn.close()
        
        if count == 1:
            return jsonify(created_tokens[0]), 201
        return jsonify({'tokens': created_tokens, 'count': len(created_tokens)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/tokens/<int:token_id>', methods=['DELETE'])
def delete_token(token_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM tokens WHERE id = %s', (token_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Token deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/token/validate', methods=['POST'])
def validate_token():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute('SELECT * FROM tokens WHERE token = %s', (token,))
        token_row = cur.fetchone()
        cur.close()
        conn.close()
        
        if not token_row:
            return jsonify({'valid': False, 'error': 'Token not found'}), 404
        
        if token_row['is_used']:
            return jsonify({'valid': False, 'error': 'Token already used'}), 400
        
        return jsonify({'valid': True, 'token_id': token_row['id']}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/documents/save-with-token', methods=['POST'])
def save_document_with_token():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute('SELECT * FROM tokens WHERE token = %s', (token,))
        token_row = cur.fetchone()
        
        if not token_row:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid token'}), 404
        
        if token_row['is_used']:
            cur.close()
            conn.close()
            return jsonify({'error': 'Token already used'}), 400
        
        import json
        cur.execute(
            '''
            INSERT INTO generated_documents (user_id, name, surname, pesel, data)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            ''',
            (None, data.get('name'), data.get('surname'), data.get('pesel'),
             json.dumps(data)))
        doc_id = cur.fetchone()['id']
        
        # Generate secure access token
        access_token = secrets.token_urlsafe(48)
        cur.execute(
            '''
            INSERT INTO doc_access_tokens (doc_id, access_token)
            VALUES (%s, %s)
            ''',
            (doc_id, access_token))
        
        cur.execute(
            'UPDATE tokens SET is_used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = %s',
            (token_row['id'],))
        
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'doc_id': doc_id, 'access_token': access_token}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/gen-token.html')
def gen_token_page():
    return serve_html('gen-token.html')


# Initialize database on startup (before gunicorn starts)
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
