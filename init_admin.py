#!/usr/bin/env python3
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
cur = conn.cursor()

# Create admin user
cur.execute('''
    INSERT INTO users (username, password, has_access, is_admin)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (username) DO UPDATE SET
    password = EXCLUDED.password, has_access = true, is_admin = true
''', ('admin', 'admin123', True, True))

conn.commit()
cur.close()
conn.close()

print("✅ Admin account created: username=admin, password=admin123")
