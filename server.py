#!/usr/bin/env python3
import http.server
import socketserver
import os
import urllib.request
import urllib.error
import json

PORT = int(os.environ.get('PORT', 5000))
HOST = "0.0.0.0"
BACKEND_URL = os.environ.get('BACKEND_URL', 'http://localhost:3000')

class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Disable caching to ensure updates are visible in Replit's iframe
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        """Proxy POST requests to /api/* to backend"""
        if self.path.startswith('/api/'):
            self._proxy_request('POST')
        else:
            self.send_response(501)
            self.end_headers()

    def do_PUT(self):
        """Proxy PUT requests to /api/* to backend"""
        if self.path.startswith('/api/'):
            self._proxy_request('PUT')
        else:
            self.send_response(501)
            self.end_headers()

    def do_GET(self):
        """Handle GET requests normally for files, proxy /api/* to backend"""
        if self.path.startswith('/api/'):
            self._proxy_request('GET')
        else:
            super().do_GET()

    def _proxy_request(self, method):
        """Proxy HTTP requests to backend API"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''

            url = BACKEND_URL + self.path
            
            # Build headers - explicitly handle Authorization
            headers = {}
            authorization = None
            
            for k, v in self.headers.items():
                k_lower = k.lower()
                # Skip certain headers
                if k_lower in ['host', 'connection', 'content-length']:
                    continue
                # Capture Authorization separately to ensure it's passed
                if k_lower == 'authorization':
                    authorization = v
                    headers[k] = v
                else:
                    headers[k] = v
            
            # If Authorization wasn't found with any casing, try to get it
            if not authorization:
                authorization = self.headers.get('Authorization') or self.headers.get('authorization')
                if authorization:
                    headers['Authorization'] = authorization
            
            req = urllib.request.Request(
                url,
                data=body if body else None,
                method=method,
                headers=headers
            )

            with urllib.request.urlopen(req) as response:
                status_code = response.status
                response_headers = dict(response.headers)
                response_body = response.read()

                self.send_response(status_code)
                for header, value in response_headers.items():
                    if header.lower() not in ['transfer-encoding', 'content-encoding']:
                        self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response_body)

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            try:
                self.wfile.write(e.read())
            except:
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    with socketserver.TCPServer((HOST, PORT), ProxyHTTPRequestHandler) as httpd:
        print(f"Server running at http://{HOST}:{PORT}/")
        print(f"API proxy: http://{HOST}:{PORT}/api/* -> {BACKEND_URL}/api/*")
        print("Press Ctrl+C to stop the server")
        httpd.serve_forever()
