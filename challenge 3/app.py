from flask import Flask, render_template, request, jsonify, send_from_directory, make_response
import hashlib
import random
import re
import os
import time
from functools import wraps

# Initialize Flask application
app = Flask(__name__)

# Security configurations
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # Limit request size to 16KB
app.config['TEMPLATES_AUTO_RELOAD'] = False  # Disable template auto-reload in production
app.config['SECRET_KEY'] = os.urandom(32)  # Random secret key on each restart

def secure_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Allow frames from same origin
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Server'] = 'IRIS Challenge Server'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def validate_formula(formula):
    """
    Validate if the formula matches exactly: y = (x**2)/7
    """
    if not formula:
        return False
    # Remove all whitespace for comparison
    formula = ''.join(formula.split())
    # Direct string comparison with the expected formula
    expected = 'y=(x**2)/7'
    return formula == expected

def rate_limit(func):
    """Basic rate limiting decorator"""
    last_requests = {}
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        current_time = int(time.time())
        
        # Allow 60 requests per minute
        if ip in last_requests:
            requests = [t for t in last_requests[ip] if current_time - t < 60]
            if len(requests) >= 60:
                return jsonify({'error': 'Too many requests'}), 429
            last_requests[ip] = requests + [current_time]
        else:
            last_requests[ip] = [current_time]
        
        return func(*args, **kwargs)
    return wrapper

# Serve index.html and static files
@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    return secure_headers(response)

@app.route('/static/<path:filename>')
def serve_static(filename):
    # Allow CSS and other necessary static files
    allowed_extensions = ['.css', '.js', '.png', '.jpg', '.ico']
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        return 'Not Found', 404
    response = make_response(send_from_directory('static', filename))
    return secure_headers(response)

@app.route('/api/generate_key', methods=['POST'])
@rate_limit
def api_generate_key():
    try:
        if not request.is_json:
            return jsonify({'error': 'Invalid content type'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        formula = data.get('input')
        if formula is None:
            return jsonify({'error': 'Formula required'}), 400
        
        if not validate_formula(formula):
            return jsonify({'error': 'Invalid formula'}), 400
        
        # Generate a unique key based on the timestamp
        timestamp = hashlib.sha256(str(random.random()).encode()).hexdigest()[:6]
        key = f"0x{timestamp}"
        
        response = make_response(jsonify({'key': key}))
        return secure_headers(response)
    except Exception as e:
        return secure_headers(make_response(jsonify({'error': 'Internal error'}), 500))

@app.route('/api/check_prediction', methods=['POST'])
@rate_limit
def api_check_prediction():
    try:
        if not request.is_json:
            return jsonify({'error': 'Invalid content type'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        key = data.get('key')
        if key is None or not isinstance(key, str):
            return jsonify({'error': 'Neural key required'}), 400
        
        if not key.startswith('0x') or not re.match(r'^0x[a-f0-9]{6}$', key):
            return jsonify({'error': 'Invalid key format'}), 400
        
        response = {
            'prediction': 'Artificial',
            'is_correct': True
        }
        
        # Generate flag with the key
        timestamp = key[2:]
        flag = f"Exploit3rs{{IRIS_BYPASS_FORMULA_T}}"
        response['flag'] = flag
        
        response = make_response(jsonify(response))
        return secure_headers(response)
    except Exception as e:
        return secure_headers(make_response(jsonify({'error': 'Internal error'}), 500))

@app.route('/api/test_formula', methods=['POST'])
@rate_limit
def test_formula():
    try:
        if not request.is_json:
            return jsonify({'error': 'Invalid content type'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        x = data.get('x')
        if x is None:
            return jsonify({'error': 'Input value required'}), 400
        
        try:
            x = int(x)
            if not (-1000 <= x <= 1000):  # Limit input range to prevent huge numbers
                return jsonify({'error': 'Input value out of range (-1000 to 1000)'}), 400
                
            # Calculate y using the formula
            y = (x**2)/7
            response = make_response(jsonify({'y': y}))
            return secure_headers(response)
        except ValueError:
            return secure_headers(make_response(jsonify({'error': 'Invalid input value'}), 400))
    except Exception as e:
        return secure_headers(make_response(jsonify({'error': 'Internal error'}), 500))

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return secure_headers(make_response(jsonify({'error': 'Not found'}), 404))

@app.errorhandler(405)
def method_not_allowed(e):
    return secure_headers(make_response(jsonify({'error': 'Method not allowed'}), 405))

@app.errorhandler(500)
def internal_error(e):
    return secure_headers(make_response(jsonify({'error': 'Internal error'}), 500))

if __name__ == '__main__':
    # Ensure templates directory is read-only
    os.chmod('templates', 0o444)
    # Ensure static directory is read-only
    os.chmod('static', 0o444)
    
    # Run with security settings
    app.run(
        debug=False,  # Disable debug mode
        host='0.0.0.0',  # Allow external connections
        port=5000,
        threaded=True
    ) 