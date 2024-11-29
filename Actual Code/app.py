from flask import Flask, render_template, request, jsonify, session
from functools import wraps
import random
import string
import secrets
import hashlib
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import re
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Secure Secret Key Configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = os.environ.get('DEBUG', 'False') == 'True'

# Logging Configuration
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Email Configuration
EMAIL_CONFIG = {
    'FROM': os.environ.get('EMAIL_FROM', 'shreevatsa.21cse@cambridge.edu.in'),
    'PASSWORD': os.environ.get('EMAIL_PASSWORD', 'Newtonisnothuman123'),
    'SMTP_SERVER': os.environ.get('SMTP_SERVER', 'smtp.gmail.com'),
    'SMTP_PORT': int(os.environ.get('SMTP_PORT', 587))
}

# Predefined Security Questions
SECURITY_QUESTIONS = {
    'mother_maiden_name': 'What is your mother\'s maiden name?',
    'first_pet': 'What was the name of your first pet?',
    'childhood_city': 'In which city did you grow up?'
}

# Simulated User Database
class UserDatabase:
    def __init__(self):
        self._users = {
            "test@example.com": {
                "password": self._hash_password("Test@123"),
                "security_questions": {
                    "mother_maiden_name": "Smith",
                    "first_pet": "Fluffy"
                }
            }
        }

    def _hash_password(self, password):
        """Hash password securely."""
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt.encode('utf-8'), 
            100000
        ).hex()
        return f"{salt}${hashed}"

    def verify_password(self, email, password):
        """Verify password."""
        if email not in self._users:
            return False
        
        stored_password = self._users[email]['password']
        salt, stored_hash = stored_password.split('$')
        
        input_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt.encode('utf-8'), 
            100000
        ).hex()
        
        return input_hash == stored_hash

    def get_security_questions(self, email):
        """Get security questions for a user."""
        return self._users.get(email, {}).get('security_questions', {})

# Initialize User Database
users_db = UserDatabase()

# OTP Management
class OTPManager:
    def __init__(self):
        self.otps = {}

    def generate_otp(self, email):
        """Generate and store OTP."""
        otp = ''.join(random.choices(string.digits, k=6))
        self.otps[email] = {
            'otp': otp,
            'created_at': datetime.now()
        }
        return otp

    def validate_otp(self, email, otp):
        """Validate OTP."""
        if email not in self.otps:
            return False
        
        stored_otp = self.otps[email]
        if (datetime.now() - stored_otp['created_at']) > timedelta(minutes=5):
            del self.otps[email]
            return False
        
        is_valid = stored_otp['otp'] == otp
        if is_valid:
            del self.otps[email]
        return is_valid

# Initialize OTP Manager
otp_manager = OTPManager()

# Email Service
class EmailService:
    @staticmethod
    def send_otp(email, otp):
        """Send OTP via email."""
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG['FROM']
            msg['To'] = email
            msg['Subject'] = 'Your One-Time Password (OTP)'

            body = f'Your OTP is: {otp}\nThis OTP will expire in 5 minutes.'
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(EMAIL_CONFIG['SMTP_SERVER'], EMAIL_CONFIG['SMTP_PORT']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['FROM'], EMAIL_CONFIG['PASSWORD'])
                server.send_message(msg)
            
            return True
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            return False

# Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    if not users_db.verify_password(email, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate and send OTP
    otp = otp_manager.generate_otp(email)
    
    if EmailService.send_otp(email, otp):
        session['email'] = email
        return jsonify({'message': 'OTP sent successfully'}), 200
    else:
        return jsonify({'error': 'Failed to send OTP'}), 500

@app.route('/verify', methods=['POST'])
def verify():
    email = session.get('email')
    otp = request.json.get('otp')

    if not email or not otp:
        return jsonify({'error': 'Missing email or OTP'}), 400

    if otp_manager.validate_otp(email, otp):
        session['authenticated'] = True
        return jsonify({'message': 'Authentication successful'}), 200
    else:
        return jsonify({'error': 'Invalid or expired OTP'}), 401

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return jsonify({'error': 'User not authenticated'}), 403
    return render_template('dashboard.html')

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
