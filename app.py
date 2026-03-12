import os
import random
from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyotp
import sqlite3
import qrcode
from datetime import datetime
import bcrypt
from flask import jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Define the absolute path for the database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'database.db')

# DB connection helper
def get_db_connection():
    return sqlite3.connect(DATABASE_PATH)

# Initialize DB with error handling
def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            totp_secret TEXT NOT NULL)''')
        conn.commit()
        print(f"Successfully initialized database at {DATABASE_PATH}")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

# Clean up old QR codes on startup
def clean_old_qr_codes():
    qr_dir = os.path.join(BASE_DIR, 'static')
    if not os.path.exists(qr_dir):
        os.makedirs(qr_dir)
    for filename in os.listdir(qr_dir):
        if filename.startswith('qrcode_') and filename.endswith('.png'):
            try:
                os.remove(os.path.join(qr_dir, filename))
            except Exception as e:
                print(f"Error deleting {filename}: {e}")

# Call init_db and cleanup at startup
init_db()
clean_old_qr_codes()

# List of cybersecurity tips
CYBER_TIPS = [
    "Use a unique password for every account to prevent credential stuffing attacks.",
    "Enable 2FA on all your accounts to add an extra layer of security.",
    "Avoid clicking on links in unsolicited emails—they might be phishing attempts.",
    "Regularly update your software to protect against known vulnerabilities.",
    "Use a password manager to securely store and generate complex passwords.",
    "Be cautious of public Wi-Fi—use a VPN to encrypt your connection.",
    "Never share your 2FA codes with anyone, even if they claim to be from support.",
    "Check for HTTPS in the URL before entering sensitive information on a website.",
    "Back up your data regularly to protect against ransomware attacks.",
    "Monitor your accounts for suspicious activity and set up alerts if possible."
]

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."
    if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in password):
        return False, "Password must contain at least one special character."
    return True, ""

def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) < 8:
        feedback.append("Password is too short (minimum 8 characters).")
    else:
        score += 1

    if any(char.isupper() for char in password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if any(char.islower() for char in password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if any(char.isdigit() for char in password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    if any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in password):
        score += 1
    else:
        feedback.append("Add at least one special character (!@#$%^&*).")

    if score == 5:
        return "Strong", ["Great job! Your password is strong."]
    elif score >= 3:
        return "Moderate", feedback
    else:
        return "Weak", feedback

@app.route('/')
def index():
    return render_template('index.html', mode='index', title='Welcome')

@app.route('/register', methods=['GET', 'POST'])
def register():
    qr_image_path = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, "danger")
            return render_template('index.html', mode='register', title='Register', qr_image=None)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        totp_secret = pyotp.random_base32()
        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)",
                         (username, hashed_password.decode('utf-8'), totp_secret))
            conn.commit()

            uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureLogin")
            img = qrcode.make(uri)
            qr_image_path = f'qrcode_{username}.png'
            img.save(f'static/{qr_image_path}')

            session['pending_qr_user'] = username
            session['qr_image_path'] = qr_image_path
            flash("Account created! Scan QR with Google Authenticator.", "info")
            return redirect(url_for('confirm_qr'))
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' already exists. Please choose a different username.", "danger")
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
        finally:
            conn.close()

    return render_template('index.html', mode='register', title='Register', qr_image=qr_image_path)

@app.route('/confirm-qr', methods=['GET', 'POST'])
def confirm_qr():
    if 'pending_qr_user' not in session:
        flash("Please register first.", "danger")
        return redirect(url_for('register'))

    qr_image_path = session.get('qr_image_path')
    if request.method == 'POST':
        try:
            if qr_image_path and os.path.exists(f'static/{qr_image_path}'):
                os.remove(f'static/{qr_image_path}')
        except OSError:
            pass
        session.pop('pending_qr_user', None)
        session.pop('qr_image_path', None)
        flash("QR code confirmed! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('index.html', mode='confirm-qr', title='Confirm QR Code', qr_image=qr_image_path)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                session['username'] = username
                session['totp_secret'] = user[3]
                session['qr_regen_count'] = 0
                return redirect(url_for('mfa'))
            else:
                flash("Username or password incorrect.", "danger")
        except sqlite3.Error:
            flash("An error occurred. Please try again.", "danger")
        finally:
            conn.close()
    return render_template('index.html', mode='login', title='Login')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'username' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token']
        conn = get_db_connection()
        user = conn.execute("SELECT totp_secret FROM users WHERE username = ?", (session['username'],)).fetchone()
        conn.close()
        if user:
            totp = pyotp.TOTP(user[0])
            if totp.verify(token):
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid 2FA token", "danger")
        else:
            flash("User not found.", "danger")
            return redirect(url_for('login'))
    return render_template('index.html', mode='mfa', title='MFA Verification')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_time = datetime.now().strftime("%I:%M %p, %B %d, %Y")
    cyber_tip = random.choice(CYBER_TIPS)

    password_strength = None
    password_feedback = None
    if request.method == 'POST':
        password = request.form.get('check_password')
        if password:
            password_strength, password_feedback = check_password_strength(password)

    return render_template(
        'index.html',
        mode='dashboard',
        title='Dashboard',
        username=session['username'],
        current_time=current_time,
        cyber_tip=cyber_tip,
        password_strength=password_strength,
        password_feedback=password_feedback
    )

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/regenerate-qr')
def regenerate_qr():
    if 'username' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))

    session['qr_regen_count'] = session.get('qr_regen_count', 0)
    if session['qr_regen_count'] >= 2:
        flash("Maximum QR regeneration limit (2 times) reached. You have been logged out.", "danger")
        return redirect(url_for('logout'))

    username = session['username']
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            new_secret = pyotp.random_base32()
            conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (new_secret, user[0]))
            conn.commit()

            session.pop('totp_secret', None)
            uri = pyotp.TOTP(new_secret).provisioning_uri(name=username, issuer_name="SecureLogin")
            img = qrcode.make(uri)
            qr_image_path = f'qrcode_{username}.png'
            img.save(f'static/{qr_image_path}')
            session['qr_regen_count'] += 1
            flash("QR code regenerated with a new secret! Scan it with Google Authenticator.", "info")
            return render_template('index.html', mode='regenerate-qr', title='Regenerate QR Code', qr_image=qr_image_path)
        else:
            flash("User not found.", "danger")
            return redirect(url_for('login'))
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
