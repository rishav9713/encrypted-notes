import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime
import secrets

# Configure logging
logging.basicConfig(filename='process.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username, name):
        self.id = user_id
        self.username = username
        self.name = name

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        user = User(user_data[0], user_data[1], user_data[3])  # user_data[0]: id, user_data[1]: username, user_data[3]: name
        return user
    return None

@app.route('/')
@login_required
def index():
    notes = load_notes()
    logging.info(f"User '{current_user.username}' accessed the index page.")
    return render_template('index.html', notes=notes, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = authenticate_user(username, password)
        if user:
            login_user(user)
            flash('Login successful!', 'success')
            logging.info(f"User '{username}' logged in.")
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            logging.warning(f"Failed login attempt for username '{username}'.")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        company_or_school = request.form.get('company_or_school')

        # Password policy checks
        if not (8 <= len(password) <= 50):
            flash('Password must be between 8 and 50 characters long.', 'error')
            return redirect(url_for('register'))

        if not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter.', 'error')
            return redirect(url_for('register'))

        if not any(char.islower() for char in password):
            flash('Password must contain at least one lowercase letter.', 'error')
            return redirect(url_for('register'))

        if not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit.', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        if not user_exists(username):
            create_user(username, hashed_password, name, phone_number, email, company_or_school)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose another.', 'error')
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logging.info(f"User '{current_user.username}' logged out.")
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    if request.method == 'POST':
        note_content = request.form.get('note_content')
        if note_content:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            insert_note(note_content, timestamp)
            flash('Note added successfully!', 'success')
            logging.info(f"User '{current_user.username}' added a new note.")
        else:
            flash('Note content is empty!', 'error')
    return redirect(url_for('index'))

@app.route('/delete_note/<int:note_id>')
@login_required
def delete_note(note_id):
    delete_note_by_id(note_id)
    flash('Note deleted successfully!', 'success')
    logging.info(f"User '{current_user.username}' deleted a note with ID {note_id}.")
    return redirect(url_for('index'))




def create_table():
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, name TEXT, phone_number TEXT, email TEXT, company_or_school TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, content TEXT, timestamp TEXT, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))")
    conn.commit()
    conn.close()

def create_user(username, password, name, phone_number, email, company_or_school):
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, name, phone_number, email, company_or_school) VALUES (?, ?, ?, ?, ?, ?)",
                   (username, password, name, phone_number, email, company_or_school))
    conn.commit()
    conn.close()

def user_exists(username):
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def authenticate_user(username, password):
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user and bcrypt.check_password_hash(user[2], password):
        loaded_user = User(user[0], user[1], user[3])  # user[0]: id, user[1]: username, user[3]: name
        return loaded_user
    return None

def insert_note(content, timestamp):
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO notes (content, timestamp, user_id) VALUES (?, ?, ?)", (content, timestamp, current_user.id))
    conn.commit()
    conn.close()

def load_notes():
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE user_id=?", (current_user.id,))
    notes = cursor.fetchall()
    conn.close()
    return notes

def delete_note_by_id(note_id):
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes WHERE id=?", (note_id,))
    conn.commit()
    conn.close()

# if __name__ == "__main__":
#     create_table()
#     app.run(debug=True, port=5003)


if __name__ == '__main__':
    create_table()
    app.run(debug=True)
