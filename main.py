from datetime import datetime
import time

from flask import Flask, redirect, url_for, request, jsonify
from flask import render_template, session
import re
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "my-secret-key-228"

def init_db():
    """Инициализация базы данных"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    # Создание таблицы пользователей
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    #создание таблицы контактов
    c.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

    c.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT NOT NULL,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    conn.commit()
    conn.close()


init_db()


def user_exists(username):
    """Проверяет существует ли пользователь с указанным именем"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()

    conn.close()

    return user is not None


def get_user_id(username):
    """Возвращает ID пользователя по имени"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = c.fetchone()

    conn.close()

    if result:
        return result[0]  # Возвращаем ID
    return None  # Пользователь не найден


def add_contactdb(user_id, contact_username):
    """Добавляет контакт в базу данных"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    # Находим ID пользователя для добавления
    c.execute('SELECT id FROM users WHERE username = ?', (contact_username,))
    contact_user = c.fetchone()

    if not contact_user:
        conn.close()
        return False

    contact_id = contact_user[0]

    # Добавляем контакт
    c.execute('INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)',
              (user_id, contact_id))
    c.execute('INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)',
              (contact_id, user_id))
    conn.commit()
    conn.close()

    return True


def in_contacts(user_id, contact_username):
    """Проверяет, есть ли пользователь в контактах"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    # Все в одном запросе с JOIN
    c.execute('''
        SELECT c.id FROM contacts c 
        JOIN users u ON c.contact_id = u.id 
        WHERE c.user_id = ? AND u.username = ?
    ''', (user_id, contact_username))

    result = c.fetchone() is not None
    conn.close()
    return result


def get_contacts(user_id):
    """Возвращает список контактов пользователя"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    c.execute('''
        SELECT u.id, u.username 
        FROM contacts c 
        JOIN users u ON c.contact_id = u.id 
        WHERE c.user_id = ?
    ''', (user_id,))

    contacts = []
    for row in c.fetchall():
        contacts.append({
            'id': row[0],
            'name': row[1]
        })

    conn.close()
    return contacts


def get_messages(user_id):
    """Возвращает все сообщения со всеми контактами"""
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    # Получаем всех контактов пользователя
    c.execute('''
        SELECT DISTINCT 
            CASE 
                WHEN m.sender_id = ? THEN m.receiver_id 
                ELSE m.sender_id 
            END as contact_id
        FROM messages m
        WHERE m.sender_id = ? OR m.receiver_id = ?
    ''', (user_id, user_id, user_id))

    contact_ids = [row[0] for row in c.fetchall()]

    messages_dict = {}

    for contact_id in contact_ids:
        # Получаем сообщения с каждым контактом
        c.execute('''
            SELECT id, sender_id, message, created_at
            FROM messages 
            WHERE (sender_id = ? AND receiver_id = ?) 
               OR (sender_id = ? AND receiver_id = ?)
            ORDER BY created_at
        ''', (user_id, contact_id, contact_id, user_id))

        messages = []
        for row in c.fetchall():
            msg_id, sender_id, content, timestamp = row
            # Преобразуем время в формат HH:MM
            time_str = timestamp.split(' ')[1][:5] if ' ' in timestamp else timestamp[:5]

            messages.append({
                'id': msg_id,
                'text': content,
                'time': time_str,
                'sent': sender_id == user_id
            })

        messages_dict[contact_id] = messages

    conn.close()
    return messages_dict

@app.route('/')
def index():
    return redirect(url_for('register'))


@app.route('/mainpage')
def mainpage():
    contacts_list = get_contacts(session.get("user_id"))
    message_list = get_messages(session.get("user_id"))
    #contacts_list = []
    return render_template("mainpage.html", contacts=contacts_list, messages=message_list)


@app.route('/register')
def register():
    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


def validate_password(password):
    """Валидация пароля"""
    if len(password) < 6:
        return False, "Пароль должен содержать минимум 6 символов"
    return True, ""


def validate_username(username):
    """Валидация имени пользователя"""
    if len(username) < 3 or len(username) > 20:
        return False, "Имя пользователя должно быть от 3 до 20 символов"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Имя пользователя может содержать только буквы, цифры и подчеркивания"
    return True, ""


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(stored_password, provided_password):
    return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()


@app.route('/register', methods=['POST'])
def receive_json_reg():
    # Check if the request contains JSON data
    data = request.get_json()
    print("Received JSON data:", data)

    operation = data.get("operation", '').strip()



    if operation == "registration":
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        print("Запрос на регистрацию")
        # Валидация данных
        if not username or not email or not password:
            return jsonify({'error': 'Все поля обязательны для заполнения'}), 400

        # Валидация имени пользователя
        is_valid_username, username_error = validate_username(username)
        if not is_valid_username:
            return jsonify({'error': username_error}), 400

        # Валидация email
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return jsonify({'error': 'Некорректный email адрес'}), 400

        # Валидация пароля
        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            return jsonify({'error': password_error}), 400

        # Проверка существования пользователя
        conn = sqlite3.connect('messenger.db')
        c = conn.cursor()

        # Проверка username
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Пользователь с таким именем уже существует'}), 400

        # Проверка email
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Пользователь с таким email уже существует'}), 400

        # Создание пользователя
        password_hash = hash_password(password)
        c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                  (username, email, password_hash))

        conn.commit()
        conn.close()

        return jsonify({'success': 'Пользователь успешно зарегистрирован'}), 201

@app.route('/login', methods=['POST'])
def receive_json_auth():

    data = request.get_json()
    print("Received JSON data:", data)

    operation = data.get("operation", '').strip()

    if operation == "authorization":
        print("Запрос на авторизацию")
        login = data.get("login", '').strip()
        password = data.get("password", '')
        conn = sqlite3.connect('messenger.db')
        c = conn.cursor()

        user = c.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            (login, login)
        ).fetchone()

        if not user:
            conn.close()
            return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

        print(user[3])
        print(password)

        if not check_password(user[3], password):
            return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

        print(f"Пользователь {login} авторизировался.")
        session['user_id'] = user[0]
        session['username'] = user[1]  # ← сохраняем username
        return jsonify({'success': 'Пользователь успешно зарегистрирован'}), 201




@app.route('/add-contact', methods=['POST'])
def receive_json_addcontact():

    data = request.get_json()
    print("Received ADD-CONTACT request", data)
    contact = data.get("username", '').strip()

    if user_exists(contact):

        print("Пользователь существует")
        if session.get("username") != contact: # если это не мой ник
            print(in_contacts(session.get("user_id"), contact))
            if not in_contacts(session.get("user_id"), contact):  # и если уже не в контактах

                add_contactdb(session.get("user_id"), contact)
                return jsonify({'success': 'Контакт добавлен'}), 201
            else:
                return jsonify({'error': 'Контакт уже добавлен'}), 400

        return jsonify({'error': 'Нельзя добавить самого себя'}), 400
    else:
        return jsonify({'error': 'Пользователя не существует'}), 400


@app.route('/send-message', methods=['POST'])
def receive_json_send():

    data = request.get_json()
    print("Received SEND-MESSAGE request", data, "from", session.get("user_id"))
    msg = data['content']
    sender_id = session.get("user_id")
    receiver_id = get_user_id(data['receiver_name'])
    print(msg, sender_id, receiver_id)

    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()

    #local_time = datetime.now().strftime('%H:%M:%S')

    #c.execute('''
    #        INSERT INTO messages (message, sender_id, receiver_id, created_at)
    #        VALUES (?, ?, ?, ?)
    #    ''', (msg, sender_id, receiver_id, local_time))

    c.execute('''
            INSERT INTO messages (message, sender_id, receiver_id) 
            VALUES (?, ?, ?)
        ''', (msg, sender_id, receiver_id))

    conn.commit()
    conn.close()



    return jsonify({'success': 'fine'}), 201





app.run(host='0.0.0.0', debug = True)
