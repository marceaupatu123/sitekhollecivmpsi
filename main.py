from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy import ForeignKey
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Nécessaire pour utiliser flash messages

# Configuration
UPLOAD_FOLDER = './Fichiers/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Commande de création d'admin

@app.cli.command('create_admin')
def create_admin():
    from getpass import getpass
    email = input('Email: ')
    first_name = input('First Name: ')
    last_name = input('Last Name: ')
    password = getpass('Password: ')
    confirm_password = getpass('Confirm Password: ')

    if password != confirm_password:
        print('Passwords do not match!')
        return

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_admin = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    print('Admin user created successfully!')
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Nouveau champ

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    chapter = db.Column(db.String(150), nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(300), nullable=False)
    kholleur = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('L\'email est déjà utilisé', 'error')
            return redirect(url_for('register'))

        new_user = User(first_name=first_name, last_name=last_name, email=email, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid password', 'error')
        else:
            flash('Invalid email', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/get_structure')
def get_structure():
    base_path = app.config['UPLOAD_FOLDER']
    structure = {}

    for root, dirs, files in os.walk(base_path):
        for dir_name in dirs:
            subject = os.path.basename(root)
            chapter = dir_name
            if subject:  # Vérifie que subject n'est pas vide
                if subject not in structure:
                    structure[subject] = []
                structure[subject].append(chapter)

    return jsonify(structure)

@app.route('/get_kholleurs')
def get_kholleurs():
    kholleurs = {
        'Maths': ['M. Dupont', 'Mme. Durand'],
        'Physique': ['M. Martin', 'Mme. Bernard']
    }
    return jsonify(kholleurs)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        subject = request.form.get('subject')
        chapter = request.form.get('chapter')
        kholleur = request.form.get('kholleur')
        difficulty = request.form.get('difficulty')
        kholleur = request.form.get('kholleur')
        if not (subject and chapter and kholleur and difficulty and kholleur):
            flash('All fields are required')
            return redirect(request.url)
        
        # Générer un nom de fichier unique
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        extension = file.filename.rsplit('.', 1)[1].lower()
        new_filename = f"{kholleur}-{difficulty}-{timestamp}.{extension}"
        new_filename = secure_filename(new_filename)
        
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], subject, chapter)
        os.makedirs(save_path, exist_ok=True)
        file.save(os.path.join(save_path, new_filename))
        
        # Save submission to database
        image_url = os.path.join(subject, chapter, new_filename).replace("\\", "/")  # Use forward slashes
        new_submission = Submission(
            user_id=current_user.id,
            subject=subject,
            chapter=chapter,
            difficulty=difficulty,
            image_url=image_url,
            kholleur=kholleur,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_submission)
        db.session.commit()
        
        flash('File successfully uploaded')
        return redirect(url_for('index'))
    flash('File type not allowed')
    return redirect(request.url)

@app.route('/get_submissions')
def get_submissions():
    subject = request.args.get('subject', '')
    chapter = request.args.get('chapter', '')
    
    query = Submission.query
    if subject:
        query = query.filter_by(subject=subject)
    if chapter:
        query = query.filter_by(chapter=chapter)
    
    submissions = query.all()
    result = []
    for submission in submissions:
        user = User.query.get(submission.user_id)
        result.append({
            'prenom': user.first_name,
            'difficulte': submission.difficulty,
            'image_url': url_for('uploaded_file', filename=submission.image_url),
            'subject': submission.subject,
            'chapter': submission.chapter,
            'kholleur': submission.kholleur,
            'date': submission.timestamp.strftime('%Y-%m-%d')
        })
    
    return jsonify(result)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)