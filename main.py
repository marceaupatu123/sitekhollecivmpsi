from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from google.cloud import storage
import firebase_admin
from firebase_admin import credentials, firestore
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Nécessaire pour utiliser flash messages

# Détection de l'environnement Google Cloud
IS_GCLOUD = os.getenv('GAE_ENV', '').startswith('standard') or os.getenv('K_SERVICE', False)

if IS_GCLOUD:
    # Initialisation de Firebase avec les identifiants par défaut de l'application
    cred = credentials.ApplicationDefault()
else:
    # Initialisation de Firebase avec les identifiants fournis par la variable d'environnement
    service_account_info = os.environ.get('FIREBASE_SERVICE_ACCOUNT_KEY')
    if service_account_info is None:
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_KEY environment variable is not set")
    service_account_info = json.loads(service_account_info)
    cred = credentials.Certificate(service_account_info)

# Configuration
UPLOAD_FOLDER = './Fichiers/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Détection de l'environnement
IS_PRODUCTION = os.getenv('GAE_ENV', '').startswith('standard')

if IS_PRODUCTION:
    # Configuration pour Google Cloud Storage
    storage_client = storage.Client()
    BUCKET_NAME = 'sacred-ember-377216'
else:
    # Configuration pour le système de fichiers local
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file_online(file, filename):
    if IS_PRODUCTION:
        # Upload to Google Cloud Storage
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(filename)
        blob.upload_from_file(file)
        return blob.public_url
    else:
        # Save to local filesystem
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return filename

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
    new_admin = {
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
        'password': hashed_password,
        'is_admin': True
    }
    db.collection('users').add(new_admin)
    print('Admin user created successfully!')

class User(UserMixin):
    def __init__(self, id, email, first_name, last_name, password, is_admin=False):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    user_ref = db.collection('users').document(user_id).get()
    if user_ref.exists:
        user_data = user_ref.to_dict()
        return User(id=user_id, **user_data)
    return None

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

        user_ref = db.collection('users').where('email', '==', email).get()
        if user_ref:
            flash('L\'email est déjà utilisé', 'error')
            return redirect(url_for('register'))

        new_user = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': generate_password_hash(password, method='pbkdf2:sha256'),
            'is_admin': False
        }
        db.collection('users').add(new_user)
        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user_ref = db.collection('users').where('email', '==', email).get()
        if user_ref:
            user_data = user_ref[0].to_dict()
            if check_password_hash(user_data['password'], password):
                user = User(id=user_ref[0].id, **user_data)
                login_user(user)
                flash('Connecté avec succès!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Mot de passe invalide', 'error')
        else:
            flash('Email invalide', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté.', 'warning')
    return redirect(url_for('index'))

@app.route('/get_structure')
def get_structure():
     structure = {
        "Maths": ["Chapitre 1 : Algèbre", "Chapitre 2 : Trigo"],
        "Physique": ["Chapitre 1 : Optique"]
     }
     return jsonify(structure)

@app.route('/get_kholleurs')
def get_kholleurs():
    kholleurs = {
        'Maths': ['M. Dupont', 'Mme. Durand'],
        'Physique': ['M. Martin', 'Mme. Bernard']
    }
    return jsonify(kholleurs)

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
        
        if not (subject and chapter and kholleur and difficulty):
            flash('All fields are required')
            return redirect(request.url)
        
        # Générer un nom de fichier unique
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        extension = file.filename.rsplit('.', 1)[1].lower()

        filename = secure_filename(f"{subject}_{chapter}_{kholleur}_{difficulty}_{timestamp}.{extension}")
        try:
            file_url = upload_file_online(file, filename)
        except Exception as e:
            flash(f'File upload failed: {str(e)}')
            return redirect(request.url)
        
        new_submission = {
            'user_id': current_user.id,
            'subject': subject,
            'chapter': chapter,
            'difficulty': difficulty,
            'image_url': file_url,  # Assurez-vous que c'est bien ce que vous voulez enregistrer
            'kholleur': kholleur,
            'timestamp': datetime.utcnow()
        }
        try:
            db.collection('submissions').add(new_submission)
        except Exception as e:
            flash(f'Database save failed: {str(e)}')
            return redirect(request.url)
        
        flash('Fichier envoyé avec succès!', 'success')
        return redirect(url_for('index'))
    
    flash('File type not allowed')
    return redirect(request.url)

@app.route('/get_submissions')
def get_submissions():
    subject = request.args.get('subject', '')
    chapter = request.args.get('chapter', '')
    
    query = db.collection('submissions')
    if subject:
        query = query.where('subject', '==', subject)
    if chapter:
        query = query.where('chapter', '==', chapter)
    
    submissions = query.stream()
    result = []
    for submission in submissions:
        submission_data = submission.to_dict()
        user_ref = db.collection('users').document(submission_data['user_id']).get()
        user_data = user_ref.to_dict()
        result.append({
            'prenom': user_data['first_name'],
            'difficulte': submission_data['difficulty'],
            'image_url': url_for('uploaded_file', filename=submission_data['image_url']),
            'subject': submission_data['subject'],
            'chapter': submission_data['chapter'],
            'kholleur': submission_data['kholleur'],
            'date': submission_data['timestamp'].strftime('%Y-%m-%d')
        })
    
    return jsonify(result)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"] ,filename)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Accès refusé : Vous n\'êtes pas administrateur.', 'error')
        return redirect(url_for('index'))
    users = db.collection('users').stream()
    users_list = [user.to_dict() for user in users]
    return render_template('admin.html', users=users_list)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Accès refusé : Vous n\'êtes pas administrateur.', 'error')
        return redirect(url_for('index'))
    user_ref = db.collection('users').document(user_id)
    user = user_ref.get().to_dict()
    if request.method == 'POST':
        user['first_name'] = request.form['first_name']
        user['last_name'] = request.form['last_name']
        user['email'] = request.form['email']
        if request.form['password'] != '':
            user['password'] = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        user_ref.set(user)
        flash('Utilisateur mis à jour avec succès!', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Accès refusé : Vous n\'êtes pas administrateur.', 'error')
        return redirect(url_for('index'))
    user_ref = db.collection('users').document(user_id)
    user_ref.delete()
    flash('Utilisateur supprimé avec succès!', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)