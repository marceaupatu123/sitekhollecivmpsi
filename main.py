from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from google.cloud import storage
import firebase_admin
from firebase_admin import credentials, firestore
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Limiter configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Firestore connection
cred = None
IS_GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
print(f"IS_GITHUB_ACTIONS: {IS_GITHUB_ACTIONS}")
IS_GCLOUD = os.getenv('GAE_ENV', '').startswith('standard') or os.getenv('K_SERVICE', False) and not IS_GITHUB_ACTIONS
print(f"IS_GCLOUD: {IS_GCLOUD}")
IS_LOCAL = os.getenv('LOCAL_ENV', 'false').lower() == 'true'
print(f"IS_LOCAL: {IS_LOCAL}")

if IS_GCLOUD:
    cred = credentials.ApplicationDefault()
elif IS_LOCAL:
    try:
        with open('./jsonid.json') as f:
            service_account_info = json.load(f)
        cred = credentials.Certificate(service_account_info)
    except FileNotFoundError:
        raise ValueError("Le fichier jsonid.json est introuvable")
    except json.JSONDecodeError:
        raise ValueError("Le fichier jsonid.json contient des données JSON invalides")
elif IS_GITHUB_ACTIONS:
     service_account_info = os.environ.get('FIREBASE_SERVICE_ACCOUNT_KEY')
     if service_account_info is None:
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_KEY environment variable is not set")
     try:
        service_account_info = json.loads(service_account_info)
        cred = credentials.Certificate(service_account_info)
        
        # Write the service account info to a temporary file
        with open('service_account.json', 'w') as f:
            json.dump(service_account_info, f)
        
        # Set the GOOGLE_APPLICATION_CREDENTIALS environment variable
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.path.abspath('service_account.json')
     except json.JSONDecodeError:
        raise ValueError("Invalid JSON data in FIREBASE_SERVICE_ACCOUNT_KEY environment variable")

firebase_admin.initialize_app(cred)
db = firestore.client()

# Configuration
UPLOAD_FOLDER = './Fichiers/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Google Cloud Storage client
if IS_LOCAL:
    storage_client = storage.Client.from_service_account_json('./jsonid.json')
else:
    storage_client = storage.Client()

BUCKET_NAME = 'sacred-ember-377216.appspot.com'

# Thread pool for async tasks
executor = ThreadPoolExecutor(max_workers=4)

@lru_cache(maxsize=128)
def get_badge_info(badge_ids: tuple):

    badges = []
    for badge_id in badge_ids:
        badge_ref = db.collection('badges').document(str(badge_id)).get()
        if badge_ref.exists:
            badges.append(badge_ref.to_dict())
    return badges

def get_comments(submission_id):
    # Fetch comments and user IDs in one go
    comments_ref = db.collection('comments').where('submission_id', '==', submission_id).order_by('timestamp').stream()
    comments_data = []
    for comment in comments_ref:
        comment_data = comment.to_dict()
        comment_data['id'] = comment.id  # Ajouter l'ID du document aux données du commentaire
        comments_data.append(comment_data)
    user_ids = {comment['user_id'] for comment in comments_data}

    # Log the fetched comments and user IDs for debugging
    print(f"Fetched comments: {comments_data}")
    print(f"User IDs: {user_ids}")

    # Check if user_ids is not empty before querying
    if not user_ids:
        return []

    # Fetch all users in one go
    users = {}
    for user_id in user_ids:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            users[user_id] = user_doc.to_dict()

    # Log the fetched users for debugging
    print(f"Fetched users: {users}")

    # Construct the final list of comments
    comments = []
    for comment_data in comments_data:
        user_id = comment_data['user_id']
        if user_id in users:
            comment_user_data = users[user_id]
            badges_data = comment_user_data.get('badges', [])
            if badges_data:
                badges = get_badge_info(tuple(badges_data))
            else :
                badges = []
            comments.append({
                'user': {
                    'name': comment_user_data['first_name'],
                    'profile_picture': comment_user_data.get('profile_picture'),
                    'badges': badges,
                    'id': user_id
                },
                'message': comment_data['message'],
                'timestamp': comment_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                'id': comment_data['id']
            })
        else:
            # Log missing user data for debugging
            print(f"Missing user data for user_id: {user_id}")
            # Handle the case where the user data is missing
            comments.append({
                'user': {
                    'name': 'Unknown',
                    'profile_picture': None,
                    'badges': [],
                    'id': 0
                },
                'message': comment_data['message'],
                'timestamp': comment_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            })
    return comments

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def compress_image(file):
    from PIL import Image
    from io import BytesIO
    image = Image.open(file)

    if image.mode == 'RGBA':
        image = image.convert('RGB')

    output = BytesIO()
    image.save(output, format='JPEG', quality=85)
    output.seek(0)
    return output

def upload_file_online(file, filename):
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(filename)
    blob.upload_from_file(file)
    blob.make_public()
    return blob.public_url

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
    def __init__(self, id, email, first_name, last_name, password, is_admin=False, profile_picture=None, badges=[]):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = password
        self.is_admin = is_admin
        self.profile_picture = profile_picture
        self.badges = badges or []

@login_manager.user_loader
def load_user(user_id):
    user_ref = db.collection('users').document(user_id).get()
    if user_ref.exists:
        user_data = user_ref.to_dict()
        return User(id=user_id, **user_data)
    return None

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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
            'is_admin': False,
            'profile_picture': "https://risibank.fr/cache/medias/0/9/966/96634/full.jpeg",
            'badges': []
        }
        db.collection('users').add(new_user)
        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
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
@limiter.limit("10 per minute")
def get_structure():
     structure = {
        "Maths": ["Chapitre 1 : Algèbre", "Chapitre 2 : Trigo"],
        "Physique": ["Chapitre 1 : Optique"]
     }
     return jsonify(structure)

@app.route('/get_kholleurs')
@limiter.limit("10 per minute")
def get_kholleurs():
    kholleurs = {
        'Maths': ['M. Dupont', 'Mme. Durand'],
        'Physique': ['M. Martin', 'Mme. Bernard']
    }
    return jsonify(kholleurs)

@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
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
        
        # Compress the image asynchronously
        future = executor.submit(compress_image, file)
        compressed_file = future.result()
        
        try:
            file_url = upload_file_online(compressed_file, filename)
        except Exception as e:
            flash(f'File upload failed: {str(e)}')
            return redirect(request.url)
        
        new_submission = {
            'user_id': current_user.id,
            'subject': subject,
            'chapter': chapter,
            'difficulty': difficulty,
            'image_url': file_url,
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
@limiter.limit("10 per minute")
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
            'id': submission.id,
            'prenom': user_data['first_name'],
            'difficulte': submission_data['difficulty'],
            'image_url': submission_data['image_url'],
            'subject': submission_data['subject'],
            'chapter': submission_data['chapter'],
            'kholleur': submission_data['kholleur'],
            'date': submission_data['timestamp'].strftime('%Y-%m-%d')
        })
    
    return jsonify(result)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Accès refusé : Vous n\'êtes pas administrateur.', 'error')
        return redirect(url_for('index'))
    users_ref = db.collection('users').stream()
    users = []
    for user in users_ref:
        user_data = user.to_dict()
        user_data['id'] = user.id
        badges = []
        if 'badges' in user_data:
            badges = get_badge_info(tuple(user_data['badges']))
        user_data['badges'] = badges
        users.append(user_data)
    
    return render_template('admin.html', users=users)

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

@app.route('/submission/<submission_id>')
def get_submission_details(submission_id):
    try:
        submission_ref = db.collection('submissions').document(submission_id).get()
        if not submission_ref.exists:
            return jsonify({'error': 'Submission not found'}), 404
        
        submission_data = submission_ref.to_dict()
        user_ref = db.collection('users').document(submission_data['user_id']).get()
        user_data = user_ref.to_dict()
        
        result = {
            'id': submission_id,
            'prenom': user_data['first_name'],
            'difficulte': submission_data['difficulty'],
            'image_url': submission_data['image_url'],
            'subject': submission_data['subject'],
            'chapter': submission_data['chapter'],
            'kholleur': submission_data['kholleur'],
            'date': submission_data['timestamp'].strftime('%Y-%m-%d'),
            'user_id': submission_data['user_id']
        }
        
        is_admin = False
        is_owner = False

        if not isinstance(current_user, AnonymousUserMixin):
            is_admin = current_user.is_admin
            is_owner = current_user.id == submission_data['user_id']

        # Récupération des commentaires
        comments = get_comments(submission_id)
        
        return render_template('details.html', submission=result, comments=comments, is_admin=is_admin, is_owner=is_owner)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/delete_submission/<submission_id>', methods=['DELETE'])
def delete_submission(submission_id):
    try:
        submission_ref = db.collection('submissions').document(submission_id)
        submission = submission_ref.get()
        if not submission.exists:
            flash('Submission not found', 'error')
            return jsonify({'status': 'error', 'message': 'Submission not found'}), 404

        submission_data = submission.to_dict()
        user_id = submission_data['user_id']
        
        if current_user.id != user_id and not current_user.is_admin:
            flash('Unauthorized', 'error')
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

        # Suppression de l'image associée
        image_url = submission_data.get('image_url')
        if image_url:
            # Extract the object name from the URL
            object_name = image_url.split('/')[-1]
            bucket = storage_client.bucket(BUCKET_NAME)
            blob = bucket.blob(object_name)
            blob.delete()

        # Suppression des commentaires associés
        comments_ref = db.collection('comments').where('submission_id', '==', submission_id).stream()
        for comment in comments_ref:
            comment.reference.delete()

        # Suppression de la soumission
        submission_ref.delete()
        flash('Enoncé de Khôlle supprimé avec succès!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500
    
@app.route('/post_comment', methods=['POST'])
@login_required
def post_comment():
    data = request.json
    new_comment = {
        'user_id': current_user.id,
        'submission_id': data['submission_id'],
        'message': data['message'],
        'timestamp': datetime.utcnow()
    }
    
    # Ajouter le nouveau commentaire à la collection 'comments'
    db.collection('comments').add(new_comment)
    
    # Récupérer les données de l'utilisateur
    user_ref = db.collection('users').document(current_user.id).get()
    
    if not user_ref.exists:
        return jsonify({'error': 'User not found'}), 404
    
    user_data = user_ref.to_dict()

    flash('Commentaire ajouté avec succès!', 'success')
    
    return jsonify({
        'success': True,
        'comment': {
            'user': {
                'name': user_data['first_name'],
                'profile_picture': user_data.get('profile_picture'),
                'badges': user_data.get('badges', [])
            },
            'message': data['message'],
            'timestamp': new_comment['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        }
    })

@app.route('/delete_comment/<comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    try:
        comment_ref = db.collection('comments').document(comment_id)
        comment = comment_ref.get()
        if not comment.exists:
            flash('Commentaire introuvable', 'error')
            return jsonify({'success': False, 'message': 'Commentaire non trouvé'}), 404

        comment_data = comment.to_dict()
        if current_user.is_admin or current_user.id == comment_data['user_id']:
            comment_ref.delete()
            return jsonify({'success': True}), 200
        else:
            flash('Non autorisé', 'error')
            return jsonify({'success': False, 'message': 'Non autorisé'}), 403
    except Exception as e:
        flash(f'Une erreur s\'est produite: {str(e)}', 'error')
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)