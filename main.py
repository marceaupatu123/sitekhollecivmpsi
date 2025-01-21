"""
This module implements a Flask web application with various functionalities including user authentication, 
file uploads, and interactions with Google Cloud Storage and Firestore.
Modules and Libraries:
- Flask: Web framework for creating the application.
- Flask-Login: User session management.
- Google Cloud Storage: For storing uploaded files.
- Firestore: Database for storing user and application data.
- PIL: For image processing.
- OpenCV: For image decoding.
- Firebase Admin: For initializing Firebase app.
- Flask-Limiter: For rate limiting API requests.
- dotenv: For loading environment variables from a .env file.
Routes:
- /unverified: Renders the unverified user page.
- /register: Handles user registration.
- /login: Handles user login.
- /logout: Logs out the current user.
- /get_structure: Returns the structure of subjects and chapters.
- /get_kholleurs: Returns the list of kholleurs.
- /upload: Handles file uploads.
- /get_submissions: Returns the list of submissions.
- /: Renders the index page.
- /admin: Renders the admin page.
- /admin/edit_user/<user_id>: Handles editing a user by admin.
- /admin/delete_user/<user_id>: Handles deleting a user by admin.
- /submission/<submission_id>: Returns the details of a submission.
- /delete_submission/<submission_id>: Deletes a submission.
- /post_comment: Handles posting a comment.
- /delete_comment/<comment_id>: Deletes a comment.
- /myprofile: Renders the user's profile page.
- /update_profile: Handles updating the user's profile.
- /update_password: Handles updating the user's password.
- /upload_image_summernote: Handles image uploads for Summernote editor.
- /delete_image: Deletes an image.
- /calendar: Renders the user's calendar.
- /pronotelogin: Renders the Pronote login page.
- /pronoteloginok: Renders the Pronote login success page.
- /uploadQR: Handles QR code uploads for Pronote login.
Functions:
- is_pronote_logged_in: Checks if the user is logged into Pronote.
- pronote_login_required: Decorator to ensure Pronote login.
- delete_file_online: Deletes a file from Google Cloud Storage.
- get_badge_info: Retrieves badge information from Firestore.
- get_comments: Retrieves comments for a submission.
- allowed_file: Checks if a file is allowed based on its extension.
- compress_image: Compresses an image file.
- upload_file_online: Uploads a file to Google Cloud Storage.
- deleteGoogleImages: Deletes images from Google Cloud Storage based on URLs in a message.
- load_user: Loads a user from Firestore.
"""

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
)
import urllib.parse
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
    AnonymousUserMixin,
)
import shlex
import subprocess
import cv2

## from pyzbar.pyzbar import decode   --- Impossible sur app engine
from urllib.parse import urlparse
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
from PIL import Image
import io
from functools import wraps
import dotenv
import uuid
import re
import numpy as np
from google.api_core.exceptions import NotFound

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Limiter configuration
limiter = Limiter(
    get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]
)

# Initialize Firestore connection
cred = None
IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS", "false").lower() == "true"
print(f"IS_GITHUB_ACTIONS: {IS_GITHUB_ACTIONS}")
IS_GCLOUD = (
    os.getenv("GAE_ENV", "").startswith("standard")
    or os.getenv("K_SERVICE", False)
    and not IS_GITHUB_ACTIONS
)
print(f"IS_GCLOUD: {IS_GCLOUD}")
IS_LOCAL = os.getenv("LOCAL_ENV", "false").lower() == "true"
print(f"IS_LOCAL: {IS_LOCAL}")

if IS_GCLOUD:
    cred = credentials.ApplicationDefault()
elif IS_LOCAL:
    try:
        with open("./jsonid.json") as f:
            service_account_info = json.load(f)
        cred = credentials.Certificate(service_account_info)
    except FileNotFoundError:
        raise ValueError("Le fichier jsonid.json est introuvable")
    except json.JSONDecodeError:
        raise ValueError("Le fichier jsonid.json contient des données JSON invalides")
elif IS_GITHUB_ACTIONS:
    service_account_info = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY")
    if service_account_info is None:
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_KEY environment variable is not set")
    try:
        service_account_info = json.loads(service_account_info)
        cred = credentials.Certificate(service_account_info)

        # Write the service account info to a temporary file
        with open("service_account.json", "w") as f:
            json.dump(service_account_info, f)

        # Set the GOOGLE_APPLICATION_CREDENTIALS environment variable
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.abspath(
            "service_account.json"
        )
    except json.JSONDecodeError:
        raise ValueError(
            "Invalid JSON data in FIREBASE_SERVICE_ACCOUNT_KEY environment variable"
        )

firebase_admin.initialize_app(cred)
db = firestore.client()

# Configuration
UPLOAD_FOLDER = "./Fichiers/"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max file size

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Initialize Google Cloud Storage client
if IS_LOCAL:
    storage_client = storage.Client.from_service_account_json("./jsonid.json")
else:
    storage_client = storage.Client()

BUCKET_NAME = "sacred-ember-377216.appspot.com"
bucket = storage_client.bucket(BUCKET_NAME)

# Thread pool for async tasks
executor = ThreadPoolExecutor(max_workers=8)


def is_pronote_logged_in():
    # Rechercher un document avec le même user_id
    existing_doc = (
        db.collection("PronoteToken").where("user_id", "==", current_user.id).get()
    )
    return bool(existing_doc)


def pronote_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_pronote_logged_in():
            flash("Vous devez vous connecter ou vous reconnecter à Pronote.", "error")
            return redirect(url_for("myprofile"))  # Redirigez vers la page de profil
        return f(*args, **kwargs)

    return decorated_function


def delete_file_online(file_url):
    try:
        # Vérifiez si l'URL est valide
        if not file_url:
            return {"success": False, "message": "No URL provided"}

        # Extraire le chemin complet du blob à partir de l'URL
        parsed_url = urlparse(file_url)
        path_segments = parsed_url.path.lstrip("/").split("/")
        blob_path = "/".join(path_segments[1:])

        blob = bucket.blob(blob_path)

        # Vérifiez si le blob existe
        if not blob.exists():
            return {"success": False, "message": "File not found"}

        # Supprimez le blob
        blob.delete()
        return {"success": True, "message": "File deleted successfully"}

    except NotFound:
        return {"success": False, "message": "File not found"}
    except Exception as e:
        return {"success": False, "message": f"An error occurred: {str(e)}"}


@lru_cache(maxsize=128)
def get_badge_info(badge_ids: tuple):

    badges = []
    for badge_id in badge_ids:
        badge_ref = db.collection("badges").document(str(badge_id)).get()
        if badge_ref.exists:
            badges.append(badge_ref.to_dict())
    return badges


def get_comments(submission_id):
    # Fetch comments and user IDs in one go
    comments_ref = (
        db.collection("comments")
        .where("submission_id", "==", submission_id)
        .order_by("timestamp")
        .stream()
    )
    comments_data = []
    for comment in comments_ref:
        comment_data = comment.to_dict()
        comment_data["id"] = (
            comment.id
        )  # Ajouter l'ID du document aux données du commentaire
        comments_data.append(comment_data)
    user_ids = {comment["user_id"] for comment in comments_data}

    # Log the fetched comments and user IDs for debugging
    print(f"Fetched comments: {comments_data}")
    print(f"User IDs: {user_ids}")

    # Check if user_ids is not empty before querying
    if not user_ids:
        return []

    # Fetch all users in one go
    users = {}
    for user_id in user_ids:
        user_doc = db.collection("users").document(user_id).get()
        if user_doc.exists():
            users[user_id] = user_doc.to_dict()

    # Log the fetched users for debugging
    print(f"Fetched users: {users}")

    # Construct the final list of comments
    comments = []
    for comment_data in comments_data:
        user_id = comment_data["user_id"]
        if user_id in users:
            comment_user_data = users[user_id]
            badges_data = comment_user_data.get("badges", [])
            if badges_data:
                badges = get_badge_info(tuple(badges_data))
            else:
                badges = []
            comments.append(
                {
                    "user": {
                        "name": comment_user_data["first_name"],
                        "profile_picture": comment_user_data.get("profile_picture"),
                        "badges": badges,
                        "id": user_id,
                    },
                    "message": comment_data["message"],
                    "timestamp": comment_data["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "id": comment_data["id"],
                }
            )
        else:
            # Log missing user data for debugging
            print(f"Missing user data for user_id: {user_id}")
            # Handle the case where the user data is missing
            comments.append(
                {
                    "user": {
                        "name": "[Utilisateur Supprimé]",
                        "profile_picture": "https://risibank.fr/cache/medias/0/26/2682/268287/full.png",
                        "badges": [],
                        "id": 0,
                    },
                    "message": comment_data["message"],
                    "timestamp": comment_data["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
    return comments


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def compress_image(file, max_size=(800, 800), quality=55):
    """Optimized image compression with EXIF orientation correction"""
    try:
        image = Image.open(file)

        # Correction de l'orientation EXIF
        try:
            exif = image._getexif()
            if exif:
                orientation = exif.get(274)  # 274 est le tag EXIF pour l'orientation
                if orientation:
                    rotate_values = {3: 180, 6: 270, 8: 90}
                    if orientation in rotate_values:
                        image = image.rotate(rotate_values[orientation], expand=True)
        except (AttributeError, KeyError, IndexError):
            # Ignore les erreurs si l'image n'a pas de données EXIF
            pass

        if image.mode == "RGBA":
            image = image.convert("RGB")

        # Resize image if larger than max_size
        if image.size[0] > max_size[0] or image.size[1] > max_size[1]:
            image.thumbnail(max_size, Image.LANCZOS)

        output = io.BytesIO()
        image.save(output, format="JPEG", optimize=True, quality=quality)
        output.seek(0)
        return output
    except Exception as e:
        print(f"Error compressing image: {e}")
        return None


def upload_file_online(file, filename, folder):
    """Optimized file upload with streaming"""
    blob = bucket.blob(f"{folder}/{filename}")
    blob.upload_from_file(file, content_type="image/jpeg", num_retries=3)
    return blob.public_url


def deleteGoogleImages(message: str):
    urls = re.findall(r"https://storage.googleapis.com/[^ ]+", message)
    for url in urls:
        try:
            delete_file_online(url)
        except Exception as e:
            flash(
                f"Erreur lors de la suppression de l'image: {str(e)}",
                "error",
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Erreur lors de la suppression de l'image: {str(e)}",
                    }
                ),
                500,
            )


class User(UserMixin):
    def __init__(
        self,
        id,
        email,
        first_name,
        last_name,
        password,
        classe,
        khôlleGroupe,
        is_admin=False,
        kholleur_key="",
        profile_picture=None,
        badges=[],
    ):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = password
        self.classe = classe
        self.khôlleGroupe = khôlleGroupe
        self.is_admin = is_admin
        self.kholleur_key = kholleur_key
        self.profile_picture = profile_picture
        self.badges = badges or []


@login_manager.user_loader
def load_user(user_id):
    user_ref = db.collection("users").document(user_id).get()
    if user_ref.exists():
        user_data = user_ref.to_dict()
        return User(id=user_id, **user_data)
    return None


@app.route("/unverified")
def unverified():
    return render_template("unverified.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        classe = "MPSI"
        khôllegroupe = request.form.get("khôlle")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas", "error")
            return redirect(url_for("register"))

        user_ref = db.collection("users").where("email", "==", email).get()
        if user_ref:
            flash("L'email est déjà utilisé", "error")
            return redirect(url_for("register"))

        new_user = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "classe": classe,
            "password": generate_password_hash(password, method="pbkdf2:sha256"),
            "is_admin": False,
            "profile_picture": "https://risibank.fr/cache/medias/0/9/966/96634/full.jpeg",
            "badges": [],
            "khôlleGroupe": int(khôllegroupe),
            "kholleur_key": "",
        }
        db.collection("users").add(new_user)
        flash("Inscription réussie! Vous pouvez maintenant vous connecter.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user_ref = db.collection("users").where("email", "==", email).get()
        if user_ref:
            user_data = user_ref[0].to_dict()
            if check_password_hash(user_data["password"], password):
                user = User(id=user_ref[0].id, **user_data)
                if user_data["khôlleGroupe"] == 0 and user_data["kholleur_key"] == "":
                    return redirect(url_for("unverified"))
                login_user(user)
                flash("Connecté avec succès!", "success")
                return redirect(url_for("index"))
            else:
                flash("Mot de passe invalide", "error")
        else:
            flash("Email invalide", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté.", "warning")
    return redirect(url_for("index"))


@app.route("/get_structure")
@limiter.limit("10 per minute")
def get_structure():
    structure = {
        "Maths": [
            "Chapitre 1 : Logique et raisonnements",
            "Chapitre 2 : Ensembles et applications",
            "Chapitre 3 : Calcul algébrique et trigonométrique",
            "Chapitre 4 : Nombres complexes",
            "Chapitre 5 : Systèmes linéaires",
            "Chapitre 6 : Techniques fondamentales pour l'étude des fonctions",
            "Chapitre 7 : Fonctions usuelles",
            "Chapitre 8 : Primitives et équations différentielles",
            "Chapitre 9 : Suites numériques",
            "Chapitre 10 : Limite et continuité des fonctions",
            "Chapitre 11 : Dérivabilité",
            "Chapitre 12 : Arithmétique des entiers",
            "Chapitre 13 : Structures algébriques usuelles",
            "Chapitre 14 : Calcul matriciel",
            "Chapitre 15 : Polynômes et fractions rationnelles",
        ],
        "Physique": [
            "Chapitre 1 : Bases de l'optique géométrique",
            "Chapitre 2 : Lentilles minces",
            "Chapitre 3 : Lois de l'électrocinétique – Régime continu",
            "Chapitre 4 : Circuit linéaire du premier ordre",
            "Chapitre 5 : Oscillateur électrique en régime libre",
            "Chapitre 6 : Régime sinusoïdal forcé",
            "Chapitre 7 : Filtrage linéaire",
            "Chapitre 8 : Propagation d'un signal",
            "Chapitre 9 : Cinématique du point",
            "Chapitre 10 : Principes de la dynamique",
            "Chapitre 11 : Énergie mécanique",
            "Chapitre 12 : Mouvement dans un champ électrique ou magnétique",
            "Chapitre 13 : État et évolution d'un système chimique",
            "Chapitre 14 : Cinétique chimique",
            "Chapitre 15 : Molécules et ions",
            "Chapitre 16 : Moment cinétique – Force centrale",
            "Chapitre 17 : Mouvement d'un solide",
            "Chapitre 18 : Description d'un système thermodynamique",
            "Chapitre 19 : Premier principe de la thermodynamique",
            "Chapitre 20 : Deuxième principe de la thermodynamique",
            "Chapitre 21 : Machines thermiques",
            "Chapitre 22 : Champ magnétique",
            "Chapitre 23 : Induction électromagnétique",
            "Chapitre 24 : Introduction à la physique quantique",
            "Chapitre 25 : Solides cristallins",
            "Chapitre 26 : Réactions acido-basiques",
            "Chapitre 27 : Réactions de dissolution ou de précipitation",
            "Chapitre 28 : Réactions d’oxydo-réduction",
            "Chapitre 29 : Diagrammes potentiel-pH",
        ],
    }
    return jsonify(structure)


@app.route("/get_kholleurs")
@limiter.limit("10 per minute")
def get_kholleurs():
    kholleurs = {
        "Maths": [
            "Luc Albert",
            "Victor Alfieri",
            "Jean-Pierre Tecourt",
            "Sébastien Bis",
            "Jean-François Pietri",
            "Marie Peyrelevade",
            "Virginie Revenu",
        ],
        "Physique": [
            "Jean-Vincent Demarais",
            "Sylvain Sadoux",
            "Clément Malaterre",
            "Frédéric Sudre",
        ],
    }
    return jsonify(kholleurs)


@app.route("/upload", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def upload_file():
    if "file" not in request.files:
        flash("No file part")
        return redirect(request.url)

    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename):
        flash("Invalid file")
        return redirect(request.url)

    subject = request.form.get("subject")
    chapter = request.form.get("chapter")
    kholleur = request.form.get("kholleur")
    difficulty = request.form.get("difficulty")

    if not all([subject, chapter, kholleur, difficulty]):
        flash("All fields are required")
        return redirect(request.url)

    try:
        # Générer nom de fichier unique
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        extension = file.filename.rsplit(".", 1)[1].lower()
        filename = secure_filename(
            f"{subject}_{chapter}_{kholleur}_{difficulty}_{timestamp}.{extension}"
        )

        # Compression et upload asynchrones
        future_compress = executor.submit(compress_image, file)
        compressed_file = future_compress.result(timeout=10)
        if not compressed_file:
            raise Exception("Image compression failed")

        future_upload = executor.submit(
            upload_file_online, compressed_file, filename, "SubmissionImages"
        )
        file_url = future_upload.result(timeout=10)

        # Sauvegarde dans Firestore
        new_submission = {
            "user_id": current_user.id,
            "subject": subject,
            "chapter": chapter,
            "classe": "MPSI",
            "difficulty": difficulty,
            "image_url": file_url,
            "kholleur": kholleur,
            "timestamp": datetime.utcnow(),
        }

        db.collection("submissions").add(new_submission)
        flash("Fichier envoyé avec succès!", "success")
        return redirect(url_for("index"))

    except TimeoutError:
        flash("Le traitement a pris trop de temps", "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Une erreur s'est produite: {str(e)}", "error")
        return redirect(url_for("index"))


@app.route("/get_submissions")
@limiter.limit("10 per minute")
def get_submissions():
    subject = request.args.get("subject", "")
    chapter = request.args.get("chapter", "")

    query = db.collection("submissions")
    if subject:
        query = query.where("subject", "==", subject)
    if chapter:
        query = query.where("chapter", "==", chapter)

    submissions = query.stream()
    result = []
    for submission in submissions:
        submission_data = submission.to_dict()
        user_ref = db.collection("users").document(submission_data["user_id"]).get()
        user_data = user_ref.to_dict()
        result.append(
            {
                "id": submission.id,
                "prenom": user_data["first_name"],
                "difficulte": submission_data["difficulty"],
                "classe": submission_data["classe"],
                "image_url": submission_data["image_url"],
                "subject": submission_data["subject"],
                "chapter": submission_data["chapter"],
                "kholleur": submission_data["kholleur"],
                "date": submission_data["timestamp"].strftime("%Y-%m-%d"),
            }
        )

    return jsonify(result)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Accès refusé : Vous n'êtes pas administrateur.", "error")
        return redirect(url_for("index"))
    users_ref = db.collection("users").stream()
    users = []
    for user in users_ref:
        user_data = user.to_dict()
        user_data["id"] = user.id
        badges = []
        if "badges" in user_data:
            badges = get_badge_info(tuple(user_data["badges"]))
        user_data["badges"] = badges
        users.append(user_data)

    return render_template("admin.html", users=users)


@app.route("/admin/edit_user/<user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash("Accès refusé : Vous n'êtes pas administrateur.", "error")
        return redirect(url_for("index"))
    user_ref = db.collection("users").document(user_id)
    user = user_ref.get().to_dict()
    if request.method == "POST":
        user["first_name"] = request.form["first_name"]
        user["last_name"] = request.form["last_name"]
        user["email"] = request.form["email"]
        if request.form["password"] != "":
            user["password"] = generate_password_hash(
                request.form["password"], method="pbkdf2:sha256"
            )
        user_ref.set(user)
        flash("Utilisateur mis à jour avec succès!", "success")
        return redirect(url_for("admin"))
    return render_template("edit_user.html", user=user)


@app.route("/admin/delete_user/<user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Accès refusé : Vous n'êtes pas administrateur.", "error")
        return redirect(url_for("index"))
    user_ref = db.collection("users").document(user_id)
    user_ref.delete()
    flash("Utilisateur supprimé avec succès!", "success")
    return redirect(url_for("admin"))


@app.route("/submission/<submission_id>")
@login_required
def get_submission_details(submission_id):
    try:
        submission_ref = db.collection("submissions").document(submission_id).get()
        if not submission_ref.exists:
            return jsonify({"error": "Submission not found"}), 404

        submission_data = submission_ref.to_dict()
        user_ref = db.collection("users").document(submission_data["user_id"]).get()
        user_data = user_ref.to_dict()

        result = {
            "id": submission_id,
            "prenom": user_data["first_name"],
            "difficulte": submission_data["difficulty"],
            "classe": submission_data["classe"],
            "image_url": submission_data["image_url"],
            "subject": submission_data["subject"],
            "chapter": submission_data["chapter"],
            "kholleur": submission_data["kholleur"],
            "date": submission_data["timestamp"].strftime("%Y-%m-%d"),
            "user_id": submission_data["user_id"],
        }

        is_admin = False
        is_owner = False

        if not isinstance(current_user, AnonymousUserMixin):
            is_admin = current_user.is_admin
            is_owner = current_user.id == submission_data["user_id"]

        # Récupération des commentaires
        comments = get_comments(submission_id)

        return render_template(
            "details.html",
            submission=result,
            comments=comments,
            is_admin=is_admin,
            is_owner=is_owner,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/delete_submission/<submission_id>", methods=["DELETE"])
def delete_submission(submission_id):
    try:
        submission_ref = db.collection("submissions").document(submission_id)
        submission = submission_ref.get()
        if not submission.exists():
            flash("Submission not found", "error")
            return jsonify({"status": "error", "message": "Submission not found"}), 404

        submission_data = submission.to_dict()
        user_id = submission_data["user_id"]

        if current_user.id != user_id and not current_user.is_admin:
            flash("Unauthorized", "error")
            return jsonify({"status": "error", "message": "Unauthorized"}), 403

        # Suppression de l'image associée
        image_url = submission_data.get("image_url")
        if image_url:
            # Extract the object name from the URL
            object_name = image_url.split("/")[-1]
            blob = bucket.blob("SubmissionImages/" + object_name)
            blob.delete()

        # Suppression des commentaires associés
        comments_ref = (
            db.collection("comments")
            .where("submission_id", "==", submission_id)
            .stream()
        )
        for comment in comments_ref:
            comment_dict = comment.to_dict()
            if "message" in comment_dict:
                deleteGoogleImages(comment_dict["message"])
            comment.reference.delete()

        # Suppression de la soumission
        submission_ref.delete()
        flash("Enoncé de Khôlle supprimé avec succès!", "success")
        return jsonify(
            {"status": "success", "message": "Submission deleted successfully!"}
        )
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "error")
        return (
            jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}),
            500,
        )


@app.route("/post_comment", methods=["POST"])
@login_required
def post_comment():
    data = request.json
    new_comment = {
        "user_id": current_user.id,
        "submission_id": data["submission_id"],
        "message": data["message"],
        "timestamp": datetime.utcnow(),
    }

    # Ajouter le nouveau commentaire à la collection 'comments'
    db.collection("comments").add(new_comment)

    # Récupérer les données de l'utilisateur
    user_ref = db.collection("users").document(current_user.id).get()

    if not user_ref.exists:
        return jsonify({"error": "User not found"}), 404

    user_data = user_ref.to_dict()

    flash("Commentaire ajouté avec succès!", "success")

    return jsonify(
        {
            "success": True,
            "comment": {
                "user": {
                    "name": user_data["first_name"],
                    "profile_picture": user_data.get("profile_picture"),
                    "badges": user_data.get("badges", []),
                },
                "message": data["message"],
                "timestamp": new_comment["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            },
        }
    )


@app.route("/delete_comment/<comment_id>", methods=["DELETE"])
def delete_comment(comment_id):
    try:
        comment_ref = db.collection("comments").document(comment_id)
        comment = comment_ref.get()
        if not comment.exists():
            flash("Commentaire introuvable", "error")
            return jsonify({"success": False, "message": "Commentaire non trouvé"}), 404

        comment_data = comment.to_dict()
        if current_user.is_admin or current_user.id == comment_data["user_id"]:
            if "message" in comment_data:
                deleteGoogleImages(comment_data["message"])
            comment_ref.delete()
            return jsonify({"success": True}), 200
        else:
            flash("Non autorisé", "error")
            return jsonify({"success": False, "message": "Non autorisé"}), 403
    except Exception as e:
        flash(f"Une erreur s'est produite: {str(e)}", "error")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/myprofile", methods=["GET"])
@login_required
def myprofile():
    badges = []
    if current_user.badges:
        badges = get_badge_info(tuple(current_user.badges))
    return render_template(
        "myprofile.html",
        user=current_user,
        profile_picture_url=current_user.profile_picture,
        badges=badges,
    )


@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    if "profile_picture" in request.files:
        file = request.files["profile_picture"]
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Compresser l'image
            image = Image.open(file)
            image = image.convert("RGB")
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=75)
            buffer.seek(0)

            # Upload to Google Cloud Storage
            file_url = upload_file_online(buffer, filename, "ProfilePictures")

            # Supprimer l'ancienne image de profil
            if (
                current_user.profile_picture
                and "storage.googleapis.com" in current_user.profile_picture
            ):
                delete_file_online(current_user.profile_picture)

            # Mettre à jour l'utilisateur avec la nouvelle image de profil
            current_user.profile_picture = file_url
            db.collection("users").document(current_user.id).update(
                {"profile_picture": file_url}
            )
            flash("Photo de profil mise à jour avec succès!", "success")
        else:
            flash("Type de fichier non autorisé", "error")
    return redirect(url_for("myprofile"))


@app.route("/update_password", methods=["GET", "POST"])
@login_required
def update_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not check_password_hash(current_user.password, current_password):
            flash("Le mot de passe actuel est incorrect", "error")
            return redirect(url_for("update_password"))

        if new_password != confirm_password:
            flash("Les nouveaux mots de passe ne correspondent pas", "error")
            return redirect(url_for("update_password"))

        hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
        db.collection("users").document(current_user.id).update(
            {"password": hashed_password}
        )
        flash("Mot de passe mis à jour avec succès!", "success")
        return redirect(url_for("myprofile"))

    return render_template("update_password.html")


@app.route("/upload_image_summernote", methods=["POST"])
def upload_image():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Compress the image
    image = Image.open(file)
    image.thumbnail((800, 800))  # Resize to 800x800 pixels
    output = io.BytesIO()
    image.save(output, format="PNG", quality=75)  # Adjust quality to 75
    output.seek(0)

    # Upload the compressed image
    random_string = uuid.uuid4().hex[:16]
    blob = bucket.blob(f"CommentImages/comment_image-{random_string}.png")
    blob.upload_from_file(output, content_type="image/png")

    # Get the public URL without using ACLs
    public_url = f"https://storage.googleapis.com/{BUCKET_NAME}/{blob.name}"

    return jsonify({"url": public_url}), 200


@app.route("/delete_image", methods=["DELETE"])
def delete_image():
    data = request.get_json()
    if "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    image_url = data["url"]
    result = delete_file_online(image_url)

    if result["success"]:
        return jsonify({"message": result["message"]}), 200
    else:
        return jsonify({"error": result["message"]}), 404


@app.route("/calendar")
@pronote_login_required
def calendar():
    blob_name = f"calendriers/{current_user.id}.icas"
    blob = bucket.blob(blob_name)
    if not blob.exists():
        existing_doc = (
            db.collection("PronoteToken").where("user_id", "==", current_user.id).get()
        )

        if existing_doc:
            token = existing_doc[
                0
            ].to_dict()  # Assurez-vous de prendre le premier document
            token_json = json.dumps(token, ensure_ascii=False)  # Convertir en JSON
            result = subprocess.run(
                ["node", "./scripts/pronotetime.js", token_json, str(current_user.id)],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                sessionInfoJson = result.stdout
                # Remplace les guillemets simples par des guillemets doubles pour les valeurs
                sessionInfoJson = re.sub(r"(?<=: )'([^']*)'", r'"\1"', sessionInfoJson)

                # Ajoute des guillemets doubles autour des clés
                sessionInfoJson = re.sub(r"(\w+):", r'"\1":', sessionInfoJson)

                # Supprime les sauts de ligne et les espaces superflus
                sessionInfoJson = sessionInfoJson.replace("\n", "").strip()

                sessionInfo = json.loads(sessionInfoJson)
                sessionInfo["user_id"] = current_user.id
                # Rechercher un document avec le même user_id
                existing_doc = (
                    db.collection("PronoteToken")
                    .where("user_id", "==", current_user.id)
                    .get()
                )

                if existing_doc:
                    # Si un document est trouvé, le mettre à jour
                    for doc in existing_doc:
                        db.collection("PronoteToken").document(doc.id).update(
                            sessionInfo
                        )
            if result.returncode != 0:
                flash(
                    "Vous devez vous connecter ou vous reconnecter à Pronote.", "error"
                )
                return redirect(
                    url_for("myprofile")
                )  # Redirigez vers la page de profil
    return render_template("calendar.html", user_id=current_user.id)


@app.route("/pronotelogin")
@login_required
def pronotelogin():
    return render_template(
        "pronotelogin.html",
        user=current_user,
        profile_picture_url=current_user.profile_picture,
    )


@app.route("/pronoteloginok")
@login_required
def pronoteloginok():
    pronote_profile_picture = request.args.get("pronote_profile_picture")
    if pronote_profile_picture:
        # Decode the URL multiple times
        for _ in range(2):  # Adjust the range if needed
            pronote_profile_picture = urllib.parse.unquote(pronote_profile_picture)
    return render_template(
        "pronoteloginok.html",
        user=current_user,
        pronote_profile_picture=pronote_profile_picture,
    )


@app.route("/uploadQR", methods=["POST"])
@login_required
def upload_QR():
    if "file" not in request.files or request.files["file"].filename == "":
        return redirect(url_for("index"))

    file = request.files["file"]
    try:
        # Lire l'image directement depuis le fichier téléchargé
        img = cv2.imdecode(np.frombuffer(file.read(), np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return "Error decoding image", 400

        decoded_objects = 0  ##decode(img)
        qr_data = "No QR code found"
        if decoded_objects:
            qr_data = decoded_objects[0].data.decode("utf-8")

            # Encoder correctement la chaîne JSON
            qr_data_json = json.dumps(qr_data)

            # Appeler le script pronote.js avec le contenu du QR code
            result = subprocess.run(
                ["node", "./scripts/pronote.js", f"qr={qr_data_json}"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                sessionInfoJson = result.stdout
                # Remplace les guillemets simples par des guillemets doubles pour les valeurs
                sessionInfoJson = re.sub(r"(?<=: )'([^']*)'", r'"\1"', sessionInfoJson)

                # Ajoute des guillemets doubles autour des clés
                sessionInfoJson = re.sub(r"(\w+):", r'"\1":', sessionInfoJson)

                # Supprime les sauts de ligne et les espaces superflus
                sessionInfoJson = sessionInfoJson.replace("\n", "").strip()

                sessionInfo = json.loads(sessionInfoJson)
                sessionInfo["user_id"] = current_user.id
                # Rechercher un document avec le même user_id
                existing_doc = (
                    db.collection("PronoteToken")
                    .where("user_id", "==", current_user.id)
                    .get()
                )

                if existing_doc:
                    # Si un document est trouvé, le mettre à jour
                    for doc in existing_doc:
                        db.collection("PronoteToken").document(doc.id).update(
                            sessionInfo
                        )
                else:
                    # Sinon, ajouter un nouveau document
                    db.collection("PronoteToken").add(sessionInfo)
                profile_picture = sessionInfo["profile_picture"]
                return redirect(
                    url_for(
                        "pronoteloginok",
                        pronote_profile_picture=profile_picture,
                    )
                )
            else:
                return f"Error processing QR Code: {result.stderr}", 500

        return f"QR Code Data: {qr_data}", 200
    except Exception as e:
        return f"An error occurred: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
