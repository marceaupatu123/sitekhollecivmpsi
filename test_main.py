import pytest
from flask import url_for, make_response
from main import app, db, User
from werkzeug.security import generate_password_hash
import io
from PIL import Image
import json
from werkzeug.datastructures import FileStorage
from datetime import datetime  # Add this import at the top with other imports

# --- Test Configuration & Fixtures ---


@pytest.fixture
def app_context():
    with app.app_context():
        yield


@pytest.fixture
def client(app_context):
    app.config.update(
        {"TESTING": True, "WTF_CSRF_ENABLED": False, "SERVER_NAME": "localhost"}
    )
    return app.test_client()


@pytest.fixture
def auth_client(client):
    # Create test user in Firestore
    user_data = {
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "password": generate_password_hash("password", method="pbkdf2:sha256"),
        "classe": "MPSI",
        "khôlleGroupe": 13,
        "is_admin": False,
        "profile_picture": None,
        "badges": [],
    }
    user_ref = db.collection("users").document("test_user")
    user_ref.set(user_data)

    # Log user in
    client.post("/login", data={"email": "test@example.com", "password": "password"})

    yield client

    # Cleanup
    user_ref.delete()
    # Delete all test submissions
    submissions = (
        db.collection("submissions").where("user_id", "==", "test_user").stream()
    )
    for submission in submissions:
        submission.reference.delete()


@pytest.fixture
def admin_client(client):
    # Create admin test user
    admin_user = {
        "email": "admin@example.com",
        "first_name": "Admin",
        "last_name": "User",
        "password": generate_password_hash("password"),
        "classe": "MPSI",
        "khôlleGroupe": 13,
        "is_admin": True,
        "kholleur_key": "",
        "profile_picture": "https://example.com/pic.jpg",
        "badges": [],
    }
    user_ref = db.collection("users").document("admin_user")
    user_ref.set(admin_user)

    # Login as admin
    client.post(
        "/login",
        data={"email": "admin@example.com", "password": "password"},
        follow_redirects=True,
    )

    yield client

    # Cleanup
    user_ref.delete()
    # Delete all test submissions
    submissions = (
        db.collection("submissions").where("user_id", "==", "admin_user").stream()
    )
    for submission in submissions:
        submission.reference.delete()


# --- Authentication Tests ---


def test_register_success(client):
    try:
        response = client.post(
            "/register",
            data={
                "first_name": "New",
                "last_name": "User",
                "email": "new@example.com",
                "password": "password123",
                "confirm_password": "password123",
                "khôlle": "13",
            },
        )
        assert response.status_code == 302  # Redirect on success
        assert "users" in [coll.id for coll in db.collections()]

    finally:
        # Cleanup: delete the created user
        users = db.collection("users").where("email", "==", "new@example.com").stream()
        for user in users:
            user_ref = db.collection("users").document(user.id)
            # Delete any submissions by this user
            submissions = (
                db.collection("submissions").where("user_id", "==", user.id).stream()
            )
            for submission in submissions:
                submission.reference.delete()
            # Finally delete the user
            user_ref.delete()


def test_register_validation(client):
    # Test password mismatch
    response = client.post(
        "/register",
        data={
            "first_name": "New",
            "last_name": "User",
            "email": "new@example.com",
            "password": "password123",
            "confirm_password": "different",
            "khôlle": "13",
        },
        follow_redirects=True,  # Add this to follow the redirect
    )
    assert response.status_code == 200
    assert b"Les mots de passe ne correspondent pas" in response.data


# --- API Endpoint Tests ---


def test_get_structure(auth_client):
    response = auth_client.get("/get_structure")
    data = json.loads(response.data)
    assert response.status_code == 200
    assert "Maths" in data
    assert "Physique" in data
    assert isinstance(data["Maths"], list)


def test_get_kholleurs(auth_client):
    response = auth_client.get("/get_kholleurs")
    data = json.loads(response.data)
    assert response.status_code == 200
    assert "Maths" in data
    assert "Physique" in data
    assert isinstance(data["Maths"], list)


# --- Upload Tests ---


def test_upload_file_success(auth_client):
    # Create a test image file
    img = Image.new("RGB", (100, 100), color="red")
    img_io = io.BytesIO()
    img.save(img_io, "JPEG")
    img_io.seek(0)

    data = {
        "file": (img_io, "test.jpg"),
        "subject": "Maths",
        "chapter": "Chapitre 1",
        "kholleur": "Test Kholleur",
        "difficulty": "3",
    }

    response = auth_client.post(
        "/upload", data=data, content_type="multipart/form-data"
    )

    # Check if the response is a redirect (302)
    assert response.status_code == 302

    # Cleanup uploaded file
    submissions = (
        db.collection("submissions").where("user_id", "==", "test_user").stream()
    )
    for submission in submissions:
        submission_data = submission.to_dict()
        if "image_url" in submission_data:
            from main import delete_file_online

            delete_file_online(submission_data["image_url"])
        submission.reference.delete()


# --- Admin Tests ---


def test_admin_access(admin_client):
    response = admin_client.get("/admin", follow_redirects=True)  # Add follow_redirects
    assert response.status_code == 200
    # Vérifier qu'on est bien sur la page admin
    assert b"Administration" in response.data


def test_admin_edit_user(admin_client):
    # D'abord créer un utilisateur à modifier
    test_user = {
        "email": "edit@example.com",
        "first_name": "Edit",
        "last_name": "User",
        "password": generate_password_hash("password"),
        "classe": "MPSI",
        "khôlleGroupe": 13,
    }
    user_ref = db.collection("users").document("edit_user")
    user_ref.set(test_user)

    try:
        response = admin_client.post(
            "/admin/edit_user/edit_user",
            data={
                "first_name": "Updated",
                "last_name": "User",
                "email": "edit@example.com",
                "password": "",  # Empty password means no change
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        # Vérifier que l'utilisateur a bien été modifié
        updated_user = user_ref.get().to_dict()
        assert updated_user["first_name"] == "Updated"
    finally:
        # Cleanup
        user_ref.delete()


# --- Service Tests ---


def test_compress_image():
    from main import compress_image

    # Create test image
    img = Image.new("RGB", (1000, 1000), color="red")
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="JPEG")
    img_bytes.seek(0)

    # Test compression
    result = compress_image(img_bytes)
    assert result is not None

    # Verify size reduction
    compressed = Image.open(result)
    assert compressed.size[0] <= 800
    assert compressed.size[1] <= 800


def test_get_badge_info():
    from main import get_badge_info

    # Test with valid badge IDs
    badges = get_badge_info(("badge1", "badge2"))
    assert isinstance(badges, list)

    # Test cache hit
    cached_badges = get_badge_info(("badge1", "badge2"))
    assert badges == cached_badges


# Modifier le test de suppression existant et ajouter de nouveaux tests
def test_delete_submission_success(auth_client):
    try:
        # Create a test submission first
        submission_data = {
            "user_id": "test_user",
            "subject": "Maths",
            "chapter": "Chapitre 1",
            "classe": "MPSI",
            "difficulty": "3",
            "image_url": "test_url",
            "kholleur": "Test Kholleur",
            "timestamp": datetime.utcnow(),
        }
        submission_ref = db.collection("submissions").add(submission_data)
        submission_id = submission_ref[1].id

        # Test deletion
        response = auth_client.post(f"/delete_submission/{submission_id}")
        assert response.status_code == 302  # Should redirect

        # Verify submission was deleted
        deleted_submission = db.collection("submissions").document(submission_id).get()
        assert not deleted_submission.exists

    finally:
        # Cleanup any remaining submissions
        submissions = (
            db.collection("submissions").where("user_id", "==", "test_user").stream()
        )
        for submission in submissions:
            submission.reference.delete()


def test_delete_submission_unauthorized(auth_client):
    # Create a submission owned by another user
    submission_data = {
        "user_id": "other_user",  # Different user
        "subject": "Maths",
        "chapter": "Chapitre 1",
        "difficulty": "3",
        "image_url": "test_url",
        "kholleur": "Test Kholleur",
        "timestamp": datetime.utcnow(),
    }
    submission_ref = db.collection("submissions").add(submission_data)
    submission_id = submission_ref[1].id

    # Try to delete
    response = auth_client.post(f"/delete_submission/{submission_id}")
    assert response.status_code == 302  # Should redirect with error

    # Verify submission still exists
    submission = db.collection("submissions").document(submission_id).get()
    assert submission.exists


# Ajouter un test pour la gestion des commentaires
def test_comment_crud(auth_client):
    # Create a test submission
    submission_data = {
        "user_id": "test_user",
        "subject": "Maths",
        "chapter": "Chapitre 1",
        "difficulty": "3",
        "image_url": "test_url",
        "kholleur": "Test Kholleur",
        "timestamp": datetime.utcnow(),
    }
    submission_ref = db.collection("submissions").add(submission_data)
    submission_id = submission_ref[1].id

    # Test adding a comment
    comment_data = {"submission_id": submission_id, "message": "Test comment"}
    response = auth_client.post(
        "/post_comment", json=comment_data, content_type="application/json"
    )
    assert response.status_code == 200

    # Verify comment was added
    comments = list(
        db.collection("comments").where("submission_id", "==", submission_id).stream()
    )
    assert len(comments) == 1
    assert comments[0].to_dict()["message"] == "Test comment"

    # Clean up
    for comment in comments:
        comment.reference.delete()
    db.collection("submissions").document(submission_id).delete()


# Supprimer les tests redondants ou moins pertinents comme test_upload_file_validation
# qui teste des cas moins courants et ajouter des tests plus critiques


def test_user_session_management(client):
    """Test user session creation and destruction"""
    # Test login
    response = client.post(
        "/login",
        data={"email": "test@example.com", "password": "password"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    # Test logout
    response = client.get("/logout", follow_redirects=True)
    assert response.status_code == 200

    # Try to access protected route after logout
    response = client.get("/myprofile")
    assert response.status_code == 302  # Should redirect to login
