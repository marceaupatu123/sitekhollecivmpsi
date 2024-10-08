from dotenv import load_dotenv

load_dotenv()

import pytest
from flask import url_for
from main import app, db
from werkzeug.security import generate_password_hash


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SERVER_NAME"] = "localhost"  # Set SERVER_NAME for URL building
    with app.app_context():
        with app.test_client() as client:
            # Initialisation de la base de données pour les tests
            db.collection("users").document("test_user").set(
                {
                    "email": "test@example.com",
                    "first_name": "Test",
                    "last_name": "User",
                    "password": generate_password_hash(
                        "password", method="pbkdf2:sha256"
                    ),
                    "khôlleGroupe": 13,
                    "is_admin": False,
                    "kholleur_key": "",
                    "profile_picture": "https://risibank.fr/cache/medias/0/3/334/33405/full.png",
                    "badges": ["MW82yMg2Hi4OJJo0eUfF"],
                }
            )
            yield client
            # Nettoyage de la base de données après les tests
            db.collection("users").document("test_user").delete()


def test_index(client):
    response = client.get(url_for("index"))
    assert response.status_code == 200
    assert "Prépa Alpha CIV".encode("utf-8") in response.data


def test_register(client):
    response = client.post(
        url_for("register"),
        data={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "password": "newpassword",
            "confirm_password": "newpassword",
            "khôlle": "13",
            "is_admin": False,
            "kholleur_key": "",
            "profile_picture": "https://risibank.fr/cache/medias/0/3/334/33405/full.png",
            "badges": ["MW82yMg2Hi4OJJo0eUfF"],
        },
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_login(client):
    response = client.post(
        url_for("login"),
        data={"email": "test@example.com", "password": "password"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Connecté avec succès!".encode("utf-8") in response.data


def test_logout(client):
    client.post(
        url_for("login"),
        data={"email": "test@example.com", "password": "password"},
        follow_redirects=True,
    )
    response = client.get(url_for("logout"), follow_redirects=True)
    assert response.status_code == 200
    assert "Vous avez été déconnecté.".encode("utf-8") in response.data


def test_get_structure(client):
    response = client.get(url_for("get_structure"))
    assert response.status_code == 200
    assert b"Maths" in response.data
    assert b"Physique" in response.data


def test_get_kholleurs(client):
    response = client.get(url_for("get_kholleurs"))
    assert response.status_code == 200
    assert b"M. Dupont" in response.data
    assert b"Mme. Durand" in response.data


def test_get_submissions(client):
    response = client.get(url_for("get_submissions"))
    assert response.status_code == 200


def test_myprofile(client):
    client.post(
        url_for("login"),
        data={"email": "test@example.com", "password": "password"},
        follow_redirects=True,
    )
    response = client.get(url_for("myprofile"))
    assert response.status_code == 200


def test_update_password(client):
    client.post(
        url_for("login"),
        data={"email": "test@example.com", "password": "password"},
        follow_redirects=True,
    )
    response = client.post(
        url_for("update_password"),
        data={
            "current_password": "password",
            "new_password": "newpassword",
            "confirm_password": "newpassword",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
