import pytest
from main import app, db, User, Submission
from flask import url_for
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

def test_register(client):
    response = client.post('/register', data={
        'first_name': 'Test',
        'last_name': 'User',
        'email': 'test@example.com',
        'password': 'password',
        'confirm_password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert 'Inscription réussie! Vous pouvez maintenant vous connecter.'.encode('utf-8') in response.data

def test_login(client):
    # Create a user first
    with app.app_context():
        user = User(
            first_name='Test',
            last_name='User',
            email='test@example.com',
            password=generate_password_hash('password', method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()

    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert 'Connecté avec succès!'.encode('utf-8') in response.data

def test_logout(client):
    # Create and login a user first
    with app.app_context():
        user = User(
            first_name='Test',
            last_name='User',
            email='test@example.com',
            password=generate_password_hash('password', method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()

    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password'
    }, follow_redirects=True)

    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert 'Vous avez été déconnecté.'.encode('utf-8') in response.data

def test_get_structure(client):
    response = client.get('/get_structure')
    assert response.status_code == 200
    assert isinstance(response.json, dict)

def test_get_kholleurs(client):
    response = client.get('/get_kholleurs')
    assert response.status_code == 200
    assert isinstance(response.json, dict)
    assert 'Maths' in response.json
    assert 'Physique' in response.json

def test_upload_file(client):
    # Create and login a user first
    with app.app_context():
        user = User(
            first_name='Test',
            last_name='User',
            email='test@example.com',
            password=generate_password_hash('password', method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()

    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password'
    }, follow_redirects=True)

    data = {
        'subject': 'Maths',
        'chapter': 'Algebra',
        'difficulty': 'Easy',
        'kholleur': 'M. Dupont'
    }
    data['file'] = (open('test_image.jpeg', 'rb'), 'test_image.jpeg')

    response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert 'Fichier envoyé avec succès!'.encode('utf-8') in response.data

def test_get_submissions(client):
    # Create a user and a submission first
    with app.app_context():
        user = User(
            first_name='Test',
            last_name='User',
            email='test@example.com',
            password=generate_password_hash('password', method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()

        submission = Submission(
            user_id=user.id,
            subject='Maths',
            chapter='Algebra',
            difficulty='Easy',
            image_url='path/to/image.png',
            kholleur='M. Dupont'
        )
        db.session.add(submission)
        db.session.commit()

    response = client.get('/get_submissions?subject=Maths&chapter=Algebra')
    assert response.status_code == 200
    assert isinstance(response.json, list)
    assert len(response.json) > 0
    assert response.json[0]['prenom'] == 'Test'
    assert response.json[0]['difficulte'] == 'Easy'
    assert response.json[0]['subject'] == 'Maths'
    assert response.json[0]['chapter'] == 'Algebra'
    assert response.json[0]['kholleur'] == 'M. Dupont'
