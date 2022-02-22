from flask_login import current_user
from flask import redirect, url_for

def get_all_but_current_users():
    from models import User
    user = current_user
    return User.query.filter(User.id != user.id).all()


def get_all_users():
    from models import User
    return User.query.all()


def get_user_by_id(user_id):
    from models import User
    return User.query.filter(User.id == user_id).first()


def create_user(email, username, password, privateKey, publicKey):
    from models import User
    user = User(name=username, email=email, password=password, private_key=privateKey, public_key=publicKey)
    from app import db
    db.session.add(user)
    db.session.commit()
