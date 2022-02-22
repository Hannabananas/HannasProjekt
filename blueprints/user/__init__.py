import json
import re
import rsa
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash
from flask_login import logout_user, login_required, current_user,login_user
from controllers.message_controller import create_message, get_user_messages
from controllers.user_controller import get_all_but_current_users, get_user_by_id, create_user
from models import User
from passlib.hash import argon2


bp_user = Blueprint('bp_user', __name__)


@bp_user.post('/signup')
def user_signup():
    email = request.form['email']
    username = request.form['name']
    password = request.form['password']
    # admin = request.form['admin']
    # if admin == 'on':
    #     admin = True
    # else:
    #     admin = False
    (publicKey, privateKey) = rsa.newkeys(1024)
    publicKey = publicKey.save_pkcs1('PEM')
    privateKey = privateKey.save_pkcs1('PEM')
    # print(publicKey)
    # print(privateKey)
    hashedPass = argon2.using(rounds=10).hash(password)
    user = User.query.filter_by(email=email).first()
    if re.match("[^@]+@[^@]+\.[^@]+", email) != None:
        if user:
            flash("Another account using this email already exists")
            return redirect(url_for('bp_open.signup_get'))
        create_user(email, username, hashedPass, privateKey, publicKey)
        return redirect(url_for('bp_open.login_get'))
    else:
        flash("Please enter a valid email address")
        return redirect(url_for('bp_open.signup_get'))





@bp_user.post('/login')
def user_login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()

    if user is None:
        flash('No user associated with the entered email exists')
        return redirect(url_for('bp_open.login_get'))

    if not argon2.verify(password, user.password):
        flash('The password entered is incorrect')
        return redirect(url_for('bp_open.login_get'))

    login_user(user)
    user.online = True
    from app import db
    db.session.commit()

    # if user.admin == False:
    return render_template('index.html')

@bp_user.get('/all_users')
@login_required
def get_all_users():
    data = get_all_but_current_users()
    return render_template('admin.html', users=data)

@bp_user.post('/makeAdmin')
def make_admin():
    user = request.form['id']
    user = User.query.filter_by(id=user).first()
    user.admin = True

    from app import db
    db.session.commit()

    users = get_all_but_current_users()
    return render_template('admin.html', users=users)

@bp_user.post('/removeAdmin')
def remove_admin():
    user = request.form['id']
    user = User.query.filter_by(id=user).first()
    user.admin = False

    from app import db
    db.session.commit()

    users = get_all_but_current_users()
    return render_template('admin.html', users=users)

@bp_user.get('/profile')
@login_required
def user_get():
    users = get_all_but_current_users()
    return render_template('user.html', users=users)


@bp_user.get('/logout')
def logout_get():
    user = current_user
    user.online = False

    from app import db
    db.session.commit()
    logout_user()
    return redirect(url_for('bp_open.index'))




@bp_user.get('/message/<user_id>')
def message_get(user_id):
    user_id = int(user_id)
    receiver = get_user_by_id(user_id)
    return render_template('message.html', receiver=receiver)


@bp_user.post('/message')
def message_post():
    body = request.form['body']
    body = body.encode('ascii')
    receiver_id = request.form['user_id']
    reciever = User.query.filter_by(id=receiver_id).first()
    reciever_key = rsa.PublicKey.load_pkcs1(reciever.public_key)
    ciphertext = rsa.encrypt(body, reciever_key)

    create_message(ciphertext, receiver_id)
    return redirect(url_for('bp_user.mailbox_get'))




@bp_user.get('/mailbox')
def mailbox_get():
    messages = get_user_messages()
    users = get_all_but_current_users()
    return render_template('mailbox.html', messages=messages, users=users)
