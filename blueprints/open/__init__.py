from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user
from passlib.hash import argon2
from models import User



# Create a blueprint object that can vbe used as an app object for this blueprint
bp_open = Blueprint('bp_open', __name__)


@bp_open.get('/')
def index():
    return render_template('index.html')


@bp_open.get('/login')
def login_get():
    return render_template('login.html')


@bp_open.get('/signup')
def signup_get():
    return render_template('signup.html')
