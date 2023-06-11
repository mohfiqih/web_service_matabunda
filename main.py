from flask import *
from flask_restx import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import jwt
import base64

import os
import pathlib
import keras
import numpy as np
import pandas as pd

app = Flask(__name__)
api = Api(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/web_mata_bunda"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

app.config['JWT_IDENTITY_CLAIM'] = 'jti'
app.secret_key = 'asdsdfsdfs13sdf_df%&'

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    token = db.Column(db.Text(), nullable=False)
    status_validasi = db.Column(db.Text(), nullable=False)
    level = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DATETIME, nullable=False)


################################ Register #####################################

@app.route('/register-user', methods=["GET", "POST"])
def flutter_register():
    if request.method == "POST":
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]
        re_password = request.form["re_password"]

        loguser = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if loguser is None:
            belum_valid = 'Belum Validasi'
            level = 'User'
            register = Users(email=email, name=name, password=generate_password_hash(
                password), status_validasi=belum_valid, level=level)
            db.session.add(register)
            db.session.commit()
            return jsonify(["Register berhasil! Silahkan Login!"])
        elif password != re_password:
            return jsonify(["Password tidak sama!"])
        else:
            return jsonify(["Email Telah digunakan!"])


@app.route('/register-admin', methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]
        re_password = request.form["re_password"]

        loguser = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if loguser is None:
            belum_valid = 'Belum Validasi'
            level = 'Administrator'
            register = Users(email=email, name=name, password=generate_password_hash(
                password), status_validasi=belum_valid, level=level)
            db.session.add(register)
            db.session.commit()
            return jsonify(["Berhasil Menambah Admin!"])
        elif password != re_password:
            return jsonify(["Password tidak sama!"])
        else:
            return jsonify(["Email Telah digunakan!"])
################################ End Register #####################################


################################ Login #####################################
SECRET_KEY = "WhatEverYouWant"
ISSUER = "myFlaskWebService"
AUDIENCE_MOBILE = "myMobileApp"


@app.route('/login', methods=["GET", "POST"])
def flutter_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if not email or not password:
            return jsonify(["Masukan email dan password!"])

        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if not user:
            return jsonify(["Password dan email salah!"])
        else:
            user = user[0]

        if check_password_hash(user.password, password):

            email_encode = email.encode("utf-8")
            base64_bytes = base64.b64encode(email_encode)
            token = base64_bytes.decode("utf-8")

            return jsonify(
                {
                    'message': f"Login berhasil!! cek email",
                    'token': token
                }
            )
        else:
            return jsonify(
                {
                    'message': f"Email dan Password salah!",
                }
            )

################################ End Login #####################################

################################ Token #####################################


@app.route('/basicToken', methods=["GET", "POST"])
def basicToken():
    if request.method == "POST":
        token = request.form['token']
        base64Bytes = token.encode('utf-8')
        msgBytes = base64.b64decode(base64Bytes)
        email = msgBytes.decode('utf-8')

        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if not token:
            return jsonify([f'Token Gagal!']), 400
        else:
            user = user[0]

        # if token:
        if user.level == "Administrator":
            validasi = 'Valid'
            user.token = token
            user.status_validasi = validasi

            db.session.add(user)
            db.session.commit()

            return jsonify(["Anda sebagai admin!"])

        elif user.level == "User":
            validasi = 'Valid'
            user.token = token
            user.status_validasi = validasi

            db.session.add(user)
            db.session.commit()

            return jsonify(["Berhasil masuk!"])


@api.route('/data-user', methods=["GET", "POST"])
class UserAPI(Resource):
    def get(self):
        log_data = db.session.execute(db.select(
            Users.email, Users.name, Users.status_validasi, Users.created_at, Users.level)).all()
        if (log_data is None):
            return f"Tidak Ada Data User!"
        else:
            data = []
            for user in log_data:
                data.append({
                    'email': user.email,
                    'name': user.name,
                    'status_validasi': user.status_validasi,
                    'level': user.level,
                    'craeted_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    # 'total': total
                })
            return data

# ------------------- Send Reset Password ------------------ #


@app.route('/send-reset', methods=["GET", "POST"])
def send_reset():
    if request.method == "POST":
        email = request.form["email"]

        if not email:
            return jsonify(["Masukan email dan password!"])

        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if not user:
            return jsonify(["Password dan email salah!"])
        else:
            user = user[0]

        if user.email:
            link = "reset"
            return jsonify(
                {
                    'message': f"Link reset berhasil dikirim!",
                    'link': link
                }
            )
        else:
            return jsonify(["Email dan Password salah!"])


@app.route('/reset', methods=['GET', 'POST'])
def repassword():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        re_password = request.form["password"]

        # get db
        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if not user:
            return f'Email {email} tidak Ada!', 400
        else:
            user = user[0]

        if email:
            user.email = email
            user.password = generate_password_hash(password)

            db.session.add(user)
            db.session.commit()

            return redirect('/success')

    return render_template('reset.html')


@app.route('/success')
def success():
    return render_template('success.html')

# # # --------------- History --------------- # # #


@app.route('/history-users')
def history_users():
    all_users = Users.query.all()
    return render_template('data_users.html', users=all_users)


if __name__ == '__main__':
    app.run(debug=True, host='192.168.56.122')
