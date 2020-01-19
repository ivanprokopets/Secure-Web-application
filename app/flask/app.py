import filetype
from flask import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import pymysql
import os
import re
import requests
import sys

# MAIN

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(128)  # CSRF protection
session_id = None

limiter = Limiter(  # Brute force protection
    app,
    key_func=get_remote_address
)


def db_connect():
    check = 1
    while check == 1:
        try:
            check = 0
            db = pymysql.connect(host='user_file_db', user='root', passwd='changeme1^&*(@#', db='filemanagedIvan',
                                 autocommit=True)
        except pymysql.err.OperationalError:
            check = 1

    cursor = db.cursor()
    return cursor, db


@app.route("/", methods=["GET"])
def landing():
    return render_template("login.html")


# LOGIN

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute", # Brute force protection
               error_message="You have tried to log in too many times. Please wait a moment and try again.")
def login():
    global session_id

    cursor, db = db_connect()

    username = request.form['username']
    password = request.form['password']

    sql_statement = "SELECT Salt from Account WHERE Username=%s;"  # SQL Injection protection
    cursor.execute(sql_statement, str(username))
    salt = cursor.fetchone()

    if salt is None:
        cursor.close()
        db.close()
        return render_template('incorrect.html')
    else:
        salt = salt[0]

    calculated_hash = hashlib.sha256((salt + password).encode()).hexdigest()

    sql_statement = "SELECT PasswordHash FROM Account WHERE Username=%s;"
    cursor.execute(sql_statement, str(username))
    password_hash = cursor.fetchone()[0]

    if password_hash == calculated_hash:
        sql_statement = "SELECT user_id from Account WHERE Username=%s;"
        cursor.execute(sql_statement, str(username))
        session['user_id'] = cursor.fetchone()[0]

        sql_statement = "SELECT DisplayName FROM Account WHERE Username=%s;"
        cursor.execute(sql_statement, str(username))
        display_name = cursor.fetchone()[0]
        display_name = re.sub('[^a-zA-Z0-9-_*. ]', '', display_name)  # XSS prevention
        session['display_name'] = display_name

        session['logged_in'] = True
        session_id = os.urandom(128)
        session['session_id'] = session_id

        cursor.close()
        db.close()
        return redirect(url_for('home'))
    else:
        cursor.close()
        db.close()
        return render_template('incorrect.html')


@app.route("/incorrect", methods=["GET"])
def incorrect():
    return render_template("incorrect.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0')
