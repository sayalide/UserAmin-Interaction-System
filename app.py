from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
import sqlite3
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.secret_key = "assf@er0234Rg"

@app.route('/')
def index():
  return render_template('home.html')

@app.route('/home', methods=['POST', "GET"])
def home():
    if 'user_name' in session:
        return render_template('home.html', user_name=session['user_name'])
    else:
        return "Invalid Details"

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    con = sqlite3.connect('database.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if request.method == 'POST':
        log_name = request.form['log_name']
        cur.execute('UPDATE users SET activate_user="TRUE" where log_name = ? ',[log_name])
        con.commit()
        msg = "Activation Done"
        cur.execute("select log_name, activate_user from users where activate_user='FALSE'")
        rows = cur. fetchall()
        return redirect(url_for('login',rows=rows, msg={msg}))

class regForm(Form):
    user_name = StringField('user_name', [validators.Length(min=1, max=80)])
    log_name = StringField('log_name', [validators.Length(min=4, max=16)])
    passkey = PasswordField('passkey', [validators.DataRequired(), validators.EqualTo('reenter', message='Invalid passkey')])
    reenter = PasswordField('Reenter_password')

@app.route('/login', methods=['GET', 'POST'])
def login():
    con = sqlite3.connect('database.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if request.method == 'POST':
        log_name = request.form['log_name']
        check_passkey = request.form['passkey']
        result = cur.execute("SELECT * FROM users WHERE log_name = ?", [log_name])
        if result != 0:
            data = cur.fetchone()
            passkey = data['passkey']
            if sha256_crypt.verify(check_passkey, passkey):
                session['logged_in'] = True
                session['log_name'] = log_name
                if data['activate_admin'] == 'TRUE' and data['activate_user'] == 'TRUE':
                  flash('Hey Admin', 'Have a access to your portal')
                  cur.execute("select log_name, activate_user from users where activate_user='FALSE'")
                  rows = cur.fetchall()
                  return render_template('adminpage.html',rows=rows)
                elif data['activate_admin'] == 'FALSE' and data['activate_user'] == 'TRUE':
                    msg = "Logged in successfully as user!!!"
                    return render_template('display.html', msg=msg)
            else:
                error = 'Invalid login'
                return render_template('loginpage.html', error=error)
        else:
            error = 'Username not found'
            return render_template('loginpage.html', error=error)
    return render_template('loginpage.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    con = sqlite3.connect('database.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    form = regForm(request.form)
    if request.method == 'POST' and form.validate():
        user_name = form.user_name.data
        log_name = form.log_name.data
        passkey = sha256_crypt.encrypt(str(form.passkey.data))
        cur.execute("INSERT INTO users(user_name, log_name, passkey) VALUES(?,?,?)", (user_name, log_name,passkey))
        con.commit()
        flash('Log in to the system', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
     app.run(debug=True)
  