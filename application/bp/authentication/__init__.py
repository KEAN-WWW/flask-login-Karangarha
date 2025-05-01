from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import check_password_hash

from .forms import RegisterForm, LoginForm
from flask_login import login_user, logout_user, login_required
from application.database import User

authentication = Blueprint('authentication', __name__, template_folder='templates')

@authentication.route('/registration', methods=['POST', 'GET'])
def registration():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.find_user_by_email(form.email.data)
        if existing_user:
            flash('Email is already registered.', 'danger')
        else:
            new_user = User.create(form.email.data, form.password.data)
            new_user.save()
            flash('Registration successful!', 'success')
            return redirect(url_for('authentication.dashboard'))
    return render_template('registration.html', form=form)


@authentication.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user is None:
            flash("User Not Found")
            return redirect(url_for("authentication.login"))

        if not user.check_password(password):
            flash("Password Incorrect")
            return redirect(url_for("authentication.login"))

        login_user(user)
        return redirect(url_for("authentication.dashboard"))

    return render_template("login.html", form=form)

@authentication.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("homepage.homepage"))

@authentication.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html")
