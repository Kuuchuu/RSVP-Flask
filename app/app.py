#!/usr/bin/env python3
from dotenv import load_dotenv
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from sqlalchemy import inspect

load_dotenv()

def strip_quotes(value):
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value

app = Flask(__name__)
app.config['SECRET_KEY'] = strip_quotes(os.getenv('RSVP_SQLKEY', 'InsecureRSVPSQLPassword_ChangeMe!'))
app.config['SQLALCHEMY_DATABASE_URI'] = strip_quotes(os.getenv('RSVP_DATABASE_URI', 'sqlite:///rsvp.db'))
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

RSVP_TITLE = strip_quotes(os.getenv('RSVP_TITLE', 'RSVP to our Wedding'))
RSVP_HEADER = strip_quotes(os.getenv('RSVP_HEADER', 'Wedding RSVP'))
RSVP_SUBHEADER = strip_quotes(os.getenv('RSVP_SUBHEADER', 'Please fill out the form below to RSVP'))

def get_registries():
    registries = []
    for i in range(1, 6):
        if registry := strip_quotes(os.getenv(f'RSVP_REGISTRY{i}', '')):
            name, url = registry.split('|')
            registries.append({'name': name, 'url': url})
    return registries

RSVP_REGISTRY = get_registries()

class RSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    guests = db.Column(db.Integer, nullable=False)
    crossed_out = db.Column(db.Boolean, default=False, nullable=False)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))

def validate_password(password):
    return bool(
        len(password) >= 8
        and re.search(r'[A-Z]', password)
        and re.search(r'[a-z]', password)
        and re.search(r'[0-9]', password)
        and re.search(r'[@$!%*?&~]', password)
    )

def validate_phone(phone):
    return re.match(r'^(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$', phone)

@app.route('/')
def index():
    return render_template('index.html', title=RSVP_TITLE, header=RSVP_HEADER, subheader=RSVP_SUBHEADER, registries=RSVP_REGISTRY)

@app.route('/rsvp', methods=['GET', 'POST'])
def rsvp():
    if request.method == 'POST':
        first_name = request.form.get('first_name').strip()
        last_name = request.form.get('last_name').strip()
        email = request.form.get('email').strip()
        phone = request.form.get('phone').strip()
        guests = request.form.get('guests').strip()

        if not first_name or not last_name or not email or not phone or not guests:
            flash('All fields are required.', 'danger')
            return render_template('rsvp.html')

        if not validate_phone(phone):
            flash('Invalid phone number format.', 'danger')
            return render_template('rsvp.html')

        if not guests.isdigit() or int(guests) < 1:
            flash('Number of guests must be a positive integer.', 'danger')
            return render_template('rsvp.html')
        
        if RSVP.query.filter_by(first_name=first_name, last_name=last_name).first() or RSVP.query.filter_by(email=email).first():
            flash('You have already submitted your RSVP with this name or email.', 'warning')
        else:
            new_rsvp = RSVP(first_name=first_name, last_name=last_name, email=email, phone=phone, guests=int(guests))
            db.session.add(new_rsvp)
            db.session.commit()
            flash('RSVP submitted successfully!', 'success')
            return redirect(url_for('index'))
    
    return render_template('rsvp.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        user = Admin.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password) and user.is_active:
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials or account disabled.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    inspector = inspect(db.engine)
    rsvp_table_exists = inspector.has_table("rsvp")
    admin_table_exists = inspector.has_table("admin")

    if request.method == 'POST':
        if 'change_password' in request.form:
            current_password = request.form.get('current_password').strip()
            new_password = request.form.get('new_password').strip()
            confirm_new_password = request.form.get('confirm_new_password').strip()

            if not check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_new_password:
                flash('New passwords do not match.', 'danger')
            elif not validate_password(new_password):
                flash('New password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&~).', 'danger')
            else:
                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                current_user.password = hashed_password
                db.session.commit()
                flash('Password changed successfully!', 'success')
        elif 'disable_admin' in request.form:
            admin_id = request.form.get('admin_id')
            if admin_to_disable := Admin.query.get(admin_id):
                admin_to_disable.is_active = False
                db.session.commit()
                flash(f'Admin {admin_to_disable.username} has been disabled.', 'success')
        elif 'delete_admin' in request.form:
            admin_id = request.form.get('admin_id')
            confirm_username = request.form.get('confirm_username').strip()
            admin_to_delete = Admin.query.get(admin_id)
            if admin_to_delete and admin_to_delete.username == confirm_username:
                db.session.delete(admin_to_delete)
                db.session.commit()
                flash(f'Admin {confirm_username} has been deleted.', 'success')
            else:
                flash('Username does not match. Admin not deleted.', 'danger')
        elif 'cross_out_rsvp' in request.form:
            rsvp_id = request.form.get('rsvp_id')
            if rsvp_to_cross_out := RSVP.query.get(rsvp_id):
                rsvp_to_cross_out.crossed_out = not rsvp_to_cross_out.crossed_out
                db.session.commit()
                flash(f'RSVP for {rsvp_to_cross_out.first_name} {rsvp_to_cross_out.last_name} has been {"crossed out" if rsvp_to_cross_out.crossed_out else "uncrossed"}.', 'success')
        elif 'delete_rsvp' in request.form:
            rsvp_id = request.form.get('rsvp_id')
            confirm_email = request.form.get('confirm_email').strip()
            rsvp_to_delete = RSVP.query.get(rsvp_id)
            if rsvp_to_delete and rsvp_to_delete.email == confirm_email:
                db.session.delete(rsvp_to_delete)
                db.session.commit()
                flash(f'RSVP for {confirm_email} has been deleted.', 'success')
            else:
                flash('Email does not match. RSVP not deleted.', 'danger')

    rsvps = RSVP.query.all() if rsvp_table_exists else []
    admins = Admin.query.all() if admin_table_exists else []
    return render_template('admin_dashboard.html', rsvps=rsvps, admins=admins)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
