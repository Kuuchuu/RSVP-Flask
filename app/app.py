#!/usr/bin/env python3
import os
import re
import csv
import glob
import png
import pyqrcode
import random
import smtplib
import zipfile
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from io import BytesIO
from io import StringIO
from PIL import Image, ImageDraw, ImageFont
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

def strip_quotes(value):
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value

app = Flask(__name__)
app.config['SECRET_KEY'] = strip_quotes(os.getenv('RSVP_SQLKEY', 'InsecureRSVPSQLPassword_ChangeMe!'))
app.config['SQLALCHEMY_DATABASE_URI'] = strip_quotes(os.getenv('RSVP_DATABASE_URI', 'sqlite:///rsvp.db'))
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THEMES_FOLDER'] = 'static/themes'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

RSVP_TITLE = strip_quotes(os.getenv('RSVP_TITLE', 'RSVP to our Wedding'))
RSVP_HEADER = strip_quotes(os.getenv('RSVP_HEADER', 'Wedding RSVP'))
RSVP_SUBHEADER = strip_quotes(os.getenv('RSVP_SUBHEADER', 'November 04, 2099 • Denver, CO'))
RSVP_DESCRIPTION = strip_quotes(os.getenv('RSVP_DESCRIPTION', 'Please fill out the form below to RSVP'))

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
    phone = db.Column(db.String(20), nullable=True)
    guests = db.Column(db.Integer, nullable=True)
    attending = db.Column(db.Boolean, nullable=False)
    crossed_out = db.Column(db.Boolean, default=False, nullable=False)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    notifications = db.Column(db.Boolean, default=True, nullable=False)

    def get_id(self):
        return self.id

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(100), nullable=False)

def get_setting(key, default=None):
    setting = Settings.query.filter_by(key=key).first()
    return setting.value if setting else default

def set_setting(key, value):
    setting = Settings.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = Settings(key=key, value=value)
        db.session.add(setting)
    db.session.commit()

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

def send_email(subject, body, to_addresses):
    smtp_server = strip_quotes(os.getenv('RSVP_SMTP_SERVER'))
    smtp_port = strip_quotes(os.getenv('RSVP_SMTP_PORT'))
    smtp_username = strip_quotes(os.getenv('RSVP_SMTP_USERNAME'))
    smtp_password = strip_quotes(os.getenv('RSVP_SMTP_PASSWORD'))
    from_address = strip_quotes(os.getenv('RSVP_SMTP_FROM_ADDRESS'))

    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = ", ".join(to_addresses)
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(from_address, to_addresses, msg.as_string())
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/generate_generic_qr_code', methods=['POST'])
@login_required
def generate_generic_qr_code():
    base_url = url_for('index', _external=True)
    qr = pyqrcode.create(base_url)

    buffer = BytesIO()
    qr.png(buffer, scale=10)
    buffer.seek(0)

    qr_image = Image.open(buffer).convert("RGBA")
    
    overlay_image_path = os.path.join('static', 'qrcode.png')
    
    if os.path.exists(overlay_image_path):
        overlay_image = Image.open(overlay_image_path).convert("RGBA")
        overlay_size = (qr_image.size[0] // 5, qr_image.size[1] // 5)
        overlay_image = overlay_image.resize(overlay_size, Image.LANCZOS)
        pos = ((qr_image.size[0] - overlay_image.size[0]) // 2, (qr_image.size[1] - overlay_image.size[1]) // 2)
        qr_image.paste(overlay_image, pos, overlay_image)
    
    result_buffer = BytesIO()
    qr_image.save(result_buffer, format="PNG")
    result_buffer.seek(0)

    return send_file(result_buffer, mimetype='image/png', as_attachment=True, download_name="generic_qr_code.png")

@app.route('/generate_qr_code', methods=['POST'])
@login_required
def generate_qr_code():
    first_name = request.form.get('first_name').strip()
    last_name = request.form.get('last_name').strip()
    email = request.form.get('email').strip()
    phone = request.form.get('phone').strip()
    guests = request.form.get('guests').strip()

    rsvp_url = url_for('rsvp', _external=True, first_name=first_name, last_name=last_name, email=email, phone=phone, guests=guests)
    qr = pyqrcode.create(rsvp_url)

    buffer = BytesIO()
    qr.png(buffer, scale=10)
    buffer.seek(0)

    qr_image = Image.open(buffer).convert("RGBA")

    overlay_image_path = os.path.join('static', 'qrcode.png')
    rsvp_qr_image = os.getenv('RSVP_QR_IMAGE', 'true').lower() == 'true'

    if rsvp_qr_image and os.path.exists(overlay_image_path):
        overlay_image = Image.open(overlay_image_path).convert("RGBA")
        overlay_size = (qr_image.size[0] // 5, qr_image.size[1] // 5)
        overlay_image = overlay_image.resize(overlay_size, Image.LANCZOS)
        pos = ((qr_image.size[0] - overlay_image.size[0]) // 2, (qr_image.size[1] - overlay_image.size[1]) // 2)
        qr_image.paste(overlay_image, pos, overlay_image)
    else:
        draw = ImageDraw.Draw(qr_image)
        initials = f"{first_name[0].upper()}{last_name[0].upper()}"
        font_size = qr_image.size[0] // 5

        try:
            font = ImageFont.truetype(os.path.join('static', 'qrcode.ttf'), font_size)
        except IOError:
            font = ImageFont.load_default()

        text_box = draw.textbbox((0, 0), initials, font=font)
        text_width = text_box[2] - text_box[0]
        text_height = text_box[3] - text_box[1]
        
        extra_padding = 10
        rectangle_width = text_width + extra_padding
        rectangle_height = text_height + extra_padding

        text_pos = ((qr_image.size[0] - text_width) // 2, (qr_image.size[1] - text_height) // 2)

        rectangle_pos = (text_pos[0] - extra_padding // 2, text_pos[1] - extra_padding // 2)
        draw.rectangle([rectangle_pos, (rectangle_pos[0] + rectangle_width, rectangle_pos[1] + rectangle_height)], fill="white")

        text_pos = ((qr_image.size[0] - text_width) // 2, (qr_image.size[1] - text_height) // 2.31 - font_size // 8)
        draw.text(text_pos, initials, font=font, fill=(0, 0, 0, 255))

    result_buffer = BytesIO()
    qr_image.save(result_buffer, format="PNG")
    result_buffer.seek(0)

    filename = f"{first_name.lower()}_{last_name.lower()}.png"
    return send_file(result_buffer, mimetype='image/png', as_attachment=True, download_name=filename)

@app.route('/download_template_csv')
@login_required
def download_template_csv():
    template_csv = [
        ['first_name', 'last_name', 'email', 'phone', 'guests']
    ]
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerows(template_csv)
    buffer.seek(0)
    
    return send_file(BytesIO(buffer.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='rsvp_template.csv')

@app.route('/generate_qr_codes_from_csv', methods=['POST'])
@login_required
def generate_qr_codes_from_csv():
    if 'csv_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('admin_dashboard'))

    file = request.files['csv_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('admin_dashboard'))

    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        with open(filepath, newline='') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            qr_codes = []
            for row in reader:
                first_name, last_name = row[0], row[1]
                email = row[2] if len(row) > 2 else ''
                phone = row[3] if len(row) > 3 else ''
                guests = row[4] if len(row) > 4 else ''

                rsvp_url = url_for('rsvp', _external=True, first_name=first_name, last_name=last_name, email=email, phone=phone, guests=guests)
                qr = pyqrcode.create(rsvp_url)

                buffer = BytesIO()
                qr.png(buffer, scale=10)
                buffer.seek(0)

                qr_image = Image.open(buffer).convert("RGBA")

                overlay_image_path = os.path.join('static', 'qrcode.png')
                rsvp_qr_image = os.getenv('RSVP_QR_IMAGE', 'true').lower() == 'true'

                if rsvp_qr_image and os.path.exists(overlay_image_path):
                    overlay_image = Image.open(overlay_image_path).convert("RGBA")
                    overlay_size = (qr_image.size[0] // 5, qr_image.size[1] // 5)
                    overlay_image = overlay_image.resize(overlay_size, Image.LANCZOS)
                    pos = ((qr_image.size[0] - overlay_image.size[0]) // 2, (qr_image.size[1] - overlay_image.size[1]) // 2)
                    qr_image.paste(overlay_image, pos, overlay_image)
                else:
                    draw = ImageDraw.Draw(qr_image)
                    initials = f"{first_name[0].upper()}{last_name[0].upper()}"
                    font_size = qr_image.size[0] // 5

                    try:
                        font = ImageFont.truetype(os.path.join('static', 'qrcode.ttf'), font_size)
                    except IOError:
                        font = ImageFont.load_default()

                    text_box = draw.textbbox((0, 0), initials, font=font)
                    text_width = text_box[2] - text_box[0]
                    text_height = text_box[3] - text_box[1]
                    
                    extra_padding = 10
                    rectangle_width = text_width + extra_padding
                    rectangle_height = text_height + extra_padding

                    text_pos = ((qr_image.size[0] - text_width) // 2, (qr_image.size[1] - text_height) // 2)

                    rectangle_pos = (text_pos[0] - extra_padding // 2, text_pos[1] - extra_padding // 2)
                    draw.rectangle([rectangle_pos, (rectangle_pos[0] + rectangle_width, rectangle_pos[1] + rectangle_height)], fill="white")

                    text_pos = ((qr_image.size[0] - text_width) // 2, (qr_image.size[1] - text_height) // 2.31 - font_size // 8)
                    draw.text(text_pos, initials, font=font, fill=(0, 0, 0, 255))

                qr_buffer = BytesIO()
                qr_image.save(qr_buffer, format="PNG")
                qr_buffer.seek(0)

                qr_codes.append((f"{first_name.lower()}_{last_name.lower()}.png", qr_buffer.read()))

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            for filename, data in qr_codes:
                zip_file.writestr(filename, data)
        zip_buffer.seek(0)

        os.remove(filepath)

        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='qr_codes.zip')

    flash('Invalid file format. Please upload a CSV file.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/')
def index():
    return render_template('index.html', title=RSVP_TITLE, header=RSVP_HEADER, subheader=RSVP_SUBHEADER, description=RSVP_DESCRIPTION, registries=RSVP_REGISTRY)

@app.route('/rsvp', methods=['GET', 'POST'])
def rsvp():
    placeholders = [
        {"first_name": "Jane", "last_name": "Doe", "email": "Jane.Doe@example.net"},
        {"first_name": "John", "last_name": "Doe", "email": "John.Doe@example.net"},
        {"first_name": "Jane", "last_name": "Smith", "email": "Jane.Smith@example.com"},
        {"first_name": "John", "last_name": "Smith", "email": "John.Smith@example.com"}
    ]
    placeholder = random.choice(placeholders)

    def is_valid_name(name):
        return name == '' or re.match("^[A-Za-z]+$", name) is not None

    first_name = request.args.get('first_name', '')
    last_name = request.args.get('last_name', '')

    if not is_valid_name(first_name) or not is_valid_name(last_name):
        # flash('Invalid name format.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        first_name = request.form.get('first_name').strip()
        last_name = request.form.get('last_name').strip()
        email = request.form.get('email').strip()
        attending = request.form.get('attending') == 'yes'
        phone = request.form.get('phone').strip() if attending else None
        guests = request.form.get('guests').strip() if attending else None

        if not first_name or not last_name or not email:
            flash('First name, last name, and email are required.', 'danger')
            return render_template('rsvp.html', placeholder=placeholder)

        if attending:
            if not phone or not guests:
                flash('Phone number and number of guests are required if attending.', 'danger')
                return render_template('rsvp.html', placeholder=placeholder)
            if not validate_phone(phone):
                flash('Invalid phone number format.', 'danger')
                return render_template('rsvp.html', placeholder=placeholder)
            if not guests.isdigit() or int(guests) < 1:
                flash('Number of guests must be a positive integer.', 'danger')
                return render_template('rsvp.html', placeholder=placeholder)

        if RSVP.query.filter_by(first_name=first_name, last_name=last_name).first() or RSVP.query.filter_by(email=email).first():
            flash('You have already submitted your RSVP with this name or email.', 'warning')
        else:
            new_rsvp = RSVP(first_name=first_name, last_name=last_name, email=email, phone=phone, guests=int(guests) if guests else None, attending=attending)
            db.session.add(new_rsvp)
            db.session.commit()

            if admin_emails := [
                admin.email
                for admin in Admin.query.filter_by(notifications=True).all()
            ]:
                subject = "New RSVP Submission"
                body = f"A new RSVP has been submitted:\n\nName: {first_name} {last_name}\nEmail: {email}\nAttending: {'Yes' if attending else 'No'}\nPhone: {phone}\nGuests: {guests}"
                send_email(subject, body, admin_emails)

            flash('RSVP submitted successfully!', 'success')
            return redirect(url_for('index'))

    first_name = request.args.get('first_name', '')
    last_name = request.args.get('last_name', '')
    email = request.args.get('email', '')

    return render_template('rsvp.html', placeholder=placeholder, first_name=first_name, last_name=last_name, email=email)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

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

    placeholders = [
        {"first_name": "Jane", "last_name": "Doe", "email": "Jane.Doe@example.net"},
        {"first_name": "John", "last_name": "Doe", "email": "John.Doe@example.net"}
    ]
    placeholder = random.choice(placeholders)

    qr_code_url = None

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
        elif 'enable_admin' in request.form:
            admin_id = request.form.get('admin_id')
            if admin_to_enable := Admin.query.get(admin_id):
                admin_to_enable.is_active = True
                db.session.commit()
                flash(f'Admin {admin_to_enable.username} has been enabled.', 'success')
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
        elif 'toggle_notifications' in request.form:
            admin_id = request.form.get('admin_id')
            notifications = 'notifications' in request.form
            if admin_id == str(current_user.id):
                current_user.notifications = notifications
                db.session.commit()
                flash('Notification setting updated.', 'success')
        elif 'theme' in request.form:
            selected_theme = request.form.get('theme')
            if selected_theme == 'custom.css':
                custom_css = request.form.get('custom_css').strip()
                with open(os.path.join(app.config['THEMES_FOLDER'], 'custom.css'), 'w') as custom_css_file:
                    custom_css_file.write(custom_css)
                set_setting('selected_theme', 'custom.css')
                with open(os.path.join(app.config['THEMES_FOLDER'], 'custom.css'), 'r') as theme_css_file:
                    css_content = theme_css_file.read()
                with open('static/style.css', 'w') as style_css_file:
                    style_css_file.write(css_content)
            else:
                set_setting('selected_theme', selected_theme)
                with open(os.path.join(app.config['THEMES_FOLDER'], selected_theme), 'r') as theme_css_file:
                    css_content = theme_css_file.read()
                with open('static/style.css', 'w') as style_css_file:
                    style_css_file.write(css_content)
            flash('Theme updated successfully!', 'success')
    
    if rsvp_table_exists:
        attending_rsvps = RSVP.query.filter_by(attending=True).all()
        not_attending_rsvps = RSVP.query.filter_by(attending=False).all()
    else:
        attending_rsvps = []
        not_attending_rsvps = []

    admins = Admin.query.all() if admin_table_exists else []

    current_theme = get_setting('selected_theme', 'light.css')
    custom_css = ''
    if current_theme == 'custom.css':
        with open(os.path.join(app.config['THEMES_FOLDER'], 'custom.css'), 'r') as custom_css_file:
            custom_css = custom_css_file.read()

    themes = [os.path.basename(theme) for theme in glob.glob(os.path.join(app.config['THEMES_FOLDER'], '*.css'))]
    return render_template('admin_dashboard.html', attending_rsvps=attending_rsvps, not_attending_rsvps=not_attending_rsvps, admins=admins, qr_code_url=qr_code_url, placeholder=placeholder, current_theme=current_theme, custom_css=custom_css, themes=themes)

@app.route('/load_theme_css')
@login_required
def load_theme_css():
    theme = request.args.get('theme', 'light.css')
    print(f"Requested theme: {theme}")
    theme_path = os.path.join(app.config['THEMES_FOLDER'], theme)
    if os.path.isfile(theme_path):
        with open(theme_path, 'r') as theme_css_file:
            css_content = theme_css_file.read()
        return css_content, 200, {'Content-Type': 'text/css'}
    print(f"Theme path does not exist: {theme_path}")
    return '', 404

@app.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    username = request.form.get('new_admin_username').strip()
    email = request.form.get('new_admin_email').strip()
    password = request.form.get('new_admin_password').strip()

    if not username or not email or not password:
        flash('All fields are required to create a new admin.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not validate_password(password):
        flash('Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&~).', 'danger')
        return redirect(url_for('admin_dashboard'))

    existing_admin = Admin.query.filter((Admin.username == username) | (Admin.email == email)).first()
    if existing_admin:
        flash('An admin with this username or email already exists.', 'danger')
        return redirect(url_for('admin_dashboard'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_admin = Admin(username=username, email=email, password=hashed_password)
    db.session.add(new_admin)
    db.session.commit()

    flash('New admin created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/<first_name>.<last_name>')
def redirect_to_rsvp(first_name, last_name):
    return redirect(url_for('rsvp', first_name=first_name, last_name=last_name))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
