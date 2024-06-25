#!/usr/bin/env python3
import re
import getpass
from app import app, db, Admin
from werkzeug.security import generate_password_hash

def validate_password(password):
    return bool(
        len(password) >= 8
        and re.search(r'[A-Z]', password)
        and re.search(r'[a-z]', password)
        and re.search(r'[0-9]', password)
        and re.search(r'[@$!%*?&~]', password)
    )

def create_admin(username, email, password, notifications=True):
    if Admin.query.filter_by(username=username).first():
        print(f"Username '{username}' already exists. Please choose a different username.")
        return False
    if Admin.query.filter_by(email=email).first():
        print(f"Email '{email}' already exists. Please choose a different email.")
        return False
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    admin = Admin(username=username, email=email, password=hashed_password, notifications=notifications)
    db.session.add(admin)
    db.session.commit()
    return True

if __name__ == '__main__':
    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    
    while True:
        password = getpass.getpass("Enter admin password: ")
        confirm_password = getpass.getpass("Confirm admin password: ")
        
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        
        if not validate_password(password):
            print("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&~). Please try again.")
            continue
        
        break
    
    with app.app_context():
        if create_admin(username, email, password):
            print("Admin user created successfully!")
        else:
            print("Failed to create admin user.")
