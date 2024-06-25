# RSVP Flask
A simple RSVP website built using Flask.

Currently supports up to 5 gift registries.

Theming and email notifications coming soon.

Admin Endpoint: app_URL/admin (127.0.0.1:5000/admin)

### Create Admin, Configure, Run

```bash
cd app
cp .env.example .env
nano .env
python init_db.py
python create_admin.py
python app.py
```

## Docker

### Build

```bash
docker build -t rsvp .
```

### Run

```bash
docker volume create rsvp_data
docker run -d -p 5000:5000 --name rsvp \
--restart unless-stopped \
-e RSVP_TITLE="My Wedding" \
-e RSVP_HEADER="Welcome to Our Wedding RSVP" \
-e RSVP_SUBHEADER="Please let us know if you can join us" \
-e RSVP_DESCRIPTION=Please fill out the form below to RSVP \
-e RSVP_SQLKEY=ChangeMe \
-e RSVP_DATABASE_URI=sqlite:///rsvp.db \
-e RSVP_REGISTRY1="Amazon|http://example.com/registry1" \
-e RSVP_REGISTRY2="Target|http://example.com/registry2" \
-e RSVP_REGISTRY3="Walmart|http://example.com/registry3" \
-e RSVP_REGISTRY4="Bed Bath & Beyond|http://example.com/registry4" \
-e RSVP_REGISTRY5="Crate & Barrel|http://example.com/registry5" \
-e RSVP_SMTP_SERVER="smtp.example.com" \
-e RSVP_SMTP_PORT="587" \
-e RSVP_SMTP_USERNAME="your_smtp_username" \
-e RSVP_SMTP_PASSWORD="your_smtp_password" \
-e RSVP_SMTP_FROM_ADDRESS="from@example.com" \
-v rsvp_data:/app/instance \
rsvp
```

### Create Admin User

```bash
docker exec -it rsvp python /app/create_admin.py
```