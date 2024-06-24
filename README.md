# RSVP Flask
A simple RSVP website built using Flask.

Currently supports up to 5 gift registries.

Theming and email notifications coming soon.

### Build

```bash
docker build -t rsvp .
```

### Run

```bash
docker volume create rsvp_data
docker run -d -p 5000:5000 --name rsvp_test \
-e RSVP_TITLE="My Wedding" \
-e RSVP_HEADER="Welcome to Our Wedding RSVP" \
-e RSVP_SUBHEADER="Please let us know if you can join us" \
-e RSVP_SQLKEY=ChangeMe \
-e RSVP_DATABASE_URI=sqlite:///rsvp.db \
-e RSVP_REGISTRY1="Amazon|http://example.com/registry1" \
-e RSVP_REGISTRY2="Target|http://example.com/registry2" \
-e RSVP_REGISTRY3="Walmart|http://example.com/registry3" \
-e RSVP_REGISTRY4="Bed Bath & Beyond|http://example.com/registry4" \
-e RSVP_REGISTRY5="Crate & Barrel|http://example.com/registry5" \
-v rsvp_data:/app/instance \
rsvp
```