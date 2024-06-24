#!/bin/sh

echo "Initializing the database..."
python /app/init_db.py
if [ $? -eq 0 ]; then
    echo "Database initialized successfully."
else
    echo "Database initialization failed."
    exit 1
fi

exec flask run --host=0.0.0.0
