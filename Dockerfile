FROM python:3.11-slim

WORKDIR /app

COPY app /app

RUN pip install --no-cache-dir -r requirements.txt

RUN python -c 'from app import db; db.create_all()'

EXPOSE 5000

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["flask", "run"]
