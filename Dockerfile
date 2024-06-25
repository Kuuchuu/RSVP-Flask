FROM python:3.11-slim

WORKDIR /app

COPY app /app

RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]