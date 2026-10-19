FROM python:3.11-slim

WORKDIR /app

# iputils-ping so the admin "test the server" tool can actually ping a host.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Create log / config / backup locations.
# NOTE (flaw #6): these are world-readable/writable.
RUN mkdir -p /var/log/notesapp /app/backups \
    && printf 'DB_PASSWORD=notesapp_pg_pw_2024\nJWT_SECRET=s3cr3t\n' > /app/config.env \
    && printf '%s\n' '-- nightly dump of users table' \
        'admin:admin123:admin' 'prof.turing:teach123:teacher' > /app/backups/users_backup.sql \
    && touch /var/log/notesapp/app.log \
    && chmod -R 0777 /var/log/notesapp /app/backups \
    && chmod 0666 /app/config.env

# Run as an unprivileged user, so code execution in the app does not mean root.
RUN useradd --system --no-create-home notesapp
USER notesapp

EXPOSE 5000

CMD ["python", "app.py"]
