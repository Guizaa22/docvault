"""Create the database schema in whatever DATABASE the app is configured for."""
from app import create_app
from app.db import init_db

app = create_app()
with app.app_context():
    init_db()
print("Database initialized.")
