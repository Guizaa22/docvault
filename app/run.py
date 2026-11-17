import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # The Werkzeug debugger allows code execution: never on by default. Local opt-in only.
    app.run(debug=os.environ.get("DOCVAULT_DEBUG") == "1")
