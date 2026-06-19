import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Bind to localhost:5000 in debug mode for development
    app.run(host='127.0.0.1', port=5000, debug=True)
