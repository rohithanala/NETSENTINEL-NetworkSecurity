from flask import Flask
from flask_socketio import SocketIO

from backend.models import db


socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="threading",
)


def create_app():
    app = Flask(
        __name__,
        static_folder="../static",
        template_folder="../templates",
    )

    app.config.from_object("config.Config")

    # Initialize the SAME SQLAlchemy instance used by all models.
    db.init_app(app)

    # Initialize Socket.IO.
    socketio.init_app(app)

    # Register API routes.
    from backend.routes import api

    app.register_blueprint(
        api,
        url_prefix="/api",
    )

    # Register page routes.
    from backend.pages import pages

    app.register_blueprint(pages)

    # Create database tables.
    with app.app_context():
        db.create_all()

    # Start packet capture if LIVE mode is enabled.
    from backend.capture import start_capture_if_enabled

    start_capture_if_enabled(app)

    return app