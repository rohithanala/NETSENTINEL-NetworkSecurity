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

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    db.init_app(app)

    # --------------------------------------------------------
    # SOCKET.IO
    # --------------------------------------------------------

    socketio.init_app(app)

    # --------------------------------------------------------
    # API
    # --------------------------------------------------------

    from backend.routes import api

    app.register_blueprint(
        api,
        url_prefix="/api",
    )

    # --------------------------------------------------------
    # PAGE ROUTES
    # --------------------------------------------------------

    from backend.pages import pages

    app.register_blueprint(
        pages
    )

    # --------------------------------------------------------
    # DATABASE TABLES
    # --------------------------------------------------------

    with app.app_context():
        db.create_all()

    # --------------------------------------------------------
    # CAPTURE / DEMO
    # --------------------------------------------------------

    from backend.capture import (
        start_capture_if_enabled,
    )

    start_capture_if_enabled(
        app=app,
        socketio=socketio,
    )

    return app