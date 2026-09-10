import os
from pathlib import Path

from dotenv import load_dotenv


# ============================================================
# ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).parent

load_dotenv(BASE_DIR / ".env")


# ============================================================
# HELPERS
# ============================================================

def get_bool(
    value,
    default=False,
):
    if value is None:
        return default

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }


# ============================================================
# DATABASE URL
# ============================================================

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{BASE_DIR / 'netsentinel.db'}",
)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

class Config:

    # --------------------------------------------------------
    # Flask
    # --------------------------------------------------------

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "netsentinel-dev",
    )

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    SQLALCHEMY_DATABASE_URI = DATABASE_URL

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --------------------------------------------------------
    # SQLite engine options
    #
    # SQLite is used by the student/prototype deployment.
    #
    # timeout:
    #     Wait for a short period instead of immediately raising
    #     "database is locked".
    #
    # check_same_thread:
    #     Allows the SQLAlchemy SQLite connection layer to work
    #     correctly with NETSENTINEL background threads.
    # --------------------------------------------------------

    if DATABASE_URL.startswith(
        "sqlite:"
    ):

        SQLALCHEMY_ENGINE_OPTIONS = {
            "connect_args": {
                "timeout": 30,
                "check_same_thread": False,
            }
        }

    else:

        SQLALCHEMY_ENGINE_OPTIONS = {}

    # --------------------------------------------------------
    # NETSENTINEL MODE
    #
    # Supported:
    #
    #     LIVE
    #     DEMO
    #
    # DEMO is deliberately the safe default for deployment.
    # Local LIVE capture should be explicitly enabled.
    # --------------------------------------------------------

    NETSENTINEL_MODE = os.getenv(
        "NETSENTINEL_MODE",
        os.getenv(
            "MONITOR_MODE",
            "DEMO",
        ),
    ).strip().upper()

    if NETSENTINEL_MODE not in {
        "LIVE",
        "DEMO",
        "SIMULATION",
        "TEST",
        "PRODUCTION",
        "REAL",
    }:

        NETSENTINEL_MODE = "DEMO"

    # Compatibility aliases

    MODE = NETSENTINEL_MODE

    MONITOR_MODE = NETSENTINEL_MODE

    # --------------------------------------------------------
    # Monitoring
    #
    # IMPORTANT:
    #
    # Render should explicitly use:
    #
    #     MONITORING_ENABLED=false
    #
    # This prevents accidental live capture.
    # --------------------------------------------------------

    MONITOR_INTERFACE = os.getenv(
        "MONITOR_INTERFACE",
        "",
    ).strip()

    MONITORING_ENABLED = get_bool(
        os.getenv(
            "MONITORING_ENABLED",
            "false",
        ),
        default=False,
    )

    # --------------------------------------------------------
    # Capture batching
    #
    # Background packet capture should NOT commit every packet.
    # --------------------------------------------------------

    CAPTURE_BATCH_SIZE = int(
        os.getenv(
            "CAPTURE_BATCH_SIZE",
            "25",
        )
    )

    CAPTURE_BATCH_FLUSH_SECONDS = float(
        os.getenv(
            "CAPTURE_BATCH_FLUSH_SECONDS",
            "1.0",
        )
    )

    # --------------------------------------------------------
    # Port scan detection
    # --------------------------------------------------------

    PORT_SCAN_WINDOW = int(
        os.getenv(
            "PORT_SCAN_WINDOW",
            "10",
        )
    )

    PORT_SCAN_THRESHOLD = int(
        os.getenv(
            "PORT_SCAN_THRESHOLD",
            "15",
        )
    )

    # --------------------------------------------------------
    # Connection-rate detection
    # --------------------------------------------------------

    CONNECTION_RATE_WINDOW = int(
        os.getenv(
            "CONNECTION_RATE_WINDOW",
            "10",
        )
    )

    CONNECTION_RATE_THRESHOLD = int(
        os.getenv(
            "CONNECTION_RATE_THRESHOLD",
            "50",
        )
    )

    # --------------------------------------------------------
    # Alert cooldown
    # --------------------------------------------------------

    ALERT_COOLDOWN_SECONDS = int(
        os.getenv(
            "ALERT_COOLDOWN_SECONDS",
            "10",
        )
    )