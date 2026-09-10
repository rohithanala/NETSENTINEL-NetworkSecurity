from flask import Flask
from flask_socketio import SocketIO
from sqlalchemy import inspect, text

from backend.models import db


socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="threading",
)


# ============================================================
# DATABASE MIGRATION
# ============================================================

def migrate_client_isolation(app):
    """
    Safely migrate the existing NETSENTINEL database to
    client-isolated telemetry.

    Migration goals:

        1. Add client_id to traffic.
        2. Add client_id to alerts.
        3. Add client_id to devices.
        4. Preserve existing telemetry.
        5. Existing records use client_id='legacy'.
        6. Change devices uniqueness from:

               (ip_address, is_demo)

           to:

               (ip_address, client_id, is_demo)

        7. Create the required client-isolation indexes.
    """

    with app.app_context():

        inspector = inspect(
            db.engine
        )

        dialect = db.engine.dialect.name

        # ====================================================
        # VERIFY REQUIRED TABLES
        # ====================================================

        existing_tables = set(
            inspector.get_table_names()
        )

        required_tables = {
            "traffic",
            "alerts",
            "devices",
        }

        missing_tables = (
            required_tables
            - existing_tables
        )

        if missing_tables:
            raise RuntimeError(
                "NETSENTINEL database migration cannot continue. "
                f"Missing tables: {sorted(missing_tables)}"
            )

        # ====================================================
        # TRAFFIC — ADD CLIENT_ID
        # ====================================================

        traffic_columns = {
            column["name"]
            for column in inspector.get_columns(
                "traffic"
            )
        }

        if "client_id" not in traffic_columns:

            db.session.execute(
                text(
                    """
                    ALTER TABLE traffic
                    ADD COLUMN client_id
                    VARCHAR(128)
                    NOT NULL
                    DEFAULT 'legacy'
                    """
                )
            )

            db.session.commit()

        # ====================================================
        # ALERTS — ADD CLIENT_ID
        # ====================================================

        inspector = inspect(
            db.engine
        )

        alert_columns = {
            column["name"]
            for column in inspector.get_columns(
                "alerts"
            )
        }

        if "client_id" not in alert_columns:

            db.session.execute(
                text(
                    """
                    ALTER TABLE alerts
                    ADD COLUMN client_id
                    VARCHAR(128)
                    NOT NULL
                    DEFAULT 'legacy'
                    """
                )
            )

            db.session.commit()

        # ====================================================
        # DEVICES — ADD CLIENT_ID
        # ====================================================

        inspector = inspect(
            db.engine
        )

        device_columns = {
            column["name"]
            for column in inspector.get_columns(
                "devices"
            )
        }

        if "client_id" not in device_columns:

            db.session.execute(
                text(
                    """
                    ALTER TABLE devices
                    ADD COLUMN client_id
                    VARCHAR(128)
                    NOT NULL
                    DEFAULT 'legacy'
                    """
                )
            )

            db.session.commit()

        # ====================================================
        # FIX DEVICES UNIQUE CONSTRAINT
        # ====================================================

        inspector = inspect(
            db.engine
        )

        unique_constraints = (
            inspector.get_unique_constraints(
                "devices"
            )
        )

        old_constraint_exists = False

        for constraint in unique_constraints:

            columns = constraint.get(
                "column_names",
                [],
            )

            normalized_columns = [
                str(column)
                for column in columns
            ]

            if normalized_columns == [
                "ip_address",
                "is_demo",
            ]:

                old_constraint_exists = True

                break

        # ====================================================
        # SQLITE DEVICE TABLE REBUILD
        # ====================================================

        if (
            dialect == "sqlite"
            and old_constraint_exists
        ):

            db.session.execute(
                text(
                    "PRAGMA foreign_keys=OFF"
                )
            )

            db.session.commit()

            try:

                db.session.execute(
                    text(
                        """
                        DROP TABLE IF EXISTS
                        devices_client_isolation_backup
                        """
                    )
                )

                db.session.commit()

                db.session.execute(
                    text(
                        """
                        ALTER TABLE devices
                        RENAME TO
                        devices_client_isolation_backup
                        """
                    )
                )

                db.session.commit()

                connection = db.engine.connect()

                try:

                    index_rows = connection.execute(
                        text(
                            """
                            PRAGMA index_list(
                                devices_client_isolation_backup
                            )
                            """
                        )
                    ).fetchall()

                finally:

                    connection.close()

                for index_row in index_rows:

                    index_name = str(
                        index_row[1]
                    )

                    origin = (
                        str(index_row[3])
                        if len(index_row) > 3
                        else ""
                    )

                    if origin == "u":
                        continue

                    if index_name.startswith(
                        "sqlite_autoindex_"
                    ):
                        continue

                    db.session.execute(
                        text(
                            f'DROP INDEX IF EXISTS "{index_name}"'
                        )
                    )

                db.session.commit()

                db.create_all()

                db.session.execute(
                    text(
                        """
                        INSERT INTO devices (
                            id,
                            ip_address,
                            mac_address,
                            hostname,
                            first_seen,
                            last_seen,
                            packet_count,
                            status,
                            client_id,
                            is_demo
                        )
                        SELECT
                            id,
                            ip_address,
                            mac_address,
                            hostname,
                            first_seen,
                            last_seen,
                            packet_count,
                            status,
                            client_id,
                            is_demo
                        FROM devices_client_isolation_backup
                        """
                    )
                )

                db.session.commit()

                db.session.execute(
                    text(
                        """
                        DROP TABLE
                        devices_client_isolation_backup
                        """
                    )
                )

                db.session.commit()

            except Exception:

                db.session.rollback()

                recovery_inspector = inspect(
                    db.engine
                )

                recovery_tables = set(
                    recovery_inspector.get_table_names()
                )

                if (
                    "devices" not in recovery_tables
                    and
                    "devices_client_isolation_backup"
                    in recovery_tables
                ):

                    db.session.execute(
                        text(
                            """
                            ALTER TABLE
                            devices_client_isolation_backup
                            RENAME TO devices
                            """
                        )
                    )

                    db.session.commit()

                raise

            finally:

                db.session.execute(
                    text(
                        "PRAGMA foreign_keys=ON"
                    )
                )

                db.session.commit()

        # ====================================================
        # POSTGRESQL / OTHER DATABASES
        # ====================================================

        elif (
            dialect != "sqlite"
            and old_constraint_exists
        ):

            inspector = inspect(
                db.engine
            )

            old_constraint_names = []

            for constraint in (
                inspector.get_unique_constraints(
                    "devices"
                )
            ):

                columns = constraint.get(
                    "column_names",
                    [],
                )

                normalized_columns = [
                    str(column)
                    for column in columns
                ]

                if normalized_columns == [
                    "ip_address",
                    "is_demo",
                ]:

                    constraint_name = (
                        constraint.get(
                            "name"
                        )
                    )

                    if constraint_name:
                        old_constraint_names.append(
                            constraint_name
                        )

            for constraint_name in old_constraint_names:

                db.session.execute(
                    text(
                        f"""
                        ALTER TABLE devices
                        DROP CONSTRAINT
                        "{constraint_name}"
                        """
                    )
                )

            if old_constraint_names:
                db.session.commit()

            inspector = inspect(
                db.engine
            )

            new_unique_exists = False

            for constraint in (
                inspector.get_unique_constraints(
                    "devices"
                )
            ):

                columns = constraint.get(
                    "column_names",
                    [],
                )

                normalized_columns = [
                    str(column)
                    for column in columns
                ]

                if normalized_columns == [
                    "ip_address",
                    "client_id",
                    "is_demo",
                ]:

                    new_unique_exists = True

                    break

            if not new_unique_exists:

                db.session.execute(
                    text(
                        """
                        ALTER TABLE devices
                        ADD CONSTRAINT
                        uq_devices_ip_client_mode
                        UNIQUE (
                            ip_address,
                            client_id,
                            is_demo
                        )
                        """
                    )
                )

                db.session.commit()

        # ====================================================
        # PERFORMANCE INDEXES
        # ====================================================

        indexes = [

            (
                "ix_traffic_client_demo_timestamp",
                """
                CREATE INDEX IF NOT EXISTS
                ix_traffic_client_demo_timestamp
                ON traffic (
                    client_id,
                    is_demo,
                    timestamp
                )
                """,
            ),

            (
                "ix_traffic_protocol_client_demo",
                """
                CREATE INDEX IF NOT EXISTS
                ix_traffic_protocol_client_demo
                ON traffic (
                    protocol,
                    client_id,
                    is_demo
                )
                """,
            ),

            (
                "ix_alerts_client_demo_timestamp",
                """
                CREATE INDEX IF NOT EXISTS
                ix_alerts_client_demo_timestamp
                ON alerts (
                    client_id,
                    is_demo,
                    timestamp
                )
                """,
            ),

            (
                "ix_alerts_severity_client_demo",
                """
                CREATE INDEX IF NOT EXISTS
                ix_alerts_severity_client_demo
                ON alerts (
                    severity,
                    client_id,
                    is_demo
                )
                """,
            ),

            (
                "ix_devices_client_demo_last_seen",
                """
                CREATE INDEX IF NOT EXISTS
                ix_devices_client_demo_last_seen
                ON devices (
                    client_id,
                    is_demo,
                    last_seen
                )
                """,
            ),

        ]

        for (
            index_name,
            create_statement,
        ) in indexes:

            db.session.execute(
                text(
                    create_statement
                )
            )

        db.session.commit()

        # ====================================================
        # FINAL VERIFICATION
        # ====================================================

        inspector = inspect(
            db.engine
        )

        traffic_columns = {
            column["name"]
            for column in inspector.get_columns(
                "traffic"
            )
        }

        alert_columns = {
            column["name"]
            for column in inspector.get_columns(
                "alerts"
            )
        }

        device_columns = {
            column["name"]
            for column in inspector.get_columns(
                "devices"
            )
        }

        required_columns = {

            "traffic": (
                "client_id"
                in traffic_columns
            ),

            "alerts": (
                "client_id"
                in alert_columns
            ),

            "devices": (
                "client_id"
                in device_columns
            ),

        }

        if not all(
            required_columns.values()
        ):

            raise RuntimeError(
                "NETSENTINEL client isolation migration failed: "
                f"{required_columns}"
            )

        # ====================================================
        # VERIFY DEVICE OWNERSHIP CONSTRAINT
        # ====================================================

        device_unique_constraints = (
            inspector.get_unique_constraints(
                "devices"
            )
        )

        ownership_constraint_exists = False

        for constraint in device_unique_constraints:

            columns = constraint.get(
                "column_names",
                [],
            )

            normalized_columns = [
                str(column)
                for column in columns
            ]

            if normalized_columns == [
                "ip_address",
                "client_id",
                "is_demo",
            ]:

                ownership_constraint_exists = True

                break

        if not ownership_constraint_exists:

            if dialect == "sqlite":

                schema_row = (
                    db.session.execute(
                        text(
                            """
                            SELECT sql
                            FROM sqlite_master
                            WHERE type='table'
                            AND name='devices'
                            """
                        )
                    )
                    .first()
                )

                schema_sql = (
                    str(schema_row[0])
                    if schema_row
                    else ""
                )

                ownership_constraint_exists = (
                    "client_id" in schema_sql
                    and
                    "ip_address" in schema_sql
                    and
                    "is_demo" in schema_sql
                )

        if not ownership_constraint_exists:

            raise RuntimeError(
                "NETSENTINEL client isolation migration failed: "
                "ownership-aware devices uniqueness constraint "
                "was not verified."
            )


# ============================================================
# APPLICATION FACTORY
# ============================================================

def create_app():

    app = Flask(
        __name__,
        static_folder="../static",
        template_folder="../templates",
    )

    app.config.from_object(
        "config.Config"
    )

    # ========================================================
    # DATABASE
    # ========================================================

    db.init_app(
        app
    )

    # ========================================================
    # SOCKET.IO
    # ========================================================

    socketio.init_app(
        app
    )

    # ========================================================
    # API
    # ========================================================

    from backend.routes import api

    app.register_blueprint(
        api,
        url_prefix="/api",
    )

    # ========================================================
    # PAGE ROUTES
    # ========================================================

    from backend.pages import pages

    app.register_blueprint(
        pages
    )

    # ========================================================
    # DATABASE TABLES
    # ========================================================

    with app.app_context():

        db.create_all()

    # ========================================================
    # CLIENT ISOLATION MIGRATION
    # ========================================================

    migrate_client_isolation(
        app
    )

    # ========================================================
    # CAPTURE / DEMO
    #
    # IMPORTANT:
    #
    # Never start packet generation/capture when monitoring
    # is explicitly disabled.
    # ========================================================

    from backend.capture import (
        start_capture_if_enabled,
    )

    monitoring_enabled = app.config.get(
        "MONITORING_ENABLED",
        False,
    )

    if isinstance(
        monitoring_enabled,
        str,
    ):

        monitoring_enabled = (
            monitoring_enabled.strip().lower()
            in {
                "1",
                "true",
                "yes",
                "on",
                "enabled",
            }
        )

    if monitoring_enabled:

        start_capture_if_enabled(
            app=app,
            socketio=socketio,
        )

    return app