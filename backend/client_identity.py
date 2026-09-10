"""
NETSENTINEL — Client identity helpers.

Provides a stable client namespace for browser/sensor requests.

The client ID is an ownership namespace only.
It is NOT an authentication credential.
"""

import re
import uuid

from flask import request


CLIENT_ID_HEADER = "X-NETSENTINEL-CLIENT-ID"

DEFAULT_CLIENT_ID = "legacy"


def normalize_client_id(value: str | None) -> str:
    """
    Return a safe, bounded client identifier.
    """

    value = str(
        value or ""
    ).strip()

    if not value:
        return DEFAULT_CLIENT_ID

    value = re.sub(
        r"[^A-Za-z0-9._:-]",
        "",
        value,
    )

    if not value:
        return DEFAULT_CLIENT_ID

    return value[:128]


def get_request_client_id() -> str:
    """
    Read the client namespace from the current request.

    Header has priority.

    Query-string fallback:
        /api/traffic?client_id=client-xxxx
    """

    value = request.headers.get(
        CLIENT_ID_HEADER
    )

    if not value:
        value = request.args.get(
            "client_id"
        )

    return normalize_client_id(
        value
    )


def new_client_id() -> str:
    """
    Generate a new unique client ID.
    """

    return (
        f"client-{uuid.uuid4().hex}"
    )