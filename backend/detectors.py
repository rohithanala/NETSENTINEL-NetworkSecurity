from collections import defaultdict, deque
import time


class DetectionEngine:
    def __init__(self, app):
        self.app = app

        # Source/destination -> deque of
        # (timestamp, destination_port)
        self.ports = defaultdict(deque)

        # Source IP -> deque of timestamps
        self.connections = defaultdict(deque)

        # Detection key -> last emitted alert timestamp
        self.last = {}

        # Prevent the cooldown dictionary from growing forever.
        self.last_cleanup = time.time()

    # ============================================================
    # QUEUE TRIMMING
    # ============================================================

    def trim(self, q, window):
        cut = time.time() - window

        while q:
            item = q[0]

            if isinstance(item, tuple):
                timestamp = item[0]
            else:
                timestamp = item

            if timestamp >= cut:
                break

            q.popleft()

    # ============================================================
    # PORT-SCAN CONFIDENCE
    # ============================================================

    def calculate_port_scan_confidence(
        self,
        unique_ports,
        threshold,
    ):
        if threshold <= 0:
            return 0.50

        excess_ratio = unique_ports / threshold

        if excess_ratio <= 1.0:
            confidence = 0.70
        elif excess_ratio <= 1.25:
            confidence = 0.74
        elif excess_ratio <= 1.50:
            confidence = 0.79
        elif excess_ratio <= 2.0:
            confidence = 0.84
        elif excess_ratio <= 3.0:
            confidence = 0.90
        else:
            confidence = 0.95

        return confidence

    # ============================================================
    # CONNECTION-RATE CONFIDENCE
    # ============================================================

    def calculate_connection_rate_confidence(
        self,
        connection_count,
        threshold,
    ):
        if threshold <= 0:
            return 0.50

        excess_ratio = connection_count / threshold

        if excess_ratio <= 1.0:
            confidence = 0.68
        elif excess_ratio <= 1.10:
            confidence = 0.71
        elif excess_ratio <= 1.25:
            confidence = 0.75
        elif excess_ratio <= 1.50:
            confidence = 0.80
        elif excess_ratio <= 2.0:
            confidence = 0.86
        elif excess_ratio <= 3.0:
            confidence = 0.91
        else:
            confidence = 0.96

        return confidence

    # ============================================================
    # ALERT COOLDOWN
    # ============================================================

    def can_emit(self, key, now):
        """
        Return True when this detection is allowed to generate
        another alert.

        The cooldown value already exists in config.py:

            ALERT_COOLDOWN_SECONDS

        This prevents the same ongoing condition from creating
        thousands of duplicate alerts.
        """

        try:
            cooldown = int(
                self.app.config.get(
                    "ALERT_COOLDOWN_SECONDS",
                    10,
                )
            )
        except (TypeError, ValueError):
            cooldown = 10

        cooldown = max(cooldown, 0)

        last_time = self.last.get(key)

        if last_time is not None:
            if now - last_time < cooldown:
                return False

        self.last[key] = now

        return True

    # ============================================================
    # COOLDOWN CACHE CLEANUP
    # ============================================================

    def cleanup_last(self, now):
        """
        Remove stale cooldown entries.

        This prevents the detection engine's cooldown dictionary
        from growing indefinitely when many different IPs are
        observed.
        """

        if now - self.last_cleanup < 60:
            return

        try:
            cooldown = int(
                self.app.config.get(
                    "ALERT_COOLDOWN_SECONDS",
                    10,
                )
            )
        except (TypeError, ValueError):
            cooldown = 10

        retention = max(
            cooldown * 2,
            60,
        )

        cutoff = now - retention

        stale_keys = [
            key
            for key, timestamp in self.last.items()
            if timestamp < cutoff
        ]

        for key in stale_keys:
            self.last.pop(key, None)

        self.last_cleanup = now

    # ============================================================
    # EVALUATION
    # ============================================================

    def evaluate(self, p):
        out = []

        now = time.time()

        self.cleanup_last(now)

        src = p.get("source_ip")
        dst = p.get("destination_ip")
        dp = p.get("destination_port")

        # ========================================================
        # PORT SCAN
        # ========================================================

        if src and dp:
            q = self.ports[(src, dst)]

            q.append(
                (
                    now,
                    dp,
                )
            )

            try:
                port_scan_window = int(
                    self.app.config.get(
                        "PORT_SCAN_WINDOW",
                        10,
                    )
                )
            except (TypeError, ValueError):
                port_scan_window = 10

            try:
                port_scan_threshold = int(
                    self.app.config.get(
                        "PORT_SCAN_THRESHOLD",
                        15,
                    )
                )
            except (TypeError, ValueError):
                port_scan_threshold = 15

            cut = now - port_scan_window

            while q and q[0][0] < cut:
                q.popleft()

            unique_ports = len(
                {
                    item[1]
                    for item in q
                }
            )

            if unique_ports >= port_scan_threshold:

                detection_key = (
                    "port_scan",
                    src,
                    dst,
                )

                if self.can_emit(
                    detection_key,
                    now,
                ):
                    confidence = (
                        self.calculate_port_scan_confidence(
                            unique_ports,
                            port_scan_threshold,
                        )
                    )

                    description = (
                        f"Potential port scan: "
                        f"{unique_ports} destination ports "
                        f"from {src}"
                    )

                    out.append(
                        (
                            "port_scan",
                            "HIGH",
                            confidence,
                            description,
                        )
                    )

        # ========================================================
        # CONNECTION RATE
        # ========================================================

        if src and dp:
            q2 = self.connections[src]

            q2.append(now)

            try:
                connection_window = int(
                    self.app.config.get(
                        "CONNECTION_RATE_WINDOW",
                        10,
                    )
                )
            except (TypeError, ValueError):
                connection_window = 10

            try:
                connection_threshold = int(
                    self.app.config.get(
                        "CONNECTION_RATE_THRESHOLD",
                        50,
                    )
                )
            except (TypeError, ValueError):
                connection_threshold = 50

            cut = now - connection_window

            while q2 and q2[0] < cut:
                q2.popleft()

            connection_count = len(q2)

            if connection_count >= connection_threshold:

                detection_key = (
                    "connection_rate",
                    src,
                )

                if self.can_emit(
                    detection_key,
                    now,
                ):
                    confidence = (
                        self.calculate_connection_rate_confidence(
                            connection_count,
                            connection_threshold,
                        )
                    )

                    description = (
                        f"High connection rate: "
                        f"{connection_count} events "
                        f"from {src}"
                    )

                    out.append(
                        (
                            "connection_rate",
                            "HIGH",
                            confidence,
                            description,
                        )
                    )

        return out