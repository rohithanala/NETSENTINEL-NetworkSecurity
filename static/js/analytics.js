/* ============================================================
   NETSENTINEL - ANALYTICS
   Real-time traffic, protocol, security and network analytics
   ============================================================ */

(() => {
    "use strict";

    console.log("NETSENTINEL: Initializing analytics...");


    /* ============================================================
       STATE
       ============================================================ */

    const state = {
        range: "5m",

        traffic: [],
        alerts: [],
        devices: [],
        analytics: {},
        stats: {},

        liveHistory: [],
        historicalHistory: [],

        lastTrafficId: 0,
        lastUpdate: null,

        trafficTimer: null,
        refreshTimer: null,

        initialized: false,
        loading: false
    };


    /* ============================================================
       DOM HELPERS
       ============================================================ */

    function $(id) {
        return document.getElementById(id);
    }

    function setText(id, value) {
        const element = $(id);

        if (element) {
            element.textContent = value;
        }
    }

    function showElement(id, display = "") {
        const element = $(id);

        if (element) {
            element.style.display = display;
        }
    }

    function hideElement(id) {
        const element = $(id);

        if (element) {
            element.style.display = "none";
        }
    }


    /* ============================================================
       ERROR HANDLING
       ============================================================ */

    function showError(message) {
        const element = $("analyticsError");

        if (!element) {
            console.error(
                "NETSENTINEL Analytics:",
                message
            );
            return;
        }

        element.textContent =
            message ||
            "Unable to load analytics data.";

        element.style.display = "block";
    }

    function hideError() {
        const element =
            $("analyticsError");

        if (element) {
            element.textContent = "";
            element.style.display = "none";
        }
    }


    /* ============================================================
       API HELPER
       ============================================================ */

    async function api(url) {
        const separator =
            url.includes("?")
                ? "&"
                : "?";

        const response =
            await fetch(
                `${url}${separator}_=${Date.now()}`,
                {
                    cache: "no-store",
                    headers: {
                        "Accept":
                            "application/json"
                    }
                }
            );

        if (!response.ok) {
            throw new Error(
                `${response.status} ${response.statusText}`
            );
        }

        return await response.json();
    }


    /* ============================================================
       NUMBER HELPERS
       ============================================================ */

    function number(value, fallback = 0) {
        const parsed =
            Number(value);

        return Number.isFinite(parsed)
            ? parsed
            : fallback;
    }

    function integer(value, fallback = 0) {
        return Math.round(
            number(value, fallback)
        );
    }

    function formatNumber(value) {
        return integer(value)
            .toLocaleString("en-IN");
    }

    function formatBytes(value) {
        const bytes =
            number(value);

        if (bytes < 1024) {
            return `${Math.round(bytes)} B`;
        }

        if (bytes < 1024 * 1024) {
            return `${(
                bytes / 1024
            ).toFixed(1)} KB`;
        }

        if (
            bytes <
            1024 * 1024 * 1024
        ) {
            return `${(
                bytes /
                (1024 * 1024)
            ).toFixed(1)} MB`;
        }

        return `${(
            bytes /
            (1024 * 1024 * 1024)
        ).toFixed(2)} GB`;
    }

    function formatRate(value) {
        const rate =
            number(value);

        if (rate >= 1000000) {
            return `${(
                rate / 1000000
            ).toFixed(1)}M`;
        }

        if (rate >= 1000) {
            return `${(
                rate / 1000
            ).toFixed(1)}K`;
        }

        return `${Math.round(rate)}`;
    }


    /* ============================================================
       TIME HELPERS
       IMPORTANT:
       Backend timestamps are naive ISO timestamps representing UTC.
       Example:
       2026-09-09T09:44:00.498362

       JavaScript otherwise interprets this as local IST time.
       ============================================================ */

    function parseTime(value) {
        if (!value) {
            return null;
        }

        let text =
            String(value).trim();

        /*
         * Backend timestamps may contain:
         *
         * 2026-09-09T09:44:00.498362
         *
         * with no timezone.
         *
         * Treat timezone-less ISO timestamps as UTC.
         */

        if (
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(
                text
            ) &&
            !/[zZ]$/.test(text) &&
            !/[+-]\d{2}:\d{2}$/.test(text)
        ) {
            text += "Z";
        }

        const timestamp =
            new Date(text).getTime();

        return Number.isFinite(timestamp)
            ? timestamp
            : null;
    }


    function rangeMilliseconds() {
        switch (state.range) {
            case "15m":
                return (
                    15 *
                    60 *
                    1000
                );

            case "1h":
                return (
                    60 *
                    60 *
                    1000
                );

            case "all":
                return Infinity;

            case "5m":
            default:
                return (
                    5 *
                    60 *
                    1000
                );
        }
    }


    function rangeLabel() {
        switch (state.range) {
            case "15m":
                return "15 MIN";

            case "1h":
                return "1 HOUR";

            case "all":
                return "ALL";

            case "5m":
            default:
                return "5 MIN";
        }
    }


    /* ============================================================
       PROTOCOL NORMALIZATION
       ============================================================ */

    function normalizeProtocol(protocol) {
        if (!protocol) {
            return "OTHER";
        }

        const value =
            String(protocol)
                .trim()
                .toUpperCase();

        if (
            value.includes("TCP")
        ) {
            return "TCP";
        }

        if (
            value.includes("UDP")
        ) {
            return "UDP";
        }

        if (
            value.includes("ICMP")
        ) {
            return "ICMP";
        }

        if (
            value.includes("IPV6") ||
            value === "IP6"
        ) {
            return "IPv6";
        }

        return "OTHER";
    }


    /* ============================================================
       SEVERITY NORMALIZATION
       ============================================================ */

    function normalizeSeverity(severity) {
        const value =
            String(
                severity || ""
            )
                .trim()
                .toUpperCase();

        if (value === "CRITICAL") {
            return "CRITICAL";
        }

        if (value === "HIGH") {
            return "HIGH";
        }

        if (value === "MEDIUM") {
            return "MEDIUM";
        }

        return "LOW";
    }


    /* ============================================================
       TRAFFIC RANGE FILTER
       ============================================================ */

    function trafficInRange(record) {
        if (
            state.range === "all"
        ) {
            return true;
        }

        const timestamp =
            parseTime(
                record.timestamp
            );

        if (
            timestamp === null
        ) {
            return true;
        }

        return (
            Date.now() -
                timestamp <=
            rangeMilliseconds()
        );
    }


    function getRangeTraffic() {
        return state.traffic.filter(
            trafficInRange
        );
    }


    /* ============================================================
       ALERT RANGE FILTER
       ============================================================ */

    function alertTimestamp(alert) {
        return (
            alert.timestamp ||
            alert.created_at ||
            alert.createdAt ||
            alert.time ||
            alert.detected_at
        );
    }


    function alertInRange(alert) {
        if (
            state.range === "all"
        ) {
            return true;
        }

        const timestamp =
            parseTime(
                alertTimestamp(alert)
            );

        if (
            timestamp === null
        ) {
            return true;
        }

        return (
            Date.now() -
                timestamp <=
            rangeMilliseconds()
        );
    }


    function getRangeAlerts() {
        return state.alerts.filter(
            alertInRange
        );
    }


    /* ============================================================
       TRAFFIC METRICS
       ============================================================ */

    function calculateTrafficMetrics(
        records
    ) {
        if (!records.length) {
            return {
                packets: 0,
                bytes: 0,
                packetsPerSecond: 0,
                bytesPerSecond: 0,
                averagePacketSize: 0,
                peakPacketsPerSecond: 0
            };
        }

        let bytes = 0;

        records.forEach(
            record => {
                bytes += number(
                    record.packet_size
                );
            }
        );

        const timestamps =
            records
                .map(
                    record =>
                        parseTime(
                            record.timestamp
                        )
                )
                .filter(
                    value =>
                        value !== null
                )
                .sort(
                    (a, b) =>
                        a - b
                );

        let durationSeconds = 1;

        if (
            timestamps.length > 1
        ) {
            durationSeconds =
                Math.max(
                    1,
                    (
                        timestamps[
                            timestamps.length - 1
                        ] -
                        timestamps[0]
                    ) / 1000
                );
        }

        const packetsPerSecond =
            records.length /
            durationSeconds;

        const bytesPerSecond =
            bytes /
            durationSeconds;

        const averagePacketSize =
            bytes /
            records.length;

        return {
            packets:
                records.length,

            bytes,

            packetsPerSecond,

            bytesPerSecond,

            averagePacketSize,

            peakPacketsPerSecond:
                calculatePeakRate(
                    records
                )
        };
    }


    function calculatePeakRate(
        records
    ) {
        if (!records.length) {
            return 0;
        }

        const buckets =
            new Map();

        records.forEach(
            record => {
                const timestamp =
                    parseTime(
                        record.timestamp
                    );

                if (
                    timestamp === null
                ) {
                    return;
                }

                const second =
                    Math.floor(
                        timestamp / 1000
                    );

                buckets.set(
                    second,
                    (
                        buckets.get(
                            second
                        ) || 0
                    ) + 1
                );
            }
        );

        if (!buckets.size) {
            return 0;
        }

        return Math.max(
            ...Array.from(
                buckets.values()
            )
        );
    }


    /* ============================================================
       PROTOCOL ANALYTICS
       ============================================================ */

    function calculateProtocols(
        records
    ) {
        const result = {
            TCP: 0,
            UDP: 0,
            ICMP: 0,
            IPv6: 0,
            OTHER: 0
        };

        records.forEach(
            record => {
                const protocol =
                    normalizeProtocol(
                        record.protocol
                    );

                result[protocol]++;
            }
        );

        return result;
    }


    function protocolFromAnalytics() {
        const source =
            state.analytics
                .protocol_distribution ||
            state.analytics.protocols ||
            {};

        const result = {
            TCP: 0,
            UDP: 0,
            ICMP: 0,
            IPv6: 0,
            OTHER: 0
        };

        Object.entries(
            source
        ).forEach(
            ([key, value]) => {
                const protocol =
                    normalizeProtocol(
                        key
                    );

                result[protocol] +=
                    number(value);
            }
        );

        return result;
    }


    /* ============================================================
       SECURITY ANALYTICS
       ============================================================ */

    function calculateSeverities(
        alerts
    ) {
        const result = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0
        };

        alerts.forEach(
            alert => {
                const severity =
                    normalizeSeverity(
                        alert.severity
                    );

                result[severity]++;
            }
        );

        return result;
    }


    function severityFromAnalytics() {
        const source =
            state.analytics.severity ||
            state.analytics.severities ||
            state.analytics.alert_severity ||
            {};

        return {
            CRITICAL:
                number(
                    source.CRITICAL ??
                    source.critical
                ),

            HIGH:
                number(
                    source.HIGH ??
                    source.high
                ),

            MEDIUM:
                number(
                    source.MEDIUM ??
                    source.medium
                ),

            LOW:
                number(
                    source.LOW ??
                    source.low
                )
        };
    }


    /* ============================================================
       TOP IP ANALYTICS
       ============================================================ */

    function calculateTopIps(
        records,
        field
    ) {
        const map =
            new Map();

        records.forEach(
            record => {
                const ip =
                    record[field];

                if (!ip) {
                    return;
                }

                map.set(
                    ip,
                    (
                        map.get(ip) ||
                        0
                    ) + 1
                );
            }
        );

        return Array.from(
            map.entries()
        )
            .map(
                ([ip, packets]) => ({
                    ip,
                    packets
                })
            )
            .sort(
                (a, b) =>
                    b.packets -
                    a.packets
            )
            .slice(0, 10);
    }


    /* ============================================================
       TOP PORT ANALYTICS
       ============================================================ */

    function calculateTopPorts(
        records
    ) {
        const map =
            new Map();

        records.forEach(
            record => {
                const port =
                    record.destination_port ??
                    record.source_port;

                if (
                    port === null ||
                    port === undefined
                ) {
                    return;
                }

                const key =
                    String(port);

                map.set(
                    key,
                    (
                        map.get(key) ||
                        0
                    ) + 1
                );
            }
        );

        return Array.from(
            map.entries()
        )
            .map(
                ([port, packets]) => ({
                    port,
                    packets
                })
            )
            .sort(
                (a, b) =>
                    b.packets -
                    a.packets
            )
            .slice(0, 10);
    }


    /* ============================================================
       DEVICE COUNT
       ============================================================ */

    function calculateDeviceCount() {
        if (
            Array.isArray(
                state.devices
            ) &&
            state.devices.length
        ) {
            const unique =
                new Set();

            state.devices.forEach(
                device => {
                    const value =
                        device.ip_address ||
                        device.ip ||
                        device.mac_address ||
                        device.mac ||
                        device.hostname;

                    if (value) {
                        unique.add(
                            value
                        );
                    }
                }
            );

            if (
                unique.size
            ) {
                return unique.size;
            }
        }

        return number(
            state.stats.active_devices,
            number(
                state.analytics.devices
            )
        );
    }


    /* ============================================================
       LIVE SAMPLE
       ============================================================ */

    function collectLiveSample() {
        const traffic =
            Array.isArray(
                state.traffic
            )
                ? state.traffic
                : [];

        const now =
            Date.now();

        const oneSecondAgo =
            now - 1000;

        const recent =
            traffic.filter(
                record => {
                    const timestamp =
                        parseTime(
                            record.timestamp
                        );

                    return (
                        timestamp !== null &&
                        timestamp >=
                            oneSecondAgo &&
                        timestamp <=
                            now + 2000
                    );
                }
            );

        const packets =
            recent.length;

        let bytes = 0;

        recent.forEach(
            record => {
                bytes += number(
                    record.packet_size
                );
            }
        );

        state.liveHistory.push({
            time: now,
            packets,
            bytes
        });

        const historyWindow =
            state.range === "all"
                ? 10 * 60 * 1000
                : Math.max(
                    10 * 60 * 1000,
                    rangeMilliseconds()
                );

        const cutoff =
            now -
            historyWindow;

        state.liveHistory =
            state.liveHistory.filter(
                point =>
                    point.time >=
                    cutoff
            );

        return {
            packets,
            bytes
        };
    }


    /* ============================================================
       HISTORICAL HISTORY
       ============================================================ */

    function buildHistoricalHistory(
        records
    ) {
        const buckets =
            new Map();

        records.forEach(
            record => {
                const timestamp =
                    parseTime(
                        record.timestamp
                    );

                if (
                    timestamp === null
                ) {
                    return;
                }

                const second =
                    Math.floor(
                        timestamp / 1000
                    ) * 1000;

                if (
                    !buckets.has(
                        second
                    )
                ) {
                    buckets.set(
                        second,
                        {
                            time: second,
                            packets: 0,
                            bytes: 0
                        }
                    );
                }

                const bucket =
                    buckets.get(
                        second
                    );

                bucket.packets++;

                bucket.bytes +=
                    number(
                        record.packet_size
                    );
            }
        );

        return Array.from(
            buckets.values()
        ).sort(
            (a, b) =>
                a.time -
                b.time
        );
    }


    /* ============================================================
       KPI RENDERING
       ============================================================ */

    function renderKpis() {
        const records =
            getRangeTraffic();

        const metrics =
            calculateTrafficMetrics(
                records
            );

        const totalPackets =
            number(
                state.analytics
                    .total_packets,
                number(
                    state.stats
                        .total_packets,
                    number(
                        state.stats
                            .capture
                            ?.packets_captured
                    )
                )
            );

        const totalAlerts =
            number(
                state.analytics.alerts,
                number(
                    state.analytics
                        .total_alerts,
                    number(
                        state.stats
                            .total_alerts
                    )
                )
            );

        const devices =
            calculateDeviceCount();

        /*
         * For a selected time range, display packets
         * actually observed in that range.
         *
         * ALL uses the backend lifetime total.
         */

        const packetsToDisplay =
            state.range === "all"
                ? totalPackets
                : records.length;

        setText(
            "totalPackets",
            formatNumber(
                packetsToDisplay
            )
        );

        setText(
            "totalDevices",
            formatNumber(
                devices
            )
        );

        setText(
            "totalAlerts",
            formatNumber(
                totalAlerts
            )
        );

        setText(
            "trafficRate",
            formatRate(
                metrics.packetsPerSecond
            )
        );

        const meta =
            $("trafficMeta");

        if (meta) {
            meta.textContent =
                `${formatNumber(metrics.packets)} packets · ${formatBytes(metrics.bytes)} · AVG ${formatBytes(metrics.averagePacketSize)}`;
        }
    }


    /* ============================================================
       SEVERITY RENDERING
       ============================================================ */

    function renderSeverity() {
        const alerts =
            getRangeAlerts();

        let severity =
            calculateSeverities(
                alerts
            );

        /*
         * Use backend severity totals only
         * when there are no locally loaded alerts.
         */

        if (
            alerts.length === 0
        ) {
            const backend =
                severityFromAnalytics();

            const backendTotal =
                backend.CRITICAL +
                backend.HIGH +
                backend.MEDIUM +
                backend.LOW;

            if (
                backendTotal > 0
            ) {
                severity =
                    backend;
            }
        }

        setText(
            "criticalCount",
            formatNumber(
                severity.CRITICAL
            )
        );

        setText(
            "highCount",
            formatNumber(
                severity.HIGH
            )
        );

        setText(
            "mediumCount",
            formatNumber(
                severity.MEDIUM
            )
        );

        setText(
            "lowCount",
            formatNumber(
                severity.LOW
            )
        );

        const total =
            Math.max(
                1,
                severity.CRITICAL +
                severity.HIGH +
                severity.MEDIUM +
                severity.LOW
            );

        const bars = [
            [
                "criticalBar",
                severity.CRITICAL
            ],
            [
                "highBar",
                severity.HIGH
            ],
            [
                "mediumBar",
                severity.MEDIUM
            ],
            [
                "lowBar",
                severity.LOW
            ]
        ];

        bars.forEach(
            ([id, value]) => {
                const element =
                    $(id);

                if (!element) {
                    return;
                }

                const percentage =
                    (
                        value /
                        total
                    ) * 100;

                element.style.width =
                    `${Math.max(
                        value > 0
                            ? 2
                            : 0,
                        percentage
                    )}%`;
            }
        );
    }


    /* ============================================================
       IP TABLE
       ============================================================ */

    function renderIpTable(
        bodyId,
        rows
    ) {
        const body =
            $(bodyId);

        if (!body) {
            return;
        }

        if (!rows.length) {
            body.innerHTML = `
                <tr class="empty-row">
                    <td colspan="3">
                        Waiting for traffic data...
                    </td>
                </tr>
            `;

            return;
        }

        body.innerHTML =
            rows
                .map(
                    (row, index) => `
                        <tr>
                            <td>
                                ${index + 1}
                            </td>

                            <td>
                                <span class="ip-value">
                                    ${escapeHtml(
                                        row.ip
                                    )}
                                </span>
                            </td>

                            <td>
                                ${formatNumber(
                                    row.packets
                                )}
                            </td>
                        </tr>
                    `
                )
                .join("");
    }


    function renderIpAnalytics() {
        const records =
            getRangeTraffic();

        renderIpTable(
            "sourceIpRows",
            calculateTopIps(
                records,
                "source_ip"
            )
        );

        renderIpTable(
            "destinationIpRows",
            calculateTopIps(
                records,
                "destination_ip"
            )
        );
    }


    /* ============================================================
       HTML ESCAPING
       ============================================================ */

    function escapeHtml(value) {
        return String(
            value ?? ""
        )
            .replaceAll(
                "&",
                "&amp;"
            )
            .replaceAll(
                "<",
                "&lt;"
            )
            .replaceAll(
                ">",
                "&gt;"
            )
            .replaceAll(
                '"',
                "&quot;"
            )
            .replaceAll(
                "'",
                "&#039;"
            );
    }


    /* ============================================================
       CANVAS SETUP
       ============================================================ */

    function setupCanvas(
        canvas
    ) {
        if (!canvas) {
            return null;
        }

        const rect =
            canvas.getBoundingClientRect();

        const width =
            Math.max(
                300,
                Math.floor(
                    rect.width
                )
            );

        const height =
            Math.max(
                220,
                Math.floor(
                    rect.height
                )
            );

        const ratio =
            window.devicePixelRatio ||
            1;

        canvas.width =
            width * ratio;

        canvas.height =
            height * ratio;

        const context =
            canvas.getContext(
                "2d"
            );

        if (!context) {
            return null;
        }

        context.setTransform(
            ratio,
            0,
            0,
            ratio,
            0,
            0
        );

        return {
            context,
            width,
            height
        };
    }


    /* ============================================================
       TRAFFIC CHART
       ============================================================ */

    function drawTrafficChart() {
        const canvas =
            $("trafficAnalyticsChart");

        if (!canvas) {
            return;
        }

        const setup =
            setupCanvas(
                canvas
            );

        if (!setup) {
            return;
        }

        const {
            context,
            width,
            height
        } = setup;

        context.clearRect(
            0,
            0,
            width,
            height
        );

        const padding = {
            left: 48,
            right: 18,
            top: 20,
            bottom: 34
        };

        const graphWidth =
            width -
            padding.left -
            padding.right;

        const graphHeight =
            height -
            padding.top -
            padding.bottom;

        /*
         * Live samples take priority once available.
         */

        let points =
            state.liveHistory.length >= 2
                ? state.liveHistory.slice()
                : state.historicalHistory.slice();

        if (!points.length) {
            drawEmptyCanvas(
                context,
                width,
                height,
                "Waiting for live traffic..."
            );

            return;
        }

        const maxValue =
            Math.max(
                1,
                ...points.map(
                    point =>
                        number(
                            point.packets
                        )
                )
            );

        const minTime =
            points[0].time;

        const maxTime =
            points[
                points.length - 1
            ].time;

        const timeSpan =
            Math.max(
                1000,
                maxTime -
                    minTime
            );


        /* ========================================================
           GRID
           ======================================================== */

        context.save();

        context.lineWidth = 1;

        for (
            let i = 0;
            i <= 4;
            i++
        ) {
            const y =
                padding.top +
                graphHeight -
                (
                    i / 4
                ) *
                    graphHeight;

            context.beginPath();

            context.moveTo(
                padding.left,
                y
            );

            context.lineTo(
                width -
                    padding.right,
                y
            );

            context.strokeStyle =
                "rgba(255,255,255,0.08)";

            context.stroke();

            context.fillStyle =
                "rgba(255,255,255,0.55)";

            context.font =
                "11px system-ui";

            context.fillText(
                formatRate(
                    (
                        maxValue /
                        4
                    ) *
                    i
                ),
                8,
                y + 4
            );
        }


        /* ========================================================
           AREA
           ======================================================== */

        if (
            points.length >= 2
        ) {
            context.beginPath();

            points.forEach(
                point => {
                    const x =
                        padding.left +
                        (
                            (
                                point.time -
                                minTime
                            ) /
                            timeSpan
                        ) *
                            graphWidth;

                    const y =
                        padding.top +
                        graphHeight -
                        (
                            number(
                                point.packets
                            ) /
                            maxValue
                        ) *
                            graphHeight;

                    context.lineTo(
                        x,
                        y
                    );
                }
            );

            const last =
                points[
                    points.length - 1
                ];

            const lastX =
                padding.left +
                (
                    (
                        last.time -
                        minTime
                    ) /
                    timeSpan
                ) *
                    graphWidth;

            context.lineTo(
                lastX,
                padding.top +
                    graphHeight
            );

            const firstX =
                padding.left;

            context.lineTo(
                firstX,
                padding.top +
                    graphHeight
            );

            context.closePath();

            context.fillStyle =
                "rgba(53,230,255,0.08)";

            context.fill();
        }


        /* ========================================================
           LINE
           ======================================================== */

        context.beginPath();

        points.forEach(
            (point, index) => {
                const x =
                    padding.left +
                    (
                        (
                            point.time -
                            minTime
                        ) /
                        timeSpan
                    ) *
                        graphWidth;

                const y =
                    padding.top +
                    graphHeight -
                    (
                        number(
                            point.packets
                        ) /
                        maxValue
                    ) *
                        graphHeight;

                if (
                    index === 0
                ) {
                    context.moveTo(
                        x,
                        y
                    );
                } else {
                    context.lineTo(
                        x,
                        y
                    );
                }
            }
        );

        context.strokeStyle =
            "#35e6ff";

        context.lineWidth = 2;

        context.stroke();


        /* ========================================================
           X AXIS
           ======================================================== */

        context.fillStyle =
            "rgba(255,255,255,0.45)";

        context.font =
            "10px system-ui";

        const labels = 5;

        for (
            let i = 0;
            i <= labels;
            i++
        ) {
            const ratio =
                i / labels;

            const x =
                padding.left +
                ratio *
                    graphWidth;

            const timestamp =
                minTime +
                ratio *
                    timeSpan;

            const date =
                new Date(
                    timestamp
                );

            const text =
                date.toLocaleTimeString(
                    "en-IN",
                    {
                        hour:
                            "2-digit",
                        minute:
                            "2-digit",
                        second:
                            "2-digit"
                    }
                );

            context.fillText(
                text,
                Math.max(
                    0,
                    x - 28
                ),
                height - 10
            );
        }

        context.restore();
    }


    /* ============================================================
       EMPTY CANVAS
       ============================================================ */

    function drawEmptyCanvas(
        context,
        width,
        height,
        message
    ) {
        context.clearRect(
            0,
            0,
            width,
            height
        );

        context.fillStyle =
            "rgba(255,255,255,0.45)";

        context.font =
            "13px system-ui";

        context.textAlign =
            "center";

        context.fillText(
            message,
            width / 2,
            height / 2
        );

        context.textAlign =
            "left";
    }


    /* ============================================================
       PROTOCOL DONUT
       ============================================================ */

    function drawProtocolChart() {
        const canvas =
            $("protocolAnalyticsChart");

        if (!canvas) {
            return;
        }

        const setup =
            setupCanvas(
                canvas
            );

        if (!setup) {
            return;
        }

        const {
            context,
            width,
            height
        } = setup;

        context.clearRect(
            0,
            0,
            width,
            height
        );

        const records =
            getRangeTraffic();

        let protocols =
            calculateProtocols(
                records
            );

        const totalPackets =
            Object.values(
                protocols
            ).reduce(
                (sum, value) =>
                    sum + value,
                0
            );

        if (
            totalPackets === 0
        ) {
            protocols =
                protocolFromAnalytics();
        }

        const entries =
            Object.entries(
                protocols
            );

        const total =
            entries.reduce(
                (sum, [, value]) =>
                    sum + number(value),
                0
            );

        if (
            total <= 0
        ) {
            drawEmptyCanvas(
                context,
                width,
                height,
                "Waiting for protocol data..."
            );

            renderProtocolLegend(
                protocols
            );

            return;
        }

        const centerX =
            width / 2;

        const centerY =
            height / 2;

        const radius =
            Math.min(
                width,
                height
            ) *
            0.35;

        const innerRadius =
            radius * 0.60;

        let angle =
            -Math.PI / 2;

        [
            "TCP",
            "UDP",
            "ICMP",
            "IPv6",
            "OTHER"
        ].forEach(
            protocol => {
                const value =
                    number(
                        protocols[
                            protocol
                        ]
                    );

                if (
                    value <= 0
                ) {
                    return;
                }

                const slice =
                    (
                        value /
                        total
                    ) *
                    Math.PI *
                    2;

                context.beginPath();

                context.arc(
                    centerX,
                    centerY,
                    radius,
                    angle,
                    angle + slice
                );

                context.arc(
                    centerX,
                    centerY,
                    innerRadius,
                    angle + slice,
                    angle,
                    true
                );

                context.closePath();

                context.fillStyle =
                    protocolColor(
                        protocol
                    );

                context.fill();

                angle += slice;
            }
        );

        context.fillStyle =
            "rgba(255,255,255,0.9)";

        context.textAlign =
            "center";

        context.font =
            "700 20px system-ui";

        context.fillText(
            formatNumber(
                total
            ),
            centerX,
            centerY + 4
        );

        context.font =
            "10px system-ui";

        context.fillStyle =
            "rgba(255,255,255,0.45)";

        context.fillText(
            "PACKETS",
            centerX,
            centerY + 22
        );

        context.textAlign =
            "left";

        renderProtocolLegend(
            protocols
        );
    }


    function protocolColor(
        protocol
    ) {
        switch (protocol) {
            case "TCP":
                return "#35e6ff";

            case "UDP":
                return "#9b7cff";

            case "ICMP":
                return "#ffc857";

            case "IPv6":
                return "#56d364";

            default:
                return "#8993a4";
        }
    }


    function renderProtocolLegend(
        protocols
    ) {
        const container =
            $("protocolLegend");

        if (!container) {
            return;
        }

        container.innerHTML =
            Object.entries(
                protocols
            )
                .map(
                    ([protocol, value]) => `
                        <div class="protocol-item">
                            <span
                                class="protocol-dot"
                                style="
                                    background:${protocolColor(
                                        protocol
                                    )}
                                "
                            ></span>

                            <span>
                                ${escapeHtml(
                                    protocol
                                )}
                            </span>

                            <strong>
                                ${formatNumber(
                                    value
                                )}
                            </strong>
                        </div>
                    `
                )
                .join("");
    }


    /* ============================================================
       REFRESH AGE
       ============================================================ */

    function renderRefreshAge() {
        const element =
            $("refreshAge");

        if (!element) {
            return;
        }

        if (
            !state.lastUpdate
        ) {
            element.textContent =
                "--";

            return;
        }

        const elapsed =
            Math.max(
                0,
                Date.now() -
                    state.lastUpdate
            );

        const seconds =
            Math.floor(
                elapsed / 1000
            );

        if (
            seconds < 1
        ) {
            element.textContent =
                "NOW";

            return;
        }

        element.textContent =
            `${seconds}s AGO`;
    }


    /* ============================================================
       LIVE STATUS
       ============================================================ */

    function renderLiveStatus() {
        const elements =
            document.querySelectorAll(
                ".analytics-live-status, [data-analytics-live-status]"
            );

        elements.forEach(
            element => {
                element.textContent =
                    "LIVE DATA · UPDATE NOW";
            }
        );
    }


    /* ============================================================
       RANGE BUTTONS
       ============================================================ */

    function setRange(
        range
    ) {
        const allowed = [
            "5m",
            "15m",
            "1h",
            "all"
        ];

        if (
            !allowed.includes(
                range
            )
        ) {
            range = "5m";
        }

        state.range =
            range;

        document
            .querySelectorAll(
                "[data-range]"
            )
            .forEach(
                button => {
                    button.classList.toggle(
                        "active",
                        button.dataset.range ===
                            range
                    );
                }
            );

        document
            .querySelectorAll(
                "button"
            )
            .forEach(
                button => {
                    const text =
                        button.textContent
                            .trim()
                            .toUpperCase();

                    const matches =
                        (
                            range === "5m" &&
                            text === "5 MIN"
                        ) ||
                        (
                            range === "15m" &&
                            text === "15 MIN"
                        ) ||
                        (
                            range === "1h" &&
                            text === "1 HOUR"
                        ) ||
                        (
                            range === "all" &&
                            text === "ALL"
                        );

                    if (matches) {
                        button.classList.add(
                            "active"
                        );
                    }
                }
            );

        state.historicalHistory =
            buildHistoricalHistory(
                getRangeTraffic()
            );

        /*
         * Reset live history when changing
         * time windows so the chart doesn't
         * mix incompatible ranges.
         */

        state.liveHistory = [];

        drawTrafficChart();
        drawProtocolChart();
        renderKpis();
        renderSeverity();
        renderIpAnalytics();
    }


    function initRangeButtons() {
        document
            .querySelectorAll(
                "[data-range]"
            )
            .forEach(
                button => {
                    button.addEventListener(
                        "click",
                        () => {
                            setRange(
                                button.dataset.range
                            );
                        }
                    );
                }
            );

        document
            .querySelectorAll(
                "button"
            )
            .forEach(
                button => {
                    const text =
                        button.textContent
                            .trim()
                            .toUpperCase();

                    if (
                        text === "5 MIN" ||
                        text === "15 MIN" ||
                        text === "1 HOUR" ||
                        text === "ALL"
                    ) {
                        button.addEventListener(
                            "click",
                            () => {
                                if (
                                    text ===
                                    "5 MIN"
                                ) {
                                    setRange(
                                        "5m"
                                    );
                                } else if (
                                    text ===
                                    "15 MIN"
                                ) {
                                    setRange(
                                        "15m"
                                    );
                                } else if (
                                    text ===
                                    "1 HOUR"
                                ) {
                                    setRange(
                                        "1h"
                                    );
                                } else {
                                    setRange(
                                        "all"
                                    );
                                }
                            }
                        );
                    }
                }
            );
    }


    /* ============================================================
       LOAD BACKEND DATA
       ============================================================ */

    async function loadData() {
        if (
            state.loading
        ) {
            return;
        }

        state.loading =
            true;

        try {
            hideError();

            const results =
                await Promise.allSettled(
                    [
                        api(
                            "/api/analytics"
                        ),

                        api(
                            "/api/stats"
                        ),

                        api(
                            "/api/devices"
                        ),

                        api(
                            "/api/traffic?limit=1000"
                        ),

                        api(
                            "/api/alerts?limit=500"
                        )
                    ]
                );

            const [
                analyticsResult,
                statsResult,
                devicesResult,
                trafficResult,
                alertsResult
            ] = results;


            /* ====================================================
               ANALYTICS
               ==================================================== */

            if (
                analyticsResult.status ===
                "fulfilled"
            ) {
                state.analytics =
                    analyticsResult.value ||
                    {};
            } else {
                console.warn(
                    "Analytics API failed:",
                    analyticsResult.reason
                );
            }


            /* ====================================================
               STATS
               ==================================================== */

            if (
                statsResult.status ===
                "fulfilled"
            ) {
                state.stats =
                    statsResult.value ||
                    {};
            } else {
                console.warn(
                    "Stats API failed:",
                    statsResult.reason
                );
            }


            /* ====================================================
               DEVICES
               ==================================================== */

            if (
                devicesResult.status ===
                "fulfilled"
            ) {
                state.devices =
                    Array.isArray(
                        devicesResult.value
                    )
                        ? devicesResult.value
                        : [];
            } else {
                console.warn(
                    "Devices API failed:",
                    devicesResult.reason
                );
            }


            /* ====================================================
               TRAFFIC
               ==================================================== */

            if (
                trafficResult.status ===
                "fulfilled"
            ) {
                state.traffic =
                    Array.isArray(
                        trafficResult.value
                    )
                        ? trafficResult.value
                        : [];
            } else {
                console.warn(
                    "Traffic API failed:",
                    trafficResult.reason
                );
            }


            /* ====================================================
               ALERTS
               ==================================================== */

            if (
                alertsResult.status ===
                "fulfilled"
            ) {
                const value =
                    alertsResult.value;

                if (
                    Array.isArray(
                        value
                    )
                ) {
                    state.alerts =
                        value;
                } else if (
                    Array.isArray(
                        value?.alerts
                    )
                ) {
                    state.alerts =
                        value.alerts;
                } else if (
                    Array.isArray(
                        value?.data
                    )
                ) {
                    state.alerts =
                        value.data;
                } else {
                    state.alerts =
                        [];
                }
            } else {
                console.warn(
                    "Alerts API failed:",
                    alertsResult.reason
                );
            }


            /* ====================================================
               LAST TRAFFIC ID
               ==================================================== */

            if (
                state.traffic.length
            ) {
                const ids =
                    state.traffic
                        .map(
                            record =>
                                integer(
                                    record.id
                                )
                        )
                        .filter(
                            id =>
                                id > 0
                        );

                if (ids.length) {
                    state.lastTrafficId =
                        Math.max(
                            state.lastTrafficId,
                            ...ids
                        );
                }
            }


            /* ====================================================
               INITIAL HISTORY
               ==================================================== */

            state.historicalHistory =
                buildHistoricalHistory(
                    getRangeTraffic()
                );

            state.lastUpdate =
                Date.now();

            renderAll();

            const allFailed =
                results.every(
                    result =>
                        result.status ===
                        "rejected"
                );

            if (
                allFailed
            ) {
                showError(
                    "Unable to retrieve NETSENTINEL analytics data."
                );
            }

        } catch (error) {
            console.error(
                "NETSENTINEL analytics:",
                error
            );

            showError(
                error.message ||
                "Analytics data could not be loaded."
            );

        } finally {
            state.loading =
                false;
        }
    }


    /* ============================================================
       LIVE TRAFFIC POLLING
       ============================================================ */

    async function pollLiveTraffic() {
        try {
            const traffic =
                await api(
                    "/api/traffic?limit=500"
                );

            if (
                !Array.isArray(
                    traffic
                )
            ) {
                return;
            }

            state.traffic =
                traffic;

            let newestId =
                state.lastTrafficId;

            traffic.forEach(
                record => {
                    const id =
                        integer(
                            record.id
                        );

                    if (
                        id > newestId
                    ) {
                        newestId =
                            id;
                    }
                }
            );

            state.lastTrafficId =
                newestId;

            /*
             * Timestamp bug is fixed in parseTime(),
             * so this now correctly identifies packets
             * captured during the previous second.
             */

            collectLiveSample();

            state.lastUpdate =
                Date.now();

            renderKpis();
            renderIpAnalytics();
            drawTrafficChart();
            drawProtocolChart();
            renderRefreshAge();
            renderLiveStatus();

        } catch (error) {
            console.warn(
                "Live traffic update failed:",
                error
            );
        }
    }


    /* ============================================================
       LIVE POLLING
       ============================================================ */

    function startLivePolling() {
        if (
            state.trafficTimer
        ) {
            clearInterval(
                state.trafficTimer
            );
        }

        state.trafficTimer =
            setInterval(
                pollLiveTraffic,
                1000
            );
    }


    function startRefreshPolling() {
        if (
            state.refreshTimer
        ) {
            clearInterval(
                state.refreshTimer
            );
        }

        state.refreshTimer =
            setInterval(
                async () => {
                    await loadData();
                },
                3000
            );
    }


    /* ============================================================
       RENDER ALL
       ============================================================ */

    function renderAll() {
        renderKpis();
        renderSeverity();
        renderIpAnalytics();
        drawTrafficChart();
        drawProtocolChart();
        renderRefreshAge();
        renderLiveStatus();
    }


    /* ============================================================
       RESIZE
       ============================================================ */

    function initResize() {
        let timer = null;

        window.addEventListener(
            "resize",
            () => {
                clearTimeout(
                    timer
                );

                timer =
                    setTimeout(
                        () => {
                            drawTrafficChart();
                            drawProtocolChart();
                        },
                        120
                    );
            }
        );
    }


    /* ============================================================
       REFRESH AGE TIMER
       ============================================================ */

    function startRefreshAgeTimer() {
        setInterval(
            renderRefreshAge,
            1000
        );
    }


    /* ============================================================
       INITIALIZATION
       ============================================================ */

    async function init() {
        if (
            state.initialized
        ) {
            return;
        }

        state.initialized =
            true;

        console.log(
            "NETSENTINEL Analytics initializing..."
        );

        initRangeButtons();

        initResize();

        startRefreshAgeTimer();

        /*
         * Don't call setRange() here because it clears
         * live history before the first backend load.
         */

        state.range =
            "5m";

        await loadData();

        startLivePolling();

        startRefreshPolling();

        console.log(
            "NETSENTINEL Analytics ready."
        );
    }


    /* ============================================================
       START
       ============================================================ */

    if (
        document.readyState ===
        "loading"
    ) {
        document.addEventListener(
            "DOMContentLoaded",
            init,
            {
                once: true
            }
        );
    } else {
        init();
    }

})();