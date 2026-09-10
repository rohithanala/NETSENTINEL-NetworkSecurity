(() => {
    "use strict";

    console.log(
        "NETSENTINEL: Initializing analytics..."
    );


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
       GRAPH CONFIGURATION
    ============================================================ */

    const GRAPH_SECONDS = 60;

    const GRAPH_SAMPLE_INTERVAL = 1000;

    const GRAPH_SMOOTHING_WINDOW = 2;


    /* ============================================================
       DOM HELPERS
    ============================================================ */

    function $(id) {
        return document.getElementById(
            id
        );
    }


    function setText(
        id,
        value
    ) {
        const element =
            $(
                id
            );

        if (element) {
            element.textContent =
                value;
        }
    }


    function showElement(
        id,
        display = ""
    ) {
        const element =
            $(
                id
            );

        if (element) {
            element.style.display =
                display;
        }
    }


    function hideElement(
        id
    ) {
        const element =
            $(
                id
            );

        if (element) {
            element.style.display =
                "none";
        }
    }


    /* ============================================================
       ERROR HANDLING
    ============================================================ */

    function showError(
        message
    ) {
        const element =
            $(
                "analyticsError"
            );

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

        element.style.display =
            "block";
    }


    function hideError() {
        const element =
            $(
                "analyticsError"
            );

        if (element) {
            element.textContent =
                "";

            element.style.display =
                "none";
        }
    }


    /* ============================================================
       API HELPER
    ============================================================ */

    async function api(
        url
    ) {
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

    function number(
        value,
        fallback = 0
    ) {
        const parsed =
            Number(
                value
            );

        return Number.isFinite(
            parsed
        )
            ? parsed
            : fallback;
    }


    function integer(
        value,
        fallback = 0
    ) {
        return Math.round(
            number(
                value,
                fallback
            )
        );
    }


    function formatNumber(
        value
    ) {
        return integer(
            value
        ).toLocaleString(
            "en-IN"
        );
    }


    function formatBytes(
        value
    ) {
        const bytes =
            number(
                value
            );

        if (
            bytes < 1024
        ) {
            return `${Math.round(bytes)} B`;
        }

        if (
            bytes <
            1024 * 1024
        ) {
            return `${(
                bytes /
                1024
            ).toFixed(1)} KB`;
        }

        if (
            bytes <
            1024 *
            1024 *
            1024
        ) {
            return `${(
                bytes /
                (
                    1024 *
                    1024
                )
            ).toFixed(1)} MB`;
        }

        return `${(
            bytes /
            (
                1024 *
                1024 *
                1024
            )
        ).toFixed(2)} GB`;
    }


    function formatRate(
        value
    ) {
        const rate =
            number(
                value
            );

        if (
            rate >= 1000000
        ) {
            return `${(
                rate /
                1000000
            ).toFixed(1)}M`;
        }

        if (
            rate >= 1000
        ) {
            return `${(
                rate /
                1000
            ).toFixed(1)}K`;
        }

        return `${Math.round(
            rate
        )}`;
    }


    /* ============================================================
       TIME HELPERS
    ============================================================ */

    function parseTime(
        value
    ) {
        if (!value) {
            return null;
        }

        let text =
            String(
                value
            ).trim();

        if (
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(
                text
            ) &&
            !/[zZ]$/.test(
                text
            ) &&
            !/[+-]\d{2}:\d{2}$/.test(
                text
            )
        ) {
            text +=
                "Z";
        }

        const timestamp =
            new Date(
                text
            ).getTime();

        return Number.isFinite(
            timestamp
        )
            ? timestamp
            : null;
    }


    function rangeMilliseconds() {
        switch (
            state.range
        ) {
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
        switch (
            state.range
        ) {
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

    function normalizeProtocol(
        protocol
    ) {
        if (!protocol) {
            return "OTHER";
        }

        const value =
            String(
                protocol
            )
                .trim()
                .toUpperCase();

        if (
            value.includes(
                "TCP"
            )
        ) {
            return "TCP";
        }

        if (
            value.includes(
                "UDP"
            )
        ) {
            return "UDP";
        }

        if (
            value.includes(
                "ICMP"
            )
        ) {
            return "ICMP";
        }

        if (
            value.includes(
                "IPV6"
            ) ||
            value === "IP6"
        ) {
            return "IPv6";
        }

        return "OTHER";
    }


    /* ============================================================
       SEVERITY NORMALIZATION
    ============================================================ */

    function normalizeSeverity(
        severity
    ) {
        const value =
            String(
                severity || ""
            )
                .trim()
                .toUpperCase();

        if (
            value === "CRITICAL"
        ) {
            return "CRITICAL";
        }

        if (
            value === "HIGH"
        ) {
            return "HIGH";
        }

        if (
            value === "MEDIUM"
        ) {
            return "MEDIUM";
        }

        return "LOW";
    }


    /* ============================================================
       TRAFFIC RANGE FILTER
    ============================================================ */

    function trafficInRange(
        record
    ) {
        if (
            state.range ===
            "all"
        ) {
            return true;
        }

        const timestamp =
            parseTime(
                record.timestamp
            );

        if (
            timestamp ===
            null
        ) {
            return false;
        }

        const age =
            Date.now() -
            timestamp;

        return (
            age >= 0 &&
            age <=
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

    function alertTimestamp(
        alert
    ) {
        return (
            alert.timestamp ||
            alert.created_at ||
            alert.createdAt ||
            alert.time ||
            alert.detected_at
        );
    }


    function alertInRange(
        alert
    ) {
        if (
            state.range ===
            "all"
        ) {
            return true;
        }

        const timestamp =
            parseTime(
                alertTimestamp(
                    alert
                )
            );

        if (
            timestamp ===
            null
        ) {
            return false;
        }

        const age =
            Date.now() -
            timestamp;

        return (
            age >= 0 &&
            age <=
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
        if (
            !records.length
        ) {
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
                        value !==
                        null
                )
                .sort(
                    (a, b) =>
                        a - b
                );

        let durationSeconds =
            1;

        if (
            timestamps.length >
            1
        ) {
            durationSeconds =
                Math.max(
                    1,
                    (
                        timestamps[
                            timestamps.length -
                                1
                        ] -
                        timestamps[0]
                    ) /
                        1000
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
        if (
            !records.length
        ) {
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
                    timestamp ===
                    null
                ) {
                    return;
                }

                const second =
                    Math.floor(
                        timestamp /
                            1000
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

        if (
            !buckets.size
        ) {
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

                result[
                    protocol
                ]++;
            }
        );

        return result;
    }


    function protocolFromAnalytics() {
        const source =
            state.analytics
                .protocol_distribution ||
            state.analytics
                .protocols ||
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

                result[
                    protocol
                ] += number(
                    value
                );
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

                result[
                    severity
                ]++;
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
                        map.get(
                            ip
                        ) || 0
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
            .slice(
                0,
                10
            );
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
                    String(
                        port
                    );

                map.set(
                    key,
                    (
                        map.get(
                            key
                        ) || 0
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
            .slice(
                0,
                10
            );
    }


    /* ============================================================
       DEVICE COUNT
    ============================================================ */

    function calculateDeviceCount() {
        return number(
            state.stats?.active_devices,
            number(
                state.analytics?.devices,
                0
            )
        );
    }


    /* ============================================================
       ROLLING LIVE TRAFFIC HISTORY
    ============================================================ */

    function buildRollingTrafficHistory() {
        const traffic =
            Array.isArray(
                state.traffic
            )
                ? state.traffic
                : [];

        const now =
            Date.now();

        const currentSecond =
            Math.floor(
                now /
                1000
            ) *
            1000;

        const firstSecond =
            currentSecond -
            (
                GRAPH_SECONDS -
                1
            ) *
            GRAPH_SAMPLE_INTERVAL;

        const buckets =
            new Map();

        for (
            let i = 0;
            i <
            GRAPH_SECONDS;
            i++
        ) {
            const time =
                firstSecond +
                i *
                GRAPH_SAMPLE_INTERVAL;

            buckets.set(
                time,
                {
                    time,
                    packets: 0,
                    bytes: 0
                }
            );
        }

        traffic.forEach(
            record => {
                const timestamp =
                    parseTime(
                        record.timestamp
                    );

                if (
                    timestamp ===
                    null
                ) {
                    return;
                }

                if (
                    timestamp <
                    firstSecond
                ) {
                    return;
                }

                if (
                    timestamp >
                    currentSecond +
                    999
                ) {
                    return;
                }

                const bucketTime =
                    Math.floor(
                        timestamp /
                        1000
                    ) *
                    1000;

                const bucket =
                    buckets.get(
                        bucketTime
                    );

                if (!bucket) {
                    return;
                }

                bucket.packets++;

                bucket.bytes +=
                    number(
                        record.packet_size
                    );
            }
        );

        let points =
            Array.from(
                buckets.values()
            ).sort(
                (a, b) =>
                    a.time -
                    b.time
            );

        /*
         * Light smoothing only.
         * Real peaks and drops remain visible.
         */

        if (
            GRAPH_SMOOTHING_WINDOW >
            1
        ) {
            points =
                points.map(
                    (
                        point,
                        index
                    ) => {
                        const start =
                            Math.max(
                                0,
                                index -
                                GRAPH_SMOOTHING_WINDOW +
                                1
                            );

                        let packetTotal =
                            0;

                        let byteTotal =
                            0;

                        let count =
                            0;

                        for (
                            let i =
                                start;
                            i <= index;
                            i++
                        ) {
                            packetTotal +=
                                number(
                                    points[i]
                                        .packets
                                );

                            byteTotal +=
                                number(
                                    points[i]
                                        .bytes
                                );

                            count++;
                        }

                        return {
                            time:
                                point.time,

                            packets:
                                packetTotal /
                                Math.max(
                                    1,
                                    count
                                ),

                            bytes:
                                byteTotal /
                                Math.max(
                                    1,
                                    count
                                )
                        };
                    }
                );
        }

        return points;
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
                    timestamp ===
                    null
                ) {
                    return;
                }

                const second =
                    Math.floor(
                        timestamp /
                        1000
                    ) *
                    1000;

                if (
                    !buckets.has(
                        second
                    )
                ) {
                    buckets.set(
                        second,
                        {
                            time:
                                second,

                            packets:
                                0,

                            bytes:
                                0
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


        /* ========================================================
           PPS FIX
        ======================================================== */

        /*
         * Backend stats already calculates traffic_rate_pps
         * from the real recent traffic window.
         *
         * This is the authoritative value for the KPI.
         *
         * The locally calculated value is only a fallback.
         */

        const backendPps =
            number(
                state.stats?.traffic_rate_pps,
                NaN
            );

        const packetsPerSecond =
            Number.isFinite(
                backendPps
            )
                ? backendPps
                : metrics.packetsPerSecond;


        /* ========================================================
           PACKETS
        ======================================================== */

        const packetsToDisplay =
            state.range ===
            "all"
                ? totalPackets
                : records.length;


        /* ========================================================
           RENDER
        ======================================================== */

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
                packetsPerSecond
            )
        );


        const meta =
            $(
                "trafficMeta"
            );

        if (meta) {
            meta.textContent =
                `${formatNumber(
                    metrics.packets
                )} packets · ${formatBytes(
                    metrics.bytes
                )} · AVG ${formatBytes(
                    metrics.averagePacketSize
                )}`;
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

        if (
            alerts.length ===
            0
        ) {
            const backend =
                severityFromAnalytics();

            const backendTotal =
                backend.CRITICAL +
                backend.HIGH +
                backend.MEDIUM +
                backend.LOW;

            if (
                backendTotal >
                0
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
                    $(
                        id
                    );

                if (!element) {
                    return;
                }

                const percentage =
                    (
                        value /
                        total
                    ) *
                    100;

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
            $(
                bodyId
            );

        if (!body) {
            return;
        }

        if (
            !rows.length
        ) {
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
                    (
                        row,
                        index
                    ) => `
                        <tr>
                            <td>
                                ${
                                    index +
                                    1
                                }
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
                .join(
                    ""
                );
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

    function escapeHtml(
        value
    ) {
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
            width *
            ratio;

        canvas.height =
            height *
            ratio;

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
            $(
                "trafficAnalyticsChart"
            );

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
            left: 52,
            right: 26,
            top: 28,
            bottom: 38
        };

        const graphWidth =
            Math.max(
                1,
                width -
                padding.left -
                padding.right
            );

        const graphHeight =
            Math.max(
                1,
                height -
                padding.top -
                padding.bottom
            );


        /* ========================================================
           DATA
        ======================================================== */

        const points =
            buildRollingTrafficHistory();

        if (
            !points.length
        ) {
            drawEmptyCanvas(
                context,
                width,
                height,
                "Waiting for live traffic..."
            );

            return;
        }


        const values =
            points.map(
                point =>
                    number(
                        point.packets
                    )
            );

        const rawMin =
            Math.min(
                ...values
            );

        const rawMax =
            Math.max(
                ...values
            );


        /* ========================================================
           DYNAMIC Y AXIS
        ======================================================== */

        let minValue =
            Math.floor(
                rawMin
            );

        let maxValue =
            Math.ceil(
                rawMax
            );

        if (
            maxValue ===
            minValue
        ) {
            minValue =
                Math.max(
                    0,
                    minValue -
                    2
                );

            maxValue =
                maxValue +
                2;
        }

        else {
            const spread =
                Math.max(
                    1,
                    maxValue -
                    minValue
                );

            minValue =
                Math.max(
                    0,
                    Math.floor(
                        minValue -
                        spread *
                        0.20
                    )
                );

            maxValue =
                Math.ceil(
                    maxValue +
                    spread *
                    0.20
                );
        }

        const valueSpan =
            Math.max(
                1,
                maxValue -
                minValue
            );

        const minTime =
            points[0].time;

        const maxTime =
            points[
                points.length -
                1
            ].time;

        const timeSpan =
            Math.max(
                GRAPH_SAMPLE_INTERVAL,
                maxTime -
                minTime
            );


        /* ========================================================
           GRID
        ======================================================== */

        context.save();

        context.lineWidth =
            1;

        const gridRows =
            5;

        for (
            let i = 0;
            i <= gridRows;
            i++
        ) {
            const ratio =
                i /
                gridRows;

            const y =
                padding.top +
                graphHeight -
                ratio *
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
                "rgba(255,255,255,0.075)";

            context.stroke();

            const value =
                minValue +
                ratio *
                valueSpan;

            context.fillStyle =
                "rgba(255,255,255,0.55)";

            context.font =
                "11px system-ui";

            context.fillText(
                formatRate(
                    value
                ),
                8,
                y + 4
            );
        }


        /* ========================================================
           VERTICAL GRID
        ======================================================== */

        const verticalLines =
            6;

        for (
            let i = 0;
            i <= verticalLines;
            i++
        ) {
            const ratio =
                i /
                verticalLines;

            const x =
                padding.left +
                ratio *
                graphWidth;

            context.beginPath();

            context.moveTo(
                x,
                padding.top
            );

            context.lineTo(
                x,
                padding.top +
                graphHeight
            );

            context.strokeStyle =
                "rgba(255,255,255,0.035)";

            context.stroke();
        }


        /* ========================================================
           COORDINATES
        ======================================================== */

        const coordinates =
            points.map(
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

                    const normalized =
                        (
                            number(
                                point.packets
                            ) -
                            minValue
                        ) /
                        valueSpan;

                    const y =
                        padding.top +
                        graphHeight -
                        normalized *
                        graphHeight;

                    return {
                        x,
                        y
                    };
                }
            );


        /* ========================================================
           AREA
        ======================================================== */

        if (
            coordinates.length >=
            2
        ) {
            context.beginPath();

            context.moveTo(
                coordinates[0].x,
                padding.top +
                graphHeight
            );

            context.lineTo(
                coordinates[0].x,
                coordinates[0].y
            );

            for (
                let i = 1;
                i <
                coordinates.length;
                i++
            ) {
                const previous =
                    coordinates[
                        i - 1
                    ];

                const current =
                    coordinates[
                        i
                    ];

                const middleX =
                    (
                        previous.x +
                        current.x
                    ) /
                    2;

                context.quadraticCurveTo(
                    middleX,
                    previous.y,
                    current.x,
                    current.y
                );
            }

            const last =
                coordinates[
                    coordinates.length -
                    1
                ];

            context.lineTo(
                last.x,
                padding.top +
                graphHeight
            );

            context.closePath();

            context.fillStyle =
                "rgba(53,230,255,0.075)";

            context.fill();
        }


        /* ========================================================
           MAIN LINE
        ======================================================== */

        context.beginPath();

        coordinates.forEach(
            (
                point,
                index
            ) => {
                if (
                    index ===
                    0
                ) {
                    context.moveTo(
                        point.x,
                        point.y
                    );

                    return;
                }

                const previous =
                    coordinates[
                        index -
                        1
                    ];

                const middleX =
                    (
                        previous.x +
                        point.x
                    ) /
                    2;

                context.quadraticCurveTo(
                    middleX,
                    previous.y,
                    point.x,
                    point.y
                );
            }
        );

        context.strokeStyle =
            "#35e6ff";

        context.lineWidth =
            2.8;

        context.lineJoin =
            "round";

        context.lineCap =
            "round";

        context.shadowColor =
            "#35e6ff";

        context.shadowBlur =
            8;

        context.stroke();

        context.shadowBlur =
            0;


        /* ========================================================
           DATA POINTS
        ======================================================== */

        coordinates.forEach(
            (
                point,
                index
            ) => {
                if (
                    index %
                    2 !==
                    0 &&
                    index !==
                    coordinates.length -
                    1
                ) {
                    return;
                }

                context.beginPath();

                context.arc(
                    point.x,
                    point.y,
                    2.2,
                    0,
                    Math.PI *
                    2
                );

                context.fillStyle =
                    "#35e6ff";

                context.shadowColor =
                    "#35e6ff";

                context.shadowBlur =
                    8;

                context.fill();

                context.shadowBlur =
                    0;
            }
        );


        /* ========================================================
           CURRENT POINT
        ======================================================== */

        const latest =
            points[
                points.length -
                1
            ];

        const latestPoint =
            coordinates[
                coordinates.length -
                1
            ];

        if (
            latest &&
            latestPoint
        ) {
            context.beginPath();

            context.arc(
                latestPoint.x,
                latestPoint.y,
                5,
                0,
                Math.PI *
                2
            );

            context.fillStyle =
                "#35e6ff";

            context.shadowColor =
                "#35e6ff";

            context.shadowBlur =
                15;

            context.fill();

            context.shadowBlur =
                0;

            /*
             * Show the actual backend PPS value
             * beside the live point instead of assuming
             * the current second alone represents the
             * current traffic rate.
             */

            const livePps =
                number(
                    state.stats?.traffic_rate_pps,
                    number(
                        latest.packets
                    )
                );

            context.fillStyle =
                "rgba(255,255,255,0.85)";

            context.font =
                "700 10px system-ui";

            context.textAlign =
                "right";

            context.fillText(
                `${formatRate(
                    livePps
                )} PPS`,
                latestPoint.x -
                9,
                latestPoint.y -
                11
            );

            context.textAlign =
                "left";
        }


        /* ========================================================
           X AXIS
        ======================================================== */

        context.fillStyle =
            "rgba(255,255,255,0.45)";

        context.font =
            "10px system-ui";

        const labels =
            5;

        for (
            let i = 0;
            i <= labels;
            i++
        ) {
            const ratio =
                i /
                labels;

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
                height -
                10
            );
        }


        /* ========================================================
           GRAPH TITLES
        ======================================================== */

        context.fillStyle =
            "rgba(255,255,255,0.35)";

        context.font =
            "700 9px system-ui";

        context.fillText(
            "PACKETS / SECOND",
            padding.left,
            13
        );

        context.textAlign =
            "right";

        context.fillText(
            "LIVE · LAST 60 SEC",
            width -
            padding.right,
            13
        );

        context.textAlign =
            "left";

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
            $(
                "protocolAnalyticsChart"
            );

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
                (
                    sum,
                    value
                ) =>
                    sum +
                    value,
                0
            );

        if (
            totalPackets ===
            0
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
                (
                    sum,
                    [, value]
                ) =>
                    sum +
                    number(
                        value
                    ),
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
            radius *
            0.60;

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
                    value <=
                    0
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
                    angle +
                    slice
                );

                context.arc(
                    centerX,
                    centerY,
                    innerRadius,
                    angle +
                    slice,
                    angle,
                    true
                );

                context.closePath();

                context.fillStyle =
                    protocolColor(
                        protocol
                    );

                context.fill();

                angle +=
                    slice;
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
        switch (
            protocol
        ) {
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
            $(
                "protocolLegend"
            );

        if (!container) {
            return;
        }

        container.innerHTML =
            Object.entries(
                protocols
            )
                .map(
                    (
                        [
                            protocol,
                            value
                        ]
                    ) => `
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
                .join(
                    ""
                );
    }


    /* ============================================================
       REFRESH AGE
    ============================================================ */

    function renderRefreshAge() {
        const element =
            $(
                "refreshAge"
            );

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
                elapsed /
                1000
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
            range =
                "5m";
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

                    if (
                        matches
                    ) {
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
                                }

                                else if (
                                    text ===
                                    "15 MIN"
                                ) {
                                    setRange(
                                        "15m"
                                    );
                                }

                                else if (
                                    text ===
                                    "1 HOUR"
                                ) {
                                    setRange(
                                        "1h"
                                    );
                                }

                                else {
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
            ] =
                results;


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
            }

            else {
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
            }

            else {
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
            }

            else {
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
            }

            else {
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
                }

                else if (
                    Array.isArray(
                        value?.alerts
                    )
                ) {
                    state.alerts =
                        value.alerts;
                }

                else if (
                    Array.isArray(
                        value?.data
                    )
                ) {
                    state.alerts =
                        value.data;
                }

                else {
                    state.alerts =
                        [];
                }
            }

            else {
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
                                id >
                                0
                        );

                if (
                    ids.length
                ) {
                    state.lastTrafficId =
                        Math.max(
                            state.lastTrafficId,
                            ...ids
                        );
                }
            }


            /* ====================================================
               HISTORICAL HISTORY
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

        }

        catch (error) {
            console.error(
                "NETSENTINEL analytics:",
                error
            );

            showError(
                error.message ||
                "Analytics data could not be loaded."
            );
        }

        finally {
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
                    "/api/traffic?limit=1000"
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
                        id >
                        newestId
                    ) {
                        newestId =
                            id;
                    }
                }
            );

            state.lastTrafficId =
                newestId;

            /*
             * Rebuild the rolling graph from actual
             * traffic timestamps.
             */

            state.liveHistory =
                buildRollingTrafficHistory();

            state.lastUpdate =
                Date.now();

            renderKpis();

            renderIpAnalytics();

            drawTrafficChart();

            drawProtocolChart();

            renderRefreshAge();

            renderLiveStatus();

        }

        catch (error) {
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
                GRAPH_SAMPLE_INTERVAL
            );
    }


    /* ============================================================
       BACKEND REFRESH POLLING
    ============================================================ */

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
                5000
            );
    }


    /* ============================================================
       RENDER ALL
    ============================================================ */

    function renderAll() {
        state.liveHistory =
            buildRollingTrafficHistory();

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
        let timer =
            null;

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

        state.range =
            "5m";

        await loadData();

        state.liveHistory =
            buildRollingTrafficHistory();

        drawTrafficChart();

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
    }

    else {
        init();
    }

})();