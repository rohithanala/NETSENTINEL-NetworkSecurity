/**
 * ============================================================
 * NETSENTINEL
 * REAL-TIME SOC DASHBOARD CONTROLLER
 * ============================================================
 *
 * Pure HTML5 Canvas dashboard visualization.
 * Chart.js is NOT required.
 *
 * Features:
 * - Live PPS graph
 * - Live BPS graph
 * - Protocol distribution
 * - Real packet telemetry
 * - Live statistics
 * - Responsive Canvas rendering
 * - Continuous graph updates
 * - Security alerts
 * - Traffic table
 * ============================================================
 */

(() => {
    "use strict";


    /* ============================================================
       CONFIGURATION
       ============================================================ */

    const GRAPH_POINTS = 30;

    const TRAFFIC_LIMIT = 500;

    const ALERT_LIMIT = 8;

    const DASHBOARD_POLL_MS = 1000;

    const ALERT_POLL_MS = 2000;

    const GRAPH_REDRAW_MS = 100;

    const GRAPH_SAMPLE_MS = 1000;


    /* ============================================================
       STATE
       ============================================================ */

    let metric = "pps";

    let trafficRecords = [];

    let alerts = [];

    let latestStats = {};

    let latestAnalytics = {};

    let latestCapture = {};

    let rateHistory = [];

    let pollTimer = null;

    let alertTimer = null;

    let chartTimer = null;

    let dashboardBusy = false;

    let alertsBusy = false;

    let lastSampleSecond = 0;


    /* ============================================================
       DOM HELPERS
       ============================================================ */

    function el(id) {

        return document.getElementById(id);
    }


    function setText(id, value) {

        const node = el(id);

        if (node) {
            node.textContent = value;
        }
    }


    /* ============================================================
       API
       ============================================================ */

    async function getJSON(url) {

        const response = await fetch(
            url,
            {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept": "application/json"
                }
            }
        );


        const body =
            await response
                .json()
                .catch(() => null);


        if (!response.ok) {

            throw new Error(
                body?.error ||
                `HTTP ${response.status}`
            );
        }


        /*
         * Support both:
         *
         * { data: [...] }
         *
         * and
         *
         * [...]
         */

        if (
            body &&
            body.data !== undefined
        ) {

            return body.data;
        }


        return body;
    }


    /* ============================================================
       FORMATTING
       ============================================================ */

    function number(
        value,
        decimals = 0
    ) {

        const n =
            Number(value);


        if (
            !Number.isFinite(n)
        ) {

            return "0";
        }


        return n.toLocaleString(
            undefined,
            {
                minimumFractionDigits:
                    decimals,

                maximumFractionDigits:
                    decimals
            }
        );
    }


    function parseTimestamp(value) {

        if (!value) {
            return null;
        }


        const raw =
            String(value);


        const hasTimezone =
            /(?:Z|[+-]\d{2}:?\d{2})$/i
                .test(raw);


        const date =
            new Date(
                hasTimezone
                    ? raw
                    : `${raw}Z`
            );


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return null;
        }


        return date;
    }


    function formatTime(value) {

        const date =
            parseTimestamp(value);


        if (!date) {
            return "—";
        }


        return date.toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        );
    }


    function timeAgo(value) {

        const date =
            parseTimestamp(value);


        if (!date) {
            return "—";
        }


        const seconds =
            Math.max(
                0,
                (
                    Date.now() -
                    date.getTime()
                ) / 1000
            );


        if (
            seconds < 2
        ) {

            return "just now";
        }


        if (
            seconds < 60
        ) {

            return `${Math.floor(
                seconds
            )}s ago`;
        }


        if (
            seconds < 3600
        ) {

            return `${Math.floor(
                seconds / 60
            )}m ago`;
        }


        if (
            seconds < 86400
        ) {

            return `${Math.floor(
                seconds / 3600
            )}h ago`;
        }


        return `${Math.floor(
            seconds / 86400
        )}d ago`;
    }


    function duration(seconds) {

        let total =
            Math.max(
                0,
                Math.floor(
                    Number(seconds) || 0
                )
            );


        const hours =
            Math.floor(
                total / 3600
            );


        total %= 3600;


        const minutes =
            Math.floor(
                total / 60
            );


        const secs =
            total % 60;


        return [
            hours,
            minutes,
            secs
        ]
            .map(
                value =>
                    String(value)
                        .padStart(
                            2,
                            "0"
                        )
            )
            .join(":");
    }


    function escapeHtml(value) {

        return String(
            value ?? ""
        )
            .replace(
                /&/g,
                "&amp;"
            )
            .replace(
                /</g,
                "&lt;"
            )
            .replace(
                />/g,
                "&gt;"
            )
            .replace(
                /"/g,
                "&quot;"
            )
            .replace(
                /'/g,
                "&#039;"
            );
    }


    function formatRate(value) {

        const n =
            Math.max(
                0,
                Number(value) || 0
            );


        if (
            n < 1000
        ) {

            return number(
                n,
                1
            );
        }


        if (
            n < 1000000
        ) {

            return `${(
                n / 1000
            ).toFixed(1)}K`;
        }


        if (
            n < 1000000000
        ) {

            return `${(
                n / 1000000
            ).toFixed(1)}M`;
        }


        return `${(
            n / 1000000000
        ).toFixed(1)}G`;
    }


    /* ============================================================
       BADGES
       ============================================================ */

    function severityBadge(
        severity
    ) {

        const value =
            String(
                severity || "LOW"
            ).toUpperCase();


        return `
            <span class="severity-badge severity-${escapeHtml(
                value.toLowerCase()
            )}">
                ${escapeHtml(value)}
            </span>
        `;
    }


    function statusBadge(
        status
    ) {

        const value =
            String(
                status || "new"
            );


        return `
            <span class="status-badge">
                ${escapeHtml(
                    value
                        .replace(
                            /_/g,
                            " "
                        )
                        .toUpperCase()
                )}
            </span>
        `;
    }


    /* ============================================================
       STATS
       ============================================================ */

    function updateStats(
        stats,
        capture
    ) {

        stats =
            stats || {};


        capture =
            capture || {};


        latestStats =
            stats;


        latestCapture =
            capture;


        const monitoring =
            Boolean(
                stats.monitoring_enabled
            );


        const captureRunning =
            Boolean(
                capture.running
            );


        const mode =
            String(
                stats.mode ||
                "LIVE"
            ).toUpperCase();


        /*
         * LIVE mode requires monitoring + capture.
         *
         * This is only for the status labels.
         * The graph itself can still display
         * historical/live packet records.
         */

        const running =
            mode === "LIVE"
                ? monitoring &&
                  captureRunning
                : monitoring;


        setText(
            "statPacketsCaptured",
            number(
                stats.packets_captured
            )
        );


        setText(
            "statActiveConnections",
            number(
                stats.active_connections
            )
        );


        setText(
            "statActiveDevices",
            number(
                stats.active_devices
            )
        );


        setText(
            "statSecurityAlerts",
            number(
                stats.security_alerts
            )
        );


        setText(
            "statThreatsDetected",
            number(
                stats.threats_detected
            )
        );


        setText(
            "statTrafficRate",
            `${number(
                stats.traffic_rate_pps,
                2
            )} pps`
        );


        setText(
            "statLastPacket",
            timeAgo(
                stats.last_packet_at
            )
        );


        setText(
            "statUptime",
            duration(
                capture.uptime_seconds ??
                stats.uptime_seconds ??
                0
            )
        );


        setText(
            "statInterface",
            stats.network_interface ||
            capture.interface ||
            "Not configured"
        );


        setText(
            "statMonitoring",
            running
                ? `ACTIVE • ${mode}`
                : "INACTIVE"
        );


        setText(
            "sensorStatus",
            running
                ? "ONLINE"
                : "OFFLINE"
        );


        setText(
            "dashStatusText",
            running
                ? "SYSTEM ONLINE"
                : "SYSTEM OFFLINE"
        );


        const dot =
            el(
                "dashStatusDot"
            );


        if (dot) {

            dot.classList.toggle(
                "status-online",
                running
            );


            dot.classList.toggle(
                "status-offline",
                !running
            );
        }
    }


    /* ============================================================
       TRAFFIC TABLE
       ============================================================ */

    function renderTraffic() {

        const body =
            el(
                "trafficRows"
            );


        if (!body) {
            return;
        }


        if (
            !Array.isArray(
                trafficRecords
            ) ||
            trafficRecords.length === 0
        ) {

            body.innerHTML = `
                <tr class="empty-row">
                    <td colspan="6">
                        Waiting for live packet telemetry...
                    </td>
                </tr>
            `;


            return;
        }


        body.innerHTML =
            trafficRecords
                .slice(
                    0,
                    15
                )
                .map(
                    record => {

                        const source =
                            record.source_ip ||
                            record.src_ip ||
                            "—";


                        const destination =
                            record.destination_ip ||
                            record.dst_ip ||
                            "—";


                        const protocol =
                            record.protocol ||
                            "OTHER";


                        const port =
                            record.destination_port ??
                            record.dst_port ??
                            record.source_port ??
                            record.src_port ??
                            "—";


                        const bytes =
                            record.packet_size ??
                            record.bytes ??
                            record.length ??
                            0;


                        return `
                            <tr>

                                <td>
                                    ${escapeHtml(
                                        formatTime(
                                            record.timestamp
                                        )
                                    )}
                                </td>

                                <td class="font-mono">
                                    ${escapeHtml(
                                        source
                                    )}
                                </td>

                                <td class="font-mono">
                                    ${escapeHtml(
                                        destination
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        String(
                                            protocol
                                        ).toUpperCase()
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        port
                                    )}
                                </td>

                                <td>
                                    ${number(
                                        bytes
                                    )}
                                </td>

                            </tr>
                        `;
                    }
                )
                .join("");
    }


    /* ============================================================
       ALERT TABLE
       ============================================================ */

    function renderAlerts() {

        const body =
            el(
                "recentAlertsBody"
            );


        if (!body) {
            return;
        }


        if (
            !Array.isArray(
                alerts
            ) ||
            alerts.length === 0
        ) {

            body.innerHTML = `
                <tr class="empty-row">
                    <td colspan="6">
                        No active security alerts.
                        IDS monitoring is running.
                    </td>
                </tr>
            `;


            return;
        }


        body.innerHTML =
            alerts
                .slice(
                    0,
                    ALERT_LIMIT
                )
                .map(
                    alert => {

                        return `
                            <tr>

                                <td>
                                    ${escapeHtml(
                                        formatTime(
                                            alert.timestamp
                                        )
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        alert.detection_type ||
                                        alert.type ||
                                        "Unknown"
                                    )}
                                </td>

                                <td class="font-mono">
                                    ${escapeHtml(
                                        alert.source_ip ||
                                        "—"
                                    )}
                                </td>

                                <td class="font-mono">
                                    ${escapeHtml(
                                        alert.destination_ip ||
                                        "—"
                                    )}
                                </td>

                                <td>
                                    ${severityBadge(
                                        alert.severity
                                    )}
                                </td>

                                <td>
                                    ${statusBadge(
                                        alert.status
                                    )}
                                </td>

                            </tr>
                        `;
                    }
                )
                .join("");
    }


    /* ============================================================
       TRAFFIC DATA HELPERS
       ============================================================ */

    function getRecordBytes(
        record
    ) {

        return Math.max(
            0,
            Number(
                record.packet_size ??
                record.bytes ??
                record.length ??
                0
            ) || 0
        );
    }


    function getTrafficTimestamp(
        record
    ) {

        const date =
            parseTimestamp(
                record.timestamp
            );


        return date
            ? date.getTime()
            : null;
    }


    /* ============================================================
       BUILD TRAFFIC HISTORY DIRECTLY FROM PACKETS
       ============================================================ */

    function buildPacketHistory() {

        const pps =
            new Array(
                GRAPH_POINTS
            ).fill(0);


        const bps =
            new Array(
                GRAPH_POINTS
            ).fill(0);


        const now =
            Date.now();


        if (
            !Array.isArray(
                trafficRecords
            )
        ) {

            return {
                pps,
                bps
            };
        }


        /*
         * IMPORTANT:
         *
         * Do NOT require the packet timestamp to be
         * inside exactly the last 30 seconds.
         *
         * We first find the newest packet timestamp.
         *
         * This allows the graph to display the actual
         * packet history returned by the API even if
         * the database timestamps are slightly behind
         * the browser clock.
         */

        const timestamps =
            trafficRecords
                .map(
                    record =>
                        getTrafficTimestamp(
                            record
                        )
                )
                .filter(
                    value =>
                        value !== null
                );


        if (
            timestamps.length === 0
        ) {

            return {
                pps,
                bps
            };
        }


        const newest =
            Math.max(
                ...timestamps
            );


        /*
         * Use browser time when packets are genuinely
         * live. Otherwise use newest packet time as the
         * graph reference.
         */

        const clockDifference =
            Math.abs(
                now -
                newest
            );


        const reference =
            clockDifference <=
            120000
                ? now
                : newest;


        /*
         * One bucket represents one second.
         */

        trafficRecords.forEach(
            record => {

                const timestamp =
                    getTrafficTimestamp(
                        record
                    );


                if (
                    timestamp === null
                ) {
                    return;
                }


                const age =
                    Math.floor(
                        (
                            reference -
                            timestamp
                        ) / 1000
                    );


                /*
                 * Ignore packets that are ahead of
                 * the reference clock.
                 */

                if (
                    age < 0
                ) {
                    return;
                }


                /*
                 * Keep the last 30 seconds.
                 */

                if (
                    age >= GRAPH_POINTS
                ) {
                    return;
                }


                const index =
                    GRAPH_POINTS -
                    1 -
                    age;


                pps[index] += 1;


                bps[index] +=
                    getRecordBytes(
                        record
                    ) * 8;
            }
        );


        return {
            pps,
            bps
        };
    }


    /* ============================================================
       LIVE RATE HISTORY
       ============================================================ */

    function addCurrentRateSample() {

        const now =
            Math.floor(
                Date.now() / 1000
            );


        if (
            now ===
            lastSampleSecond
        ) {

            return;
        }


        lastSampleSecond =
            now;


        const pps =
            Math.max(
                0,
                Number(
                    latestStats
                        .traffic_rate_pps
                ) || 0
            );


        const bps =
            Math.max(
                0,
                Number(
                    latestStats
                        .traffic_rate_bps
                ) || 0
            );


        /*
         * Always record the sample.
         *
         * Even zero is useful because it allows
         * the graph to fall naturally.
         */

        rateHistory.push(
            {
                timestamp: now,
                pps,
                bps
            }
        );


        while (
            rateHistory.length >
            GRAPH_POINTS
        ) {

            rateHistory.shift();
        }
    }


    /* ============================================================
       FINAL GRAPH DATA
       ============================================================ */

    function buildGraphData() {

        const packetHistory =
            buildPacketHistory();


        const pps =
            packetHistory.pps.slice();


        const bps =
            packetHistory.bps.slice();


        /*
         * Overlay live statistics.
         *
         * Only use non-zero live values so a stopped
         * capture does not erase packet history.
         */

        rateHistory.forEach(
            sample => {

                const now =
                    Math.floor(
                        Date.now() / 1000
                    );


                const age =
                    now -
                    sample.timestamp;


                if (
                    age < 0 ||
                    age >= GRAPH_POINTS
                ) {

                    return;
                }


                const index =
                    GRAPH_POINTS -
                    1 -
                    age;


                if (
                    sample.pps > 0
                ) {

                    pps[index] =
                        Math.max(
                            pps[index],
                            sample.pps
                        );
                }


                if (
                    sample.bps > 0
                ) {

                    bps[index] =
                        Math.max(
                            bps[index],
                            sample.bps
                        );
                }
            }
        );


        /*
         * Current live statistics are used as the
         * final point when there is no packet count
         * in the current bucket.
         */

        const currentPps =
            Number(
                latestStats
                    .traffic_rate_pps
            ) || 0;


        const currentBps =
            Number(
                latestStats
                    .traffic_rate_bps
            ) || 0;


        const last =
            GRAPH_POINTS - 1;


        if (
            currentPps > 0
        ) {

            pps[last] =
                Math.max(
                    pps[last],
                    currentPps
                );
        }


        if (
            currentBps > 0
        ) {

            bps[last] =
                Math.max(
                    bps[last],
                    currentBps
                );
        }


        return {
            pps,
            bps
        };
    }


    /* ============================================================
       CANVAS PREPARATION
       ============================================================ */

    function prepareCanvas(
        canvas,
        height = 320
    ) {

        if (!canvas) {
            return null;
        }


        const parent =
            canvas.parentElement;


        const rect =
            parent
                ? parent.getBoundingClientRect()
                : canvas.getBoundingClientRect();


        const width =
            Math.max(
                320,
                Math.floor(
                    rect.width ||
                    canvas.clientWidth ||
                    600
                )
            );


        const dpr =
            Math.min(
                window.devicePixelRatio ||
                1,
                2
            );


        /*
         * Reset physical resolution.
         */

        canvas.width =
            Math.floor(
                width * dpr
            );


        canvas.height =
            Math.floor(
                height * dpr
            );


        canvas.style.width =
            "100%";


        canvas.style.height =
            `${height}px`;


        const ctx =
            canvas.getContext(
                "2d"
            );


        if (!ctx) {
            return null;
        }


        ctx.setTransform(
            dpr,
            0,
            0,
            dpr,
            0,
            0
        );


        ctx.clearRect(
            0,
            0,
            width,
            height
        );


        return {
            ctx,
            width,
            height
        };
    }


    /* ============================================================
       TRAFFIC GRAPH
       ============================================================ */

    function drawTrafficChart() {

        const canvas =
            el(
                "liveTrafficChart"
            );


        if (!canvas) {
            return;
        }


        const prepared =
            prepareCanvas(
                canvas,
                320
            );


        if (!prepared) {
            return;
        }


        const {
            ctx,
            width,
            height
        } = prepared;


        const left = 65;

        const right = 25;

        const top = 28;

        const bottom = 42;


        const plotWidth =
            Math.max(
                10,
                width -
                left -
                right
            );


        const plotHeight =
            Math.max(
                10,
                height -
                top -
                bottom
            );


        const graph =
            buildGraphData();


        const values =
            metric === "pps"
                ? graph.pps
                : graph.bps;


        /*
         * Scale.
         *
         * The previous minimum scale of 5 could make
         * small traffic appear almost invisible.
         *
         * We dynamically scale according to the data.
         */

        const maximum =
            Math.max(
                ...values,
                0
            );


        const minimumScale =
            metric === "pps"
                ? 5
                : 1000;


        let scale =
            Math.max(
                minimumScale,
                maximum
            );


        /*
         * Give the graph some vertical headroom.
         */

        if (
            scale > 0
        ) {

            scale *= 1.20;
        }


        /*
         * Background.
         */

        const background =
            ctx.createLinearGradient(
                0,
                0,
                0,
                height
            );


        background.addColorStop(
            0,
            "rgba(8,22,31,0.34)"
        );


        background.addColorStop(
            1,
            "rgba(3,12,18,0.12)"
        );


        ctx.fillStyle =
            background;


        ctx.fillRect(
            0,
            0,
            width,
            height
        );


        /*
         * Plot border.
         */

        ctx.strokeStyle =
            "rgba(100,180,210,0.12)";


        ctx.lineWidth =
            1;


        ctx.strokeRect(
            left,
            top,
            plotWidth,
            plotHeight
        );


        /*
         * Horizontal grid.
         */

        for (
            let i = 0;
            i <= 4;
            i++
        ) {

            const ratio =
                i / 4;


            const y =
                top +
                plotHeight -
                ratio *
                plotHeight;


            ctx.beginPath();


            ctx.moveTo(
                left,
                y
            );


            ctx.lineTo(
                width - right,
                y
            );


            ctx.strokeStyle =
                "rgba(100,180,210,0.14)";


            ctx.stroke();


            ctx.fillStyle =
                "rgba(170,200,215,0.72)";


            ctx.font =
                "11px Segoe UI";


            ctx.textAlign =
                "right";


            ctx.textBaseline =
                "middle";


            if (
                metric === "pps"
            ) {

                ctx.fillText(
                    formatRate(
                        scale *
                        ratio
                    ),
                    left - 10,
                    y
                );

            } else {

                ctx.fillText(
                    `${formatRate(
                        scale *
                        ratio
                    )} bps`,
                    left - 10,
                    y
                );
            }
        }


        /*
         * Vertical grid.
         */

        for (
            let i = 0;
            i < GRAPH_POINTS;
            i += 5
        ) {

            const x =
                left +
                (
                    i /
                    (
                        GRAPH_POINTS -
                        1
                    )
                ) *
                plotWidth;


            ctx.beginPath();


            ctx.moveTo(
                x,
                top
            );


            ctx.lineTo(
                x,
                top +
                plotHeight
            );


            ctx.strokeStyle =
                "rgba(100,180,210,0.07)";


            ctx.stroke();
        }


        /*
         * Check for usable data.
         */

        const hasTraffic =
            values.some(
                value =>
                    Number(value) > 0
            );


        /*
         * Empty state.
         */

        if (
            !hasTraffic
        ) {

            ctx.fillStyle =
                "rgba(160,190,205,0.82)";


            ctx.font =
                "600 14px Segoe UI";


            ctx.textAlign =
                "center";


            ctx.textBaseline =
                "middle";


            const message =
                trafficRecords.length > 0
                    ? "PACKET DATA RECEIVED — WAITING FOR RATE SAMPLE"
                    : latestStats.monitoring_enabled
                        ? "WAITING FOR LIVE TRAFFIC..."
                        : "START NETWORK CAPTURE TO DISPLAY TRAFFIC";


            ctx.fillText(
                message,
                width / 2,
                height / 2
            );


            drawTimeLabels(
                ctx,
                width,
                height,
                left,
                plotWidth
            );


            return;
        }


        /*
         * Convert values into points.
         */

        const points =
            values.map(
                (
                    value,
                    index
                ) => {

                    const x =
                        left +
                        (
                            index /
                            (
                                GRAPH_POINTS -
                                1
                            )
                        ) *
                        plotWidth;


                    const normalized =
                        Math.min(
                            1,
                            Math.max(
                                0,
                                value /
                                scale
                            )
                        );


                    const y =
                        top +
                        plotHeight -
                        normalized *
                        plotHeight;


                    return {
                        x,
                        y,
                        value
                    };
                }
            );


        /*
         * Area fill.
         */

        const areaGradient =
            ctx.createLinearGradient(
                0,
                top,
                0,
                top +
                plotHeight
            );


        areaGradient.addColorStop(
            0,
            "rgba(69,221,255,0.32)"
        );


        areaGradient.addColorStop(
            0.55,
            "rgba(69,221,255,0.12)"
        );


        areaGradient.addColorStop(
            1,
            "rgba(69,221,255,0.01)"
        );


        ctx.beginPath();


        ctx.moveTo(
            points[0].x,
            top +
            plotHeight
        );


        points.forEach(
            point => {

                ctx.lineTo(
                    point.x,
                    point.y
                );
            }
        );


        ctx.lineTo(
            points[
                points.length - 1
            ].x,
            top +
            plotHeight
        );


        ctx.closePath();


        ctx.fillStyle =
            areaGradient;


        ctx.fill();


        /*
         * Main line.
         */

        ctx.beginPath();


        points.forEach(
            (
                point,
                index
            ) => {

                if (
                    index === 0
                ) {

                    ctx.moveTo(
                        point.x,
                        point.y
                    );


                    return;
                }


                const previous =
                    points[
                        index - 1
                    ];


                const middleX =
                    (
                        previous.x +
                        point.x
                    ) / 2;


                ctx.quadraticCurveTo(
                    previous.x,
                    previous.y,
                    middleX,
                    (
                        previous.y +
                        point.y
                    ) / 2
                );


                ctx.quadraticCurveTo(
                    middleX,
                    (
                        previous.y +
                        point.y
                    ) / 2,
                    point.x,
                    point.y
                );
            }
        );


        ctx.strokeStyle =
            "#45ddff";


        ctx.lineWidth =
            2.5;


        ctx.lineJoin =
            "round";


        ctx.lineCap =
            "round";


        ctx.shadowBlur =
            12;


        ctx.shadowColor =
            "rgba(69,221,255,0.65)";


        ctx.stroke();


        ctx.shadowBlur =
            0;


        /*
         * Highlight all non-zero points subtly.
         */

        points.forEach(
            point => {

                if (
                    point.value <= 0
                ) {

                    return;
                }


                ctx.beginPath();


                ctx.arc(
                    point.x,
                    point.y,
                    2.5,
                    0,
                    Math.PI * 2
                );


                ctx.fillStyle =
                    "#45ddff";


                ctx.fill();
            }
        );


        /*
         * Highlight current point.
         */

        const latest =
            points[
                points.length - 1
            ];


        if (
            latest.value > 0
        ) {

            ctx.beginPath();


            ctx.arc(
                latest.x,
                latest.y,
                5,
                0,
                Math.PI * 2
            );


            ctx.fillStyle =
                "#ffffff";


            ctx.shadowBlur =
                18;


            ctx.shadowColor =
                "#45ddff";


            ctx.fill();


            ctx.shadowBlur =
                0;
        }


        /*
         * Current value.
         */

        ctx.fillStyle =
            "#a9eaff";


        ctx.font =
            "600 13px Segoe UI";


        ctx.textAlign =
            "right";


        ctx.textBaseline =
            "alphabetic";


        if (
            metric === "pps"
        ) {

            ctx.fillText(
                `${number(
                    latest.value,
                    2
                )} pps`,
                width - right,
                top
            );

        } else {

            ctx.fillText(
                `${formatRate(
                    latest.value
                )} bps`,
                width - right,
                top
            );
        }


        drawTimeLabels(
            ctx,
            width,
            height,
            left,
            plotWidth
        );
    }


    /* ============================================================
       TIME LABELS
       ============================================================ */

    function drawTimeLabels(
        ctx,
        width,
        height,
        left,
        plotWidth
    ) {

        ctx.fillStyle =
            "rgba(150,180,195,0.65)";


        ctx.font =
            "10px Segoe UI";


        ctx.textAlign =
            "center";


        ctx.textBaseline =
            "alphabetic";


        const labels = [
            {
                index: 0,
                text: "30s"
            },
            {
                index: 10,
                text: "20s"
            },
            {
                index: 20,
                text: "10s"
            },
            {
                index: 29,
                text: "NOW"
            }
        ];


        labels.forEach(
            label => {

                const x =
                    left +
                    (
                        label.index /
                        (
                            GRAPH_POINTS -
                            1
                        )
                    ) *
                    plotWidth;


                ctx.fillText(
                    label.text,
                    x,
                    height - 15
                );
            }
        );
    }


    /* ============================================================
       PROTOCOL DISTRIBUTION
       ============================================================ */

    function getProtocolDistribution() {

        const result = {
            TCP: 0,
            UDP: 0,
            ICMP: 0,
            OTHER: 0
        };


        const distribution =
            latestAnalytics
                ?.protocol_distribution;


        if (
            distribution &&
            typeof distribution ===
            "object"
        ) {

            Object.entries(
                distribution
            ).forEach(
                (
                    [
                        protocol,
                        count
                    ]
                ) => {

                    const normalized =
                        String(
                            protocol ||
                            "OTHER"
                        )
                            .trim()
                            .toUpperCase();


                    const numeric =
                        Number(
                            count
                        ) || 0;


                    if (
                        normalized ===
                        "TCP"
                    ) {

                        result.TCP +=
                            numeric;

                    } else if (
                        normalized ===
                        "UDP"
                    ) {

                        result.UDP +=
                            numeric;

                    } else if (
                        normalized ===
                        "ICMP" ||
                        normalized ===
                        "ICMPV4" ||
                        normalized ===
                        "ICMPV6"
                    ) {

                        result.ICMP +=
                            numeric;

                    } else {

                        result.OTHER +=
                            numeric;
                    }
                }
            );
        }


        let total =
            Object.values(
                result
            ).reduce(
                (
                    sum,
                    value
                ) =>
                    sum + value,
                0
            );


        /*
         * Fallback to packet telemetry.
         */

        if (
            total === 0 &&
            trafficRecords.length > 0
        ) {

            trafficRecords.forEach(
                record => {

                    const protocol =
                        String(
                            record.protocol ||
                            "OTHER"
                        )
                            .trim()
                            .toUpperCase();


                    if (
                        protocol ===
                        "TCP"
                    ) {

                        result.TCP++;

                    } else if (
                        protocol ===
                        "UDP"
                    ) {

                        result.UDP++;

                    } else if (
                        protocol ===
                        "ICMP" ||
                        protocol ===
                        "ICMPV4" ||
                        protocol ===
                        "ICMPV6"
                    ) {

                        result.ICMP++;

                    } else {

                        result.OTHER++;
                    }
                }
            );
        }


        return result;
    }


    /* ============================================================
       PROTOCOL CHART
       ============================================================ */

    function drawProtocolChart() {

        const canvas =
            el(
                "protocolChart"
            );


        if (!canvas) {
            return;
        }


        const prepared =
            prepareCanvas(
                canvas,
                320
            );


        if (!prepared) {
            return;
        }


        const {
            ctx,
            width,
            height
        } = prepared;


        const counts =
            getProtocolDistribution();


        const labels = [
            "TCP",
            "UDP",
            "ICMP",
            "OTHER"
        ];


        const values = [
            counts.TCP,
            counts.UDP,
            counts.ICMP,
            counts.OTHER
        ];


        const colors = [
            "#45ddff",
            "#4ee39a",
            "#ffc857",
            "#8995a3"
        ];


        const total =
            values.reduce(
                (
                    sum,
                    value
                ) =>
                    sum + value,
                0
            );


        const cx =
            width / 2;


        const cy =
            125;


        const radius =
            Math.min(
                88,
                Math.max(
                    65,
                    width * 0.20
                )
            );


        const ringWidth =
            Math.max(
                20,
                radius * 0.34
            );


        ctx.fillStyle =
            "rgba(8,22,31,0.10)";


        ctx.fillRect(
            0,
            0,
            width,
            height
        );


        /*
         * Empty state.
         */

        if (
            total === 0
        ) {

            ctx.beginPath();


            ctx.arc(
                cx,
                cy,
                radius,
                0,
                Math.PI * 2
            );


            ctx.strokeStyle =
                "rgba(130,160,175,0.18)";


            ctx.lineWidth =
                ringWidth;


            ctx.stroke();


            ctx.fillStyle =
                "#edfaff";


            ctx.font =
                "700 22px Segoe UI";


            ctx.textAlign =
                "center";


            ctx.textBaseline =
                "middle";


            ctx.fillText(
                "0",
                cx,
                cy - 6
            );


            ctx.fillStyle =
                "#8298a5";


            ctx.font =
                "10px Segoe UI";


            ctx.fillText(
                "NO DATA",
                cx,
                cy + 18
            );

        } else {

            let start =
                -Math.PI / 2;


            values.forEach(
                (
                    value,
                    index
                ) => {

                    if (
                        value <= 0
                    ) {

                        return;
                    }


                    const angle =
                        (
                            value /
                            total
                        ) *
                        Math.PI *
                        2;


                    ctx.beginPath();


                    ctx.arc(
                        cx,
                        cy,
                        radius,
                        start,
                        start +
                        angle
                    );


                    ctx.strokeStyle =
                        colors[index];


                    ctx.lineWidth =
                        ringWidth;


                    ctx.lineCap =
                        "butt";


                    ctx.shadowBlur =
                        8;


                    ctx.shadowColor =
                        colors[index];


                    ctx.stroke();


                    ctx.shadowBlur =
                        0;


                    start +=
                        angle;
                }
            );


            /*
             * Center value.
             */

            ctx.textAlign =
                "center";


            ctx.textBaseline =
                "middle";


            ctx.fillStyle =
                "#edfaff";


            ctx.font =
                "700 25px Segoe UI";


            ctx.fillText(
                number(total),
                cx,
                cy - 8
            );


            ctx.fillStyle =
                "#8298a5";


            ctx.font =
                "10px Segoe UI";


            ctx.fillText(
                "TOTAL PACKETS",
                cx,
                cy + 18
            );
        }


        /*
         * Legend.
         */

        labels.forEach(
            (
                label,
                index
            ) => {

                const column =
                    index % 2;


                const row =
                    Math.floor(
                        index / 2
                    );


                const x =
                    35 +
                    column *
                    (
                        width / 2
                    );


                const y =
                    230 +
                    row * 30;


                ctx.beginPath();


                ctx.arc(
                    x,
                    y,
                    4,
                    0,
                    Math.PI * 2
                );


                ctx.fillStyle =
                    colors[index];


                ctx.fill();


                ctx.textAlign =
                    "left";


                ctx.textBaseline =
                    "alphabetic";


                ctx.fillStyle =
                    "#a8bac4";


                ctx.font =
                    "12px Segoe UI";


                const percentage =
                    total > 0
                        ? (
                            values[index] /
                            total *
                            100
                        )
                        : 0;


                ctx.fillText(
                    `${label} ${number(
                        values[index]
                    )} (${percentage.toFixed(
                        1
                    )}%)`,
                    x + 11,
                    y + 4
                );
            }
        );
    }


    /* ============================================================
       DASHBOARD REFRESH
       ============================================================ */

    async function refreshDashboard() {

        if (
            dashboardBusy
        ) {

            return;
        }


        dashboardBusy =
            true;


        try {

            let stats = {};

            let traffic = {};

            let capture = {};

            let analytics = {};


            /*
             * STATS
             */

            try {

                stats =
                    await getJSON(
                        "/api/stats"
                    );

            } catch (error) {

                console.error(
                    "NETSENTINEL stats error:",
                    error
                );
            }


            /*
             * TRAFFIC
             */

            try {

                traffic =
                    await getJSON(
                        `/api/traffic?limit=${TRAFFIC_LIMIT}`
                    );

            } catch (error) {

                console.error(
                    "NETSENTINEL traffic error:",
                    error
                );
            }


            /*
             * CAPTURE
             */

            try {

                capture =
                    await getJSON(
                        "/api/capture/status"
                    );

            } catch (error) {

                console.error(
                    "NETSENTINEL capture error:",
                    error
                );
            }


            /*
             * ANALYTICS
             */

            try {

                analytics =
                    await getJSON(
                        "/api/analytics"
                    );

            } catch (error) {

                /*
                 * Analytics endpoint is optional.
                 * Do not break the dashboard if it
                 * is unavailable.
                 */

                console.warn(
                    "NETSENTINEL analytics unavailable:",
                    error
                );
            }


            latestAnalytics =
                analytics || {};


            /*
             * TRAFFIC RECORDS
             */

            if (
                Array.isArray(
                    traffic
                )
            ) {

                trafficRecords =
                    traffic;

            } else if (
                Array.isArray(
                    traffic?.records
                )
            ) {

                trafficRecords =
                    traffic.records;

            } else {

                trafficRecords =
                    [];
            }


            /*
             * STATS
             */

            updateStats(
                stats,
                capture
            );


            /*
             * LIVE SAMPLE
             */

            addCurrentRateSample();


            /*
             * TABLES
             */

            renderTraffic();


            /*
             * GRAPHS
             */

            drawTrafficChart();

            drawProtocolChart();


        } catch (error) {

            console.error(
                "NETSENTINEL dashboard error:",
                error
            );


            setText(
                "dashStatusText",
                "API ERROR"
            );


            setText(
                "sensorStatus",
                "API ERROR"
            );

        } finally {

            dashboardBusy =
                false;
        }
    }


    /* ============================================================
       ALERT REFRESH
       ============================================================ */

    async function refreshAlerts() {

        if (
            alertsBusy
        ) {

            return;
        }


        alertsBusy =
            true;


        try {

            const response =
                await getJSON(
                    "/api/alerts?limit=100"
                );


            if (
                Array.isArray(
                    response
                )
            ) {

                alerts =
                    response;

            } else if (
                Array.isArray(
                    response?.records
                )
            ) {

                alerts =
                    response.records;

            } else {

                alerts =
                    [];
            }


            renderAlerts();


        } catch (error) {

            console.error(
                "NETSENTINEL alerts error:",
                error
            );


            const body =
                el(
                    "recentAlertsBody"
                );


            if (body) {

                body.innerHTML = `
                    <tr class="empty-row">
                        <td colspan="6">
                            Unable to load alert telemetry.
                        </td>
                    </tr>
                `;
            }

        } finally {

            alertsBusy =
                false;
        }
    }


    /* ============================================================
       METRIC TOGGLE
       ============================================================ */

    function initMetricToggle() {

        const toggle =
            el(
                "trafficChartToggle"
            );


        if (!toggle) {
            return;
        }


        toggle.addEventListener(
            "click",
            event => {

                const button =
                    event.target.closest(
                        ".chip"
                    );


                if (!button) {
                    return;
                }


                const selected =
                    button.dataset.metric;


                if (
                    ![
                        "pps",
                        "bps"
                    ].includes(
                        selected
                    )
                ) {

                    return;
                }


                metric =
                    selected;


                toggle
                    .querySelectorAll(
                        ".chip"
                    )
                    .forEach(
                        chip => {

                            chip.classList.remove(
                                "active"
                            );
                        }
                    );


                button.classList.add(
                    "active"
                );


                drawTrafficChart();
            }
        );
    }


    /* ============================================================
       RESIZE
       ============================================================ */

    function initResize() {

        let frame =
            null;


        window.addEventListener(
            "resize",
            () => {

                if (frame) {

                    cancelAnimationFrame(
                        frame
                    );
                }


                frame =
                    requestAnimationFrame(
                        () => {

                            drawTrafficChart();

                            drawProtocolChart();
                        }
                    );
            }
        );
    }


    /* ============================================================
       GRAPH ANIMATION
       ============================================================ */

    function startGraphAnimation() {

        if (
            chartTimer
        ) {

            clearInterval(
                chartTimer
            );
        }


        chartTimer =
            setInterval(
                () => {

                    /*
                     * Only add a new sample when
                     * a new second has started.
                     */

                    addCurrentRateSample();


                    /*
                     * Redraw frequently for a
                     * smooth visual refresh.
                     */

                    drawTrafficChart();

                    drawProtocolChart();

                },
                GRAPH_REDRAW_MS
            );
    }


    /* ============================================================
       POLLING
       ============================================================ */

    function startPolling() {

        if (
            pollTimer
        ) {

            clearInterval(
                pollTimer
            );
        }


        if (
            alertTimer
        ) {

            clearInterval(
                alertTimer
            );
        }


        if (
            chartTimer
        ) {

            clearInterval(
                chartTimer
            );
        }


        pollTimer =
            setInterval(
                refreshDashboard,
                DASHBOARD_POLL_MS
            );


        alertTimer =
            setInterval(
                refreshAlerts,
                ALERT_POLL_MS
            );


        chartTimer =
            setInterval(
                () => {

                    addCurrentRateSample();

                    drawTrafficChart();

                    drawProtocolChart();

                },
                GRAPH_REDRAW_MS
            );
    }


    /* ============================================================
       INITIALIZATION
       ============================================================ */

    function init() {

        console.info(
            "NETSENTINEL: Initializing SOC dashboard..."
        );


        initMetricToggle();


        initResize();


        /*
         * Draw immediately.
         */

        drawTrafficChart();

        drawProtocolChart();


        renderTraffic();

        renderAlerts();


        /*
         * Load data immediately.
         */

        refreshDashboard();

        refreshAlerts();


        /*
         * Start polling.
         */

        startPolling();


        /*
         * Start graph animation.
         */

        startGraphAnimation();


        console.info(
            "NETSENTINEL: SOC dashboard initialized."
        );
    }


    /* ============================================================
       BOOT
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