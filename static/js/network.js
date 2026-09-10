"use strict";

/*
 * ============================================================
 * NETSENTINEL — NETWORK COMMAND MAP
 * ============================================================
 * Real-time network topology renderer
 *
 * IMPORTANT:
 * Device inventory = ACTIVE LOCAL DEVICES only.
 *
 * Active-device definition:
 *   - private/local IP
 *   - seen within the last 5 minutes
 *
 * Public Internet endpoints and multicast addresses are shown
 * only as external traffic endpoints in the topology.
 * They are NOT counted as physical devices.
 * ============================================================
 */

/* ============================================================
   CONFIGURATION
============================================================ */

const DEVICE_LIMIT = 500;
const TRAFFIC_LIMIT = 500;
const POLL_INTERVAL = 2500;

const ACTIVE_DEVICE_WINDOW_MS = 5 * 60 * 1000;

const MAX_LOCAL_NODES = 7;
const MAX_EXTERNAL_NODES = 9;

const PARTICLE_COUNT = 45;


/* ============================================================
   STATE
============================================================ */

let devices = [];
let traffic = [];
let stats = {};

let topologyNodes = [];
let topologyEdges = [];
let particles = [];

let animationFrame = null;
let topologyPaused = false;


/* ============================================================
   DOM
============================================================ */

const canvas =
    document.getElementById("networkCanvas");

const deviceRows =
    document.getElementById("networkRows");

const searchInput =
    document.getElementById("deviceSearch");

const statusFilter =
    document.getElementById("statusFilter");

const refreshButton =
    document.getElementById("refreshButton");

const resetTopologyButton =
    document.getElementById("resetTopology");

const topologyEmpty =
    document.getElementById("topologyEmpty");

const interfaceName =
    document.getElementById("interfaceName");

const sensorStatus =
    document.getElementById("networkSensorStatus");

const inventoryCount =
    document.getElementById("inventoryCount");


/* ============================================================
   CANVAS
============================================================ */

let ctx = null;

if (canvas) {
    ctx = canvas.getContext("2d");
}


/* ============================================================
   BASIC HELPERS
============================================================ */

function num(value) {
    const n = Number(value);

    return Number.isFinite(n)
        ? n
        : 0;
}


function esc(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function getIp(device) {
    return (
        device?.ip_address ||
        device?.ip ||
        device?.source_ip ||
        "Unknown"
    );
}


function getMac(device) {
    return (
        device?.mac_address ||
        device?.mac ||
        device?.macAddress ||
        device?.hardware_address ||
        ""
    );
}


function getHostname(device) {
    return (
        device?.hostname ||
        device?.host_name ||
        device?.hostname_resolved ||
        device?.dns_name ||
        device?.name ||
        "Unknown"
    );
}


function getPacketCount(device) {
    return num(
        device?.packet_count ??
        device?.packets ??
        device?.packets_observed ??
        device?.total_packets ??
        0
    );
}


function formatMac(mac) {
    if (!mac) {
        return "N/A";
    }

    const value =
        String(mac)
            .trim()
            .toUpperCase();

    const clean =
        value.replace(
            /[^0-9A-F]/g,
            ""
        );

    if (clean.length === 12) {
        return clean
            .match(/.{2}/g)
            .join(":");
    }

    return value;
}


function formatNumber(value) {
    return num(value).toLocaleString();
}


function formatTime(timestamp) {
    if (!timestamp) {
        return "—";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return date.toLocaleTimeString();
}


function timestampMs(timestamp) {
    if (!timestamp) {
        return null;
    }

    const value =
        new Date(timestamp).getTime();

    return Number.isFinite(value)
        ? value
        : null;
}


/* ============================================================
   IP CLASSIFICATION
============================================================ */

function isIPv4(ip) {
    const value =
        String(ip || "").trim();

    const parts =
        value.split(".");

    if (parts.length !== 4) {
        return false;
    }

    return parts.every(
        part =>
            /^\d+$/.test(part) &&
            Number(part) >= 0 &&
            Number(part) <= 255
    );
}


function isIPv6(ip) {
    return String(ip || "").includes(":");
}


function isPrivateIPv4(ip) {
    if (!isIPv4(ip)) {
        return false;
    }

    const parts =
        String(ip)
            .split(".")
            .map(Number);

    if (parts[0] === 10) {
        return true;
    }

    if (
        parts[0] === 172 &&
        parts[1] >= 16 &&
        parts[1] <= 31
    ) {
        return true;
    }

    if (
        parts[0] === 192 &&
        parts[1] === 168
    ) {
        return true;
    }

    if (parts[0] === 127) {
        return true;
    }

    if (
        parts[0] === 169 &&
        parts[1] === 254
    ) {
        return true;
    }

    return false;
}


function isLocalAddress(ip) {
    const value =
        String(ip || "")
            .toLowerCase()
            .trim();

    if (!value) {
        return false;
    }

    if (
        value ===
        "localhost"
    ) {
        return true;
    }

    if (
        value ===
        "::1"
    ) {
        return true;
    }

    if (
        isPrivateIPv4(
            value
        )
    ) {
        return true;
    }

    if (
        value.startsWith(
            "fe80:"
        )
    ) {
        return true;
    }

    if (
        value.startsWith(
            "fc"
        )
    ) {
        return true;
    }

    if (
        value.startsWith(
            "fd"
        )
    ) {
        return true;
    }

    return false;
}


function isMulticastAddress(ip) {
    const value =
        String(ip || "")
            .toLowerCase()
            .trim();

    if (!value) {
        return false;
    }

    if (
        isIPv4(value)
    ) {
        const first =
            Number(
                value.split(".")[0]
            );

        return (
            first >= 224 &&
            first <= 239
        );
    }

    if (
        isIPv6(value)
    ) {
        return (
            value.startsWith("ff")
        );
    }

    return false;
}


function isUsableExternalEndpoint(ip) {
    if (!ip) {
        return false;
    }

    if (
        isMulticastAddress(ip)
    ) {
        return false;
    }

    if (
        String(ip) ===
        "255.255.255.255"
    ) {
        return false;
    }

    return true;
}


function shortenIp(ip) {
    const value =
        String(ip || "Unknown");

    if (value.length <= 20) {
        return value;
    }

    if (
        value.includes(":")
    ) {
        const parts =
            value.split(":");

        if (
            parts.length >= 5
        ) {
            return (
                parts
                    .slice(0, 2)
                    .join(":") +
                ":…" +
                parts
                    .slice(-2)
                    .join(":")
            );
        }
    }

    return (
        value.slice(0, 8) +
        "…" +
        value.slice(-6)
    );
}


/* ============================================================
   STATUS
============================================================ */

function normalizeStatus(device) {
    const status =
        String(
            device?.status || ""
        )
            .trim()
            .toLowerCase();

    if (
        status ===
            "critical" ||
        status ===
            "danger"
    ) {
        return "CRITICAL";
    }

    if (
        status ===
            "suspicious" ||
        status ===
            "warning"
    ) {
        return "SUSPICIOUS";
    }

    if (
        status ===
            "inactive" ||
        status ===
            "offline"
    ) {
        return "INACTIVE";
    }

    return "ONLINE";
}


function statusClass(status) {
    switch (
        String(status)
            .toUpperCase()
    ) {
        case "CRITICAL":
            return "status-critical";

        case "SUSPICIOUS":
            return "status-suspicious";

        case "INACTIVE":
            return "status-inactive";

        default:
            return "status-online";
    }
}


/* ============================================================
   API
============================================================ */

async function fetchJSON(url) {
    const response =
        await fetch(
            url,
            {
                cache: "no-store"
            }
        );

    if (!response.ok) {
        throw new Error(
            `${response.status} ${response.statusText}`
        );
    }

    return response.json();
}


/* ============================================================
   ACTIVE DEVICE LOGIC
============================================================ */

/*
 * Backend stats already defines active devices using the
 * five-minute activity window.
 *
 * The Network page now follows the same concept:
 *   - local/private IP only
 *   - last_seen within five minutes
 */

function getActivityReferenceMs() {
    const latest =
        timestampMs(
            stats?.last_packet_at
        );

    return latest ||
        Date.now();
}


function isActiveDevice(device) {
    const ip =
        getIp(device);

    if (
        !ip ||
        ip === "Unknown"
    ) {
        return false;
    }

    if (
        !isLocalAddress(ip)
    ) {
        return false;
    }

    const lastSeen =
        timestampMs(
            device?.last_seen
        );

    if (
        lastSeen === null
    ) {
        return false;
    }

    const reference =
        getActivityReferenceMs();

    const age =
        Math.abs(
            reference -
            lastSeen
        );

    return (
        age <=
        ACTIVE_DEVICE_WINDOW_MS
    );
}


function uniqueActiveLocalDevices() {
    const map =
        new Map();

    for (
        const device of devices
    ) {
        if (
            !isActiveDevice(
                device
            )
        ) {
            continue;
        }

        const ip =
            getIp(device);

        if (
            !map.has(ip)
        ) {
            map.set(
                ip,
                device
            );
        }
    }

    return Array.from(
        map.values()
    );
}


/* ============================================================
   STATISTICS
============================================================ */

function renderStats() {
    const activeDevices =
        document.getElementById(
            "activeDevices"
        );

    const activeConnections =
        document.getElementById(
            "activeConnections"
        );

    const packetsObserved =
        document.getElementById(
            "packetsObserved"
        );

    const ipv6Devices =
        document.getElementById(
            "ipv6Devices"
        );

    const activeLocalDevices =
        uniqueActiveLocalDevices();

    const ipv6Count =
        activeLocalDevices.filter(
            device =>
                isIPv6(
                    getIp(device)
                )
        ).length;

    /*
     * The backend is authoritative for the headline count.
     * Fallback uses the same local active-device definition.
     */

    const activeCount =
        Number.isFinite(
            Number(
                stats?.active_devices
            )
        )
            ? num(
                stats.active_devices
            )
            : activeLocalDevices.length;

    if (
        activeDevices
    ) {
        activeDevices.textContent =
            formatNumber(
                activeCount
            );
    }

    if (
        activeConnections
    ) {
        activeConnections.textContent =
            formatNumber(
                stats.active_connections ??
                0
            );
    }

    if (
        packetsObserved
    ) {
        packetsObserved.textContent =
            formatNumber(
                stats.packets_captured ??
                0
            );
    }

    if (
        ipv6Devices
    ) {
        ipv6Devices.textContent =
            formatNumber(
                ipv6Count
            );
    }
}


/* ============================================================
   SENSOR STATE
============================================================ */

function renderSensorState() {
    const capture =
        stats.capture || {};

    const running =
        Boolean(
            capture.running
        );

    if (
        sensorStatus
    ) {
        sensorStatus.textContent =
            running
                ? "CAPTURE ACTIVE"
                : "CAPTURE OFFLINE";

        sensorStatus.style.color =
            running
                ? "#70e0a1"
                : "#ff7373";
    }

    if (
        interfaceName
    ) {
        const iface =
            stats.network_interface ||
            capture.interface ||
            "AUTO";

        interfaceName.textContent =
            `Interface: ${iface}`;
    }
}


/* ============================================================
   DEVICE FILTERING
============================================================ */

function filteredDevices() {
    const search =
        (
            searchInput?.value ||
            ""
        )
            .trim()
            .toLowerCase();

    const selectedStatus =
        (
            statusFilter?.value ||
            "ALL"
        )
            .toUpperCase();

    const activeLocalDevices =
        uniqueActiveLocalDevices();

    return activeLocalDevices.filter(
        device => {
            const ip =
                getIp(device);

            const mac =
                getMac(device);

            const hostname =
                getHostname(device);

            const status =
                normalizeStatus(device);

            const matchesSearch =
                !search ||
                String(ip)
                    .toLowerCase()
                    .includes(search) ||
                String(mac)
                    .toLowerCase()
                    .includes(search) ||
                String(hostname)
                    .toLowerCase()
                    .includes(search);

            const matchesStatus =
                selectedStatus ===
                    "ALL" ||
                status ===
                    selectedStatus;

            return (
                matchesSearch &&
                matchesStatus
            );
        }
    );
}


/* ============================================================
   DEVICE INVENTORY
============================================================ */

function renderDevices() {
    if (
        !deviceRows
    ) {
        return;
    }

    const visible =
        filteredDevices();

    const totalActive =
        uniqueActiveLocalDevices()
            .length;

    if (
        inventoryCount
    ) {
        inventoryCount.textContent =
            `${totalActive} ${
                totalActive === 1
                    ? "device"
                    : "devices"
            }`;
    }

    if (
        !visible.length
    ) {
        deviceRows.innerHTML = `
            <tr>
                <td
                    colspan="6"
                    class="empty-devices"
                >
                    No active network devices match the current filter.
                </td>
            </tr>
        `;

        return;
    }

    deviceRows.innerHTML =
        visible
            .map(
                device => {
                    const ip =
                        getIp(device);

                    const mac =
                        formatMac(
                            getMac(device)
                        );

                    const hostname =
                        getHostname(device);

                    const packets =
                        getPacketCount(device);

                    const status =
                        normalizeStatus(device);

                    return `
                        <tr>
                            <td>
                                <span
                                    class="mono ip-value"
                                    title="${esc(ip)}"
                                >
                                    ${esc(
                                        shortenIp(ip)
                                    )}
                                </span>
                            </td>

                            <td>
                                <span
                                    class="mono mac-value"
                                    title="${esc(mac)}"
                                >
                                    ${esc(mac)}
                                </span>
                            </td>

                            <td>
                                <span
                                    class="hostname-value"
                                    title="${esc(hostname)}"
                                >
                                    ${esc(hostname)}
                                </span>
                            </td>

                            <td>
                                <span class="packet-value">
                                    ${formatNumber(packets)}
                                </span>
                            </td>

                            <td>
                                <span class="last-seen-value">
                                    ${esc(
                                        formatTime(
                                            device?.last_seen
                                        )
                                    )}
                                </span>
                            </td>

                            <td>
                                <span
                                    class="status-pill ${statusClass(
                                        status
                                    )}"
                                >
                                    <i></i>
                                    ${esc(status)}
                                </span>
                            </td>
                        </tr>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   UNIQUE DEVICES
============================================================ */

function uniqueDevices() {
    const map =
        new Map();

    for (
        const device of devices
    ) {
        const ip =
            getIp(device);

        if (
            !ip ||
            ip === "Unknown"
        ) {
            continue;
        }

        if (
            !map.has(ip)
        ) {
            map.set(
                ip,
                device
            );
        }
    }

    return Array.from(
        map.values()
    );
}


/* ============================================================
   TRAFFIC SCORE
============================================================ */

function trafficScoreForIp(ip) {
    return traffic.reduce(
        (
            total,
            packet
        ) => {
            if (
                packet?.source_ip === ip ||
                packet?.destination_ip === ip
            ) {
                return (
                    total +
                    num(
                        packet?.packet_size
                    )
                );
            }

            return total;
        },
        0
    );
}


/* ============================================================
   RECENT TRAFFIC
============================================================ */

function recentTrafficPackets() {
    if (
        !traffic.length
    ) {
        return [];
    }

    const reference =
        timestampMs(
            stats?.last_packet_at
        ) ||
        Date.now();

    return traffic.filter(
        packet => {
            const timestamp =
                timestampMs(
                    packet?.timestamp
                );

            if (
                timestamp === null
            ) {
                return false;
            }

            const age =
                Math.abs(
                    reference -
                    timestamp
                );

            return (
                age <=
                ACTIVE_DEVICE_WINDOW_MS
            );
        }
    );
}


/* ============================================================
   EXTERNAL TRAFFIC ENDPOINTS
============================================================ */

/*
 * External topology nodes now come from RECENT TRAFFIC,
 * not from the historical Device table.
 *
 * This prevents old public IP addresses from becoming
 * 189 "devices" on the Network page.
 */

function recentExternalEndpoints() {
    const packets =
        recentTrafficPackets();

    const scores =
        new Map();

    for (
        const packet of packets
    ) {
        const endpoints = [
            packet?.source_ip,
            packet?.destination_ip
        ];

        for (
            const ip of endpoints
        ) {
            if (
                !ip ||
                isLocalAddress(ip) ||
                !isUsableExternalEndpoint(ip)
            ) {
                continue;
            }

            const current =
                scores.get(ip) || 0;

            scores.set(
                ip,
                current +
                num(
                    packet?.packet_size
                )
            );
        }
    }

    return Array.from(
        scores.entries()
    )
        .sort(
            (a, b) =>
                b[1] -
                a[1]
        )
        .slice(
            0,
            MAX_EXTERNAL_NODES
        )
        .map(
            ([ip, score]) => ({
                ip_address: ip,
                hostname:
                    "External endpoint",
                packet_count: 0,
                traffic_score: score,
                status: "online",
                is_extra: true
            })
        );
}


/* ============================================================
   TOPOLOGY DATA
============================================================ */

function buildTopologyData() {
    if (
        !canvas
    ) {
        return;
    }

    const rect =
        canvas.getBoundingClientRect();

    const width =
        Math.max(
            rect.width,
            600
        );

    const height =
        Math.max(
            rect.height,
            400
        );


    /* ----------------------------------------------------------
       ACTIVE LOCAL DEVICES
    ---------------------------------------------------------- */

    const local =
        uniqueActiveLocalDevices()
            .sort(
                (a, b) =>
                    getPacketCount(b) -
                    getPacketCount(a)
            )
            .slice(
                0,
                MAX_LOCAL_NODES
            );


    /* ----------------------------------------------------------
       RECENT EXTERNAL TRAFFIC
    ---------------------------------------------------------- */

    const external =
        recentExternalEndpoints();


    topologyNodes = [];
    topologyEdges = [];


    /* ----------------------------------------------------------
       SENSOR
    ---------------------------------------------------------- */

    const sensor = {
        id: "sensor",

        type: "sensor",

        x:
            width *
            0.50,

        y:
            height *
            0.50,

        radius: 36,

        label:
            "NETSENTINEL",

        sublabel:
            stats.mode ||
            "LIVE"
    };

    topologyNodes.push(
        sensor
    );


    /* ----------------------------------------------------------
       LOCAL DEVICES
    ---------------------------------------------------------- */

    const localX =
        width *
        0.16;

    local.forEach(
        (
            device,
            index
        ) => {
            const y =
                local.length === 1
                    ? height * 0.50
                    : (
                        height * 0.18 +
                        (
                            index /
                            (
                                local.length -
                                1
                            )
                        ) *
                        height * 0.64
                    );

            const node = {
                id:
                    `local-${index}`,

                type:
                    "local",

                x:
                    localX,

                y:
                    y,

                radius:
                    23,

                ip:
                    getIp(device),

                label:
                    shortenIp(
                        getIp(device)
                    ),

                sublabel:
                    getHostname(device),

                status:
                    normalizeStatus(device),

                packets:
                    getPacketCount(device)
            };

            topologyNodes.push(
                node
            );

            topologyEdges.push({
                from:
                    node.id,

                to:
                    "sensor",

                type:
                    "local"
            });
        }
    );


    /* ----------------------------------------------------------
       EXTERNAL ENDPOINTS
    ---------------------------------------------------------- */

    const externalX =
        width *
        0.84;

    external.forEach(
        (
            device,
            index
        ) => {
            const y =
                external.length === 1
                    ? height * 0.50
                    : (
                        height * 0.13 +
                        (
                            index /
                            (
                                external.length -
                                1
                            )
                        ) *
                        height * 0.74
                    );

            const node = {
                id:
                    `external-${index}`,

                type:
                    "external",

                x:
                    externalX,

                y:
                    y,

                radius:
                    19,

                ip:
                    getIp(device),

                label:
                    shortenIp(
                        getIp(device)
                    ),

                sublabel:
                    "External endpoint",

                status:
                    "ONLINE",

                packets:
                    0
            };

            topologyNodes.push(
                node
            );

            topologyEdges.push({
                from:
                    "sensor",

                to:
                    node.id,

                type:
                    "external"
            });
        }
    );


    /* ----------------------------------------------------------
       EMPTY STATE
    ---------------------------------------------------------- */

    if (
        topologyEmpty
    ) {
        topologyEmpty.style.display =
            topologyNodes.length <= 1
                ? "flex"
                : "none";
    }


    createParticles();
}


/* ============================================================
   NODE LOOKUP
============================================================ */

function findNode(id) {
    return topologyNodes.find(
        node =>
            node.id === id
    );
}


/* ============================================================
   PARTICLES
============================================================ */

function createParticles() {
    particles = [];

    if (
        !topologyEdges.length
    ) {
        return;
    }

    for (
        let i = 0;
        i < PARTICLE_COUNT;
        i++
    ) {
        particles.push({
            edgeIndex:
                Math.floor(
                    Math.random() *
                    topologyEdges.length
                ),

            progress:
                Math.random(),

            speed:
                0.0007 +
                Math.random() *
                0.0018,

            size:
                1.5 +
                Math.random() *
                2.2
        });
    }
}


/* ============================================================
   BEZIER POINT
============================================================ */

function bezierPoint(
    from,
    to,
    progress
) {
    const dx =
        to.x -
        from.x;

    const controlX =
        from.x +
        dx * 0.50;

    const controlY =
        (
            from.y +
            to.y
        ) * 0.50;

    const p =
        progress;

    const inv =
        1 -
        p;

    return {
        x:
            inv * inv * from.x +
            2 *
                inv *
                p *
                controlX +
            p *
                p *
                to.x,

        y:
            inv * inv * from.y +
            2 *
                inv *
                p *
                controlY +
            p *
                p *
                to.y
    };
}


/* ============================================================
   GRID
============================================================ */

function drawGrid(
    context,
    width,
    height
) {
    context.save();

    context.fillStyle =
        "#071015";

    context.fillRect(
        0,
        0,
        width,
        height
    );

    context.strokeStyle =
        "rgba(80,150,170,0.055)";

    context.lineWidth =
        1;

    const grid =
        32;

    for (
        let x = 0;
        x <= width;
        x += grid
    ) {
        context.beginPath();

        context.moveTo(
            x,
            0
        );

        context.lineTo(
            x,
            height
        );

        context.stroke();
    }

    for (
        let y = 0;
        y <= height;
        y += grid
    ) {
        context.beginPath();

        context.moveTo(
            0,
            y
        );

        context.lineTo(
            width,
            y
        );

        context.stroke();
    }

    context.restore();
}


/* ============================================================
   ZONES
============================================================ */

function drawZones(
    context,
    width,
    height
) {
    context.save();

    context.fillStyle =
        "rgba(30,100,120,0.035)";

    context.fillRect(
        0,
        0,
        width * 0.31,
        height
    );

    context.fillStyle =
        "rgba(80,80,150,0.025)";

    context.fillRect(
        width * 0.69,
        0,
        width * 0.31,
        height
    );

    context.strokeStyle =
        "rgba(100,180,190,0.08)";

    context.setLineDash(
        [5, 8]
    );

    context.beginPath();

    context.moveTo(
        width * 0.31,
        0
    );

    context.lineTo(
        width * 0.31,
        height
    );

    context.stroke();

    context.beginPath();

    context.moveTo(
        width * 0.69,
        0
    );

    context.lineTo(
        width * 0.69,
        height
    );

    context.stroke();

    context.setLineDash([]);

    context.font =
        "700 10px Arial";

    context.fillStyle =
        "#536a73";

    context.textAlign =
        "center";

    context.fillText(
        "LOCAL NETWORK",
        width * 0.16,
        24
    );

    context.fillText(
        "SECURITY SENSOR",
        width * 0.50,
        24
    );

    context.fillText(
        "EXTERNAL NETWORK",
        width * 0.84,
        24
    );

    context.restore();
}


/* ============================================================
   CONNECTIONS
============================================================ */

function drawConnection(
    context,
    from,
    to,
    type
) {
    const dx =
        to.x -
        from.x;

    const controlX =
        from.x +
        dx * 0.50;

    const controlY =
        (
            from.y +
            to.y
        ) * 0.50;

    let alpha =
        0.18;

    if (
        type ===
        "external"
    ) {
        alpha =
            0.22;
    }

    if (
        type ===
        "local"
    ) {
        alpha =
            0.25;
    }

    context.save();

    context.beginPath();

    context.moveTo(
        from.x,
        from.y
    );

    context.quadraticCurveTo(
        controlX,
        controlY,
        to.x,
        to.y
    );

    context.strokeStyle =
        type ===
            "external"
            ? `rgba(150,160,255,${alpha})`
            : `rgba(80,210,230,${alpha})`;

    context.lineWidth =
        1.4;

    context.stroke();

    context.restore();
}


/* ============================================================
   PARTICLE RENDERER
============================================================ */

function drawParticles(
    context
) {
    for (
        const particle of particles
    ) {
        const edge =
            topologyEdges[
                particle.edgeIndex
            ];

        if (!edge) {
            continue;
        }

        const from =
            findNode(
                edge.from
            );

        const to =
            findNode(
                edge.to
            );

        if (
            !from ||
            !to
        ) {
            continue;
        }

        particle.progress +=
            particle.speed *
            16;

        if (
            particle.progress >=
            1
        ) {
            particle.progress =
                0;
        }

        const point =
            bezierPoint(
                from,
                to,
                particle.progress
            );

        const particleColor =
            edge.type ===
                "external"
                ? "#9da8ff"
                : "#62e6ff";

        context.save();

        context.beginPath();

        context.arc(
            point.x,
            point.y,
            particle.size,
            0,
            Math.PI * 2
        );

        context.fillStyle =
            particleColor;

        context.shadowColor =
            particleColor;

        context.shadowBlur =
            10;

        context.fill();

        context.restore();
    }
}


/* ============================================================
   LOCAL DEVICE NODE
============================================================ */

function drawDeviceNode(
    context,
    node
) {
    let stroke =
        "#4ed8e9";

    if (
        node.status ===
        "CRITICAL"
    ) {
        stroke =
            "#ff6464";
    }

    if (
        node.status ===
        "SUSPICIOUS"
    ) {
        stroke =
            "#ffb45c";
    }

    context.save();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius + 6,
        0,
        Math.PI * 2
    );

    context.strokeStyle =
        `${stroke}22`;

    context.lineWidth =
        1;

    context.stroke();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        "#0c1a20";

    context.fill();

    context.strokeStyle =
        stroke;

    context.lineWidth =
        1.8;

    context.stroke();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        4,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        stroke;

    context.shadowColor =
        stroke;

    context.shadowBlur =
        9;

    context.fill();

    context.shadowBlur =
        0;

    const labelX =
        node.x +
        node.radius +
        13;

    context.textAlign =
        "left";

    context.font =
        "700 10px Arial";

    context.fillStyle =
        "#d7e9ee";

    context.fillText(
        node.label,
        labelX,
        node.y - 3
    );

    context.font =
        "9px Arial";

    context.fillStyle =
        "#708991";

    const sublabel =
        node.sublabel ===
            "Unknown"
            ? "Network device"
            : node.sublabel;

    context.fillText(
        sublabel,
        labelX,
        node.y + 11
    );

    context.restore();
}


/* ============================================================
   EXTERNAL NODE
============================================================ */

function drawExternalNode(
    context,
    node
) {
    context.save();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius + 5,
        0,
        Math.PI * 2
    );

    context.strokeStyle =
        "rgba(157,168,255,0.12)";

    context.lineWidth =
        1;

    context.stroke();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        "#11152a";

    context.fill();

    context.strokeStyle =
        "#8f9aff";

    context.lineWidth =
        1.5;

    context.stroke();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        3.5,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        "#9da8ff";

    context.shadowColor =
        "#9da8ff";

    context.shadowBlur =
        8;

    context.fill();

    context.shadowBlur =
        0;

    const labelX =
        node.x -
        node.radius -
        13;

    context.textAlign =
        "right";

    context.font =
        "700 9px Arial";

    context.fillStyle =
        "#cbd0ff";

    context.fillText(
        node.label,
        labelX,
        node.y - 3
    );

    context.font =
        "8px Arial";

    context.fillStyle =
        "#69728c";

    context.fillText(
        node.sublabel,
        labelX,
        node.y + 11
    );

    context.restore();
}


/* ============================================================
   SENSOR NODE
============================================================ */

function drawSensor(
    context,
    node,
    time
) {
    const pulse =
        (
            Math.sin(
                time * 0.003
            ) +
            1
        ) *
        0.5;

    context.save();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius +
            15 +
            pulse * 8,
        0,
        Math.PI * 2
    );

    context.strokeStyle =
        `rgba(80,220,235,${0.07 + pulse * 0.08})`;

    context.lineWidth =
        2;

    context.stroke();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius + 7,
        0,
        Math.PI * 2
    );

    context.strokeStyle =
        "rgba(80,220,235,0.20)";

    context.lineWidth =
        1;

    context.stroke();

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        node.radius,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        "#0a2027";

    context.fill();

    context.strokeStyle =
        "#62e6ff";

    context.lineWidth =
        2;

    context.shadowColor =
        "#62e6ff";

    context.shadowBlur =
        18;

    context.stroke();

    context.shadowBlur =
        0;

    context.beginPath();

    context.arc(
        node.x,
        node.y,
        8,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        "#62e6ff";

    context.shadowColor =
        "#62e6ff";

    context.shadowBlur =
        16;

    context.fill();

    context.shadowBlur =
        0;

    context.textAlign =
        "center";

    context.font =
        "800 12px Arial";

    context.fillStyle =
        "#e5fbff";

    context.fillText(
        node.label,
        node.x,
        node.y +
            node.radius +
            22
    );

    context.font =
        "700 9px Arial";

    context.fillStyle =
        "#6ed5df";

    context.fillText(
        node.sublabel,
        node.x,
        node.y +
            node.radius +
            37
    );

    context.restore();
}


/* ============================================================
   LIVE INDICATOR
============================================================ */

function drawLiveIndicator(
    context,
    width
) {
    context.save();

    context.beginPath();

    context.arc(
        width - 26,
        24,
        3,
        0,
        Math.PI * 2
    );

    context.fillStyle =
        topologyPaused
            ? "#ffb45c"
            : "#70e0a1";

    context.shadowColor =
        context.fillStyle;

    context.shadowBlur =
        8;

    context.fill();

    context.shadowBlur =
        0;

    context.textAlign =
        "right";

    context.font =
        "700 8px Arial";

    context.fillStyle =
        "#6c828b";

    context.fillText(
        topologyPaused
            ? "PAUSED"
            : "LIVE TELEMETRY",
        width - 35,
        27
    );

    context.restore();
}


/* ============================================================
   MAIN DRAW
============================================================ */

function drawTopology(
    time = performance.now()
) {
    if (
        !canvas ||
        !ctx
    ) {
        return;
    }

    const rect =
        canvas.getBoundingClientRect();

    const width =
        Math.max(
            rect.width,
            600
        );

    const height =
        Math.max(
            rect.height,
            400
        );

    const ratio =
        window.devicePixelRatio ||
        1;

    const targetWidth =
        Math.floor(
            width * ratio
        );

    const targetHeight =
        Math.floor(
            height * ratio
        );

    if (
        canvas.width !==
            targetWidth ||
        canvas.height !==
            targetHeight
    ) {
        canvas.width =
            targetWidth;

        canvas.height =
            targetHeight;
    }

    ctx.setTransform(
        ratio,
        0,
        0,
        ratio,
        0,
        0
    );

    ctx.clearRect(
        0,
        0,
        width,
        height
    );

    drawGrid(
        ctx,
        width,
        height
    );

    drawZones(
        ctx,
        width,
        height
    );

    for (
        const edge of topologyEdges
    ) {
        const from =
            findNode(
                edge.from
            );

        const to =
            findNode(
                edge.to
            );

        if (
            !from ||
            !to
        ) {
            continue;
        }

        drawConnection(
            ctx,
            from,
            to,
            edge.type
        );
    }

    if (
        !topologyPaused
    ) {
        drawParticles(
            ctx
        );
    }

    for (
        const node of topologyNodes
    ) {
        if (
            node.type ===
            "sensor"
        ) {
            drawSensor(
                ctx,
                node,
                time
            );
        }

        else if (
            node.type ===
            "external"
        ) {
            drawExternalNode(
                ctx,
                node
            );
        }

        else {
            drawDeviceNode(
                ctx,
                node
            );
        }
    }

    drawLiveIndicator(
        ctx,
        width
    );

    if (
        !topologyPaused
    ) {
        animationFrame =
            requestAnimationFrame(
                drawTopology
            );
    }
}


/* ============================================================
   LOAD NETWORK
============================================================ */

async function loadNetwork() {
    try {
        const [
            deviceResponse,
            trafficResponse,
            statsResponse
        ] =
            await Promise.all([
                fetchJSON(
                    `/api/devices?limit=${DEVICE_LIMIT}`
                ),

                fetchJSON(
                    `/api/traffic?limit=${TRAFFIC_LIMIT}`
                ),

                fetchJSON(
                    "/api/stats"
                )
            ]);

        devices =
            Array.isArray(
                deviceResponse
            )
                ? deviceResponse
                : [];

        traffic =
            Array.isArray(
                trafficResponse
            )
                ? trafficResponse
                : [];

        stats =
            statsResponse ||
            {};

        renderStats();

        renderSensorState();

        renderDevices();

        buildTopologyData();

        if (
            animationFrame
        ) {
            cancelAnimationFrame(
                animationFrame
            );

            animationFrame =
                null;
        }

        if (
            !topologyPaused
        ) {
            animationFrame =
                requestAnimationFrame(
                    drawTopology
                );
        }

        else {
            drawTopology();
        }

    }

    catch (error) {
        console.error(
            "NETSENTINEL: Network update failed:",
            error
        );

        if (
            sensorStatus
        ) {
            sensorStatus.textContent =
                "TELEMETRY ERROR";

            sensorStatus.style.color =
                "#ff7373";
        }
    }
}


/* ============================================================
   RESET TOPOLOGY
============================================================ */

function resetTopology() {
    topologyPaused =
        false;

    if (
        animationFrame
    ) {
        cancelAnimationFrame(
            animationFrame
        );

        animationFrame =
            null;
    }

    buildTopologyData();

    animationFrame =
        requestAnimationFrame(
            drawTopology
        );
}


/* ============================================================
   SEARCH
============================================================ */

if (
    searchInput
) {
    searchInput.addEventListener(
        "input",
        () => {
            renderDevices();
        }
    );
}


/* ============================================================
   STATUS FILTER
============================================================ */

if (
    statusFilter
) {
    statusFilter.addEventListener(
        "change",
        () => {
            renderDevices();
        }
    );
}


/* ============================================================
   REFRESH
============================================================ */

if (
    refreshButton
) {
    refreshButton.addEventListener(
        "click",
        async () => {
            refreshButton.disabled =
                true;

            const originalText =
                refreshButton.textContent;

            refreshButton.textContent =
                "Refreshing...";

            await loadNetwork();

            refreshButton.disabled =
                false;

            refreshButton.textContent =
                originalText ||
                "Refresh";
        }
    );
}


/* ============================================================
   RESET BUTTON
============================================================ */

if (
    resetTopologyButton
) {
    resetTopologyButton.addEventListener(
        "click",
        () => {
            resetTopology();
        }
    );
}


/* ============================================================
   DOUBLE CLICK = PAUSE / RESUME
============================================================ */

if (
    canvas
) {
    canvas.addEventListener(
        "dblclick",
        () => {
            topologyPaused =
                !topologyPaused;

            if (
                topologyPaused
            ) {
                if (
                    animationFrame
                ) {
                    cancelAnimationFrame(
                        animationFrame
                    );

                    animationFrame =
                        null;
                }

                drawTopology();
            }

            else {
                animationFrame =
                    requestAnimationFrame(
                        drawTopology
                    );
            }
        }
    );
}


/* ============================================================
   RESIZE
============================================================ */

window.addEventListener(
    "resize",
    () => {
        buildTopologyData();

        if (
            topologyPaused
        ) {
            drawTopology();
        }
    }
);


/* ============================================================
   INITIAL LOAD
============================================================ */

loadNetwork();


/* ============================================================
   CONTINUOUS TELEMETRY
============================================================ */

setInterval(
    () => {
        loadNetwork();
    },
    POLL_INTERVAL
);