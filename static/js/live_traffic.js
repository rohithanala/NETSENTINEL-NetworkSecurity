"use strict";

const TRAFFIC_LIMIT = 300;
const POLL_INTERVAL = 1000;

let trafficData = [];
let paused = false;
let timer = null;

const elements = {
    rows: document.getElementById("live_trafficRows"),

    packetCount: document.getElementById("packetCount"),
    byteCount: document.getElementById("byteCount"),

    tcpCount: document.getElementById("tcpCount"),
    udpCount: document.getElementById("udpCount"),

    protocolFilter: document.getElementById("protocolFilter"),

    pauseButton: document.getElementById("pauseButton"),
    clearButton: document.getElementById("clearButton"),

    trafficStatus: document.getElementById("trafficStatus"),
    trafficStatusText: document.getElementById("trafficStatusText"),

    captureState: document.getElementById("captureState"),
    interfaceName: document.getElementById("interfaceName"),
    lastUpdate: document.getElementById("lastUpdate")
};


/* ---------------------------------------------------------
   Helpers
--------------------------------------------------------- */

function escapeHTML(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function formatBytes(bytes) {

    bytes = Number(bytes) || 0;

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}


function formatTime(timestamp) {

    if (!timestamp) {
        return "—";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return escapeHTML(timestamp);
    }

    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}


function protocolClass(protocol) {

    const p = String(protocol || "OTHER").toLowerCase();

    if (p === "tcp") return "tcp";
    if (p === "udp") return "udp";
    if (p === "icmp") return "icmp";
    if (p === "arp") return "arp";

    return "other";
}


function portText(packet) {

    const source = packet.source_port;
    const destination = packet.destination_port;

    if (
        source === null ||
        source === undefined ||
        destination === null ||
        destination === undefined
    ) {
        return "—";
    }

    return `${escapeHTML(source)} → ${escapeHTML(destination)}`;
}


/* ---------------------------------------------------------
   Render traffic
--------------------------------------------------------- */

function renderTraffic() {

    if (!elements.rows) {
        console.error(
            "NETSENTINEL: live_trafficRows element was not found."
        );

        return;
    }

    const selectedProtocol =
        elements.protocolFilter?.value || "ALL";

    let visible = trafficData;

    if (selectedProtocol !== "ALL") {

        visible = trafficData.filter(packet =>
            String(packet.protocol || "OTHER").toUpperCase() ===
            selectedProtocol
        );
    }

    if (!visible.length) {

        elements.rows.innerHTML = `
            <tr>
                <td colspan="7" class="empty-state">
                    No packets match the selected filter.
                </td>
            </tr>
        `;

        return;
    }

    elements.rows.innerHTML = visible
        .map((packet, index) => {

            const protocol =
                String(packet.protocol || "OTHER").toUpperCase();

            const source =
                packet.source_ip || "—";

            const destination =
                packet.destination_ip || "—";

            const flags =
                packet.tcp_flags || "—";

            const size =
                Number(packet.packet_size) || 0;

            return `
                <tr class="${index < 5 ? "live-row" : ""}">

                    <td>
                        ${escapeHTML(formatTime(packet.timestamp))}
                    </td>

                    <td>
                        <span class="ip">
                            ${escapeHTML(source)}
                        </span>
                    </td>

                    <td>
                        <span class="ip">
                            ${escapeHTML(destination)}
                        </span>
                    </td>

                    <td>
                        <span class="protocol ${protocolClass(protocol)}">
                            ${escapeHTML(protocol)}
                        </span>
                    </td>

                    <td>
                        <span class="port">
                            ${portText(packet)}
                        </span>
                    </td>

                    <td>
                        <span class="flag">
                            ${escapeHTML(flags)}
                        </span>
                    </td>

                    <td>
                        ${formatBytes(size)}
                    </td>

                </tr>
            `;
        })
        .join("");
}


/* ---------------------------------------------------------
   Statistics
--------------------------------------------------------- */

function updateStatistics() {

    const packets = trafficData.length;

    const bytes = trafficData.reduce(
        (total, packet) =>
            total + (Number(packet.packet_size) || 0),
        0
    );

    const tcp = trafficData.filter(
        packet =>
            String(packet.protocol || "").toUpperCase() === "TCP"
    ).length;

    const udp = trafficData.filter(
        packet =>
            String(packet.protocol || "").toUpperCase() === "UDP"
    ).length;

    if (elements.packetCount) {
        elements.packetCount.textContent =
            packets.toLocaleString();
    }

    if (elements.byteCount) {
        elements.byteCount.textContent =
            formatBytes(bytes);
    }

    if (elements.tcpCount) {
        elements.tcpCount.textContent =
            tcp.toLocaleString();
    }

    if (elements.udpCount) {
        elements.udpCount.textContent =
            udp.toLocaleString();
    }
}


/* ---------------------------------------------------------
   Capture status
--------------------------------------------------------- */

async function loadCaptureStatus() {

    try {

        const response =
            await getJSON("/api/capture/status");

        const running =
            Boolean(response.running);

        if (elements.captureState) {

            elements.captureState.className =
                running
                    ? "traffic-status"
                    : "traffic-status paused";

            elements.captureState.innerHTML = `
                <i class="status-dot"></i>
                <span>
                    ${running ? "CAPTURING" : "STOPPED"}
                </span>
            `;
        }

        if (elements.interfaceName) {

            elements.interfaceName.textContent =
                response.interface || "—";
        }

    } catch (error) {

        console.error(
            "NETSENTINEL capture status error:",
            error
        );

        if (elements.captureState) {

            elements.captureState.className =
                "traffic-status paused";

            elements.captureState.innerHTML = `
                <i class="status-dot"></i>
                <span>ERROR</span>
            `;
        }
    }
}


/* ---------------------------------------------------------
   Load live traffic
--------------------------------------------------------- */

async function loadTraffic() {

    if (paused) {
        return;
    }

    try {

        const response =
            await getJSON(
                `/api/traffic?limit=${TRAFFIC_LIMIT}`
            );

        if (!Array.isArray(response)) {

            console.error(
                "NETSENTINEL: /api/traffic did not return an array.",
                response
            );

            return;
        }

        trafficData = response;

        updateStatistics();
        renderTraffic();

        if (elements.lastUpdate) {

            elements.lastUpdate.textContent =
                new Date().toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit"
                });
        }

    } catch (error) {

        console.error(
            "NETSENTINEL traffic loading error:",
            error
        );
    }
}


/* ---------------------------------------------------------
   Pause / Resume
--------------------------------------------------------- */

function togglePause() {

    paused = !paused;

    if (elements.pauseButton) {

        elements.pauseButton.textContent =
            paused ? "Resume" : "Pause";
    }

    if (elements.trafficStatus) {

        elements.trafficStatus.className =
            paused
                ? "traffic-status paused"
                : "traffic-status";

        if (elements.trafficStatusText) {

            elements.trafficStatusText.textContent =
                paused ? "PAUSED" : "LIVE";
        }
    }

    if (!paused) {
        loadTraffic();
    }
}


/* ---------------------------------------------------------
   Clear table
--------------------------------------------------------- */

function clearTraffic() {

    trafficData = [];

    updateStatistics();
    renderTraffic();

    if (elements.lastUpdate) {
        elements.lastUpdate.textContent = "—";
    }
}


/* ---------------------------------------------------------
   Event listeners
--------------------------------------------------------- */

if (elements.protocolFilter) {

    elements.protocolFilter.addEventListener(
        "change",
        renderTraffic
    );
}


if (elements.pauseButton) {

    elements.pauseButton.addEventListener(
        "click",
        togglePause
    );
}


if (elements.clearButton) {

    elements.clearButton.addEventListener(
        "click",
        clearTraffic
    );
}


/* ---------------------------------------------------------
   Start
--------------------------------------------------------- */

async function startTrafficMonitor() {

    console.log(
        "NETSENTINEL: Live Traffic Monitor starting..."
    );

    await loadTraffic();

    await loadCaptureStatus();

    timer = setInterval(
        loadTraffic,
        POLL_INTERVAL
    );

    setInterval(
        loadCaptureStatus,
        2000
    );
}


startTrafficMonitor().catch(error => {

    console.error(
        "NETSENTINEL Traffic Monitor startup error:",
        error
    );

});