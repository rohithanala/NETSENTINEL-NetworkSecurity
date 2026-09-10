"use strict";

const ALERT_LIMIT = 500;
const POLL_INTERVAL = 2000;

let alertsData = [];
let previousAlertIds = new Set();
let firstLoad = true;


/* ---------------------------------------------------------
   DOM
--------------------------------------------------------- */

const elements = {
    rows: document.getElementById("alertsRows"),

    totalAlerts: document.getElementById("totalAlerts"),
    highAlerts: document.getElementById("highAlerts"),
    mediumAlerts: document.getElementById("mediumAlerts"),
    newAlerts: document.getElementById("newAlerts"),

    search: document.getElementById("alertSearch"),
    severity: document.getElementById("severityFilter"),
    detection: document.getElementById("detectionFilter"),
    status: document.getElementById("statusFilter"),

    refresh: document.getElementById("refreshButton"),
    clearFilters: document.getElementById("clearFiltersButton")
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


function formatTime(timestamp) {

    if (!timestamp) {
        return "—";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return escapeHTML(timestamp);
    }

    return date.toLocaleString([], {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}


function severityClass(severity) {

    const value =
        String(severity || "UNKNOWN").toUpperCase();

    if (value === "CRITICAL") {
        return "severity-critical";
    }

    if (value === "HIGH") {
        return "severity-high";
    }

    if (value === "MEDIUM") {
        return "severity-medium";
    }

    if (value === "LOW") {
        return "severity-low";
    }

    return "severity-unknown";
}


function statusClass(status) {

    const value =
        String(status || "new").toLowerCase();

    if (value === "acknowledged") {
        return "status-acknowledged";
    }

    if (value === "resolved") {
        return "status-resolved";
    }

    if (value === "false_positive") {
        return "status-false_positive";
    }

    return "status-new";
}


function formatDetectionName(type) {

    if (!type) {
        return "Unknown Detection";
    }

    return String(type)
        .replace(/_/g, " ")
        .replace(/\b\w/g, char => char.toUpperCase());
}


function normalizeConfidence(value) {

    let confidence = Number(value);

    if (!Number.isFinite(confidence)) {
        return 0;
    }

    /*
       Backend normally provides confidence as 0-100.
       Protect against accidental 0-1 values.
    */

    if (confidence > 0 && confidence <= 1) {
        confidence *= 100;
    }

    return Math.max(
        0,
        Math.min(100, confidence)
    );
}


/* ---------------------------------------------------------
   Statistics
--------------------------------------------------------- */

function updateStatistics() {

    const total =
        alertsData.length;

    const high =
        alertsData.filter(alert => {

            const severity =
                String(alert.severity || "")
                    .toUpperCase();

            return (
                severity === "HIGH" ||
                severity === "CRITICAL"
            );

        }).length;

    const medium =
        alertsData.filter(alert =>
            String(alert.severity || "")
                .toUpperCase() === "MEDIUM"
        ).length;

    const newlyDetected =
        alertsData.filter(alert =>
            String(alert.status || "new")
                .toLowerCase() === "new"
        ).length;


    if (elements.totalAlerts) {
        elements.totalAlerts.textContent =
            total.toLocaleString();
    }

    if (elements.highAlerts) {
        elements.highAlerts.textContent =
            high.toLocaleString();
    }

    if (elements.mediumAlerts) {
        elements.mediumAlerts.textContent =
            medium.toLocaleString();
    }

    if (elements.newAlerts) {
        elements.newAlerts.textContent =
            newlyDetected.toLocaleString();
    }
}


/* ---------------------------------------------------------
   Detection filter
--------------------------------------------------------- */

function updateDetectionFilter() {

    if (!elements.detection) {
        return;
    }

    const current =
        elements.detection.value;

    const detections =
        [...new Set(
            alertsData
                .map(alert =>
                    String(alert.detection_type || "")
                )
                .filter(Boolean)
        )]
        .sort();


    elements.detection.innerHTML = `
        <option value="ALL">
            All Detections
        </option>
    `;

    detections.forEach(type => {

        const option =
            document.createElement("option");

        option.value = type;
        option.textContent =
            formatDetectionName(type);

        elements.detection.appendChild(option);
    });


    if (
        detections.includes(current)
    ) {
        elements.detection.value = current;
    }
}


/* ---------------------------------------------------------
   Filtering
--------------------------------------------------------- */

function getFilteredAlerts() {

    const search =
        String(
            elements.search?.value || ""
        )
        .trim()
        .toLowerCase();

    const severity =
        elements.severity?.value || "ALL";

    const detection =
        elements.detection?.value || "ALL";

    const status =
        elements.status?.value || "ALL";


    return alertsData.filter(alert => {

        const alertSeverity =
            String(alert.severity || "")
                .toUpperCase();

        const alertDetection =
            String(alert.detection_type || "");

        const alertStatus =
            String(alert.status || "new")
                .toLowerCase();


        if (
            severity !== "ALL" &&
            alertSeverity !== severity
        ) {
            return false;
        }


        if (
            detection !== "ALL" &&
            alertDetection !== detection
        ) {
            return false;
        }


        if (
            status !== "ALL" &&
            alertStatus !== status
        ) {
            return false;
        }


        if (search) {

            const searchable = [

                alert.source_ip,

                alert.destination_ip,

                alert.protocol,

                alert.detection_type,

                alert.description,

                alert.severity,

                alert.status

            ]
            .join(" ")
            .toLowerCase();


            if (!searchable.includes(search)) {
                return false;
            }
        }


        return true;
    });
}


/* ---------------------------------------------------------
   Render
--------------------------------------------------------- */

function renderAlerts() {

    if (!elements.rows) {

        console.error(
            "NETSENTINEL: alertsRows element was not found."
        );

        return;
    }


    const filtered =
        getFilteredAlerts();


    if (!filtered.length) {

        elements.rows.innerHTML = `
            <tr>
                <td colspan="9" class="empty-alerts">
                    No security alerts match the current filters.
                </td>
            </tr>
        `;

        return;
    }


    elements.rows.innerHTML =
        filtered.map(alert => {

            const severity =
                String(
                    alert.severity || "UNKNOWN"
                ).toUpperCase();


            const status =
                String(
                    alert.status || "new"
                ).toLowerCase();


            const confidence =
                normalizeConfidence(
                    alert.confidence
                );


            const isNew =
                !firstLoad &&
                !previousAlertIds.has(alert.id);


            return `
                <tr class="alert-row ${isNew ? "new-alert" : ""}">

                    <td>
                        ${escapeHTML(
                            formatTime(alert.timestamp)
                        )}
                    </td>

                    <td>
                        <span class="detection-name">
                            ${escapeHTML(
                                formatDetectionName(
                                    alert.detection_type
                                )
                            )}
                        </span>
                    </td>

                    <td>
                        <span class="ip-address">
                            ${escapeHTML(
                                alert.source_ip || "—"
                            )}
                        </span>
                    </td>

                    <td>
                        <span class="ip-address">
                            ${escapeHTML(
                                alert.destination_ip || "—"
                            )}
                        </span>
                    </td>

                    <td>
                        ${escapeHTML(
                            alert.protocol || "—"
                        )}
                    </td>

                    <td>
                        <span class="severity ${severityClass(severity)}">
                            ${escapeHTML(severity)}
                        </span>
                    </td>

                    <td>

                        <span
                            class="confidence"
                            style="color: ${confidence >= 80
                                ? "#ff6b6b"
                                : confidence >= 50
                                    ? "#ffd166"
                                    : "#70e0a1"}"
                        >
                            ${confidence.toFixed(0)}%
                        </span>

                        <div class="confidence-bar">

                            <div
                                class="confidence-fill"
                                style="
                                    width:${confidence}%;
                                    color:${confidence >= 80
                                        ? "#ff6b6b"
                                        : confidence >= 50
                                            ? "#ffd166"
                                            : "#70e0a1"};
                                "
                            ></div>

                        </div>

                    </td>

                    <td>

                        <div class="description">
                            ${escapeHTML(
                                alert.description || "No description available."
                            )}
                        </div>

                    </td>

                    <td>

                        <select
                            class="alert-status-control"
                            data-alert-id="${Number(alert.id)}"
                        >

                            <option
                                value="new"
                                ${status === "new" ? "selected" : ""}
                            >
                                New
                            </option>

                            <option
                                value="acknowledged"
                                ${status === "acknowledged" ? "selected" : ""}
                            >
                                Acknowledged
                            </option>

                            <option
                                value="resolved"
                                ${status === "resolved" ? "selected" : ""}
                            >
                                Resolved
                            </option>

                            <option
                                value="false_positive"
                                ${status === "false_positive" ? "selected" : ""}
                            >
                                False Positive
                            </option>

                        </select>

                    </td>

                </tr>
            `;

        }).join("");
}


/* ---------------------------------------------------------
   Load alerts
--------------------------------------------------------- */

async function loadAlerts() {

    try {

        const response =
            await getJSON(
                `/api/alerts?limit=${ALERT_LIMIT}`
            );


        if (!Array.isArray(response)) {

            console.error(
                "NETSENTINEL: /api/alerts did not return an array.",
                response
            );

            return;
        }


        previousAlertIds =
            new Set(
                alertsData.map(alert => alert.id)
            );


        alertsData =
            response;


        updateStatistics();

        updateDetectionFilter();

        renderAlerts();


        firstLoad = false;


    } catch (error) {

        console.error(
            "NETSENTINEL alerts loading error:",
            error
        );


        if (elements.rows) {

            elements.rows.innerHTML = `
                <tr>
                    <td colspan="9" class="alert-error">
                        Unable to load security alerts.
                    </td>
                </tr>
            `;
        }
    }
}


/* ---------------------------------------------------------
   Update alert status
--------------------------------------------------------- */

async function updateAlertStatus(alertId, status) {

    try {

        const response =
            await fetch(
                `/api/alerts/${alertId}`,
                {
                    method: "PATCH",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        status: status
                    })
                }
            );


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );
        }


        const alert =
            alertsData.find(
                item =>
                    Number(item.id) ===
                    Number(alertId)
            );


        if (alert) {
            alert.status = status;
        }


        updateStatistics();
        renderAlerts();


    } catch (error) {

        console.error(
            "NETSENTINEL status update error:",
            error
        );


        /*
           Reload from backend so the UI cannot
           remain inconsistent with the database.
        */

        await loadAlerts();
    }
}


/* ---------------------------------------------------------
   Status change listener
--------------------------------------------------------- */

if (elements.rows) {

    elements.rows.addEventListener(
        "change",
        event => {

            const target =
                event.target;


            if (
                !target.classList.contains(
                    "alert-status-control"
                )
            ) {
                return;
            }


            const alertId =
                target.dataset.alertId;

            const status =
                target.value;


            updateAlertStatus(
                alertId,
                status
            );
        }
    );
}


/* ---------------------------------------------------------
   Filters
--------------------------------------------------------- */

if (elements.search) {

    elements.search.addEventListener(
        "input",
        renderAlerts
    );
}


if (elements.severity) {

    elements.severity.addEventListener(
        "change",
        renderAlerts
    );
}


if (elements.detection) {

    elements.detection.addEventListener(
        "change",
        renderAlerts
    );
}


if (elements.status) {

    elements.status.addEventListener(
        "change",
        renderAlerts
    );
}


/* ---------------------------------------------------------
   Buttons
--------------------------------------------------------- */

if (elements.refresh) {

    elements.refresh.addEventListener(
        "click",
        loadAlerts
    );
}


if (elements.clearFilters) {

    elements.clearFilters.addEventListener(
        "click",
        () => {

            if (elements.search) {
                elements.search.value = "";
            }

            if (elements.severity) {
                elements.severity.value = "ALL";
            }

            if (elements.detection) {
                elements.detection.value = "ALL";
            }

            if (elements.status) {
                elements.status.value = "ALL";
            }

            renderAlerts();
        }
    );
}


/* ---------------------------------------------------------
   Start
--------------------------------------------------------- */

async function startAlertsMonitor() {

    console.log(
        "NETSENTINEL: Security Alert Center starting..."
    );


    await loadAlerts();


    setInterval(
        loadAlerts,
        POLL_INTERVAL
    );
}


startAlertsMonitor().catch(error => {

    console.error(
        "NETSENTINEL Alert Center startup error:",
        error
    );

});