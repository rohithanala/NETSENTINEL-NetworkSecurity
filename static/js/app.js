"use strict";

/* ============================================================
   NETSENTINEL — SHARED APPLICATION CONTROLLER
   ============================================================

   Responsibilities:
   - Create a unique browser client ID.
   - Persist that ID in localStorage.
   - Send the client ID with every NETSENTINEL API request.
   - Keep existing helper functions available to all pages.

   IMPORTANT:
   The client ID is an ownership namespace for dashboard
   telemetry. It is NOT an authentication credential.
   ============================================================ */


/* ============================================================
   CLIENT ID CONFIGURATION
   ============================================================ */

const NETSENTINEL_CLIENT_STORAGE_KEY =
    "netsentinel_client_id";

const NETSENTINEL_CLIENT_HEADER =
    "X-NETSENTINEL-CLIENT-ID";


/* ============================================================
   CLIENT ID GENERATION
   ============================================================ */

function generateClientId() {

    try {

        if (
            window.crypto &&
            typeof window.crypto.randomUUID === "function"
        ) {
            return `client-${window.crypto.randomUUID()}`;
        }

    } catch (error) {

        console.warn(
            "NETSENTINEL: crypto.randomUUID unavailable.",
            error
        );
    }


    /*
     * Fallback for browsers without randomUUID().
     */

    const randomPart =
        Math.random()
            .toString(36)
            .slice(2, 12);

    const timePart =
        Date.now()
            .toString(36);

    return `client-${timePart}-${randomPart}`;
}


/* ============================================================
   GET / CREATE CLIENT ID
   ============================================================ */

function getNetSentinelClientId() {

    let clientId = null;


    /*
     * Try existing browser storage first.
     */

    try {

        clientId =
            window.localStorage.getItem(
                NETSENTINEL_CLIENT_STORAGE_KEY
            );

    } catch (error) {

        console.warn(
            "NETSENTINEL: localStorage is unavailable.",
            error
        );
    }


    /*
     * Validate the stored value.
     */

    if (
        !clientId ||
        !/^client-[A-Za-z0-9._:-]{8,128}$/.test(
            clientId
        )
    ) {

        clientId =
            generateClientId();


        try {

            window.localStorage.setItem(
                NETSENTINEL_CLIENT_STORAGE_KEY,
                clientId
            );

        } catch (error) {

            console.warn(
                "NETSENTINEL: Could not persist client ID.",
                error
            );
        }
    }


    return clientId;
}


/* ============================================================
   GLOBAL CLIENT ID
   ============================================================ */

const NETSENTINEL_CLIENT_ID =
    getNetSentinelClientId();


/*
 * Expose the identity for other NETSENTINEL frontend modules.
 */

window.NETSENTINEL_CLIENT_ID =
    NETSENTINEL_CLIENT_ID;

window.NETSENTINEL_CLIENT_HEADER =
    NETSENTINEL_CLIENT_HEADER;


/* ============================================================
   LOG CLIENT ID
   ============================================================ */

console.info(
    "NETSENTINEL client:",
    NETSENTINEL_CLIENT_ID
);


/* ============================================================
   FETCH WRAPPER
   ============================================================

   Every same-origin /api/* request automatically receives:

       X-NETSENTINEL-CLIENT-ID

   This means existing files such as:

       dashboard.js
       network.js
       analytics.js
       alerts.js
       live_traffic.js

   do NOT need to manually add the header to every fetch call.
   ============================================================ */

(() => {

    const originalFetch =
        window.fetch.bind(window);


    window.fetch =
        async function netsentinelFetch(
            input,
            init = {}
        ) {

            try {

                /*
                 * Resolve the request URL.
                 */

                let requestUrl;


                if (
                    input instanceof Request
                ) {

                    requestUrl =
                        new URL(
                            input.url,
                            window.location.href
                        );

                } else {

                    requestUrl =
                        new URL(
                            String(input),
                            window.location.href
                        );
                }


                /*
                 * Only attach the NETSENTINEL client ID to
                 * our own same-origin API requests.
                 */

                const isSameOrigin =
                    requestUrl.origin ===
                    window.location.origin;


                const isApiRequest =
                    requestUrl.pathname.startsWith(
                        "/api/"
                    );


                if (
                    isSameOrigin &&
                    isApiRequest
                ) {

                    const headers =
                        new Headers(
                            init.headers ||
                            (
                                input instanceof Request
                                    ? input.headers
                                    : undefined
                            )
                        );


                    headers.set(
                        NETSENTINEL_CLIENT_HEADER,
                        NETSENTINEL_CLIENT_ID
                    );


                    init = {
                        ...init,
                        headers
                    };
                }


            } catch (error) {

                /*
                 * Never break a normal request just because
                 * client-ID preparation failed.
                 */

                console.warn(
                    "NETSENTINEL: Client ID request wrapper warning.",
                    error
                );
            }


            return originalFetch(
                input,
                init
            );
        };

})();


/* ============================================================
   JSON HELPER
   ============================================================ */

async function getJSON(
    url,
    options = {}
) {

    const response =
        await fetch(
            url,
            options
        );


    if (
        !response.ok
    ) {

        throw new Error(
            `HTTP ${response.status}`
        );
    }


    return response.json();
}


/* ============================================================
   HTML ESCAPING
   ============================================================ */

function esc(
    value
) {

    return String(
        value ?? ""
    )
        .replace(
            /[&<>"']/g,
            character => (
                {
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#039;"
                }[
                    character
                ]
            )
        );
}


/* ============================================================
   TIME FORMATTER
   ============================================================ */

function time(
    value
) {

    const date =
        new Date(
            value
        );


    return (
        value &&
        !Number.isNaN(
            date.getTime()
        )
    )
        ? date.toLocaleTimeString()
        : "—";
}


/* ============================================================
   NUMBER FORMATTER
   ============================================================ */

function num(
    value
) {

    return Number(
        value || 0
    ).toLocaleString();
}


/* ============================================================
   OPTIONAL GLOBAL HELPERS
   ============================================================ */

window.NETSENTINEL = {

    clientId:
        NETSENTINEL_CLIENT_ID,

    clientHeader:
        NETSENTINEL_CLIENT_HEADER,

    getClientId:
        getNetSentinelClientId,

    getJSON,

    esc,

    time,

    num
};