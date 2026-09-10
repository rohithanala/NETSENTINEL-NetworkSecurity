(() => {
    "use strict";

    class CyberNetworkBackground {
        constructor() {
            this.canvas = document.getElementById("cyberNetworkBackground");

            if (!this.canvas) {
                console.error(
                    "NETSENTINEL: cyberNetworkBackground canvas not found."
                );
                return;
            }

            this.ctx = this.canvas.getContext("2d");

            if (!this.ctx) {
                console.error(
                    "NETSENTINEL: Canvas 2D context unavailable."
                );
                return;
            }

            this.nodes = [];
            this.packets = [];
            this.alertPulses = [];

            this.width = 0;
            this.height = 0;

            this.scanAngle = 0;
            this.lastTime = performance.now();

            this.packetActivity = 1;
            this.threatActivity = 0;
            this.monitoring = true;

            this.resize();
            this.createNodes();
            this.createPackets();

            window.addEventListener("resize", () => {
                this.resize();
                this.createNodes();
                this.createPackets();
            });

            this.fetchSystemState();

            setInterval(() => {
                this.fetchSystemState();
            }, 2000);

            requestAnimationFrame((time) => {
                this.animate(time);
            });
        }

        resize() {
            const ratio = Math.min(
                window.devicePixelRatio || 1,
                2
            );

            this.width = window.innerWidth;
            this.height = window.innerHeight;

            this.canvas.width = this.width * ratio;
            this.canvas.height = this.height * ratio;

            this.canvas.style.width = `${this.width}px`;
            this.canvas.style.height = `${this.height}px`;

            this.ctx.setTransform(
                ratio,
                0,
                0,
                ratio,
                0,
                0
            );
        }

        createNodes() {
            const count = Math.max(
                28,
                Math.min(
                    65,
                    Math.floor(
                        (this.width * this.height) / 22000
                    )
                )
            );

            this.nodes = [];

            for (let i = 0; i < count; i++) {
                this.nodes.push({
                    x: Math.random() * this.width,
                    y: Math.random() * this.height,

                    radius:
                        Math.random() * 2.2 + 1.1,

                    speedX:
                        (Math.random() - 0.5) * 0.035,

                    speedY:
                        (Math.random() - 0.5) * 0.035,

                    phase:
                        Math.random() *
                        Math.PI *
                        2,

                    activity:
                        Math.random()
                });
            }
        }

        createPackets() {
            this.packets = [];

            for (let i = 0; i < 42; i++) {
                let nodeA =
                    Math.floor(
                        Math.random() *
                        this.nodes.length
                    );

                let nodeB =
                    Math.floor(
                        Math.random() *
                        this.nodes.length
                    );

                if (nodeA === nodeB) {
                    nodeB =
                        (nodeB + 1) %
                        this.nodes.length;
                }

                this.packets.push({
                    nodeA,
                    nodeB,

                    progress:
                        Math.random(),

                    speed:
                        0.00012 +
                        Math.random() *
                        0.00028
                });
            }
        }

        distance(a, b) {
            const dx = a.x - b.x;
            const dy = a.y - b.y;

            return Math.sqrt(
                dx * dx +
                dy * dy
            );
        }

        drawBackground() {
            const gradient =
                this.ctx.createRadialGradient(
                    this.width * 0.5,
                    this.height * 0.45,
                    0,

                    this.width * 0.5,
                    this.height * 0.45,
                    Math.max(
                        this.width,
                        this.height
                    )
                );

            gradient.addColorStop(
                0,
                "rgba(5, 32, 45, 0.72)"
            );

            gradient.addColorStop(
                0.45,
                "rgba(3, 17, 27, 0.78)"
            );

            gradient.addColorStop(
                1,
                "rgba(1, 7, 12, 0.96)"
            );

            this.ctx.fillStyle = gradient;

            this.ctx.fillRect(
                0,
                0,
                this.width,
                this.height
            );
        }

        drawGrid() {
            const spacing = 55;

            this.ctx.lineWidth = 0.5;

            this.ctx.strokeStyle =
                "rgba(50, 170, 200, 0.075)";

            for (
                let x = 0;
                x <= this.width;
                x += spacing
            ) {
                this.ctx.beginPath();

                this.ctx.moveTo(x, 0);
                this.ctx.lineTo(
                    x,
                    this.height
                );

                this.ctx.stroke();
            }

            for (
                let y = 0;
                y <= this.height;
                y += spacing
            ) {
                this.ctx.beginPath();

                this.ctx.moveTo(0, y);
                this.ctx.lineTo(
                    this.width,
                    y
                );

                this.ctx.stroke();
            }

            /*
             * Additional circuit-style horizontal
             * and vertical traces.
             */

            this.ctx.lineWidth = 0.7;

            this.ctx.strokeStyle =
                "rgba(70, 190, 220, 0.035)";

            for (let i = 0; i < 14; i++) {
                const y =
                    (i + 1) *
                    (this.height / 15);

                this.ctx.beginPath();

                this.ctx.moveTo(
                    0,
                    y
                );

                this.ctx.lineTo(
                    this.width,
                    y
                );

                this.ctx.stroke();
            }
        }

        drawConnections() {
            const maxDistance = 215;

            for (
                let i = 0;
                i < this.nodes.length;
                i++
            ) {
                const a = this.nodes[i];

                const nearby = [];

                for (
                    let j = 0;
                    j < this.nodes.length;
                    j++
                ) {
                    if (i === j) {
                        continue;
                    }

                    const b = this.nodes[j];

                    const distance =
                        this.distance(
                            a,
                            b
                        );

                    if (
                        distance <
                        maxDistance
                    ) {
                        nearby.push({
                            node: b,
                            distance
                        });
                    }
                }

                nearby.sort(
                    (first, second) =>
                        first.distance -
                        second.distance
                );

                const connections =
                    nearby.slice(0, 3);

                for (
                    const connection
                    of connections
                ) {
                    const b =
                        connection.node;

                    const alpha =
                        Math.max(
                            0.025,
                            0.19 -
                            connection.distance /
                            1250
                        );

                    this.ctx.beginPath();

                    this.ctx.moveTo(
                        a.x,
                        a.y
                    );

                    this.ctx.lineTo(
                        b.x,
                        b.y
                    );

                    this.ctx.lineWidth = 0.75;

                    this.ctx.strokeStyle =
                        `rgba(65, 205, 235, ${alpha})`;

                    this.ctx.stroke();
                }
            }
        }

        updateNodes(time) {
            for (
                const node of this.nodes
            ) {
                node.x +=
                    node.speedX *
                    (0.8 + this.packetActivity);

                node.y +=
                    node.speedY *
                    (0.8 + this.packetActivity);

                if (node.x < -30) {
                    node.x =
                        this.width + 30;
                }

                if (
                    node.x >
                    this.width + 30
                ) {
                    node.x = -30;
                }

                if (node.y < -30) {
                    node.y =
                        this.height + 30;
                }

                if (
                    node.y >
                    this.height + 30
                ) {
                    node.y = -30;
                }
            }
        }

        drawNodes(time) {
            for (
                const node of this.nodes
            ) {
                const pulse =
                    Math.sin(
                        time * 0.002 +
                        node.phase
                    ) *
                    0.5 +
                    0.5;

                const radius =
                    node.radius +
                    pulse *
                    1.25;

                /*
                 * Outer glow.
                 */

                this.ctx.beginPath();

                this.ctx.arc(
                    node.x,
                    node.y,
                    radius * 5,
                    0,
                    Math.PI * 2
                );

                this.ctx.fillStyle =
                    `rgba(30, 190, 230, ${
                        0.018 +
                        pulse * 0.028
                    })`;

                this.ctx.fill();

                /*
                 * Node.
                 */

                this.ctx.beginPath();

                this.ctx.arc(
                    node.x,
                    node.y,
                    radius,
                    0,
                    Math.PI * 2
                );

                this.ctx.fillStyle =
                    `rgba(100, 225, 250, ${
                        0.38 +
                        pulse * 0.38
                    })`;

                this.ctx.fill();

                /*
                 * Tiny center.
                 */

                this.ctx.beginPath();

                this.ctx.arc(
                    node.x,
                    node.y,
                    0.8,
                    0,
                    Math.PI * 2
                );

                this.ctx.fillStyle =
                    "rgba(220, 250, 255, 0.9)";

                this.ctx.fill();
            }
        }

        updatePackets(delta) {
            const activity =
                Math.max(
                    0.5,
                    Math.min(
                        3.5,
                        0.7 +
                        this.packetActivity
                    )
                );

            for (
                const packet
                of this.packets
            ) {
                const a =
                    this.nodes[
                        packet.nodeA
                    ];

                const b =
                    this.nodes[
                        packet.nodeB
                    ];

                if (!a || !b) {
                    continue;
                }

                packet.progress +=
                    packet.speed *
                    delta *
                    activity;

                if (
                    packet.progress >=
                    1
                ) {
                    packet.progress = 0;

                    packet.nodeA =
                        packet.nodeB;

                    let next =
                        Math.floor(
                            Math.random() *
                            this.nodes.length
                        );

                    if (
                        next ===
                        packet.nodeA
                    ) {
                        next =
                            (next + 1) %
                            this.nodes.length;
                    }

                    packet.nodeB =
                        next;
                }
            }
        }

        drawPackets() {
            for (
                const packet
                of this.packets
            ) {
                const a =
                    this.nodes[
                        packet.nodeA
                    ];

                const b =
                    this.nodes[
                        packet.nodeB
                    ];

                if (!a || !b) {
                    continue;
                }

                const x =
                    a.x +
                    (b.x - a.x) *
                    packet.progress;

                const y =
                    a.y +
                    (b.y - a.y) *
                    packet.progress;

                this.ctx.beginPath();

                this.ctx.arc(
                    x,
                    y,
                    2.2,
                    0,
                    Math.PI * 2
                );

                this.ctx.shadowBlur = 14;

                this.ctx.shadowColor =
                    "rgba(70, 220, 255, 0.95)";

                this.ctx.fillStyle =
                    "rgba(120, 240, 255, 0.95)";

                this.ctx.fill();

                this.ctx.shadowBlur = 0;
            }
        }

        drawRadar(delta) {
            this.scanAngle +=
                delta *
                0.00042;

            if (
                this.scanAngle >
                Math.PI * 2
            ) {
                this.scanAngle -=
                    Math.PI * 2;
            }

            const centerX =
                this.width * 0.5;

            const centerY =
                this.height * 0.5;

            const radius =
                Math.max(
                    this.width,
                    this.height
                ) *
                0.72;

            /*
             * Radar rings.
             */

            this.ctx.lineWidth = 0.7;

            for (
                let ring = 1;
                ring <= 4;
                ring++
            ) {
                const ringRadius =
                    radius *
                    (ring / 4);

                this.ctx.beginPath();

                this.ctx.arc(
                    centerX,
                    centerY,
                    ringRadius,
                    0,
                    Math.PI * 2
                );

                this.ctx.strokeStyle =
                    "rgba(50, 190, 220, 0.025)";

                this.ctx.stroke();
            }

            /*
             * Sweep line.
             */

            const sweepX =
                centerX +
                Math.cos(
                    this.scanAngle
                ) *
                radius;

            const sweepY =
                centerY +
                Math.sin(
                    this.scanAngle
                ) *
                radius;

            this.ctx.beginPath();

            this.ctx.moveTo(
                centerX,
                centerY
            );

            this.ctx.lineTo(
                sweepX,
                sweepY
            );

            this.ctx.strokeStyle =
                "rgba(65, 225, 245, 0.085)";

            this.ctx.lineWidth = 1;

            this.ctx.stroke();

            /*
             * Sweep glow.
             */

            const gradient =
                this.ctx.createLinearGradient(
                    centerX,
                    centerY,
                    sweepX,
                    sweepY
                );

            gradient.addColorStop(
                0,
                "rgba(60, 220, 240, 0)"
            );

            gradient.addColorStop(
                0.72,
                "rgba(60, 220, 240, 0.018)"
            );

            gradient.addColorStop(
                1,
                "rgba(60, 220, 240, 0.075)"
            );

            this.ctx.beginPath();

            this.ctx.moveTo(
                centerX,
                centerY
            );

            this.ctx.lineTo(
                sweepX,
                sweepY
            );

            this.ctx.strokeStyle =
                gradient;

            this.ctx.lineWidth = 5;

            this.ctx.stroke();
        }

        createThreatPulse() {
            if (
                this.threatActivity <= 0
            ) {
                return;
            }

            const node =
                this.nodes[
                    Math.floor(
                        Math.random() *
                        this.nodes.length
                    )
                ];

            if (!node) {
                return;
            }

            this.alertPulses.push({
                x: node.x,
                y: node.y,
                radius: 4,
                life: 1
            });
        }

        updateAlertPulses(delta) {
            for (
                const pulse
                of this.alertPulses
            ) {
                pulse.radius +=
                    delta *
                    0.045;

                pulse.life -=
                    delta *
                    0.0007;
            }

            this.alertPulses =
                this.alertPulses.filter(
                    pulse =>
                        pulse.life > 0
                );
        }

        drawAlertPulses() {
            for (
                const pulse
                of this.alertPulses
            ) {
                this.ctx.beginPath();

                this.ctx.arc(
                    pulse.x,
                    pulse.y,
                    pulse.radius,
                    0,
                    Math.PI * 2
                );

                this.ctx.strokeStyle =
                    `rgba(255, 75, 85, ${
                        pulse.life * 0.7
                    })`;

                this.ctx.lineWidth = 1.5;

                this.ctx.shadowBlur = 15;

                this.ctx.shadowColor =
                    "rgba(255, 70, 80, 0.75)";

                this.ctx.stroke();

                this.ctx.shadowBlur = 0;
            }
        }

        drawVignette() {
            const gradient =
                this.ctx.createRadialGradient(
                    this.width / 2,
                    this.height / 2,
                    Math.min(
                        this.width,
                        this.height
                    ) *
                    0.12,

                    this.width / 2,
                    this.height / 2,
                    Math.max(
                        this.width,
                        this.height
                    ) *
                    0.76
                );

            gradient.addColorStop(
                0,
                "rgba(0, 0, 0, 0)"
            );

            gradient.addColorStop(
                0.7,
                "rgba(0, 0, 0, 0.08)"
            );

            gradient.addColorStop(
                1,
                "rgba(0, 0, 0, 0.65)"
            );

            this.ctx.fillStyle =
                gradient;

            this.ctx.fillRect(
                0,
                0,
                this.width,
                this.height
            );
        }

        async fetchSystemState() {
            try {
                const response =
                    await fetch(
                        "/api/stats",
                        {
                            cache: "no-store"
                        }
                    );

                if (!response.ok) {
                    return;
                }

                const stats =
                    await response.json();

                const pps =
                    Number(
                        stats.traffic_rate_pps ||
                        0
                    );

                const threats =
                    Number(
                        stats.threats_detected ||
                        0
                    );

                this.packetActivity =
                    Math.min(
                        3,
                        0.6 +
                        pps / 10
                    );

                this.threatActivity =
                    Math.min(
                        1,
                        threats / 5
                    );

                this.monitoring =
                    Boolean(
                        stats.monitoring_enabled
                    );

                /*
                 * Threat pulses.
                 */

                if (
                    this.threatActivity >
                    0
                ) {
                    this.createThreatPulse();
                }

            } catch (error) {
                /*
                 * The visualization continues
                 * even if the API is temporarily
                 * unavailable.
                 */
            }
        }

        animate(time) {
            const delta =
                Math.min(
                    time -
                    this.lastTime,
                    50
                );

            this.lastTime = time;

            this.ctx.clearRect(
                0,
                0,
                this.width,
                this.height
            );

            this.drawBackground();

            this.drawGrid();

            this.updateNodes(time);

            this.drawConnections();

            this.drawRadar(delta);

            this.updatePackets(delta);

            this.drawPackets();

            this.updateAlertPulses(delta);

            this.drawAlertPulses();

            this.drawNodes(time);

            this.drawVignette();

            requestAnimationFrame(
                (nextTime) =>
                    this.animate(nextTime)
            );
        }
    }

    function start() {
        new CyberNetworkBackground();
    }

    if (
        document.readyState ===
        "loading"
    ) {
        document.addEventListener(
            "DOMContentLoaded",
            start
        );
    } else {
        start();
    }
})();