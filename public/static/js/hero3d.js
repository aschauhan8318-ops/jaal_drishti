// Holographic shield around an email envelope. Colour follows the verdict
// stored in <body data-level="...">. Falls back to the CSS orb if WebGL fails.
import * as THREE from "three";

const COLORS = {
    idle: [0x22d3ee, 0xa78bfa],
    scanning: [0xa78bfa, 0x22d3ee],
    safe: [0x34d399, 0x22d3ee],
    suspicious: [0xfbbf24, 0xf472b6],
    phishing: [0xfb7185, 0xf472b6],
};

const canvas = document.getElementById("hero-canvas");
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

function glowTexture() {
    const size = 128;
    const c = document.createElement("canvas");
    c.width = c.height = size;
    const ctx = c.getContext("2d");
    const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    g.addColorStop(0, "rgba(255,255,255,1)");
    g.addColorStop(0.25, "rgba(255,255,255,.45)");
    g.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, size, size);
    return new THREE.CanvasTexture(c);
}

function envelopeLines() {
    const w = 0.62, h = 0.42;
    const p = [
        // outline
        [-w, -h], [w, -h], [w, -h], [w, h], [w, h], [-w, h], [-w, h], [-w, -h],
        // flap
        [-w, h], [0, 0.02], [0, 0.02], [w, h],
        // bottom folds
        [-w, -h], [-0.18, 0.12], [w, -h], [0.18, 0.12],
    ];
    const geo = new THREE.BufferGeometry().setFromPoints(p.map(([x, y]) => new THREE.Vector3(x, y, 0)));
    return geo;
}

function init() {
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: "low-power" });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    camera.position.set(0, 0, 6);

    const additive = { transparent: true, blending: THREE.AdditiveBlending, depthWrite: false };
    const [mainHex, accentHex] = COLORS[document.body.dataset.level] || COLORS.idle;
    const main = new THREE.Color(mainHex);
    const accent = new THREE.Color(accentHex);

    const root = new THREE.Group();
    scene.add(root);

    // Shield: wireframe icosahedron with a faint shell and glow
    const ico = new THREE.IcosahedronGeometry(1.45, 1);
    const shieldMat = new THREE.LineBasicMaterial({ color: main, opacity: 0.85, ...additive });
    const shield = new THREE.LineSegments(new THREE.EdgesGeometry(ico), shieldMat);
    const shellMat = new THREE.MeshBasicMaterial({ color: main, opacity: 0.07, side: THREE.DoubleSide, ...additive });
    const shell = new THREE.Mesh(ico, shellMat);
    root.add(shield, shell);

    const glowMat = new THREE.SpriteMaterial({ map: glowTexture(), color: main, opacity: 0.55, ...additive });
    const glow = new THREE.Sprite(glowMat);
    glow.scale.set(5, 5, 1);
    scene.add(glow);

    // Email envelope in the centre
    const envMat = new THREE.LineBasicMaterial({ color: 0xffffff, opacity: 0.95, ...additive });
    const envelope = new THREE.LineSegments(envelopeLines(), envMat);
    scene.add(envelope);

    // Orbit rings with travelling "packets"
    const rings = [];
    const ringSpecs = [
        { r: 2.05, tilt: [1.2, 0.2, 0], speed: 0.6, color: accent },
        { r: 2.35, tilt: [0.4, 1.1, 0.3], speed: -0.45, color: main },
        { r: 2.65, tilt: [-0.9, 0.5, 0.8], speed: 0.3, color: accent },
    ];
    for (const spec of ringSpecs) {
        const group = new THREE.Group();
        group.rotation.set(...spec.tilt);
        const ringMat = new THREE.MeshBasicMaterial({ color: spec.color, opacity: 0.35, ...additive });
        group.add(new THREE.Mesh(new THREE.TorusGeometry(spec.r, 0.008, 6, 160), ringMat));
        const packetMat = new THREE.SpriteMaterial({ map: glowMat.map, color: spec.color, opacity: 0.95, ...additive });
        const packet = new THREE.Sprite(packetMat);
        packet.scale.set(0.32, 0.32, 1);
        group.add(packet);
        scene.add(group);
        rings.push({ group, packet, ringMat, packetMat, ...spec });
    }

    // Particle field
    const count = 260;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
        const r = 3 + Math.random() * 3;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        positions.set([r * Math.sin(phi) * Math.cos(theta), r * Math.sin(phi) * Math.sin(theta), r * Math.cos(phi)], i * 3);
    }
    const pGeo = new THREE.BufferGeometry();
    pGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const pMat = new THREE.PointsMaterial({ color: accent, size: 0.05, map: glowMat.map, opacity: 0.8, ...additive });
    const particles = new THREE.Points(pGeo, pMat);
    scene.add(particles);

    // Follow verdict changes (e.g. "scanning" while the form submits)
    new MutationObserver(() => {
        const [m, a] = COLORS[document.body.dataset.level] || COLORS.idle;
        main.setHex(m);
        accent.setHex(a);
        for (const mat of [shieldMat, shellMat, glowMat]) mat.color.copy(main);
        pMat.color.copy(accent);
        rings.forEach((ring, i) => {
            const c = i === 1 ? main : accent;
            ring.ringMat.color.copy(c);
            ring.packetMat.color.copy(c);
        });
    }).observe(document.body, { attributes: true, attributeFilter: ["data-level"] });

    // Mouse parallax
    const pointer = { x: 0, y: 0 };
    addEventListener("pointermove", e => {
        pointer.x = e.clientX / innerWidth - 0.5;
        pointer.y = e.clientY / innerHeight - 0.5;
    });

    function resize() {
        const { clientWidth: w, clientHeight: h } = canvas.parentElement;
        renderer.setSize(w, h, false);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
    }
    new ResizeObserver(resize).observe(canvas.parentElement);
    resize();

    const clock = new THREE.Clock();
    function frame() {
        const t = clock.getElapsedTime();
        const level = document.body.dataset.level;
        const speed = level === "scanning" ? 3 : level === "phishing" ? 1.6 : 1;

        root.rotation.y = t * 0.25 * speed;
        root.rotation.x = Math.sin(t * 0.3) * 0.25;
        const pulse = level === "phishing" ? 1 + Math.sin(t * 4) * 0.05 : 1 + Math.sin(t * 1.5) * 0.02;
        root.scale.setScalar(pulse);
        glow.material.opacity = level === "phishing" ? 0.45 + Math.sin(t * 4) * 0.2 : 0.5;

        envelope.rotation.y = Math.sin(t * 0.8) * 0.5;
        envelope.position.y = Math.sin(t * 1.2) * 0.08;

        for (const ring of rings) {
            const a = t * ring.speed * speed;
            ring.packet.position.set(Math.cos(a) * ring.r, Math.sin(a) * ring.r, 0);
        }
        particles.rotation.y = t * 0.03;
        particles.rotation.x = t * 0.015;

        scene.rotation.y += (pointer.x * 0.5 - scene.rotation.y) * 0.05;
        scene.rotation.x += (pointer.y * 0.3 - scene.rotation.x) * 0.05;

        renderer.render(scene, camera);
    }

    document.body.classList.add("has-webgl");

    if (reduceMotion) {
        frame();
        return;
    }

    // Only animate while the hero is visible and the tab is active
    let visible = true;
    const update = () => renderer.setAnimationLoop(visible && !document.hidden ? frame : null);
    new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; update(); }).observe(canvas);
    document.addEventListener("visibilitychange", update);
    update();
}

try {
    init();
} catch (e) {
    console.warn("3D hero disabled:", e);
    canvas.remove();
}
