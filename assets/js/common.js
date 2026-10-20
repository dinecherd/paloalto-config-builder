/* PAN Lab Helper — JS commun (aucune dépendance, compatible file://)
   Usage dans chaque page :
     <body data-root="../" data-page="nat-sim">   (data-root = "" pour index.html)
     <div id="site-nav"></div> ... <div id="site-foot"></div>
     <script src="../assets/js/common.js"></script>
   API exposée : PAN.toast(msg), PAN.copy(text), PAN.ip.*, PAN.esc(str) */
(function () {
  const root = document.body.dataset.root || "";
  const page = document.body.dataset.page || "home";

  const LINKS = [
    { id: "home", href: "index.html", label: "Accueil" },
    { id: "guide-sec", href: "pages/guide-securite.html", label: "Guide Sécurité" },
    { id: "guide-nat", href: "pages/guide-nat.html", label: "Guide NAT" },
    { id: "sec-sim", href: "pages/simulateur-securite.html", label: "Simulateur Règle" },
    { id: "nat-sim", href: "pages/simulateur-nat.html", label: "Simulateur NAT" },
    { id: "quiz", href: "pages/quiz.html", label: "Quiz" },
  ];

  /* ---------- nav + footer ---------- */
  const nav = document.getElementById("site-nav");
  if (nav) {
    nav.outerHTML = `
    <nav class="nav" id="nav"><div class="wrap">
      <a class="brand" href="${root}index.html" aria-label="Accueil">
        <span class="logo"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"><path d="M12 2 3 6v6c0 5 3.8 9.4 9 10 5.2-.6 9-5 9-10V6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg></span>
        <span>PAN Lab Helper<small>EDU-210 · PAN-OS 11.0</small></span>
      </a>
      <button class="nav-burger" aria-label="Menu" aria-expanded="false">☰</button>
      <ul class="nav-links">
        ${LINKS.map(l => `<li><a href="${root}${l.href}"${l.id === page ? ' aria-current="page"' : ""}>${l.label}</a></li>`).join("")}
      </ul>
    </div></nav>`;
    const n = document.getElementById("nav");
    const b = n.querySelector(".nav-burger");
    b.addEventListener("click", () => { const o = n.classList.toggle("open"); b.setAttribute("aria-expanded", o); });
  }
  const foot = document.getElementById("site-foot");
  if (foot) {
    foot.outerHTML = `
    <footer class="foot"><div class="wrap">
      <div><b style="color:var(--tx2)">PAN Lab Helper</b> — outil pédagogique non officiel basé sur le cursus EDU-210 (PAN-OS 11.0).<br>
      Palo Alto Networks, PAN-OS et EDU-210 sont des marques de leurs propriétaires respectifs. Vérifiez toujours avec la documentation officielle.</div>
      <div>Conçu par <b style="color:var(--or2)">Dinèche RADJOU</b></div>
    </div></footer>`;
  }

  /* ---------- scroll progress ---------- */
  const prog = document.createElement("div"); prog.id = "progress"; document.body.prepend(prog);
  const onScroll = () => {
    const h = document.documentElement.scrollHeight - innerHeight;
    prog.style.width = (h > 0 ? (scrollY / h) * 100 : 0) + "%";
  };
  addEventListener("scroll", onScroll, { passive: true }); onScroll();

  /* ---------- reveal on scroll ---------- */
  const io = "IntersectionObserver" in window ? new IntersectionObserver(es => es.forEach(e => {
    if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }), { threshold: .12 }) : null;
  const watch = () => document.querySelectorAll("[data-reveal]:not(.in)").forEach((el, i) => {
    if (el.dataset.delay) el.style.transitionDelay = el.dataset.delay + "ms";
    io ? io.observe(el) : el.classList.add("in");
  });
  watch();

  /* ---------- spotlight cards ---------- */
  document.addEventListener("pointermove", e => {
    const c = e.target.closest && e.target.closest(".card");
    if (!c) return;
    if (!c.querySelector(".spot")) c.insertAdjacentHTML("afterbegin", '<span class="spot"></span>');
    const r = c.getBoundingClientRect();
    c.style.setProperty("--mx", e.clientX - r.left + "px");
    c.style.setProperty("--my", e.clientY - r.top + "px");
  });

  /* ---------- animated network background ---------- */
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!document.body.hasAttribute("data-no-bg")) {
    const cv = document.createElement("canvas"); cv.id = "bg-net"; document.body.prepend(cv);
    const ctx = cv.getContext("2d"); let W, H, pts;
    const init = () => {
      W = cv.width = innerWidth * devicePixelRatio; H = cv.height = innerHeight * devicePixelRatio;
      cv.style.width = innerWidth + "px"; cv.style.height = innerHeight + "px";
      const n = Math.min(70, Math.round(innerWidth / 22));
      pts = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .25 * devicePixelRatio, vy: (Math.random() - .5) * .25 * devicePixelRatio }));
    };
    const D = 140;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      const d = D * devicePixelRatio;
      for (const p of pts) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1;
      }
      for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
        const a = pts[i], b = pts[j], dx = a.x - b.x, dy = a.y - b.y, dd = Math.hypot(dx, dy);
        if (dd < d) { ctx.strokeStyle = `rgba(250,120,70,${(1 - dd / d) * .18})`; ctx.lineWidth = devicePixelRatio; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
      }
      ctx.fillStyle = "rgba(255,160,110,.5)";
      for (const p of pts) { ctx.beginPath(); ctx.arc(p.x, p.y, 1.4 * devicePixelRatio, 0, 7); ctx.fill(); }
      if (!reduce) requestAnimationFrame(draw);
    };
    init(); draw(); addEventListener("resize", init);
  }

  /* ---------- toast / copy ---------- */
  const toastEl = document.createElement("div"); toastEl.id = "toast"; toastEl.setAttribute("role", "status"); document.body.append(toastEl);
  let tt;
  function toast(m) { toastEl.textContent = m; toastEl.classList.add("show"); clearTimeout(tt); tt = setTimeout(() => toastEl.classList.remove("show"), 2200); }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch { const t = document.createElement("textarea"); t.value = text; document.body.append(t); t.select(); document.execCommand("copy"); t.remove(); }
    toast("Copié dans le presse-papiers ✓");
  }
  // boutons copier automatiques : <div class="code" data-copy>...</div>
  document.addEventListener("click", e => {
    const b = e.target.closest("[data-copy-target]");
    if (b) { const el = document.querySelector(b.dataset.copyTarget); if (el) copy(el.innerText); }
  });

  /* ---------- helpers IP ---------- */
  const ip = {
    valid: s => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(String(s).trim()),
    validCidr: s => { const [a, m] = String(s).trim().split("/"); return ip.valid(a) && (m === undefined || (/^\d+$/.test(m) && +m <= 32)); },
    toInt: s => s.split(".").reduce((a, o) => (a << 8) + +o, 0) >>> 0,
    isPrivate: s => { if (!ip.valid(s)) return false; const n = ip.toInt(s);
      return (n >>> 24) === 10 || (n >>> 20) === (0xAC1 /*172.16/12*/) || (n >>> 16) === 0xC0A8 || (n >>> 24) === 127; },
    validPort: p => /^\d+$/.test(String(p)) && +p >= 1 && +p <= 65535,
  };
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  window.PAN = { toast, copy, ip, esc, reveal: watch, root };
})();
