/* PANW Config Builder — JS commun (aucune dépendance, compatible file:// et GitHub Pages)
   Usage dans chaque page :
     <body data-root="../" data-page="cfg" data-product="panos|panorama">   (data-root = "" pour index.html)
     <div id="site-nav"></div> ... <div id="site-foot"></div>
     <script src="../assets/js/common.js"></script>
   data-page : home | pan-os | cfg | panorama | pano-cfg | nat-sim | sec-sim
   API exposée (window.PAN) :
     PAN.toast(msg)                 notification éphémère
     PAN.copy(text) → Promise       copie presse-papiers (+ toast)
     PAN.esc(str)                   échappement HTML
     PAN.ip.*                       valid, validCidr, toInt, isPrivate, validPort
     PAN.reveal()                   (ré)active data-reveal / data-stagger / data-count / data-tilt sur le contenu ajouté
     PAN.transition(fn)             exécute fn dans une View Transition (si dispo, sinon direct)
     PAN.palette.add([{label, icon?, sub?, kw?, group?, href? | run?}]) / .open() / .close()   palette ⌘K
     PAN.confetti(el?)              petite explosion de confettis (respecte prefers-reduced-motion)
     PAN.countUp(el)                anime un compteur [data-count]
     PAN.product                    "panos" | "panorama" | "" (hub)
     PAN.ZIP_URL, PAN.SITE_URL */
(function () {
  const body = document.body;
  const root = body.dataset.root || "";
  const page = body.dataset.page || "home";
  const ZIP_URL = "https://github.com/dinecherd/panw/archive/refs/heads/main.zip";
  const SITE_URL = "https://dinecherd.github.io/panw/";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(pointer: fine)").matches;

  const PANOS_PAGES = ["pan-os", "cfg", "nat-sim", "sec-sim"], PANO_PAGES = ["panorama", "pano-cfg"];
  let product = body.dataset.product || (PANOS_PAGES.includes(page) ? "panos" : PANO_PAGES.includes(page) ? "panorama" : "");
  if (product && !body.dataset.product) body.dataset.product = product;

  const NAV = [
    { id: "home", href: "index.html", label: "Accueil", icon: "🏠" },
    { label: "PAN-OS", prod: "panos", sub: "NGFW 11.0", items: [
      { id: "pan-os", href: "pages/pan-os.html", label: "PAN-OS", icon: "🛡️", desc: "Vue d'ensemble pare-feu NGFW 11.0" },
      { id: "cfg", href: "pages/configurateur.html", label: "Configurateur PAN-OS", icon: "⚙️", desc: "68 modules + parcours guidés, GUI & CLI" },
      { id: "nat-sim", href: "pages/simulateur-nat.html", label: "Assistant NAT", icon: "🔀", desc: "Flux animé avant / après NAT" },
      { id: "sec-sim", href: "pages/simulateur-securite.html", label: "Assistant Règle", icon: "🧱", desc: "Score bonnes pratiques, test de flux" },
    ] },
    { label: "Panorama", prod: "panorama", sub: "11.1", items: [
      { id: "panorama", href: "pages/panorama.html", label: "Panorama", icon: "🛰️", desc: "Vue d'ensemble gestion centralisée 11.1" },
      { id: "pano-cfg", href: "pages/panorama-configurateur.html", label: "Configurateur Panorama", icon: "🎛️", desc: "Templates, device groups, logs, push" },
    ] },
  ];
  const PROD_LABEL = { panos: "PAN-OS 11.0", panorama: "Panorama 11.1" };

  /* ---------- nav + footer ---------- */
  const nav = document.getElementById("site-nav");
  if (nav) {
    const link = l => `<a href="${root}${l.href}"${l.id === page ? ' aria-current="page"' : ""}>${l.label}</a>`;
    const dd = (g, i) => {
      const cur = g.items.some(l => l.id === page) || g.prod === product;
      return `<li class="nav-dd${cur ? " cur" : ""}" data-prod="${g.prod}">
        <button class="nav-dd-b" type="button" aria-expanded="false" aria-controls="dd-${i}">${g.label}<small>${g.sub}</small><span class="caret" aria-hidden="true">▾</span></button>
        <div class="nav-dd-m" id="dd-${i}" role="menu">${g.items.map(l => `<a role="menuitem" href="${root}${l.href}"${l.id === page ? ' aria-current="page"' : ""}>
          <i>${l.icon}</i><span><b>${l.label}</b><small>${l.desc}</small></span></a>`).join("")}</div></li>`;
    };
    nav.outerHTML = `
    <div class="topbar" id="topbar"><div class="wrap">
      <span class="topbar-t"><b>PANW Config Builder</b> · fonctionne aussi <b>hors ligne</b></span>
      <a class="btn-dl" data-magnetic href="${ZIP_URL}" title="Télécharge le site complet (.zip) : dézippe puis ouvre index.html, fonctionne hors ligne" rel="noopener">⬇ Télécharger le site (local)</a>
    </div></div>
    <nav class="nav" id="nav"><div class="wrap">
      <a class="brand" href="${root}index.html" aria-label="Accueil PANW Config Builder">
        <span class="logo"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"><path d="M12 2 3 6v6c0 5 3.8 9.4 9 10 5.2-.6 9-5 9-10V6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg></span>
        <span>PANW Config Builder<small>${product ? PROD_LABEL[product] : "PAN-OS 11.0 · Panorama 11.1"}</small></span>
      </a>
      ${product ? `<span class="nav-prod" title="Produit courant"><i></i>${product === "panorama" ? "Panorama" : "PAN-OS"}</span>` : ""}
      <button class="nav-burger" type="button" aria-label="Menu" aria-expanded="false"><span></span><span></span><span></span></button>
      <ul class="nav-links">
        ${NAV.map((g, i) => g.items ? dd(g, i) : `<li>${link(g)}</li>`).join("")}
        <li><button class="nav-k" type="button" data-palette title="Palette de commandes (⌘K / Ctrl K)">🔎 <span>Rechercher</span> <kbd>⌘K</kbd></button></li>
        <li class="nav-dl-m"><a href="${ZIP_URL}" title="Dézippe puis ouvre index.html, fonctionne hors ligne">⬇ Télécharger le site (local)</a></li>
      </ul>
    </div></nav>`;
    const n = document.getElementById("nav");
    const b = n.querySelector(".nav-burger");
    const closeDD = except => n.querySelectorAll(".nav-dd.open").forEach(x => { if (x !== except) { x.classList.remove("open"); x.querySelector(".nav-dd-b").setAttribute("aria-expanded", "false"); } });
    b.addEventListener("click", () => { const o = n.classList.toggle("open"); b.setAttribute("aria-expanded", o); body.classList.toggle("nav-open", o); });
    n.querySelectorAll(".nav-dd-b").forEach(btn => btn.addEventListener("click", e => {
      const li = btn.parentElement; const o = !li.classList.contains("open");
      closeDD(li); li.classList.toggle("open", o); btn.setAttribute("aria-expanded", o); e.stopPropagation();
    }));
    document.addEventListener("click", e => { if (!e.target.closest(".nav-dd")) closeDD(); });
    document.addEventListener("keydown", e => { if (e.key === "Escape") { closeDD(); n.classList.remove("open"); b.setAttribute("aria-expanded", "false"); body.classList.remove("nav-open"); } });
  }
  const foot = document.getElementById("site-foot");
  if (foot) {
    foot.outerHTML = `
    <footer class="foot"><div class="wrap">
      <div><b style="color:var(--tx2)">PANW Config Builder</b> — outil d'aide à la configuration Palo Alto Networks, non officiel (PAN-OS 11.0 · Panorama 11.1).<br>
      Palo Alto Networks, PAN-OS et Panorama sont des marques de leurs propriétaires respectifs. Relisez toujours la configuration générée avant de l'appliquer en production.<br>
      <a href="${ZIP_URL}" title="Dézippe puis ouvre index.html, fonctionne hors ligne">⬇ Télécharger le site (local)</a> · <a href="${SITE_URL}" rel="noopener">${SITE_URL.replace("https://", "")}</a></div>
      <div class="foot-links"><a href="${root}pages/configurateur.html">Configurateur PAN-OS</a><a href="${root}pages/panorama-configurateur.html">Configurateur Panorama</a>
      <span>Conçu par <b style="color:var(--or2)">Dinèche RADJOU</b></span></div>
    </div></footer>`;
  }

  /* ---------- scroll progress ---------- */
  const prog = document.createElement("div"); prog.id = "progress"; body.prepend(prog);
  let rafS = 0;
  const onScroll = () => {
    if (rafS) return;
    rafS = requestAnimationFrame(() => {
      rafS = 0;
      const h = document.documentElement.scrollHeight - innerHeight;
      prog.style.width = (h > 0 ? (scrollY / h) * 100 : 0) + "%";
      body.classList.toggle("scrolled", scrollY > 30);
    });
  };
  addEventListener("scroll", onScroll, { passive: true }); onScroll();

  /* ---------- compteurs animés : <b data-count="68" data-suffix="+" data-duration="1400">0</b> ---------- */
  function countUp(el) {
    if (el.dataset.counted) return; el.dataset.counted = 1;
    const to = parseFloat(el.dataset.count) || 0, dec = (String(el.dataset.count).split(".")[1] || "").length;
    const pre = el.dataset.prefix || "", suf = el.dataset.suffix || "", dur = +el.dataset.duration || 1400;
    const f = x => pre + x.toLocaleString("fr-FR", { minimumFractionDigits: dec, maximumFractionDigits: dec }) + suf;
    if (reduce) { el.textContent = f(to); return; }
    const t0 = performance.now();
    const step = t => { const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 4); el.textContent = f(+(to * e).toFixed(dec)); if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }

  /* ---------- reveal on scroll (+ cascade) ---------- */
  const io = "IntersectionObserver" in window ? new IntersectionObserver(es => es.forEach(e => {
    if (!e.isIntersecting) return;
    const t = e.target;
    if (t.hasAttribute("data-count")) countUp(t); else t.classList.add("in");
    io.unobserve(t);
  }), { threshold: .12, rootMargin: "0px 0px -40px 0px" }) : null;
  function watch() {
    document.querySelectorAll("[data-stagger]:not([data-staggered])").forEach(c => {
      c.dataset.staggered = 1;
      const stepMs = +c.dataset.stagger || 80, kind = c.dataset.staggerType || "";
      [...c.children].forEach((ch, i) => {
        if (!ch.hasAttribute("data-reveal")) ch.setAttribute("data-reveal", kind);
        if (!ch.dataset.delay) ch.dataset.delay = (+c.dataset.delay || 0) + i * stepMs;
      });
    });
    document.querySelectorAll("[data-reveal]:not(.in)").forEach(el => {
      if (el.dataset.delay) el.style.transitionDelay = el.dataset.delay + "ms";
      io ? io.observe(el) : el.classList.add("in");
    });
    document.querySelectorAll("[data-count]:not([data-counted])").forEach(el => io ? io.observe(el) : countUp(el));
  }
  watch();
  /* filet de sécurité : rien ne doit rester invisible (impression, onglets en arrière-plan…) */
  addEventListener("beforeprint", () => { document.querySelectorAll("[data-reveal]").forEach(el => el.classList.add("in")); document.querySelectorAll("[data-count]").forEach(countUp); });

  /* ---------- spotlight cards + tilt ---------- */
  document.addEventListener("pointermove", e => {
    const c = e.target.closest && e.target.closest(".card, .glass, [data-spot]");
    if (!c) return;
    if (c.classList.contains("card") && !c.querySelector(":scope > .spot")) c.insertAdjacentHTML("afterbegin", '<span class="spot"></span>');
    const r = c.getBoundingClientRect();
    c.style.setProperty("--mx", e.clientX - r.left + "px");
    c.style.setProperty("--my", e.clientY - r.top + "px");
    if (!reduce && fine && c.hasAttribute("data-tilt")) {
      const px = (e.clientX - r.left) / r.width - .5, py = (e.clientY - r.top) / r.height - .5, k = +c.dataset.tilt || 8;
      c.style.transform = `perspective(900px) rotateX(${(-py * k).toFixed(2)}deg) rotateY(${(px * k).toFixed(2)}deg) translateY(-4px)`;
    }
  }, { passive: true });
  document.addEventListener("pointerout", e => {
    const c = e.target.closest && e.target.closest("[data-tilt]");
    if (c && !c.contains(e.relatedTarget)) c.style.transform = "";
  });

  /* ---------- boutons magnétiques : .btn.primary, .btn-dl, [data-magnetic] ---------- */
  if (fine && !reduce) {
    let mag = null;
    const SEL = ".btn.primary, .btn-dl, [data-magnetic]";
    document.addEventListener("pointermove", e => {
      const m = e.target.closest && e.target.closest(SEL);
      if (mag && mag !== m) { mag.style.transform = ""; mag.classList.remove("is-mag"); }
      mag = m;
      if (!m || m.disabled) return;
      const r = m.getBoundingClientRect(), k = +m.dataset.magnetic || .28;
      const x = (e.clientX - r.left - r.width / 2) * k, y = (e.clientY - r.top - r.height / 2) * k;
      m.classList.add("is-mag");
      m.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px)`;
    }, { passive: true });
    document.addEventListener("pointerleave", () => { if (mag) { mag.style.transform = ""; mag = null; } });
  }

  /* ---------- curseur / spotlight global ---------- */
  if (fine && !reduce && !body.hasAttribute("data-no-cursor")) {
    const g = document.createElement("div"); g.id = "cursor-glow"; g.setAttribute("aria-hidden", "true"); body.append(g);
    let tx = innerWidth / 2, ty = innerHeight / 3, cx = tx, cy = ty, run = false;
    const loop = () => { cx += (tx - cx) * .14; cy += (ty - cy) * .14; g.style.transform = `translate3d(${cx}px, ${cy}px, 0)`;
      if (Math.abs(tx - cx) + Math.abs(ty - cy) > .5) requestAnimationFrame(loop); else run = false; };
    addEventListener("pointermove", e => { tx = e.clientX; ty = e.clientY; g.classList.add("on");
      const hot = e.target.closest && e.target.closest("a, button, [role=tab], input, select, textarea, label");
      g.classList.toggle("hot", !!hot);
      if (!run) { run = true; requestAnimationFrame(loop); } }, { passive: true });
    document.addEventListener("pointerleave", () => g.classList.remove("on"));
  }

  /* ---------- fond réseau animé (couleur = accent du produit) ---------- */
  if (!body.hasAttribute("data-no-bg")) {
    const cv = document.createElement("canvas"); cv.id = "bg-net"; cv.setAttribute("aria-hidden", "true"); body.prepend(cv);
    const ctx = cv.getContext && cv.getContext("2d");
    if (ctx) {
      const acc = (getComputedStyle(body).getPropertyValue("--acc-rgb") || "250,88,45").trim() || "250,88,45";
      let W, H, pts, vis = true;
      const init = () => {
        const dpr = Math.min(2, devicePixelRatio || 1);
        W = cv.width = innerWidth * dpr; H = cv.height = innerHeight * dpr;
        cv.style.width = innerWidth + "px"; cv.style.height = innerHeight + "px";
        const n = Math.min(70, Math.round(innerWidth / 22));
        pts = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .25 * dpr, vy: (Math.random() - .5) * .25 * dpr }));
        cv.dpr = dpr;
      };
      const D = 140;
      const draw = () => {
        if (!vis) return;
        const dpr = cv.dpr; ctx.clearRect(0, 0, W, H);
        const d = D * dpr;
        for (const p of pts) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1; }
        for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
          const a = pts[i], b = pts[j], dd = Math.hypot(a.x - b.x, a.y - b.y);
          if (dd < d) { ctx.strokeStyle = `rgba(${acc},${(1 - dd / d) * .2})`; ctx.lineWidth = dpr; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
        }
        ctx.fillStyle = `rgba(${acc},.55)`;
        for (const p of pts) { ctx.beginPath(); ctx.arc(p.x, p.y, 1.4 * dpr, 0, 7); ctx.fill(); }
        if (!reduce) requestAnimationFrame(draw);
      };
      document.addEventListener("visibilitychange", () => { const was = vis; vis = !document.hidden; if (vis && !was && !reduce) requestAnimationFrame(draw); });
      init(); draw(); addEventListener("resize", () => { init(); if (reduce) draw(); });
    }
  }

  /* ---------- transitions de page ---------- */
  const crossDocVT = /^https?:$/.test(location.protocol) && "onpagereveal" in window;
  function transition(fn) {
    if (!reduce && document.startViewTransition && !document.hidden) {
      try {
        const vt = document.startViewTransition(fn);
        ["ready", "finished"].forEach(k => vt[k] && vt[k].catch(() => { /* transition interrompue : sans gravité */ }));
        vt.updateCallbackDone && vt.updateCallbackDone.catch(e => { if (!e || e.name !== "AbortError") console.error(e); });
        return vt;
      } catch { /* */ }
    }
    fn();
  }
  if (!reduce && !crossDocVT) {
    body.classList.add("page-enter");
    setTimeout(() => body.classList.remove("page-enter"), 700);
    document.addEventListener("click", e => {
      const a = e.target.closest && e.target.closest("a[href]");
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      if (a.target && a.target !== "_self" || a.hasAttribute("download")) return;
      const href = a.getAttribute("href");
      if (!href || href.startsWith("#") || /^(mailto|tel|javascript):/i.test(href)) return;
      let url; try { url = new URL(a.href, location.href); } catch { return; }
      if (url.origin !== location.origin && location.protocol !== "file:") return;
      if (url.protocol !== location.protocol || !/\.html?$|\/$/.test(url.pathname)) return;
      if (url.pathname === location.pathname && url.hash) return;
      e.preventDefault();
      body.classList.add("page-leave");
      setTimeout(() => { location.href = a.href; }, 230);
    });
    addEventListener("pageshow", e => { if (e.persisted) body.classList.remove("page-leave"); });
  }

  /* ---------- toast / copy ---------- */
  const toastEl = document.createElement("div"); toastEl.id = "toast"; toastEl.setAttribute("role", "status"); toastEl.setAttribute("aria-live", "polite"); body.append(toastEl);
  let tt;
  function toast(m) { toastEl.textContent = m; toastEl.classList.add("show"); clearTimeout(tt); tt = setTimeout(() => toastEl.classList.remove("show"), 2600); }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch { const t = document.createElement("textarea"); t.value = text; t.style.cssText = "position:fixed;opacity:0"; body.append(t); t.select(); try { document.execCommand("copy"); } catch { /* */ } t.remove(); }
    toast("Copié dans le presse-papiers ✓");
  }
  // boutons copier automatiques : <button data-copy-target="#id">
  document.addEventListener("click", e => {
    const b = e.target.closest && e.target.closest("[data-copy-target]");
    if (b) {
      const el = document.querySelector(b.dataset.copyTarget);
      if (el) { copy(el.innerText); const o = b.innerHTML; b.classList.add("copied"); b.textContent = "✓ Copié"; setTimeout(() => { b.innerHTML = o; b.classList.remove("copied"); }, 1400); }
    }
  });

  /* ---------- confettis ---------- */
  function confetti(el) {
    if (reduce) return;
    const r = el && el.getBoundingClientRect ? el.getBoundingClientRect() : { left: innerWidth / 2, top: innerHeight / 2, width: 0, height: 0 };
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    const cols = ["var(--or)", "var(--or2)", "var(--ok)", "var(--sky)", "#FFD166"];
    for (let i = 0; i < 26; i++) {
      const s = document.createElement("i"); s.className = "confetti";
      const a = Math.random() * Math.PI * 2, d = 60 + Math.random() * 110;
      s.style.cssText = `left:${x}px;top:${y}px;background:${cols[i % cols.length]};--dx:${Math.cos(a) * d}px;--dy:${Math.sin(a) * d - 40}px;--rot:${Math.random() * 720 - 360}deg`;
      body.append(s); setTimeout(() => s.remove(), 1100);
    }
  }

  /* ---------- palette de commandes (⌘K) ---------- */
  const palItems = [];
  NAV.forEach(g => (g.items || [g]).forEach(l => palItems.push({ icon: l.icon || "↗", label: l.label, sub: l.desc || "Page", href: root + l.href, group: "Pages", kw: g.label })));
  palItems.push({ icon: "⬇", label: "Télécharger le site (local, .zip)", sub: "Dézippe puis ouvre index.html — fonctionne hors ligne", href: ZIP_URL, group: "Pages", kw: "zip offline hors ligne download" });
  let pal = null, palSel = 0, palList = [];
  const norm = s => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
  function palBuild() {
    pal = document.createElement("div"); pal.id = "palette"; pal.hidden = true;
    pal.innerHTML = `<div class="pal-back" data-pal-close></div>
      <div class="pal-box glass" role="dialog" aria-modal="true" aria-label="Palette de commandes">
        <input type="text" id="pal-q" placeholder="Aller à un module, un parcours, une page…" autocomplete="off" spellcheck="false" aria-label="Rechercher">
        <ul id="pal-list" role="listbox"></ul>
        <div class="pal-foot"><span><kbd>↑</kbd><kbd>↓</kbd> naviguer</span><span><kbd>⏎</kbd> ouvrir</span><span><kbd>Esc</kbd> fermer</span><span><kbd>/</kbd> recherche</span></div>
      </div>`;
    body.append(pal);
    const qi = pal.querySelector("#pal-q");
    qi.addEventListener("input", palRender);
    qi.addEventListener("keydown", e => {
      if (e.key === "ArrowDown") { e.preventDefault(); palSel = Math.min(palList.length - 1, palSel + 1); palHi(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); palSel = Math.max(0, palSel - 1); palHi(); }
      else if (e.key === "Enter") { e.preventDefault(); palGo(palList[palSel]); }
    });
    pal.addEventListener("click", e => {
      if (e.target.closest("[data-pal-close]")) return palClose();
      const li = e.target.closest("[data-k]"); if (li) palGo(palList[+li.dataset.k]);
    });
    pal.addEventListener("pointermove", e => { const li = e.target.closest("[data-k]"); if (li && +li.dataset.k !== palSel) { palSel = +li.dataset.k; palHi(); } });
  }
  function palRender() {
    const qs = norm(pal.querySelector("#pal-q").value).split(/\s+/).filter(Boolean);
    palList = palItems.filter(it => { const h = norm(it.label + " " + (it.sub || "") + " " + (it.kw || "") + " " + (it.group || "")); return qs.every(w => h.includes(w)); });
    palList.sort((a, b) => (qs.length ? (norm(b.label).includes(qs[0]) - norm(a.label).includes(qs[0])) : 0));
    palList = palList.slice(0, 60); palSel = 0;
    let g = null;
    pal.querySelector("#pal-list").innerHTML = palList.map((it, k) => {
      const head = it.group !== g ? `<li class="pal-g" role="presentation">${esc((g = it.group) || "")}</li>` : "";
      return head + `<li data-k="${k}" role="option"><i>${it.icon || "↗"}</i><span><b>${esc(it.label)}</b>${it.sub ? `<small>${esc(it.sub)}</small>` : ""}</span></li>`;
    }).join("") || `<li class="pal-empty">Aucun résultat</li>`;
    palHi();
  }
  function palHi() {
    pal.querySelectorAll("[data-k]").forEach(li => { const on = +li.dataset.k === palSel; li.classList.toggle("on", on); li.setAttribute("aria-selected", on); if (on) li.scrollIntoView({ block: "nearest" }); });
  }
  function palGo(it) {
    if (!it) return; palClose();
    if (it.run) return it.run();
    if (it.href) { if (it.href.startsWith("#")) location.hash = it.href.slice(1); else location.href = it.href; }
  }
  function palOpen() {
    if (!pal) palBuild();
    pal.hidden = false; body.classList.add("pal-open");
    const qi = pal.querySelector("#pal-q"); qi.value = ""; palRender();
    requestAnimationFrame(() => { pal.classList.add("show"); qi.focus(); });
  }
  function palClose() { if (!pal) return; pal.classList.remove("show"); body.classList.remove("pal-open"); setTimeout(() => { pal.hidden = true; }, 160); }
  const palette = { add: items => { (items || []).forEach(i => i && i.label && palItems.push(i)); }, open: palOpen, close: palClose, items: palItems };
  document.addEventListener("click", e => { if (e.target.closest && e.target.closest("[data-palette]")) palOpen(); });

  /* ---------- raccourcis clavier ---------- */
  document.addEventListener("keydown", e => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); pal && !pal.hidden ? palClose() : palOpen(); return; }
    if (e.key === "Escape" && pal && !pal.hidden) { palClose(); return; }
    if (e.key === "/" && !typing) {
      e.preventDefault();
      const s = document.querySelector("[data-search], #cfg-search");
      if (s && s.offsetParent !== null) { s.focus(); s.select && s.select(); } else palOpen();
    }
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

  window.PAN = Object.assign(window.PAN || {}, { toast, copy, ip, esc, reveal: watch, root, transition, palette, confetti, countUp, product, page, ZIP_URL, SITE_URL });
})();
