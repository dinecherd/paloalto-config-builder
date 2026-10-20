/* PAN Lab Helper — JS partagé des guides (vanilla, compatible file://)
   À charger APRÈS ../assets/js/common.js
   - Sommaire sticky + progression de lecture + section active
   - Chrome des mocks WebUI (.pan[data-mock]) : barre de menus, titre, onglets
   - Remplissage animé des champs, anneaux des numéros d'étapes
   - Pipeline animé, démo d'évaluation top-down, animateur "règle d'or" NAT */
(function () {
  "use strict";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = (window.PAN && PAN.esc) || (s => String(s));
  const toast = (m) => window.PAN && PAN.toast(m);
  const onView = (els, cb, opts) => {
    if (!("IntersectionObserver" in window)) { els.forEach(cb); return; }
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (e.isIntersecting) { cb(e.target); io.unobserve(e.target); }
    }), opts || { threshold: .25 });
    els.forEach(el => io.observe(el));
  };

  /* ---------- 1. Sommaire ---------- */
  const toc = $(".toc");
  const sections = $$(".g-main > section[id]");
  if (toc && sections.length) {
    const list = $("ol", toc);
    sections.forEach(s => {
      const h = $("h2", s);
      const t = s.dataset.toc || (h ? h.textContent : s.id);
      const li = document.createElement("li");
      li.innerHTML = `<a href="#${s.id}">${esc(t.trim())}</a>`;
      list.append(li);
    });
    const links = $$("a", list);
    const ring = $(".toc-ring .fg", toc), pct = $(".toc-ring b", toc), main = $(".g-main");
    const C = 113.1;
    const head = $(".toc-head", toc), tog = $(".toc-toggle", toc);
    const setOpen = o => { toc.classList.toggle("open", o); if (tog) tog.setAttribute("aria-expanded", o); };
    if (head) head.addEventListener("click", () => setOpen(!toc.classList.contains("open")));
    links.forEach(a => a.addEventListener("click", () => setOpen(false)));
    let ticking = false;
    const update = () => {
      ticking = false;
      const r = main.getBoundingClientRect();
      const total = r.height - innerHeight * .6;
      const p = Math.max(0, Math.min(1, (-r.top + innerHeight * .25) / (total > 0 ? total : 1)));
      if (ring) ring.style.strokeDashoffset = (C * (1 - p)).toFixed(1);
      if (pct) pct.textContent = Math.round(p * 100) + "%";
      let cur = 0;
      sections.forEach((s, i) => { if (s.getBoundingClientRect().top < innerHeight * .32) cur = i; });
      links.forEach((a, i) => {
        a.classList.toggle("on", i === cur);
        a.classList.toggle("done", i < cur);
        if (i === cur) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
      });
    };
    addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } }, { passive: true });
    addEventListener("resize", update);
    update();
  }

  /* ---------- 2. Mocks WebUI ---------- */
  const MENU = ["Dashboard", "ACC", "Monitor", "Policies", "Objects", "Network", "Device"];
  let mockId = 0;
  $$(".pan[data-mock]").forEach(p => {
    const d = p.dataset;
    if (!p.id) p.id = "mock-" + (++mockId);
    const top = `<div class="pan-top" aria-hidden="true">${MENU.map(m => `<span${m === d.menu ? ' class="on"' : ""}>${m}</span>`).join("")}<span style="margin-left:auto;opacity:1"><span class="pan-commit">Commit</span></span></div>`;
    const title = `<div class="pan-title"><span>${esc(d.mock)}</span>${d.path ? `<span class="pan-path">${esc(d.path)}</span>` : ""}</div>`;
    let tabs = "";
    if (d.tabs) {
      const ts = d.tabs.split("|");
      tabs = `<div class="pan-tabs" role="tablist" aria-label="Onglets de la fenêtre ${esc(d.mock)}">${ts.map(t =>
        `<button type="button" role="tab" data-tab="${esc(t)}" aria-selected="${t === d.active}"${t === d.active ? ' class="on"' : ""}>${esc(t)}</button>`).join("")}</div>`;
    }
    p.insertAdjacentHTML("afterbegin", top + title + tabs);
    if (d.foot) {
      const f = d.foot === "commit"
        ? `<div class="pan-foot"><span class="pan-btn">Preview Changes</span><span class="pan-btn">Validate Commit</span><span class="pan-btn pri">Commit</span></div>`
        : d.foot === "table"
          ? `<div class="pan-foot" style="justify-content:flex-start;flex-wrap:wrap"><span class="pan-btn">⊕ Add</span><span class="pan-btn">⊖ Delete</span><span class="pan-btn">Clone</span><span class="pan-btn">Override</span><span class="pan-btn">Move ▾</span><span class="pan-btn">Enable</span><span class="pan-btn">Disable</span></div>`
          : `<div class="pan-foot"><span class="pan-btn pri">OK</span><span class="pan-btn">Cancel</span></div>`;
      p.insertAdjacentHTML("beforeend", f);
    }
    p.setAttribute("role", "figure");
    if (!p.hasAttribute("aria-label")) p.setAttribute("aria-label", `Capture simulée de la WebUI PAN-OS : ${d.mock}${d.active ? " — onglet " + d.active : ""}`);
  });
  // clic sur un onglet : saute vers le mock du même groupe affichant cet onglet
  document.addEventListener("click", e => {
    const b = e.target.closest(".pan-tabs button[data-tab]");
    if (!b) return;
    const p = b.closest(".pan[data-mock]");
    const g = p && p.dataset.group;
    if (!g || b.classList.contains("on")) return;
    const target = $$(`.pan[data-group="${g}"]`).find(x => x.dataset.active === b.dataset.tab);
    if (!target) { toast(`Onglet « ${b.dataset.tab} » : rien à modifier dans ce tuto`); return; }
    const anchor = target.closest(".gstep") || target;
    anchor.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    const btn = $(`.pan-tabs button.on`, target);
    setTimeout(() => btn && btn.focus({ preventScroll: true }), reduce ? 0 : 600);
  });

  /* ---------- 3. Remplissage animé des champs ---------- */
  const fills = $$(".pan").filter(p => p.querySelector(".fill"));
  if (!reduce) {
    fills.forEach(p => p.classList.add("fill-ready"));
    onView(fills, p => {
      $$(".fill", p).forEach((f, i) => setTimeout(() => {
        f.classList.add("typed");
        if (f.classList.contains("pan-val")) { f.classList.remove("hl"); void f.offsetWidth; f.classList.add("hl"); }
      }, 250 + i * 320));
    }, { threshold: .35 });
  }

  /* ---------- 4. Numéros d'étapes ---------- */
  const steps = $$(".gstep");
  steps.forEach(s => {
    const n = $(".gnum", s);
    if (n && !n.querySelector("svg")) n.insertAdjacentHTML("afterbegin",
      '<svg viewBox="0 0 56 56" aria-hidden="true"><circle class="bg" cx="28" cy="28" r="26"/><circle class="fg" cx="28" cy="28" r="26"/></svg>');
  });
  if (reduce) steps.forEach(s => s.classList.add("seen"));
  else onView(steps, s => s.classList.add("seen"), { threshold: .2 });

  /* ---------- 5. Do / Don't : marque les cellules ---------- */
  // (les lignes .dd-row reçoivent .in via common.js ; rien à faire ici)

  /* ---------- 6. Pipeline animé ---------- */
  $$(".pipe[data-cycle]").forEach(pipe => {
    const items = $$("li", pipe);
    if (reduce || !items.length) return;
    let i = 0, timer = null;
    const tick = () => { items.forEach((li, k) => li.classList.toggle("on", k === i)); i = (i + 1) % items.length; };
    const io = "IntersectionObserver" in window ? new IntersectionObserver(es => es.forEach(e => {
      if (e.isIntersecting && !timer) { tick(); timer = setInterval(tick, 1300); }
      else if (!e.isIntersecting && timer) { clearInterval(timer); timer = null; }
    }), { threshold: .3 }) : null;
    io && io.observe(pipe);
    pipe.addEventListener("mouseover", e => {
      const li = e.target.closest("li"); if (!li) return;
      clearInterval(timer); timer = null; items.forEach(x => x.classList.toggle("on", x === li));
    });
  });

  /* ---------- 7. Démo évaluation top-down ---------- */
  $$("[data-topdown]").forEach(box => {
    const rows = $$("tbody tr", box), btn = $("button[data-run]", box), out = $(".td-out", box);
    const pkts = JSON.parse(box.dataset.topdown);
    let k = 0, busy = false;
    btn.addEventListener("click", () => {
      if (busy) return; busy = true;
      const pk = pkts[k % pkts.length]; k++;
      rows.forEach(r => r.classList.remove("hl", "miss"));
      out.innerHTML = `Paquet : <b>${esc(pk.label)}</b>`;
      const match = rows.findIndex(r => r.dataset.rule === pk.match);
      let i = 0;
      const step = () => {
        rows.forEach(r => r.classList.remove("hl"));
        if (i > match) { busy = false; return; }
        rows[i].classList.add("hl");
        if (i === match) {
          out.innerHTML = `Paquet : <b>${esc(pk.label)}</b> → 1ʳᵉ correspondance : <b style="color:var(--or2)">${esc(pk.match)}</b> (règle n°${i + 1}) — action <b>${esc(pk.action)}</b>. Les règles suivantes ne sont <u>pas</u> évaluées.`;
          busy = false; return;
        }
        i++; setTimeout(step, reduce ? 0 : 520);
      };
      step();
    });
  });

  /* ---------- 8. SVG SMIL : pause si reduced-motion ---------- */
  if (reduce) $$("svg").forEach(s => { try { s.pauseAnimations && s.pauseAnimations(); } catch (e) { /* noop */ } });

  /* ---------- 9. Animateur de la RÈGLE D'OR (NAT) ---------- */
  const G = $("#golden");
  if (G && window.GOLDEN_MODES) {
    const M = window.GOLDEN_MODES;
    const svg = $("svg", G);
    const q = id => svg.getElementById ? svg.getElementById(id) : $("#" + id, svg);
    const pkt = q("gr-pkt"), fSrc = q("gr-src"), fDst = q("gr-dst"), fZn = q("gr-zn"), fw = q("gr-fw");
    const natBox = $("#gr-nat", G), secBox = $("#gr-sec", G), note = $("#gr-note", G), st = $(".golden-ctrl .st", G);
    const playBtn = $("#gr-play", G);
    const setTxt = (id, t) => { const el = q(id); if (el) el.textContent = t; };
    const setFill = (id, c) => { const el = q(id); if (el) el.setAttribute("fill", c); };
    const setStroke = (id, c) => { const el = q(id); if (el) el.setAttribute("stroke", c); };
    let mode = Object.keys(M)[0], t0 = 0, playing = !reduce, phase = -1, raf = 0;
    const X0 = 30, XF = 325, X1 = 620; // positions du paquet
    const kv = rows => `<div class="kv">${rows.map(r => `<span>${esc(r[0])}</span><b data-k="${esc(r[0])}">${esc(r[1])}${r[2] ? `<em class="${r[2]}">${r[2] === "pre" ? "PRÉ-NAT" : "POST-NAT"}</em>` : ""}</b>`).join("")}</div>`;
    const apply = () => {
      const m = M[mode];
      setTxt("gr-lz", m.lz); setTxt("gr-rz", m.rz); setFill("gr-lzr", m.lc); setFill("gr-rzr", m.rc);
      setStroke("gr-lzb", m.lc); setStroke("gr-rzb", m.rc);
      setTxt("gr-lh", m.lh); setTxt("gr-lip", m.lip); setTxt("gr-rh", m.rh); setTxt("gr-rip", m.rip);
      setTxt("gr-ghost", m.ghost || ""); setTxt("gr-ghost2", m.ghost2 || "");
      setTxt("gr-nat-t", m.natLabel);
      natBox.innerHTML = kv(m.nat); secBox.innerHTML = kv(m.sec); note.innerHTML = "<b>À retenir</b>" + m.note;
      const ba = $("#gr-ba", G);
      if (ba) {
        const hi = (v, on) => on ? `<mark>${esc(v)}</mark>` : esc(v);
        ba.innerHTML = `<span>Avant <em class="pre">PRÉ-NAT</em></span><b>SRC ${esc(m.before.src)} → DST ${esc(m.before.dst)}</b>` +
          `<span>Après <em class="post">POST-NAT</em></span><b>SRC ${hi(m.after.src, m.chg === "src")} → DST ${hi(m.after.dst, m.chg === "dst")}</b>`;
      }
      $$(".golden-modes button", G).forEach(b => b.setAttribute("aria-pressed", b.dataset.mode === mode));
      phase = -1; t0 = performance.now();
      if (!playing) render(reduce ? .9 : 0);
    };
    const showPkt = (after) => {
      const m = M[mode], v = after ? m.after : m.before;
      fSrc.textContent = "SRC " + v.src; fDst.textContent = "DST " + v.dst; fZn.textContent = v.z;
      fSrc.classList.toggle("chg", after && m.chg === "src");
      fDst.classList.toggle("chg", after && m.chg === "dst");
    };
    const render = (p) => {
      // p ∈ [0,1] : 0-.32 aller FW | .32-.52 traitement | .52-.84 sortie | .84-1 pause
      let x, after = false, glow = 0;
      if (p < .32) x = X0 + (XF - X0) * ease(p / .32);
      else if (p < .52) { x = XF; glow = Math.sin(((p - .32) / .2) * Math.PI); after = p > .42; }
      else if (p < .84) { x = XF + (X1 - XF) * ease((p - .52) / .32); after = true; }
      else { x = X1; after = true; }
      pkt.setAttribute("transform", `translate(${x.toFixed(1)},118)`);
      fw.setAttribute("opacity", (.35 + .65 * glow).toFixed(2));
      const ph = p < .32 ? 0 : p < .42 ? 1 : 2;
      if (ph !== phase) {
        phase = ph; showPkt(after);
        st.textContent = ph === 0 ? "① Paquet ORIGINAL (pré-NAT) : c'est lui qui est comparé aux règles NAT et de sécurité."
          : ph === 1 ? "② Le firewall évalue la politique NAT sur le paquet original, détermine la zone de destination, puis la politique de sécurité…"
            : "③ Paquet TRADUIT (post-NAT) : il sort du firewall vers la zone de destination finale.";
        if (ph === 2) $$("b[data-k]", G).forEach(b => { if (b.querySelector("em.post")) { b.classList.remove("flash"); void b.offsetWidth; b.classList.add("flash"); } });
      }
    };
    const ease = t => t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    const loop = now => {
      if (!playing) return;
      const D = 7600;
      render(((now - t0) % D) / D);
      raf = requestAnimationFrame(loop);
    };
    const setPlay = v => {
      playing = v; playBtn.textContent = v ? "❚❚ Pause" : "▶ Lecture";
      playBtn.setAttribute("aria-pressed", String(!v));
      if (v) { t0 = performance.now(); cancelAnimationFrame(raf); raf = requestAnimationFrame(loop); }
    };
    $$(".golden-modes button", G).forEach(b => b.addEventListener("click", () => { mode = b.dataset.mode; apply(); }));
    playBtn.addEventListener("click", () => setPlay(!playing));
    $("#gr-before", G).addEventListener("click", () => { setPlay(false); render(.1); });
    $("#gr-after", G).addEventListener("click", () => { setPlay(false); render(.9); });
    apply();
    if (reduce) { setPlay(false); render(.9); } else setPlay(true);
    // pause hors écran (économie CPU)
    if ("IntersectionObserver" in window) new IntersectionObserver(es => es.forEach(e => {
      if (!e.isIntersecting && playing) { cancelAnimationFrame(raf); G.dataset.paused = "1"; }
      else if (e.isIntersecting && G.dataset.paused) { delete G.dataset.paused; if (playing) raf = requestAnimationFrame(loop); }
    })).observe(G);
  }

  /* ---------- 10. Compteurs ---------- */
  $$("[data-count]").forEach(el => {
    const n = +el.dataset.count;
    if (reduce) { el.textContent = n; return; }
    el.textContent = "0";
    onView([el], () => {
      const t0 = performance.now(), D = 1100;
      const f = now => { const p = Math.min(1, (now - t0) / D); el.textContent = Math.round(n * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(f); };
      requestAnimationFrame(f);
    });
  });
})();
