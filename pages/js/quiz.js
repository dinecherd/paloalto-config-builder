/* Quiz EDU-210 — logique (vanilla JS, aucune dépendance, compatible file://) */
(function () {
  "use strict";
  const DATA = Array.isArray(window.QUIZ_DATA) ? window.QUIZ_DATA : [];
  const MODS = window.QUIZ_MODULES || {};
  const MOD_IDS = Object.keys(MODS);
  const CORE = ["M05", "M06", "M07"];
  const SEC_PER_Q = 75;
  const KEY_BEST = "pan-edu210-quiz-best";
  const KEY_PREFS = "pan-edu210-quiz-prefs";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const esc = (window.PAN && PAN.esc) || (s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
  const toast = (window.PAN && PAN.toast) || (() => {});
  const fmt = s => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
  const $ = s => document.querySelector(s);
  const LETTERS = "ABCDEFGH";
  const GUIDE = { M06: "guide-securite.html", M07: "guide-nat.html" };

  /* ---------- stockage (protégé) ---------- */
  const store = {
    get(k) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : null; } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* stockage indisponible */ } }
  };

  /* ---------- état ---------- */
  const prefs = Object.assign({ mods: MOD_IDS.slice(), n: 10, mode: "train" }, store.get(KEY_PREFS) || {});
  prefs.mods = (prefs.mods || []).filter(m => MODS[m]);
  if (![10, 20, 40].includes(prefs.n)) prefs.n = 10;
  if (!["train", "exam"].includes(prefs.mode)) prefs.mode = "train";
  let S = null;          // session en cours
  let lastSet = null;    // pour « Recommencer »

  const shuffle = a => { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  const countBy = m => DATA.filter(q => q.m === m).length;

  /* ================= RÉGLAGES ================= */
  const chips = $("#qz-chips");
  chips.innerHTML = MOD_IDS.map(m => {
    const n = countBy(m);
    return `<button type="button" class="qz-chip${CORE.includes(m) ? " hot" : ""}" data-m="${m}" aria-pressed="false"${n ? "" : " disabled"}>
      <span class="tick" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-10"/></svg></span>
      <b>${m}</b> ${esc(MODS[m])} <span class="n" aria-label="${n} questions">${n}</span></button>`;
  }).join("");

  $("#qz-total").textContent = DATA.length + " questions";
  $("#qz-scen").textContent = DATA.filter(q => q.sc).length + " scénarios de lab";
  showBest();

  function syncSetup() {
    chips.querySelectorAll(".qz-chip").forEach(b => b.setAttribute("aria-pressed", prefs.mods.includes(b.dataset.m)));
    document.querySelectorAll("#qz-count button").forEach(b => b.setAttribute("aria-pressed", +b.dataset.n === prefs.n));
    document.querySelectorAll("#qz-mode button").forEach(b => b.setAttribute("aria-pressed", b.dataset.mode === prefs.mode));
    const avail = DATA.filter(q => prefs.mods.includes(q.m)).length;
    const n = Math.min(prefs.n, avail);
    $("#qz-avail").textContent = avail === 0 ? "Sélectionnez au moins un module."
      : `${avail} question${avail > 1 ? "s" : ""} disponible${avail > 1 ? "s" : ""} · ${n} tirée${n > 1 ? "s" : ""}` +
        (prefs.mode === "exam" ? ` · ${fmtTime(n * SEC_PER_Q)} chrono` : "");
    $("#qz-start").disabled = avail === 0;
    store.set(KEY_PREFS, prefs);
  }
  chips.addEventListener("click", e => {
    const b = e.target.closest(".qz-chip"); if (!b) return;
    const m = b.dataset.m;
    prefs.mods = prefs.mods.includes(m) ? prefs.mods.filter(x => x !== m) : prefs.mods.concat(m);
    syncSetup();
  });
  document.querySelectorAll("[data-preset]").forEach(b => b.addEventListener("click", () => {
    const p = b.dataset.preset;
    prefs.mods = p === "all" ? MOD_IDS.slice() : p === "none" ? [] : CORE.slice();
    syncSetup();
  }));
  $("#qz-count").addEventListener("click", e => { const b = e.target.closest("button"); if (b) { prefs.n = +b.dataset.n; syncSetup(); } });
  $("#qz-mode").addEventListener("click", e => { const b = e.target.closest("button"); if (b) { prefs.mode = b.dataset.mode; syncSetup(); } });
  $("#qz-start").addEventListener("click", () => {
    const pool = shuffle(DATA.filter(q => prefs.mods.includes(q.m))).slice(0, prefs.n);
    if (pool.length) start(pool, prefs.mode);
  });
  syncSetup();

  function showBest() {
    const b = store.get(KEY_BEST), el = $("#qz-best");
    if (b && typeof b.pct === "number") {
      el.hidden = false;
      el.textContent = `🏆 Meilleur score : ${b.pct}% (${b.ok}/${b.n}${b.mode === "exam" ? ", examen" : ""})`;
    }
  }

  /* ================= ÉCRANS ================= */
  function show(id) {
    ["#scr-setup", "#scr-quiz", "#scr-res"].forEach(s => { $(s).hidden = s !== id; });
    requestAnimationFrame(() => {
      const top = Math.max(0, $(id).getBoundingClientRect().top + scrollY - 84);
      if (Math.abs(scrollY - top) > 40) scrollTo({ top, behavior: reduce ? "auto" : "smooth" });
    });
  }

  /* ================= QUIZ ================= */
  function start(questions, mode) {
    stopTimer();
    lastSet = { questions: questions.slice(), mode };
    S = {
      mode, i: 0, ok: 0, streak: 0, bestStreak: 0, t0: Date.now(), timeUp: false,
      items: questions.map(q => ({ q, order: shuffle(q.c.map((_, k) => k)), picked: [], done: false, correct: false })),
      busy: false
    };
    $("#qz-dots").innerHTML = S.items.map(() => "<span></span>").join("");
    $("#qz-bar").setAttribute("aria-valuemax", S.items.length);
    updateHud();
    const tm = $("#qz-timer");
    tm.hidden = mode !== "exam";
    if (mode === "exam") {
      S.deadline = Date.now() + S.items.length * SEC_PER_Q * 1000;
      S.warned = false;
      tick(); S.timer = setInterval(tick, 500);
    }
    show("#scr-quiz");
    renderQ(true);
  }

  function updateHud() {
    const n = S.items.length, doneCount = S.items.filter(it => it.done).length;
    $("#qz-pos").innerHTML = `Question ${Math.min(S.i + 1, n)} <small>/ ${n}</small>`;
    $("#qz-bar i").style.width = (doneCount / n * 100) + "%";
    $("#qz-bar").setAttribute("aria-valuenow", doneCount);
    const st = $("#qz-streak");
    st.querySelector("span").textContent = S.streak;
    st.classList.toggle("on", S.streak >= 3);
    st.hidden = S.mode === "exam";
    $("#qz-score").hidden = S.mode === "exam";
    $("#qz-score span").textContent = S.ok;
    $("#qz-dots").querySelectorAll("span").forEach((d, k) => {
      const it = S.items[k];
      d.className = k === S.i && !it.done ? "cur" : !it.done ? "" : S.mode === "exam" ? "done" : it.correct ? "ok" : "ko";
    });
  }

  function renderQ(first) {
    const it = S.items[S.i], q = it.q, multi = q.t === "m";
    const stage = $("#qz-stage");
    const html = `
      <article class="card qz-card${reduce ? "" : " in"}" aria-labelledby="qz-qtext">
        <div class="qz-meta">
          <span class="badge or">${esc(q.m)} · ${esc(MODS[q.m] || "")}</span>
          ${q.sc ? '<span class="badge warn">Scénario</span>' : ""}
          ${multi ? '<span class="badge">Choix multiple</span>' : ""}
        </div>
        <h2 class="qz-q" id="qz-qtext" tabindex="-1">${fmt(q.q)}</h2>
        <p class="qz-hint">${multi ? "Plusieurs réponses possibles : sélectionnez-les puis validez." : S.mode === "exam" ? "Une seule réponse : sélectionnez-la puis passez à la suite." : "Une seule réponse."}</p>
        <div class="qz-opts" role="group" aria-label="Réponses">
          ${it.order.map((ci, k) => `
            <button type="button" class="qz-opt${multi ? " multi" : ""}" data-k="${k}" aria-pressed="false" style="animation-delay:${reduce ? 0 : 120 + k * 60}ms">
              <span class="k" aria-hidden="true">${k < 9 ? k + 1 : LETTERS[k]}</span>
              <span class="tx">${fmt(q.c[ci])}</span>
              <span class="st" aria-hidden="true"></span>
            </button>`).join("")}
        </div>
        <div class="qz-actions">
          <span class="mut small" id="qz-sel-hint"></span>
          <span class="spacer"></span>
          <button type="button" class="btn primary" id="qz-submit" ${multi || S.mode === "exam" ? "" : "hidden"} disabled>${S.mode === "exam" ? (S.i === S.items.length - 1 ? "Terminer" : "Valider et continuer") : "Valider"} <span class="qz-kbd">↵</span></button>
          <button type="button" class="btn primary" id="qz-next" hidden>${S.i === S.items.length - 1 ? "Voir le score" : "Question suivante"} <span class="qz-kbd">↵</span></button>
        </div>
        <div id="qz-fbslot"></div>
      </article>`;
    stage.innerHTML = html;
    updateHud();
    const card = stage.querySelector(".qz-card");
    card.addEventListener("animationend", () => card.classList.remove("in", "good", "shake"));
    stage.querySelector(".qz-opts").addEventListener("click", e => { const b = e.target.closest(".qz-opt"); if (b) choose(+b.dataset.k); });
    $("#qz-submit").addEventListener("click", submit);
    $("#qz-next").addEventListener("click", next);
    if (!first) $("#qz-qtext").focus({ preventScroll: true });
    S.busy = false;
  }

  function choose(k) {
    const it = S.items[S.i];
    if (!it || it.done || S.busy || k >= it.order.length) return;
    const multi = it.q.t === "m";
    if (multi) it.picked = it.picked.includes(k) ? it.picked.filter(x => x !== k) : it.picked.concat(k);
    else it.picked = [k];
    document.querySelectorAll(".qz-opt").forEach(b => b.setAttribute("aria-pressed", it.picked.includes(+b.dataset.k)));
    const sb = $("#qz-submit"); sb.disabled = it.picked.length === 0;
    if (multi) $("#qz-sel-hint").textContent = it.picked.length ? `${it.picked.length} sélectionnée${it.picked.length > 1 ? "s" : ""}` : "";
    if (!multi && S.mode === "train") submit();
  }

  function submit() {
    const it = S.items[S.i];
    if (!it || it.done || S.busy || !it.picked.length) return;
    const correctK = it.order.map((ci, k) => it.q.a.includes(ci) ? k : -1).filter(k => k >= 0);
    it.correct = correctK.length === it.picked.length && correctK.every(k => it.picked.includes(k));
    it.done = true;
    if (it.correct) { S.ok++; S.streak++; S.bestStreak = Math.max(S.bestStreak, S.streak); } else S.streak = 0;

    if (S.mode === "exam") { updateHud(); next(); return; }

    // ---- feedback immédiat ----
    const card = $(".qz-card");
    document.querySelectorAll(".qz-opt").forEach(b => {
      const k = +b.dataset.k, isC = correctK.includes(k), isP = it.picked.includes(k);
      b.disabled = true;
      const st = b.querySelector(".st");
      if (isC && isP) { b.classList.add("right"); st.textContent = "✓"; }
      else if (isC) { b.classList.add("missed"); st.textContent = "✓"; }
      else if (isP) { b.classList.add("wrong"); st.textContent = "✕"; }
      else b.classList.add("dim");
    });
    card.classList.remove("in", "good", "shake"); void card.offsetWidth;
    card.classList.add(it.correct ? "good" : "shake");
    const goodLetters = correctK.map(k => k + 1).join(", ");
    $("#qz-fbslot").innerHTML = `
      <div class="qz-fb ${it.correct ? "ok" : "ko"}">
        <h4>${it.correct ? "✓ Bonne réponse" : "✕ Pas tout à fait"}${it.correct && S.streak >= 3 ? ` <span class="badge or">🔥 ${S.streak} d'affilée</span>` : ""}</h4>
        ${it.correct ? "" : `<p><b>Réponse attendue : ${goodLetters}</b></p>`}
        <p>${fmt(it.q.e)}</p>
        <span class="badge qz-ref">📘 ${esc(it.q.r)}</span>
      </div>`;
    $("#qz-live").textContent = (it.correct ? "Bonne réponse. " : `Mauvaise réponse. Réponse attendue : ${goodLetters}. `) + it.q.e;
    $("#qz-submit").hidden = true;
    $("#qz-sel-hint").textContent = "";
    const nb = $("#qz-next"); nb.hidden = false; nb.focus({ preventScroll: true });
    const fb = $("#qz-fbslot");
    const r = fb.getBoundingClientRect();
    if (r.bottom > innerHeight) scrollBy({ top: r.bottom - innerHeight + 24, behavior: reduce ? "auto" : "smooth" });
    if (it.correct) {
      const st = $("#qz-streak"); st.classList.remove("bump"); void st.offsetWidth; st.classList.add("bump");
      if (S.streak > 0 && S.streak % 5 === 0) { confetti(); toast(`🔥 Série de ${S.streak} bonnes réponses !`); }
    }
    updateHud();
  }

  function next() {
    if (!S || S.busy) return;
    S.busy = true;
    const go = () => {
      if (!S || S.finished) return;
      if (S.i >= S.items.length - 1) { finish(); return; }
      S.i++; renderQ(false);
    };
    const card = $(".qz-card");
    if (reduce || !card) { go(); return; }
    card.classList.remove("in", "good", "shake"); void card.offsetWidth;
    card.classList.add("out");
    let fired = false;
    const once = () => { if (!fired) { fired = true; go(); } };
    card.addEventListener("animationend", once, { once: true });
    setTimeout(once, 450);
  }

  /* ---------- chrono examen ---------- */
  function fmtTime(s) { s = Math.max(0, Math.round(s)); return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0"); }
  function tick() {
    if (!S || !S.deadline) return;
    const left = (S.deadline - Date.now()) / 1000, tm = $("#qz-timer");
    tm.textContent = "⏱ " + fmtTime(left);
    tm.classList.toggle("low", left <= 60);
    if (left <= 60 && !S.warned) { S.warned = true; toast("⏱ Plus qu'une minute !"); $("#qz-live").textContent = "Attention : il reste une minute."; }
    if (left <= 0) { S.timeUp = true; stopTimer(); toast("Temps écoulé !"); finish(); }
  }
  function stopTimer() { if (S && S.timer) { clearInterval(S.timer); S.timer = null; } }

  $("#qz-quit").addEventListener("click", () => { stopTimer(); S = null; show("#scr-setup"); });

  /* ================= RÉSULTATS ================= */
  function finish() {
    if (!S || S.finished) return;
    S.finished = true;
    stopTimer();
    const n = S.items.length, ok = S.items.filter(it => it.correct).length;
    S.ok = ok;
    const pct = Math.round(ok / n * 100);
    const secs = (Date.now() - S.t0) / 1000;
    show("#scr-res");

    // record
    const best = store.get(KEY_BEST);
    const isRecord = !best || typeof best.pct !== "number" || pct > best.pct || (pct === best.pct && n > (best.n || 0));
    if (isRecord) store.set(KEY_BEST, { pct, ok, n, mode: S.mode, date: new Date().toISOString().slice(0, 10) });
    showBest();

    // verdict
    const v = pct >= 90 ? ["Prêt pour le PCNSA 🚀", "Excellent : continuez à varier les modules."]
      : pct >= 75 ? ["Solide 💪", "Revoyez les quelques erreurs ci-dessous pour viser 90 %."]
      : pct >= 50 ? ["En progression 📈", "Relisez les explications puis rejouez vos erreurs."]
      : ["À retravailler 📚", "Reprenez les slides et les labs concernés, puis retentez."];
    $("#qz-verdict").textContent = v[0];
    $("#qz-verdict-sub").textContent = (S.timeUp ? "Temps écoulé : les questions sans réponse comptent comme fausses. " : "") + v[1];
    const color = pct >= 75 ? ["#22C55E", "#86EFAC", "rgba(34,197,94,.55)"] : pct >= 50 ? ["#F59E0B", "#FCD34D", "rgba(245,158,11,.5)"] : ["#EF4444", "#FCA5A5", "rgba(239,68,68,.5)"];
    $("#qz-g1").setAttribute("stop-color", color[0]); $("#qz-g2").setAttribute("stop-color", color[1]);
    const arc = $("#qz-arc"), C = 2 * Math.PI * 84;
    arc.style.setProperty("--gauge-glow", color[2]);
    arc.style.transition = "none"; arc.style.strokeDashoffset = C; void arc.getBoundingClientRect();
    arc.style.transition = "";
    $("#qz-frac").textContent = `${ok} / ${n} correctes`;
    requestAnimationFrame(() => { arc.style.strokeDashoffset = C * (1 - pct / 100); });
    countUp($("#qz-pct"), pct, "%");
    $("#qz-gauge-t").textContent = `Score : ${pct} %, ${ok} sur ${n}`;

    // KPIs
    $("#qz-kpis").innerHTML = [
      [ok + " / " + n, "Bonnes réponses"],
      [fmtTime(secs), S.mode === "exam" ? "Temps (examen)" : "Durée"],
      [S.bestStreak, "Meilleure série 🔥"],
      [isRecord ? "🏆 Record" : (best.pct + "%"), isRecord ? "Nouveau meilleur score" : "Meilleur score"]
    ].map(([b, s], k) => `<div class="qz-kpi${k === 3 && isRecord ? " qz-new" : ""}"><b>${esc(b)}</b><span>${esc(s)}</span></div>`).join("");

    // par module
    const per = {};
    S.items.forEach(it => { const p = per[it.q.m] || (per[it.q.m] = { n: 0, ok: 0 }); p.n++; if (it.correct) p.ok++; });
    const rows = MOD_IDS.filter(m => per[m]);
    $("#qz-mods").innerHTML = rows.map(m => {
      const p = per[m], r = Math.round(p.ok / p.n * 100);
      const c = r >= 75 ? "var(--ok)" : r >= 50 ? "var(--warn)" : "var(--bad)";
      return `<div class="qz-mrow"><span class="lbl" title="${esc(MODS[m])}"><b>${m}</b>${esc(MODS[m])}</span>
        <span class="trk" role="img" aria-label="${m} : ${p.ok} sur ${p.n}"><i data-w="${r}" style="background:${c}"></i></span>
        <span class="v">${p.ok}/${p.n}</span></div>`;
    }).join("");
    requestAnimationFrame(() => requestAnimationFrame(() =>
      document.querySelectorAll("#qz-mods i").forEach((i, k) => { i.style.transitionDelay = (reduce ? 0 : 200 + k * 90) + "ms"; i.style.width = Math.max(i.dataset.w, 2) + "%"; })));

    $("#qz-retry-err").disabled = ok === n;
    setRevFilter(ok === n ? "all" : "ko");
    if (pct >= 80) setTimeout(confetti, reduce ? 0 : 900);
    setTimeout(() => $("#qz-again").focus({ preventScroll: true }), 50);
  }

  function countUp(el, to, suffix) {
    if (reduce) { el.textContent = to + suffix; return; }
    const t0 = performance.now(), D = 1500;
    const step = t => { const p = Math.min(1, (t - t0) / D), e = 1 - Math.pow(1 - p, 3); el.textContent = Math.round(to * e) + suffix; if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }

  function setRevFilter(f) {
    document.querySelectorAll("#qz-revf button").forEach(b => b.setAttribute("aria-pressed", b.dataset.f === f));
    renderReview(f);
  }
  $("#qz-revf").addEventListener("click", e => { const b = e.target.closest("button"); if (b) setRevFilter(b.dataset.f); });

  function renderReview(f) {
    if (!S) return;
    const list = S.items.map((it, idx) => ({ it, idx })).filter(x => f === "all" || !x.it.correct);
    if (!list.length) { $("#qz-rev").innerHTML = `<div class="qz-empty">🎉 Aucune erreur, bravo !</div>`; return; }
    $("#qz-rev").innerHTML = list.map(({ it, idx }) => {
      const q = it.q;
      const pickedC = it.picked.map(k => it.order[k]);
      const lines = q.c.map((txt, ci) => {
        const isC = q.a.includes(ci), isP = pickedC.includes(ci);
        if (isC) return `<li class="c"><span class="m">✓</span><span>${fmt(txt)}${isP ? "" : ' <em class="mut">(non cochée)</em>'}</span></li>`;
        if (isP) return `<li class="x"><span class="m">✕</span><span>${fmt(txt)}</span></li>`;
        return "";
      }).join("");
      const guide = GUIDE[q.m] ? ` <a class="badge or" href="${GUIDE[q.m]}">Revoir le guide →</a>` : "";
      return `<div class="qz-ri${it.correct ? " ok" : ""}">
        <div class="row" style="gap:8px"><span class="badge">#${idx + 1}</span><span class="badge or">${esc(q.m)}</span>${q.sc ? '<span class="badge warn">Scénario</span>' : ""}
          <span class="badge ${it.correct ? "ok" : "bad"}">${it.correct ? "Correct" : it.done ? "Faux" : "Sans réponse"}</span></div>
        <div class="q">${fmt(q.q)}</div>
        <ul>${lines}</ul>
        <div class="e">${fmt(q.e)} <span class="badge">📘 ${esc(q.r)}</span>${guide}</div>
      </div>`;
    }).join("");
  }

  $("#qz-again").addEventListener("click", () => { if (lastSet) start(shuffle(lastSet.questions), lastSet.mode); });
  $("#qz-retry-err").addEventListener("click", () => {
    if (!S) return;
    const wrong = S.items.filter(it => !it.correct).map(it => it.q);
    if (wrong.length) start(shuffle(wrong), S.mode);
  });
  $("#qz-settings").addEventListener("click", () => { show("#scr-setup"); setTimeout(() => $("#qz-start").focus({ preventScroll: true }), 50); });

  /* ================= CLAVIER ================= */
  document.addEventListener("keydown", e => {
    if ($("#scr-quiz").hidden || !S || e.ctrlKey || e.metaKey || e.altKey) return;
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    const it = S.items[S.i]; if (!it) return;
    if (/^[1-9]$/.test(e.key)) { e.preventDefault(); choose(+e.key - 1); return; }
    if (e.key === "Enter") {
      if (it.done && S.mode === "train") { e.preventDefault(); next(); return; }
      if (!it.done && it.picked.length) { e.preventDefault(); submit(); return; }
      // sinon : comportement natif (ex. Entrée sur un bouton de réponse focalisé)
    }
  });

  /* ================= CONFETTIS (canvas léger) ================= */
  const cv = $("#qz-confetti");
  let cAnim = 0;
  function confetti() {
    if (reduce || !cv.getContext) return;
    const ctx = cv.getContext("2d"), dpr = Math.min(2, window.devicePixelRatio || 1);
    cv.width = innerWidth * dpr; cv.height = innerHeight * dpr;
    cv.style.width = innerWidth + "px"; cv.style.height = innerHeight + "px";
    const cols = ["#FA582D", "#FF8A3D", "#FFC59A", "#38BDF8", "#22C55E", "#A78BFA", "#F1F5F9"];
    const N = innerWidth < 600 ? 90 : 150;
    const ps = Array.from({ length: N }, (_, i) => {
      const left = i % 2 === 0;
      return {
        x: (left ? 0.08 : 0.92) * cv.width, y: cv.height * 0.72,
        vx: (left ? 1 : -1) * (4 + Math.random() * 9) * dpr, vy: -(10 + Math.random() * 12) * dpr,
        w: (5 + Math.random() * 6) * dpr, h: (8 + Math.random() * 8) * dpr,
        r: Math.random() * 6.28, vr: (Math.random() - .5) * .35, c: cols[i % cols.length], life: 0
      };
    });
    cancelAnimationFrame(cAnim);
    const t0 = performance.now();
    const frame = t => {
      ctx.clearRect(0, 0, cv.width, cv.height);
      let alive = 0;
      for (const p of ps) {
        p.vy += 0.38 * dpr; p.vx *= 0.985; p.vy *= 0.985; p.x += p.vx; p.y += p.vy; p.r += p.vr;
        if (p.y < cv.height + 40) alive++;
        ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.r);
        ctx.globalAlpha = Math.max(0, 1 - (t - t0) / 2600);
        ctx.fillStyle = p.c; ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h * Math.abs(Math.cos(p.r * 2)) + 1);
        ctx.restore();
      }
      if (alive && t - t0 < 2600) cAnim = requestAnimationFrame(frame);
      else ctx.clearRect(0, 0, cv.width, cv.height);
    };
    cAnim = requestAnimationFrame(frame);
  }
})();
