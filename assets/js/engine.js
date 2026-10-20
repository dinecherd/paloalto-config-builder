/* PAN Config Builder — moteur générique des modules de configuration.
   Un module = { id, module, title, icon, desc, fields[], example?, build(v) → { steps[], cli[], verify[], notes[] } }
   enregistré via PAN.cfg.register(def). Voir assets/js/modules/m02-m04.js pour l'exemple de référence.

   fields[] : { id, label, type, default?, placeholder?, hint?, required?, validate?, options?, show?, group?, min?, max?, wide? }
     type      : text | ip | cidr | ipcidr | port | number | select | checkbox | textarea | list | password
                 (list = valeurs séparées par virgules → tableau ; ip/cidr/... appliquent la validation correspondante)
     validate  : nom d'un validateur intégré (voir V ci-dessous) ou fonction (val, values) → "message d'erreur" | null
     options   : [[valeur, libellé], ...] pour select
     show      : (values) → bool  (champ conditionnel, ignoré en validation s'il est masqué)
     group     : titre de section (une nouvelle section commence quand le groupe change)
   steps[]  : { title, path:[...menu], action?, tab?, fields:[[label, valeur], ...], note?, warn? }
              valeurs vides/false/[] sont masquées ; tableaux affichés séparés par des virgules ; true → "✓ coché"
   cli[]    : lignes en mode configure (le moteur ajoute "configure" et "commit") — "# ..." = commentaire
   verify[] : commandes en mode opérationnel (après commit), optionnel
   noCommit : true si le module ne nécessite pas de commit (ex. opérations) */
(function () {
  const reg = [];
  const byId = {};

  /* ---------- validateurs intégrés ---------- */
  const ipOk = s => PAN.ip.valid(s);
  const V = {
    required: v => (v === "" || v == null || (Array.isArray(v) && !v.length)) ? "Champ obligatoire" : null,
    ip: v => ipOk(v) ? null : "Adresse IPv4 invalide (ex. 192.168.1.1)",
    cidr: v => { const [a, m] = String(v).split("/"); return ipOk(a) && /^\d+$/.test(m || "") && +m <= 32 ? null : "Format IP/masque attendu (ex. 192.168.1.1/24)"; },
    ipcidr: v => PAN.ip.validCidr(v) ? null : "IP ou IP/masque attendu",
    port: v => PAN.ip.validPort(v) ? null : "Port entre 1 et 65535",
    portrange: v => /^\d+(-\d+)?(,\d+(-\d+)?)*$/.test(String(v)) && String(v).split(/[,-]/).every(p => +p >= 1 && +p <= 65535) ? null : "Port, plage (8000-8080) ou liste (80,443)",
    hostname: v => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(v) ? null : "Lettres, chiffres et tirets, 63 caractères max",
    fqdn: v => /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/.test(v) ? null : "FQDN invalide (ex. pool.ntp.org)",
    host: v => ipOk(v) || V.fqdn(v) === null ? null : "IP ou FQDN attendu",
    name: v => /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/.test(v) ? null : "Nom PAN-OS : 63 caractères max, commence par une lettre/chiffre (lettres, chiffres, espace, . _ -)",
    email: v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? null : "Adresse e-mail invalide",
    iface: v => /^(ethernet\d+\/\d+(\.\d+)?|ae\d+(\.\d+)?|loopback(\.\d+)?|tunnel(\.\d+)?|vlan(\.\d+)?)$/.test(v) ? null : "Interface PAN-OS (ex. ethernet1/1, ethernet1/2.10, tunnel.1)",
    vlan: v => /^\d+$/.test(v) && +v >= 1 && +v <= 4094 ? null : "VLAN entre 1 et 4094",
    url: v => /^https?:\/\/\S+$/.test(v) ? null : "URL complète attendue (https://...)",
  };
  V.listOf = (k) => arr => { for (const x of arr) { const e = V[k](x); if (e) return `« ${x} » : ${e}`; } return null; };

  /* ---------- helpers CLI exposés aux modules ---------- */
  const q = v => { v = String(v); return /[\s"';|]/.test(v) || v === "" ? `"${v.replace(/"/g, '\\"')}"` : v; };
  const members = a => { a = [].concat(a).filter(x => x !== "" && x != null); return a.length > 1 ? `[ ${a.map(q).join(" ")} ]` : q(a[0] ?? "any"); };
  const yn = b => (b ? "yes" : "no");

  function register(def) {
    if (byId[def.id]) { console.warn("Module en double :", def.id); return; }
    reg.push(def); byId[def.id] = def;
  }

  /* =========================================================
     UI (uniquement sur la page configurateur)
     ========================================================= */
  function mount() {
    const app = document.getElementById("cfg-app");
    if (!app) return;
    const side = document.getElementById("cfg-side");
    const main = document.getElementById("cfg-main");
    const search = document.getElementById("cfg-search");
    const state = { def: null, values: {}, mode: localGet("cfg-mode") || "gui", done: {} };

    /* ---- sidebar ---- */
    function renderSide(filter = "") {
      const f = filter.trim().toLowerCase();
      const groups = {};
      reg.filter(d => !f || (d.title + d.module + (d.desc || "") + (d.tags || "")).toLowerCase().includes(f))
        .forEach(d => (groups[d.module] = groups[d.module] || []).push(d));
      side.innerHTML = Object.keys(groups).sort(modSort).map(m => `
        <div class="cfg-grp"><div class="cfg-grp-t">${PAN.esc(MODNAMES[m] || m)}</div>
        ${groups[m].map(d => `<a href="#${d.id}" class="cfg-link${state.def && state.def.id === d.id ? " on" : ""}" data-id="${d.id}"><i>${d.icon || "⚙️"}</i>${PAN.esc(d.title)}</a>`).join("")}</div>`).join("")
        || `<p class="mut small" style="padding:12px">Aucun module trouvé.</p>`;
    }
    search && search.addEventListener("input", () => renderSide(search.value));

    /* ---- dashboard (aucun module choisi) ---- */
    function renderHome() {
      state.def = null; renderSide(search ? search.value : "");
      const groups = {};
      reg.forEach(d => (groups[d.module] = groups[d.module] || []).push(d));
      main.innerHTML = `
        <div class="cfg-head fade-up"><span class="kicker">Configurateur PAN-OS 11.0</span>
        <h1>Que veux-tu <span class="grad">configurer</span>&nbsp;?</h1>
        <p class="lead">Choisis un module, renseigne tes informations : tu obtiens le pas-à-pas WebUI avec validation de chaque étape, ou la CLI prête à coller.</p></div>
        ${Object.keys(groups).sort(modSort).map((m, gi) => `
          <h3 class="cfg-dash-t fade-up" style="animation-delay:${gi * 60}ms">${PAN.esc(MODNAMES[m] || m)}</h3>
          <div class="grid g3">${groups[m].map((d, i) => `
            <a class="card hover cfg-card fade-up" style="animation-delay:${gi * 60 + i * 40}ms" href="#${d.id}">
              <div class="ico">${d.icon || "⚙️"}</div><h3>${PAN.esc(d.title)}</h3><p class="mut small">${PAN.esc(d.desc || "")}</p></a>`).join("")}
          </div>`).join("")}`;
      scrollTo({ top: 0 });
    }

    /* ---- formulaire ---- */
    function defaults(def, useExample) {
      const v = {};
      def.fields.forEach(f => {
        let d = useExample && def.example && f.id in def.example ? def.example[f.id] : f.default;
        if (d === undefined) d = f.type === "checkbox" ? false : f.type === "list" ? [] : "";
        v[f.id] = Array.isArray(d) ? d.slice() : d;
      });
      return v;
    }
    const visible = (f, v) => !f.show || f.show(v);

    function fieldErr(f, v) {
      if (!visible(f, v)) return null;
      const val = v[f.id];
      const empty = val === "" || val == null || (Array.isArray(val) && !val.length) || val === false && f.type !== "checkbox";
      if (empty) return f.required ? "Champ obligatoire" : null;
      const typeV = { ip: "ip", cidr: "cidr", ipcidr: "ipcidr", port: "port" }[f.type];
      const checks = [typeV, f.validate].filter(Boolean);
      for (const c of checks) {
        let e = null;
        if (typeof c === "function") e = c(val, v);
        else if (f.type === "list") e = V.listOf(c)(val);
        else if (V[c]) e = V[c](val);
        if (e) return e;
      }
      if (f.type === "number" && val !== "") {
        if (isNaN(+val)) return "Nombre attendu";
        if (f.min != null && +val < f.min) return `Minimum ${f.min}`;
        if (f.max != null && +val > f.max) return `Maximum ${f.max}`;
      }
      return null;
    }

    function inputHTML(f, val) {
      const id = "f-" + f.id, ph = f.placeholder ? ` placeholder="${PAN.esc(f.placeholder)}"` : "";
      switch (f.type) {
        case "select":
          return `<select id="${id}" data-f="${f.id}">${f.options.map(([o, l]) => `<option value="${PAN.esc(o)}"${String(o) === String(val) ? " selected" : ""}>${PAN.esc(l ?? o)}</option>`).join("")}</select>`;
        case "checkbox":
          return `<label class="cfg-check"><input type="checkbox" id="${id}" data-f="${f.id}"${val ? " checked" : ""}><span>${PAN.esc(f.label)}</span></label>`;
        case "textarea":
          return `<textarea id="${id}" data-f="${f.id}" rows="3"${ph}>${PAN.esc(val)}</textarea>`;
        case "list":
          return `<input type="text" id="${id}" data-f="${f.id}" value="${PAN.esc((val || []).join(", "))}"${ph}>`;
        case "password":
          return `<input type="password" id="${id}" data-f="${f.id}" value="${PAN.esc(val)}" autocomplete="new-password"${ph}>`;
        default:
          return `<input type="text" id="${id}" data-f="${f.id}" value="${PAN.esc(val)}"${ph}${f.type === "number" || f.type === "port" ? ' inputmode="numeric"' : ""}>`;
      }
    }

    function renderForm() {
      const def = state.def, v = state.values;
      let html = "", grp = null, open = false;
      def.fields.forEach(f => {
        if (f.group && f.group !== grp) { if (open) html += "</div></fieldset>"; grp = f.group; html += `<fieldset class="cfg-fs"><legend>${PAN.esc(grp)}</legend><div class="cfg-fields">`; open = true; }
        else if (!open) { html += `<fieldset class="cfg-fs"><div class="cfg-fields">`; open = true; }
        const hid = visible(f, v) ? "" : " hidden";
        html += `<div class="field${f.wide || f.type === "textarea" ? " wide" : ""}" data-wrap="${f.id}"${hid}>
          ${f.type === "checkbox" ? "" : `<label for="f-${f.id}">${PAN.esc(f.label)}${f.required ? ' <b class="req">*</b>' : ""}</label>`}
          ${inputHTML(f, v[f.id])}
          ${f.hint ? `<div class="hint">${f.hint}</div>` : ""}<div class="err" data-err="${f.id}"></div></div>`;
      });
      if (open) html += "</div></fieldset>";
      document.getElementById("cfg-form").innerHTML = html;
    }

    function readField(el) {
      const f = state.def.fields.find(x => x.id === el.dataset.f);
      if (f.type === "checkbox") return el.checked;
      if (f.type === "list") return el.value.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
      return el.value.trim();
    }

    function validateAll(show) {
      let ok = true, first = null;
      state.def.fields.forEach(f => {
        const wrap = document.querySelector(`[data-wrap="${f.id}"]`);
        if (wrap) wrap.hidden = !visible(f, state.values);
        const e = fieldErr(f, state.values);
        const errEl = document.querySelector(`[data-err="${f.id}"]`), inp = document.getElementById("f-" + f.id);
        const touched = show || (inp && inp.dataset.touched);
        if (errEl) errEl.textContent = e && touched ? e : "";
        if (inp) inp.classList.toggle("invalid", !!(e && touched));
        if (e) { ok = false; first = first || inp; }
      });
      const st = document.getElementById("cfg-status");
      if (st) st.innerHTML = ok ? `<span class="badge ok">✓ Données valides</span>` : `<span class="badge warn">⚠ Champs à compléter / corriger</span>`;
      return { ok, first };
    }

    /* ---- sortie ---- */
    function fmt(val) {
      if (val === true) return "✓ coché";
      if (Array.isArray(val)) return val.join(", ");
      return String(val);
    }
    const hasVal = x => !(x === "" || x == null || x === false || (Array.isArray(x) && !x.length));

    function renderOutput() {
      const out = document.getElementById("cfg-out");
      const { ok } = validateAll(false);
      if (!ok) { out.innerHTML = `<div class="cfg-empty"><div class="cfg-empty-ico">🧩</div><p>Complète les champs obligatoires pour générer la configuration.</p></div>`; return; }
      let res;
      try { res = state.def.build(state.values) || {}; }
      catch (e) { console.error(e); out.innerHTML = `<div class="callout bad"><b>Erreur de génération</b>${PAN.esc(e.message)}</div>`; return; }
      const steps = (res.steps || []).slice();
      if (!state.def.noCommit) steps.push({ title: "Valider la configuration (Commit)", path: ["Commit"], action: "Cliquer sur Commit en haut à droite → vérifier la prévisualisation → Commit. Attendre « Configuration committed successfully ».", fields: [], commit: true });
      const cli = buildCli(res);
      state.last = { res, steps, cli };
      const key = state.def.id + JSON.stringify(state.values);
      if (state.doneKey !== key) { state.done = {}; state.doneKey = key; }

      out.innerHTML = `
        <div class="cfg-modes" role="tablist">
          <button role="tab" data-mode="gui" aria-selected="${state.mode === "gui"}">🖱️ GUI pas-à-pas</button>
          <button role="tab" data-mode="cli" aria-selected="${state.mode === "cli"}">⌨️ CLI</button>
          <span class="spacer"></span>
          <button class="btn sm ghost" id="cfg-dl">⬇ Exporter .txt</button>
        </div>
        ${(res.notes || []).map(n => `<div class="callout ${n.type || "or"}">${n.title ? `<b>${PAN.esc(n.title)}</b>` : ""}${n.html || PAN.esc(n.text || "")}</div>`).join("")}
        <div id="cfg-view"></div>`;
      renderView();
    }

    function buildCli(res) {
      const lines = ["configure"];
      (res.cli || []).forEach(l => lines.push(l));
      if (!state.def.noCommit) lines.push("commit");
      if (res.verify && res.verify.length) { lines.push("exit", "", "# --- Vérification (mode opérationnel) ---"); res.verify.forEach(l => lines.push(l)); }
      if (res.cliRaw) return res.cliRaw.join("\n");
      return lines.join("\n");
    }

    function hl(line) {
      const e = PAN.esc(line);
      if (/^\s*#/.test(line)) return `<span class="c">${e}</span>`;
      return e.replace(/^(\s*)(set|delete|edit|commit|configure|exit|show|test|request|debug|run|move|rename|clear|ping|save|load|revert|validate)\b/, '$1<span class="k">$2</span>')
        .replace(/(&quot;[^&]*?&quot;)/g, '<span class="s">$1</span>')
        .replace(/\b(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\b/g, '<span class="n">$1</span>');
    }

    function renderView() {
      const view = document.getElementById("cfg-view"), { steps, cli } = state.last;
      document.querySelectorAll(".cfg-modes [data-mode]").forEach(b => b.setAttribute("aria-selected", b.dataset.mode === state.mode));
      if (state.mode === "cli") {
        view.innerHTML = `<div class="cfg-cli fade-up"><button class="btn sm copy-btn" data-copy-target="#cfg-cli-code">Copier</button>
          <div class="code" id="cfg-cli-code">${cli.split("\n").map(hl).join("\n")}</div>
          <p class="hint" style="margin-top:8px">Colle ces lignes dans une session SSH (admin@firewall&gt;). Le mode <code>configure</code> est ouvert automatiquement en première ligne.</p></div>`;
        return;
      }
      const n = steps.length, d = Object.keys(state.done).filter(k => state.done[k]).length;
      view.innerHTML = `
        <div class="cfg-prog"><div class="cfg-prog-bar"><i style="width:${n ? (d / n) * 100 : 0}%"></i></div><span>${d}/${n} étapes validées</span></div>
        <ol class="cfg-steps">${steps.map((s, i) => stepHTML(s, i)).join("")}</ol>
        <div class="cfg-finish${d === n && n ? " show" : ""}" id="cfg-finish">🎉 Configuration terminée — pense à vérifier dans les logs / la CLI.</div>`;
      view.querySelectorAll(".cfg-step").forEach((el, i) => setTimeout(() => el.classList.add("in"), 60 * i));
    }

    function stepHTML(s, i) {
      const done = !!state.done[i];
      const rows = (s.fields || []).filter(([, v]) => hasVal(v));
      return `<li class="cfg-step${done ? " done" : ""}" data-i="${i}">
        <div class="cfg-step-h">
          <span class="cfg-num">${done ? "✓" : i + 1}</span>
          <div class="cfg-step-tt"><b>${PAN.esc(s.title)}</b>
            <div class="cfg-path">${(s.path || []).map(p => `<span>${PAN.esc(p)}</span>`).join("<i>›</i>")}${s.tab ? `<i>›</i><span class="tab">onglet ${PAN.esc(s.tab)}</span>` : ""}</div></div>
          <label class="cfg-done"><input type="checkbox" data-done="${i}"${done ? " checked" : ""}> Fait</label>
        </div>
        ${s.action ? `<p class="cfg-action">👉 ${PAN.esc(s.action)}</p>` : ""}
        ${rows.length ? `<div class="pan cfg-pan"><div class="pan-title"><span>${PAN.esc(s.window || s.title)}</span><span style="color:#9AA5B1">✕</span></div>
          <div class="pan-body">${rows.map(([l, v]) => `<div class="pan-row"><span>${PAN.esc(l)}</span><span class="pan-val">${PAN.esc(fmt(v))}</span></div>`).join("")}</div>
          <div class="pan-foot"><button class="pan-btn pri" tabindex="-1">OK</button><button class="pan-btn" tabindex="-1">Cancel</button></div></div>` : ""}
        ${s.note ? `<div class="callout small">${PAN.esc(s.note)}</div>` : ""}
        ${s.warn ? `<div class="callout warn small">⚠ ${PAN.esc(s.warn)}</div>` : ""}
      </li>`;
    }

    /* ---- ouverture d'un module ---- */
    function open(id) {
      const def = byId[id];
      if (!def) return renderHome();
      state.def = def; state.values = defaults(def, true); state.done = {};
      renderSide(search ? search.value : "");
      main.innerHTML = `
        <div class="cfg-head fade-up">
          <a href="#" class="small">← Tous les modules</a>
          <div class="row" style="margin-top:10px"><span class="cfg-ico">${def.icon || "⚙️"}</span>
            <div><span class="kicker">${PAN.esc(MODNAMES[def.module] || def.module)}</span><h1 class="cfg-h1">${PAN.esc(def.title)}</h1></div></div>
          ${def.desc ? `<p class="lead">${PAN.esc(def.desc)}</p>` : ""}
        </div>
        <div class="cfg-layout">
          <div class="panel cfg-in fade-up" style="animation-delay:80ms">
            <div class="row cfg-in-h"><h3>1 · Tes informations</h3><span class="spacer"></span><span id="cfg-status"></span></div>
            <form id="cfg-form" autocomplete="off" novalidate></form>
            <div class="row" style="margin-top:6px">
              <button class="btn sm" type="button" id="cfg-ex">↺ Exemple</button>
              <button class="btn sm ghost" type="button" id="cfg-clear">Vider</button>
              <span class="spacer"></span>
              <button class="btn primary sm" type="button" id="cfg-gen">Générer →</button>
            </div>
          </div>
          <div class="cfg-outwrap fade-up" style="animation-delay:160ms"><h3 class="cfg-out-t">2 · Ta configuration</h3><div id="cfg-out"></div></div>
        </div>`;
      renderForm(); renderOutput();
      document.getElementById("cfg-ex").onclick = () => { state.values = defaults(def, true); renderForm(); renderOutput(); PAN.toast("Exemple chargé"); };
      document.getElementById("cfg-clear").onclick = () => {
        state.values = {}; def.fields.forEach(f => state.values[f.id] = f.type === "checkbox" ? false : f.type === "list" ? [] : f.type === "select" ? f.options[0][0] : "");
        renderForm(); renderOutput();
      };
      document.getElementById("cfg-gen").onclick = () => {
        const { ok, first } = validateAll(true);
        if (!ok) { first && first.focus(); PAN.toast("Corrige les champs en rouge"); return; }
        renderOutput(); document.querySelector(".cfg-outwrap").scrollIntoView({ behavior: "smooth", block: "start" });
      };
      scrollTo({ top: 0 });
    }

    /* ---- événements délégués ---- */
    let t;
    main.addEventListener("input", e => {
      const el = e.target.closest("[data-f]"); if (!el || !state.def) return;
      el.dataset.touched = 1; state.values[el.dataset.f] = readField(el);
      clearTimeout(t); t = setTimeout(() => { validateAll(false); renderOutput(); }, 180);
    });
    main.addEventListener("change", e => {
      const el = e.target.closest("[data-f]");
      if (el && state.def) { el.dataset.touched = 1; state.values[el.dataset.f] = readField(el); validateAll(false); renderOutput(); return; }
      const dn = e.target.closest("[data-done]");
      if (dn) {
        state.done[dn.dataset.done] = dn.checked; renderView();
        const n = state.last.steps.length, d = Object.values(state.done).filter(Boolean).length;
        if (dn.checked && d === n) PAN.toast("Toutes les étapes sont validées 🎉");
      }
    });
    main.addEventListener("click", e => {
      const m = e.target.closest("[data-mode]");
      if (m) { state.mode = m.dataset.mode; localSet("cfg-mode", state.mode); renderView(); }
      if (e.target.id === "cfg-dl") download();
    });

    function download() {
      const { steps, cli } = state.last, v = state.values;
      const txt = [`# ${state.def.module} — ${state.def.title}`, `# Généré par PAN Config Builder (PAN-OS 11.0)`, "",
        "========== PARAMÈTRES ==========", ...state.def.fields.filter(f => visible(f, v) && hasVal(v[f.id]) && f.type !== "password").map(f => `${f.label}: ${fmt(v[f.id])}`), "",
        "========== GUI PAS-À-PAS ==========", ...steps.flatMap((s, i) => [`${i + 1}. ${s.title}`, `   Chemin : ${(s.path || []).join(" > ")}${s.tab ? " > onglet " + s.tab : ""}`, ...(s.action ? [`   Action : ${s.action}`] : []),
          ...(s.fields || []).filter(([, x]) => hasVal(x)).map(([l, x]) => `   - ${l} : ${fmt(x)}`), ...(s.note ? [`   Note : ${s.note}`] : []), ""]),
        "========== CLI ==========", cli].join("\n");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([txt], { type: "text/plain;charset=utf-8" }));
      a.download = `${state.def.id}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }

    const route = () => { const id = decodeURIComponent(location.hash.slice(1)); id && byId[id] ? open(id) : renderHome(); };
    addEventListener("hashchange", route);
    route();
  }

  const MODNAMES = {
    STD: "Déploiement standard client",
    M02: "Système & management", M03: "Sauvegarde & gestion de config", M04: "Comptes administrateurs",
    M05: "Interfaces, zones & routage", M06: "Règles de sécurité & objets", M07: "NAT", M08: "Applications (App-ID)",
    M09: "Profils de sécurité", M10: "Filtrage URL", M11: "WildFire", M12: "Identification utilisateurs (User-ID)", M13: "Décryptage SSL",
    M14: "Logs, alertes & rapports", SUP: "VPN, GlobalProtect, HA & protections",
  };
  const ORDER = ["STD", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12", "M13", "M14", "SUP"];
  const modSort = (a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b);
  function localGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
  function localSet(k, v) { try { localStorage.setItem(k, v); } catch { /* stockage indisponible */ } }

  window.PAN = window.PAN || {};
  PAN.cfg = { register, list: reg, get: id => byId[id], V, q, members, yn, MODNAMES, modSort, mount };
  document.addEventListener("DOMContentLoaded", mount);
})();
