/* PANW Config Builder — moteur générique des modules de configuration (PAN-OS 11.0 & Panorama 11.1).
   Un module = { id, module, title, icon, desc, fields[], example?, build(v) → { steps[], cli[], verify[], notes[], push?, fwCli?, cliRaw? } }
   enregistré via PAN.cfg.register(def). Voir assets/js/modules/m02-m04.js pour l'exemple de référence.

   fields[] : { id, label, type, default?, placeholder?, hint?, required?, validate?, options?, show?, group?, min?, max?, wide?, share? }
     type      : text | ip | cidr | ipcidr | port | number | select | checkbox | textarea | list | password
                 (list = valeurs séparées par virgules → tableau ; ip/cidr/... appliquent la validation correspondante)
     validate  : nom d'un validateur intégré (voir V ci-dessous) ou fonction (val, values) → "message d'erreur" | null
     options   : [[valeur, libellé], ...] pour select
     show      : (values) → bool  (champ conditionnel, ignoré en validation s'il est masqué)
     group     : titre de section (une nouvelle section commence quand le groupe change)
     share     : true/false — force (ou interdit) la reprise de valeur entre modules d'un parcours
                 (par défaut : partagé sauf ids génériques type name/desc/from/to…, voir NO_SHARE)
   steps[]  : { title, path:[...menu], action?, tab?, window?, fields:[[label, valeur], ...], note?, warn? }
              valeurs vides/false/[] sont masquées ; tableaux affichés séparés par des virgules ; true → "✓ coché"
   cli[]    : lignes en mode configure (le moteur ajoute "configure" et "commit") — "# ..." = commentaire
   cliRaw[] : (option) CLI complète fournie telle quelle (remplace configure/cli/commit)
   verify[] : commandes en mode opérationnel (après commit), optionnel
   push[]   : (option, retour de build OU def.push = tableau | (v) → tableau) commandes opérationnelles Panorama
              exécutées après commit (ex. commit-all template-stack name TS-Paris) → bloc « Push vers les pare-feux »
              + étape GUI « Commit → Push to Devices » (portée = v.dg / v.stack / v.template)
   fwCli[]  : (option, retour de build) commandes côté PARE-FEU → bloc CLI séparé « Côté pare-feu » (configure … commit)
   noCommit : true si le module ne nécessite pas de commit (ex. opérations)

   Catégories : PAN.cfg.category(code, name)  → ajoute le titre et l'ordre d'affichage (ordre d'appel).
   Parcours   : PAN.cfg.scenario({ id, title, icon, desc, steps:[moduleIds], tags?, level?, duration?, values?, moduleValues? })
                values = { fieldId: valeur } préréglages appliqués à tous les modules du parcours ;
                moduleValues = { moduleId: { fieldId: valeur } } préréglages par module (priorité : exemple < préréglage
                < valeurs enregistrées < valeurs partagées saisies dans le parcours)
                lien : configurateur.html#parcours=<id>[&step=N] ; module seul : configurateur.html#<moduleId>
   Produit    : <body data-product="panorama"> (défaut "panos") → titres, étape Commit to Panorama, thème. */
(function () {
  const reg = [];
  const byId = {};
  const scns = [];
  const scnById = {};

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
    serial: v => /^\d{12,15}$/.test(String(v)) ? null : "Numéro de série : 12 à 15 chiffres",
  };
  V.listOf = (k) => arr => { for (const x of arr) { const e = V[k](x); if (e) return `« ${x} » : ${e}`; } return null; };

  /* ---------- helpers CLI exposés aux modules ---------- */
  const q = v => { v = String(v); return /[\s"';|]/.test(v) || v === "" ? `"${v.replace(/"/g, '\\"')}"` : v; };
  const members = a => { a = [].concat(a).filter(x => x !== "" && x != null); return a.length > 1 ? `[ ${a.map(q).join(" ")} ]` : q(a[0] ?? "any"); };
  const yn = b => (b ? "yes" : "no");

  /* ---------- catégories ---------- */
  const MODNAMES = {
    STD: "Déploiement standard client",
    M02: "Système & management", M03: "Sauvegarde & gestion de config", M04: "Comptes administrateurs",
    M05: "Interfaces, zones & routage", M06: "Règles de sécurité & objets", M07: "NAT", M08: "Applications (App-ID)",
    M09: "Profils de sécurité", M10: "Filtrage URL", M11: "WildFire", M12: "Identification utilisateurs (User-ID)", M13: "Décryptage SSL",
    M14: "Logs, alertes & rapports", SUP: "VPN, GlobalProtect, HA & protections",
  };
  const ORDER = ["STD", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12", "M13", "M14", "SUP"];
  const modSort = (a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b);
  function category(code, name) {
    if (!code) return;
    MODNAMES[code] = name || MODNAMES[code] || code;
    if (!ORDER.includes(code)) ORDER.push(code);
  }

  function register(def) {
    if (!def || !def.id) { console.warn("Module sans id", def); return; }
    if (byId[def.id]) { console.warn("Module en double :", def.id); return; }
    def.fields = def.fields || [];
    reg.push(def); byId[def.id] = def;
  }
  function scenario(def) {
    if (!def || !def.id) return;
    if (scnById[def.id]) { console.warn("Parcours en double :", def.id); return; }
    def.steps = def.steps || [];
    scns.push(def); scnById[def.id] = def;
  }

  /* ---------- produit ---------- */
  const product = () => (document.body && document.body.dataset.product === "panorama") ? "panorama" : "panos";
  const PROD = () => product() === "panorama"
    ? { key: "panorama", name: "Panorama", label: "Panorama 11.1", prompt: "admin@Panorama>" }
    : { key: "panos", name: "PAN-OS", label: "PAN-OS 11.0", prompt: "admin@firewall>" };

  /* ---------- logique pure (testable sans DOM) ---------- */
  const hasVal = x => !(x === "" || x == null || x === false || (Array.isArray(x) && !x.length));
  const visible = (f, v) => { try { return !f.show || !!f.show(v); } catch (e) { return true; } };
  const blank = f => f.type === "checkbox" ? false : f.type === "list" ? [] : "";
  const toArr = x => (typeof x === "string" ? [x] : Array.isArray(x) ? x : []).filter(l => l != null && l !== false);

  function defaults(def, useExample) {
    const v = {};
    def.fields.forEach(f => {
      let d = useExample && def.example && f.id in def.example ? def.example[f.id] : f.default;
      if (d === undefined) d = blank(f);
      v[f.id] = Array.isArray(d) ? d.slice() : d;
    });
    return v;
  }

  function fieldErr(f, v) {
    if (!visible(f, v)) return null;
    const val = v[f.id];
    const empty = val === "" || val == null || (Array.isArray(val) && !val.length) || val === false && f.type !== "checkbox";
    if (empty) return f.required ? "Champ obligatoire" : null;
    const typeV = { ip: "ip", cidr: "cidr", ipcidr: "ipcidr", port: "port" }[f.type];
    const checks = [typeV, f.validate].filter(Boolean);
    for (const c of checks) {
      let e = null;
      try {
        if (typeof c === "function") e = c(val, v);
        else if (f.type === "list") e = V[c] ? V.listOf(c)(val) : null;
        else if (V[c]) e = V[c](val);
      } catch (err) { e = null; }
      if (e) return e;
    }
    if (f.type === "number" && val !== "") {
      if (isNaN(+val)) return "Nombre attendu";
      if (f.min != null && +val < f.min) return `Minimum ${f.min}`;
      if (f.max != null && +val > f.max) return `Maximum ${f.max}`;
    }
    return null;
  }
  const errors = (def, v) => def.fields.map(f => [f, fieldErr(f, v)]).filter(([, e]) => e);

  function coerce(f, x) {
    if (x === undefined || x === null) return undefined;
    if (f.type === "checkbox") return !!x;
    if (f.type === "list") return Array.isArray(x) ? x.map(String) : String(x).split(/[,\n]/).map(s => s.trim()).filter(Boolean);
    if (Array.isArray(x)) x = x.join(", ");
    x = String(x);
    if (f.type === "select" && f.options && !f.options.some(([o]) => String(o) === x)) return undefined;
    return x;
  }

  /* ids trop génériques pour être repris automatiquement d'un module à l'autre */
  const NO_SHARE = new Set(("name desc description comment from to src dst rule rules ruleName prof type pos mkobj mkgrp action act tags " +
    "timeout group cats cat apps app useRule testIp tdst tsrc tport sched permitted mode lock entries cont use ref rec exp incl excl exc " +
    "custom apply allow block at dow base method sev risk proto port ip mask monitor container svc srv url user pw pwd pwd2 iface ifs " +
    "zone zoneNew dyn members list profile enabled value key").split(" "));
  const shareable = f => f.type !== "password" && (f.share === true || (f.share !== false && !NO_SHARE.has(f.id)));

  function compute(def, v) {
    const isPano = product() === "panorama";
    const res = def.build(v) || {};
    const steps = (res.steps || []).slice();
    let push = toArr(res.push);
    if (!push.length && def.push) push = toArr(typeof def.push === "function" ? def.push(v) : def.push);
    const fwCli = toArr(res.fwCli);
    if (!def.noCommit) {
      steps.push(isPano
        ? { title: "Valider sur Panorama (Commit to Panorama)", path: ["Commit", "Commit to Panorama"], commit: true, fields: [],
            action: "Cliquer sur Commit (en haut à droite) → Commit to Panorama → vérifier la prévisualisation → Commit. Suivre la tâche dans Tasks (en bas à droite)." }
        : { title: "Valider la configuration (Commit)", path: ["Commit"], commit: true, fields: [],
            action: "Cliquer sur Commit en haut à droite → vérifier la prévisualisation → Commit. Attendre « Configuration committed successfully »." });
    }
    if (push.length) {
      steps.push({ title: "Pousser vers les pare-feux (Push to Devices)", path: ["Commit", "Push to Devices"], commit: true,
        action: "Commit → Push to Devices (ou « Commit and Push ») → Edit Selections : cocher la portée ci-dessous → OK → Push. Suivre l'avancement dans Tasks.",
        fields: [["Device Groups", v.dg || ""], ["Templates / Template Stacks", v.stack || v.template || ""],
          ["Commandes CLI équivalentes", push.filter(l => !/^\s*#/.test(l)).join("\n")]] });
    }
    return { res, steps, push, fwCli, cli: cliText(def, res, push), fwText: fwCli.length ? ["configure", ...fwCli, "commit"].join("\n") : "" };
  }

  function cliText(def, res, push) {
    let lines, exited = false;
    if (res.cliRaw) { lines = res.cliRaw.slice(); exited = true; }
    else {
      lines = ["configure", ...(res.cli || [])];
      if (!def.noCommit) lines.push("commit");
    }
    if (push && push.length) {
      if (!exited) { lines.push("exit"); exited = true; }
      lines.push("", "# --- Push vers les pare-feux (mode opérationnel Panorama) ---", ...push);
    }
    if (!res.cliRaw && res.verify && res.verify.length) {
      if (!exited) lines.push("exit");
      lines.push("", "# --- Vérification (mode opérationnel) ---", ...res.verify);
    }
    return lines.join("\n");
  }

  function fmt(val) {
    if (val === true) return "✓ coché";
    if (Array.isArray(val)) return val.join(", ");
    return String(val);
  }

  /* ---------- texte exporté d'un module ---------- */
  function moduleText(def, v, c, withHeader = true) {
    const P = PROD();
    const out = [];
    if (withHeader) out.push(`# ${def.module} — ${def.title}`, `# Généré par PANW Config Builder (${P.label}) — ${new Date().toLocaleString("fr-FR")}`, "");
    out.push("========== PARAMÈTRES ==========", ...def.fields.filter(f => visible(f, v) && hasVal(v[f.id]) && f.type !== "password").map(f => `${f.label}: ${fmt(v[f.id])}`), "",
      "========== GUI PAS-À-PAS ==========", ...c.steps.flatMap((s, i) => [`${i + 1}. ${s.title}`, `   Chemin : ${(s.path || []).join(" > ")}${s.tab ? " > onglet " + s.tab : ""}`, ...(s.action ? [`   Action : ${s.action}`] : []),
        ...(s.fields || []).filter(([, x]) => hasVal(x)).map(([l, x]) => `   - ${l} : ${fmt(x).replace(/\n/g, "\n       ")}`), ...(s.note ? [`   Note : ${s.note}`] : []), ...(s.warn ? [`   Attention : ${s.warn}`] : []), ""]),
      `========== CLI${product() === "panorama" ? " (Panorama)" : ""} ==========`, c.cli);
    if (c.fwText) out.push("", "========== CLI CÔTÉ PARE-FEU ==========", c.fwText);
    return out.join("\n");
  }

  /* ---------- encodage du lien de partage ---------- */
  const b64e = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const b64d = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return decodeURIComponent(escape(atob(s))); };

  /* ---------- stockage ---------- */
  function localGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
  function localSet(k, v) { try { localStorage.setItem(k, v); } catch { /* stockage indisponible */ } }
  function localDel(k) { try { localStorage.removeItem(k); } catch { /* */ } }

  /* =========================================================
     UI (uniquement sur une page configurateur : #cfg-app)
     ========================================================= */
  function mount() {
    const app = document.getElementById("cfg-app");
    if (!app || app.dataset.mounted) return;
    app.dataset.mounted = 1;
    const P = PROD(), isPano = P.key === "panorama";
    app.classList.add("cfg-app");
    if (!document.getElementById("cfg-main")) {
      app.innerHTML = `<aside class="cfg-sidebar"><input type="text" id="cfg-search" placeholder="🔎 Rechercher…" aria-label="Rechercher un module">
        <nav id="cfg-side" aria-label="Modules"></nav></aside><div id="cfg-main" class="cfg-mainc"></div>`;
    }
    const sideAside = app.querySelector(".cfg-sidebar") || app;
    let side = document.getElementById("cfg-side");
    if (!side) { side = document.createElement("nav"); side.id = "cfg-side"; sideAside.append(side); }
    const main = document.getElementById("cfg-main");
    const search = document.getElementById("cfg-search");
    if (search) { search.placeholder = search.placeholder.replace(/\s*$/, "") + "   ( / )"; search.setAttribute("data-search", ""); }

    /* valider les parcours (modules inexistants ignorés) */
    scns.forEach(s => { const miss = s.steps.filter(id => !byId[id]); if (miss.length) console.warn(`Parcours ${s.id} : modules inconnus ignorés`, miss); s._steps = s.steps.filter(id => byId[id]); });

    /* ---- projet client ---- */
    const SKEY = "panw-project-" + P.key;
    const emptyProject = () => ({ v: 1, product: P.key, client: "", values: {}, done: {}, shared: {}, last: null, updated: 0 });
    let PRJ = emptyProject();
    try { const raw = localGet(SKEY); if (raw) PRJ = Object.assign(emptyProject(), JSON.parse(raw)); } catch { PRJ = emptyProject(); }
    let saveT;
    const save = (now) => {
      PRJ.updated = Date.now();
      clearTimeout(saveT);
      const w = () => { localSet(SKEY, JSON.stringify(PRJ)); const s = document.getElementById("cfg-saved"); if (s) { s.textContent = "✓ Enregistré " + new Date().toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" }); s.classList.remove("flash"); void s.offsetWidth; s.classList.add("flash"); } };
      now ? w() : (saveT = setTimeout(w, 300));
    };
    const storable = (def, v) => { const o = {}; def.fields.forEach(f => { if (f.type !== "password" && v[f.id] !== undefined) o[f.id] = v[f.id]; }); return o; };

    const state = { def: null, values: {}, mode: localGet("cfg-mode") || "gui", scn: null, idx: 0, last: null };

    /* priorité : défaut/exemple < préréglages du parcours < valeurs enregistrées < valeurs partagées du parcours */
    function initialValues(def, scn) {
      const inScn = !!scn;
      const v = defaults(def, true);
      const saved = PRJ.values[def.id] || {};
      const preset = inScn && typeof scn === "object" ? Object.assign({}, scn.values || {}, (scn.moduleValues || {})[def.id] || {}) : {};
      def.fields.forEach(f => {
        let x = coerce(f, preset[f.id]);
        const sv = coerce(f, saved[f.id]); if (sv !== undefined) x = sv;
        if (inScn && shareable(f) && PRJ.shared[f.id] !== undefined) { const s = coerce(f, PRJ.shared[f.id]); if (s !== undefined) x = s; }
        if (f.id === "client" && PRJ.client && (saved.client === undefined || inScn)) x = PRJ.client;
        if (x !== undefined) v[f.id] = x;
      });
      return v;
    }
    const doneMap = id => (PRJ.done[id] = PRJ.done[id] || {});
    const stepKey = (s, i) => i + ":" + s.title;
    const isDone = (id, s, i) => !!(PRJ.done[id] && PRJ.done[id][stepKey(s, i)]);
    function moduleProgress(def, scn) {
      try { const c = compute(def, initialValues(def, scn)); const n = c.steps.length, d = c.steps.filter((s, i) => isDone(def.id, s, i)).length; return { n, d, full: n > 0 && d === n }; }
      catch { return { n: 0, d: 0, full: false }; }
    }

    /* ---- palette de commandes (⌘K) ---- */
    if (PAN.palette) {
      PAN.palette.add(scns.map(s => ({ icon: s.icon || "🧭", label: "Parcours : " + s.title, sub: `${s._steps.length} étapes${s.duration ? " · " + s.duration : ""}`, kw: (s.tags || "") + " parcours scenario", href: "#parcours=" + s.id, group: "Parcours" })));
      PAN.palette.add(reg.map(d => ({ icon: d.icon || "⚙️", label: d.title, sub: MODNAMES[d.module] || d.module, kw: (d.tags || "") + " " + (d.desc || "") + " " + d.id, href: "#" + d.id, group: "Modules" })));
      PAN.palette.add([
        { icon: "⬇", label: "Exporter le projet client (JSON)", group: "Projet", run: () => exportProject() },
        { icon: "⬆", label: "Importer un projet client (JSON)", group: "Projet", run: () => importProject() },
        { icon: "🖨", label: "Imprimer / PDF de la vue courante", group: "Projet", run: () => printCurrent() },
      ]);
    }

    /* ---- sidebar ---- */
    function projectCard() {
      return `<div class="cfg-project glass">
        <label for="cfg-client" class="small">👤 Projet client</label>
        <input type="text" id="cfg-client" placeholder="Nom du client (ex. ACME Paris)" value="${PAN.esc(PRJ.client || "")}" autocomplete="off">
        <div class="cfg-project-a">
          <button class="btn sm ghost" type="button" data-act="prj-export" title="Exporter toutes les valeurs du projet en JSON">⬇ JSON</button>
          <button class="btn sm ghost" type="button" data-act="prj-import" title="Importer un projet JSON">⬆ Importer</button>
          <button class="btn sm ghost" type="button" data-act="prj-new" title="Nouveau projet (efface les valeurs enregistrées)">✚ Nouveau</button>
        </div>
        <div class="cfg-saved small mut" id="cfg-saved">${PRJ.updated ? "✓ Enregistré localement" : "Sauvegarde automatique locale"}</div>
      </div>`;
    }
    if (!document.getElementById("cfg-project-slot")) {
      const slot = document.createElement("div"); slot.id = "cfg-project-slot";
      sideAside.insertBefore(slot, sideAside.firstChild);
    }
    const renderProject = () => { document.getElementById("cfg-project-slot").innerHTML = projectCard(); };
    renderProject();
    sideAside.addEventListener("input", e => {
      if (e.target.id === "cfg-client") {
        PRJ.client = e.target.value.trim();
        if (PRJ.client) PRJ.shared.client = PRJ.client;
        save();
        if (state.def && state.def.fields.some(f => f.id === "client")) { const inp = document.getElementById("f-client"); if (inp) { inp.value = PRJ.client; state.values.client = PRJ.client; refresh(); } }
      }
    });
    sideAside.addEventListener("click", e => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      if (b.dataset.act === "prj-export") exportProject();
      if (b.dataset.act === "prj-import") importProject();
      if (b.dataset.act === "prj-new") {
        if (!confirm("Démarrer un nouveau projet ? Les valeurs et étapes « Fait » enregistrées dans ce navigateur seront effacées (pense à exporter le JSON avant).")) return;
        PRJ = emptyProject(); localDel(SKEY); renderProject(); route(); PAN.toast("Nouveau projet démarré");
      }
    });

    function renderSide(filter = "") {
      const f = filter.trim().toLowerCase();
      const match = s => !f || s.toLowerCase().includes(f);
      const groups = {};
      reg.filter(d => match(d.title + " " + d.module + " " + (d.desc || "") + " " + (d.tags || "") + " " + d.id))
        .forEach(d => (groups[d.module] = groups[d.module] || []).push(d));
      const sc = scns.filter(s => match(s.title + " " + (s.desc || "") + " " + (s.tags || "")));
      const cur = state.def && state.def.id, curS = state.scn && state.scn.id;
      side.innerHTML = (sc.length ? `<div class="cfg-grp"><div class="cfg-grp-t">🧭 Parcours guidés</div>
          ${sc.map(s => `<a href="#parcours=${s.id}" class="cfg-link${curS === s.id ? " on" : ""}"><i>${s.icon || "🧭"}</i>${PAN.esc(s.title)}</a>`).join("")}</div>` : "")
        + Object.keys(groups).sort(modSort).map(m => `
        <div class="cfg-grp"><div class="cfg-grp-t">${PAN.esc(MODNAMES[m] || m)}</div>
        ${groups[m].map(d => `<a href="#${d.id}" class="cfg-link${cur === d.id && !curS ? " on" : ""}" data-id="${d.id}"><i>${d.icon || "⚙️"}</i>${PAN.esc(d.title)}</a>`).join("")}</div>`).join("")
        || `<p class="mut small" style="padding:12px">Aucun module trouvé.</p>`;
    }
    search && search.addEventListener("input", () => renderSide(search.value));
    search && search.addEventListener("keydown", e => {
      if (e.key === "Enter") { const a = side.querySelector("a.cfg-link"); if (a) { location.hash = a.getAttribute("href").slice(1); search.blur(); } }
      if (e.key === "Escape") { search.value = ""; renderSide(""); search.blur(); }
    });

    /* ---- accueil du configurateur ---- */
    function renderHome() {
      state.def = null; state.scn = null; renderSide(search ? search.value : "");
      const groups = {};
      reg.forEach(d => (groups[d.module] = groups[d.module] || []).push(d));
      const last = PRJ.last && (PRJ.last.scn ? scnById[PRJ.last.scn] : byId[PRJ.last.mod]);
      const lastHref = PRJ.last ? (PRJ.last.scn ? `#parcours=${PRJ.last.scn}&step=${PRJ.last.step || 0}` : "#" + PRJ.last.mod) : "";
      main.innerHTML = `
        <div class="cfg-head fade-up"><span class="kicker">Configurateur ${P.label}</span>
        <h1>Que veux-tu <span class="grad grad-anim">configurer</span>&nbsp;?</h1>
        <p class="lead">Suis un <b>parcours guidé</b> de bout en bout, ou choisis un module : renseigne tes informations, tu obtiens le pas-à-pas WebUI avec validation de chaque étape, ou la CLI prête à coller.</p>
        <div class="row cfg-home-a">
          ${last ? `<a class="btn primary" href="${lastHref}">▶ Reprendre : ${PAN.esc(last.title)}</a>` : ""}
          <button class="btn ghost" type="button" data-act="palette">⌘K&nbsp; Aller à un module…</button>
          <span class="mut small cfg-kbd-hint"><kbd>/</kbd> rechercher · <kbd>⌘K</kbd> / <kbd>Ctrl K</kbd> palette · <kbd>Ctrl ⏎</kbd> générer</span>
        </div></div>
        ${scns.length ? `<h2 class="cfg-dash-t cfg-dash-big fade-up"><b>🧭</b>Parcours guidés <span class="mut small">— enchaînement de modules, valeurs reprises d'une étape à l'autre, export global</span></h2>
          <div class="grid g3 cfg-scn-grid">${scns.map((s, i) => scnCard(s, i)).join("")}</div>` : ""}
        ${Object.keys(groups).sort(modSort).map((m, gi) => `
          <h3 class="cfg-dash-t fade-up" style="animation-delay:${Math.min(gi * 50, 400)}ms"><b>${PAN.esc(m)}</b>${PAN.esc(MODNAMES[m] || m)}</h3>
          <div class="grid g3">${groups[m].map((d, i) => `
            <a class="card hover cfg-card fade-up" style="animation-delay:${Math.min(gi * 50 + i * 35, 600)}ms" href="#${d.id}">
              ${PRJ.values[d.id] ? `<span class="cfg-card-dot" title="Valeurs enregistrées dans le projet"></span>` : ""}
              <div class="ico">${d.icon || "⚙️"}</div><h3>${PAN.esc(d.title)}</h3><p class="mut small">${PAN.esc(d.desc || "")}</p></a>`).join("")}
          </div>`).join("")}`;
      document.title = `Configurateur ${P.name} · PANW Config Builder`;
      PAN.reveal && PAN.reveal();
    }
    function scnCard(s, i) {
      const ms = s._steps.map(id => byId[id]);
      const pr = ms.map(d => moduleProgress(d, s)), done = pr.filter(p => p.full).length;
      return `<a class="card hover cfg-card cfg-scn-card fade-up" style="animation-delay:${i * 60}ms" href="#parcours=${s.id}">
        <div class="row" style="gap:8px;margin-bottom:10px"><div class="ico" style="margin:0">${s.icon || "🧭"}</div><span class="spacer"></span>
          ${s.level ? `<span class="badge">${PAN.esc(s.level)}</span>` : ""}${s.duration ? `<span class="badge or">⏱ ${PAN.esc(s.duration)}</span>` : ""}</div>
        <h3>${PAN.esc(s.title)}</h3><p class="mut small">${PAN.esc(s.desc || "")}</p>
        <div class="cfg-scn-chips">${ms.map((d, k) => `<span class="${pr[k].full ? "ok" : ""}" title="${PAN.esc(d.title)}">${d.icon || "⚙️"}</span>`).join("")}</div>
        <div class="cfg-prog-bar sm"><i style="width:${ms.length ? (done / ms.length) * 100 : 0}%"></i></div>
        <p class="small mut" style="margin-top:6px">${done ? `${done}/${ms.length} étapes terminées` : `${ms.length} étapes · commencer →`}</p></a>`;
    }

    /* ---- formulaire ---- */
    function inputHTML(f, val) {
      const id = "f-" + f.id, ph = f.placeholder ? ` placeholder="${PAN.esc(f.placeholder)}"` : "";
      const req = f.required ? " aria-required=\"true\"" : "";
      switch (f.type) {
        case "select":
          return `<select id="${id}" data-f="${f.id}"${req}>${(f.options || []).map(([o, l]) => `<option value="${PAN.esc(o)}"${String(o) === String(val) ? " selected" : ""}>${PAN.esc(l ?? o)}</option>`).join("")}</select>`;
        case "checkbox":
          return `<label class="cfg-check"><input type="checkbox" id="${id}" data-f="${f.id}"${val ? " checked" : ""}><span>${PAN.esc(f.label)}</span></label>`;
        case "textarea":
          return `<textarea id="${id}" data-f="${f.id}" rows="3"${ph}${req}>${PAN.esc(val ?? "")}</textarea>`;
        case "list":
          return `<input type="text" id="${id}" data-f="${f.id}" value="${PAN.esc((val || []).join(", "))}"${ph}${req}>`;
        case "password":
          return `<input type="password" id="${id}" data-f="${f.id}" value="${PAN.esc(val ?? "")}" autocomplete="new-password"${ph}${req}>`;
        default:
          return `<input type="text" id="${id}" data-f="${f.id}" value="${PAN.esc(val ?? "")}"${ph}${req}${f.type === "number" || f.type === "port" ? ' inputmode="numeric"' : ""} spellcheck="false">`;
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
          ${f.type === "checkbox" ? "" : `<label for="f-${f.id}">${PAN.esc(f.label)}${f.required ? ' <b class="req">*</b>' : ""}<span class="vmark" aria-hidden="true">✓</span></label>`}
          ${inputHTML(f, v[f.id])}
          ${f.hint ? `<div class="hint">${f.hint}</div>` : ""}<div class="err" data-err="${f.id}" aria-live="polite"></div></div>`;
      });
      if (open) html += "</div></fieldset>";
      if (!def.fields.length) html = `<p class="mut small">Ce module ne nécessite aucune saisie.</p>`;
      document.getElementById("cfg-form").innerHTML = html;
    }

    function readField(el) {
      const f = state.def.fields.find(x => x.id === el.dataset.f);
      if (f.type === "checkbox") return el.checked;
      if (f.type === "list") return el.value.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
      return el.value.trim();
    }

    function validateAll(show) {
      let ok = true, first = null, total = 0, good = 0, bad = 0, reqMiss = 0;
      state.def.fields.forEach(f => {
        const wrap = main.querySelector(`[data-wrap="${f.id}"]`);
        const vis = visible(f, state.values);
        if (wrap) wrap.hidden = !vis;
        const e = fieldErr(f, state.values);
        const errEl = main.querySelector(`[data-err="${f.id}"]`), inp = document.getElementById("f-" + f.id);
        const touched = show || (inp && inp.dataset.touched);
        if (errEl) errEl.textContent = e && touched ? e : "";
        if (inp) { inp.classList.toggle("invalid", !!(e && touched)); inp.setAttribute("aria-invalid", !!(e && touched)); }
        const filled = hasVal(state.values[f.id]);
        if (wrap) wrap.classList.toggle("ok", vis && !e && filled && f.type !== "checkbox");
        if (vis && f.type !== "checkbox") { total++; if (filled && !e) good++; }
        if (e) { ok = false; bad++; if (e === "Champ obligatoire") reqMiss++; first = first || inp; }
      });
      const st = document.getElementById("cfg-status");
      if (st) st.innerHTML = ok ? `<span class="badge ok">✓ Données valides</span>` : `<span class="badge warn">⚠ ${bad} champ${bad > 1 ? "s" : ""} à corriger</span>`;
      const fp = document.getElementById("cfg-fprog");
      if (fp) {
        const pct = total ? Math.round(good / total * 100) : 100;
        fp.querySelector("i").style.width = pct + "%";
        fp.querySelector("span").textContent = `${good}/${total} champs renseignés${reqMiss ? ` · ${reqMiss} obligatoire${reqMiss > 1 ? "s" : ""} manquant${reqMiss > 1 ? "s" : ""}` : ""}`;
        fp.classList.toggle("full", ok);
      }
      return { ok, first };
    }

    /* ---- sortie ---- */
    function renderOutput() {
      const out = document.getElementById("cfg-out");
      if (!out) return;
      const { ok } = validateAll(false);
      if (!ok) {
        const errs = errors(state.def, state.values);
        out.innerHTML = `<div class="cfg-empty"><div class="cfg-empty-ico">🧩</div><p>Complète les champs pour générer la configuration :</p>
          <ul class="cfg-miss">${errs.slice(0, 6).map(([f, e]) => `<li><a href="#" data-focus="${f.id}">${PAN.esc(f.label)}</a> — <span class="mut">${PAN.esc(e)}</span></li>`).join("")}</ul></div>`;
        state.last = null; return;
      }
      let c;
      try { c = compute(state.def, state.values); }
      catch (e) { console.error(e); out.innerHTML = `<div class="callout bad"><b>Erreur de génération</b>${PAN.esc(e.message)}</div>`; state.last = null; return; }
      state.last = c;
      out.innerHTML = `
        <div class="cfg-modes" role="tablist">
          <button role="tab" data-mode="gui" aria-selected="${state.mode === "gui"}">🖱️ GUI pas-à-pas</button>
          <button role="tab" data-mode="cli" aria-selected="${state.mode === "cli"}">⌨️ CLI</button>
          <span class="spacer"></span>
          <button class="btn sm ghost" type="button" data-act="copy-cli" title="Copier toute la CLI">⧉ Copier la CLI</button>
          <button class="btn sm ghost" type="button" data-act="dl" title="Télécharger GUI + CLI en .txt">⬇ .txt</button>
        </div>
        ${(c.res.notes || []).map(n => `<div class="callout ${n.type || "or"}">${n.title ? `<b>${PAN.esc(n.title)}</b>` : ""}${n.html || PAN.esc(n.text || "")}</div>`).join("")}
        <div id="cfg-view"></div>`;
      renderView();
    }

    function hl(line) {
      const e = PAN.esc(line);
      if (/^\s*#/.test(line)) return `<span class="c">${e}</span>`;
      return e.replace(/^(\s*)(set|delete|edit|commit|commit-all|configure|exit|show|test|request|debug|run|move|rename|clear|ping|save|load|revert|validate|scp|tftp)\b/, '$1<span class="k">$2</span>')
        .replace(/(&quot;[^&]*?&quot;)/g, '<span class="s">$1</span>')
        .replace(/\b(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\b/g, '<span class="n">$1</span>');
    }
    const codeBlock = (id, txt, title, hint) => `<div class="cfg-cli fade-up">${title ? `<div class="cfg-cli-t">${title}</div>` : ""}
      <div class="cfg-cli-box"><button class="btn sm copy-btn" type="button" data-copy-target="#${id}">⧉ Copier</button>
      <div class="code" id="${id}">${txt.split("\n").map(hl).join("\n")}</div></div>${hint ? `<p class="hint" style="margin-top:8px">${hint}</p>` : ""}</div>`;

    function renderView() {
      const view = document.getElementById("cfg-view"); if (!view || !state.last) return;
      const { steps, cli, fwText } = state.last, id = state.def.id;
      main.querySelectorAll(".cfg-modes [data-mode]").forEach(b => b.setAttribute("aria-selected", b.dataset.mode === state.mode));
      if (state.mode === "cli") {
        view.innerHTML = codeBlock("cfg-cli-code", cli, isPano ? "🛰️ Sur Panorama" : "",
          `Colle ces lignes dans une session SSH (${PAN.esc(P.prompt)}). Le mode <code>configure</code> est ouvert automatiquement en première ligne.`)
          + (fwText ? codeBlock("cfg-cli-fw", fwText, "🧱 Côté pare-feu", "À saisir en SSH sur le pare-feu (admin@firewall&gt;).") : "");
        return;
      }
      const n = steps.length, d = steps.filter((s, i) => isDone(id, s, i)).length;
      view.innerHTML = `
        <div class="cfg-prog"><div class="cfg-prog-bar"><i style="width:${n ? (d / n) * 100 : 0}%"></i></div><span>${d}/${n} étapes faites</span>
          <button class="btn sm ghost" type="button" data-act="all-done">${d === n && n ? "↺ Tout décocher" : "✓ Tout cocher"}</button></div>
        <ol class="cfg-steps">${steps.map((s, i) => stepHTML(s, i)).join("")}</ol>
        <div class="cfg-finish${d === n && n ? " show" : ""}" id="cfg-finish">🎉 Configuration terminée — pense à vérifier dans les logs / la CLI.</div>`;
      const els = view.querySelectorAll(".cfg-step");
      els.forEach((el, i) => setTimeout(() => el.classList.add("in"), Math.min(50 * i, 500)));
    }

    function stepHTML(s, i) {
      const done = isDone(state.def.id, s, i);
      const rows = (s.fields || []).filter(([, v]) => hasVal(v));
      return `<li class="cfg-step${done ? " done" : ""}${s.commit ? " commit" : ""}" data-i="${i}">
        <div class="cfg-step-h">
          <span class="cfg-num">${done ? "✓" : i + 1}</span>
          <div class="cfg-step-tt"><b>${PAN.esc(s.title)}</b>
            <div class="cfg-path">${(s.path || []).map(p => `<span>${PAN.esc(p)}</span>`).join("<i>›</i>")}${s.tab ? `<i>›</i><span class="tab">onglet ${PAN.esc(s.tab)}</span>` : ""}</div></div>
          <label class="cfg-done"><input type="checkbox" data-done="${i}"${done ? " checked" : ""}> Fait</label>
        </div>
        ${s.action ? `<p class="cfg-action">👉 ${PAN.esc(s.action)}</p>` : ""}
        ${rows.length ? `<div class="pan cfg-pan"><div class="pan-title"><span>${PAN.esc(s.window || s.title)}</span><span style="color:#9AA5B1">✕</span></div>
          <div class="pan-body">${rows.map(([l, v]) => `<div class="pan-row"><span>${PAN.esc(l)}</span><span class="pan-val" data-copyval title="Cliquer pour copier">${PAN.esc(fmt(v))}</span></div>`).join("")}</div>
          <div class="pan-foot"><button class="pan-btn pri" tabindex="-1" type="button">OK</button><button class="pan-btn" tabindex="-1" type="button">Cancel</button></div></div>` : ""}
        ${s.note ? `<div class="callout small">${PAN.esc(s.note)}</div>` : ""}
        ${s.warn ? `<div class="callout warn small">⚠ ${PAN.esc(s.warn)}</div>` : ""}
      </li>`;
    }

    /* ---- coquille d'un module (formulaire + sortie) ---- */
    function moduleShell(def) {
      return `<div class="cfg-layout">
          <div class="panel cfg-in fade-up" style="animation-delay:80ms">
            <div class="row cfg-in-h"><h3>1 · Tes informations</h3><span class="spacer"></span><span id="cfg-status"></span></div>
            <div class="cfg-prog cfg-fprog" id="cfg-fprog"><div class="cfg-prog-bar"><i style="width:0"></i></div><span></span></div>
            <form id="cfg-form" autocomplete="off" novalidate></form>
            <div class="row cfg-form-a">
              <button class="btn sm" type="button" data-act="example" title="Remplir avec des valeurs d'exemple">✨ Charger un exemple</button>
              <button class="btn sm ghost" type="button" data-act="reset" title="Revenir aux valeurs par défaut">↺ Réinitialiser</button>
              <button class="btn sm ghost" type="button" data-act="clear" title="Vider tous les champs">Vider</button>
              <span class="spacer"></span>
              <button class="btn primary sm" type="button" data-act="gen" title="Ctrl/⌘ + Entrée">Générer →</button>
            </div>
          </div>
          <div class="cfg-outwrap fade-up" style="animation-delay:160ms"><h3 class="cfg-out-t">2 · Ta configuration</h3><div id="cfg-out"></div></div>
        </div>`;
    }
    const headActions = (scope) => `<div class="row cfg-head-a">
        <button class="btn sm ghost" type="button" data-act="share" title="Copier un lien qui contient les valeurs saisies">🔗 Lien de partage</button>
        <button class="btn sm ghost" type="button" data-act="print" title="Imprimer ou enregistrer en PDF">🖨 Imprimer / PDF</button>
        <button class="btn sm ghost" type="button" data-act="${scope === "scn" ? "scn-dl" : "dl"}">⬇ ${scope === "scn" ? "CLI complète du parcours" : "Télécharger"} .txt</button>
      </div>`;

    function bindModule(def, scn) {
      state.def = def; state.values = initialValues(def, scn);
      renderForm(); renderOutput();
    }

    /* ---- ouverture d'un module seul ---- */
    function openModule(id) {
      const def = byId[id];
      if (!def) return renderHome();
      state.scn = null;
      PRJ.last = { mod: id }; save();
      state.def = def; renderSide(search ? search.value : "");
      main.innerHTML = `
        <div class="cfg-head fade-up">
          <a href="#" class="small">← Tous les modules et parcours</a>
          <div class="row" style="margin-top:10px"><span class="cfg-ico">${def.icon || "⚙️"}</span>
            <div><span class="kicker">${PAN.esc(MODNAMES[def.module] || def.module)}</span><h1 class="cfg-h1">${PAN.esc(def.title)}</h1></div></div>
          ${def.desc ? `<p class="lead">${PAN.esc(def.desc)}</p>` : ""}
          ${headActions("mod")}
          ${scenariosWith(id)}
        </div>${moduleShell(def)}`;
      document.title = `${def.title} · PANW Config Builder`;
      bindModule(def, false);
    }
    function scenariosWith(id) {
      const s = scns.filter(x => x._steps.includes(id));
      return s.length ? `<p class="small mut cfg-in-scn">Fait partie du parcours : ${s.map(x => `<a href="#parcours=${x.id}&step=${x._steps.indexOf(id)}">${x.icon || "🧭"} ${PAN.esc(x.title)}</a>`).join(" · ")}</p>` : "";
    }

    /* ---- ouverture d'un parcours ---- */
    function openScenario(sid, step) {
      const s = scnById[sid];
      if (!s || !s._steps.length) return renderHome();
      const n = s._steps.length;
      const idx = Math.max(0, Math.min(n - 1, +step || 0));
      state.scn = s; state.idx = idx;
      const def = byId[s._steps[idx]];
      PRJ.last = { scn: sid, step: idx }; save();
      state.def = def; renderSide(search ? search.value : "");
      main.innerHTML = `
        <div class="cfg-head fade-up">
          <a href="#" class="small">← Tous les modules et parcours</a>
          <div class="row" style="margin-top:10px"><span class="cfg-ico">${s.icon || "🧭"}</span>
            <div><span class="kicker">Parcours guidé · ${n} étapes${s.duration ? " · ⏱ " + PAN.esc(s.duration) : ""}${s.level ? " · " + PAN.esc(s.level) : ""}</span><h1 class="cfg-h1">${PAN.esc(s.title)}</h1></div></div>
          ${s.desc ? `<p class="lead">${PAN.esc(s.desc)}</p>` : ""}
          ${headActions("scn")}
        </div>
        <nav class="cfg-stepper fade-up" id="cfg-stepper" aria-label="Étapes du parcours"></nav>
        <section class="cfg-scn-step" id="cfg-scn-step">
          <div class="row cfg-scn-h"><span class="badge or">Étape ${idx + 1}/${n}</span><span class="cfg-ico sm">${def.icon || "⚙️"}</span>
            <div style="min-width:0"><h2 class="cfg-scn-title">${PAN.esc(def.title)}</h2><p class="mut small">${PAN.esc(def.desc || "")} <a href="#${def.id}">Ouvrir seul ↗</a></p></div></div>
          <div class="callout small cfg-shared-note">🔁 Les champs déjà saisis dans une étape précédente (hostname, IP, zones, serveurs…) sont repris automatiquement.</div>
          ${moduleShell(def)}
        </section>
        <div class="row cfg-scn-nav">
          ${idx > 0 ? `<a class="btn ghost" href="#parcours=${sid}&step=${idx - 1}">← ${PAN.esc(byId[s._steps[idx - 1]].title)}</a>` : ""}
          <span class="spacer"></span>
          ${idx < n - 1 ? `<a class="btn primary" data-magnetic href="#parcours=${sid}&step=${idx + 1}">Étape suivante : ${PAN.esc(byId[s._steps[idx + 1]].title)} →</a>`
            : `<button class="btn primary" type="button" data-act="scn-dl">🎉 Terminer : CLI complète .txt</button><button class="btn" type="button" data-act="print">🖨 Rapport PDF</button>`}
        </div>`;
      document.title = `${s.title} · PANW Config Builder`;
      bindModule(def, s);
      renderStepper();
    }
    function renderStepper() {
      const el = document.getElementById("cfg-stepper"); if (!el || !state.scn) return;
      const s = state.scn, n = s._steps.length;
      const pr = s._steps.map(id => moduleProgress(byId[id], s));
      const doneN = pr.filter(p => p.full).length;
      el.style.setProperty("--p", (n > 1 ? state.idx / (n - 1) : 1) * 100 + "%");
      el.innerHTML = `<div class="cfg-stepper-top"><span>${doneN}/${n} étapes terminées</span><div class="cfg-prog-bar"><i style="width:${doneN / n * 100}%"></i></div></div>
        <ol>${s._steps.map((id, i) => { const d = byId[id];
          return `<li class="${i === state.idx ? "on" : ""}${pr[i].full ? " done" : ""}${i < state.idx ? " past" : ""}"><a href="#parcours=${s.id}&step=${i}" title="${PAN.esc(d.title)}">
            <i>${pr[i].full ? "✓" : i + 1}</i><span>${PAN.esc(d.title)}</span></a></li>`; }).join("")}</ol>`;
    }

    /* ---- rafraîchissement après saisie ---- */
    function persistValues() {
      PRJ.values[state.def.id] = storable(state.def, state.values);
      save();
    }
    function refresh() { validateAll(false); renderOutput(); }

    /* ---- événements délégués ---- */
    let t;
    main.addEventListener("input", e => {
      const el = e.target.closest("[data-f]"); if (!el || !state.def) return;
      el.dataset.touched = 1;
      const f = state.def.fields.find(x => x.id === el.dataset.f);
      state.values[el.dataset.f] = readField(el);
      if (f && shareable(f)) PRJ.shared[f.id] = state.values[f.id];
      if (f && f.id === "client") { PRJ.client = String(state.values.client || ""); const c = document.getElementById("cfg-client"); if (c) c.value = PRJ.client; }
      persistValues();
      clearTimeout(t); t = setTimeout(() => { refresh(); renderStepper(); }, 160);
    });
    main.addEventListener("focusout", e => {
      const el = e.target.closest && e.target.closest("[data-f]"); if (!el || !state.def) return;
      if (el.value !== "" || el.type === "checkbox") { el.dataset.touched = 1; validateAll(false); }
    });
    main.addEventListener("change", e => {
      const el = e.target.closest("[data-f]");
      if (el && state.def) {
        el.dataset.touched = 1;
        const f = state.def.fields.find(x => x.id === el.dataset.f);
        state.values[el.dataset.f] = readField(el);
        if (f && shareable(f)) PRJ.shared[f.id] = state.values[f.id];
        persistValues(); refresh(); return;
      }
      const dn = e.target.closest("[data-done]");
      if (dn && state.last) {
        const i = +dn.dataset.done, s = state.last.steps[i], m = doneMap(state.def.id);
        if (dn.checked) m[stepKey(s, i)] = true; else delete m[stepKey(s, i)];
        save(true); renderView(); renderStepper();
        const n = state.last.steps.length, d = state.last.steps.filter((x, k) => isDone(state.def.id, x, k)).length;
        if (dn.checked && d === n) {
          PAN.toast(state.scn && state.idx < state.scn._steps.length - 1 ? "Étape terminée 🎉 — passe à la suivante" : "Toutes les étapes sont validées 🎉");
          PAN.confetti && PAN.confetti(dn);
        }
      }
    });
    main.addEventListener("keydown", e => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && state.def) { e.preventDefault(); generate(); }
    });
    main.addEventListener("click", e => {
      const m = e.target.closest("[data-mode]");
      if (m) { state.mode = m.dataset.mode; localSet("cfg-mode", state.mode); renderView(); return; }
      const fo = e.target.closest("[data-focus]");
      if (fo) { e.preventDefault(); const inp = document.getElementById("f-" + fo.dataset.focus); if (inp) { inp.focus(); inp.scrollIntoView({ behavior: "smooth", block: "center" }); } return; }
      const cv = e.target.closest("[data-copyval]");
      if (cv) { PAN.copy(cv.textContent); cv.classList.remove("copied"); void cv.offsetWidth; cv.classList.add("copied"); return; }
      const b = e.target.closest("[data-act]"); if (!b) return;
      const act = b.dataset.act, def = state.def;
      if (act === "palette") return PAN.palette && PAN.palette.open();
      if (act === "print") return printCurrent();
      if (act === "scn-dl") return downloadScenario();
      if (act === "share") return shareLink();
      if (!def) return;
      if (act === "example") { state.values = defaults(def, true); if (PRJ.client && def.fields.some(f => f.id === "client")) state.values.client = PRJ.client; persistValues(); renderForm(); refresh(); PAN.toast("Exemple chargé ✨"); }
      if (act === "reset") {
        if (PRJ.values[def.id] && !confirm("Revenir aux valeurs par défaut de ce module ?")) return;
        state.values = defaults(def, false); delete PRJ.values[def.id]; delete PRJ.done[def.id]; save(true);
        renderForm(); refresh(); renderStepper(); PAN.toast("Module réinitialisé");
      }
      if (act === "clear") { state.values = {}; def.fields.forEach(f => state.values[f.id] = f.type === "select" ? (f.options[0] || [""])[0] : blank(f)); persistValues(); renderForm(); refresh(); }
      if (act === "gen") generate();
      if (act === "dl") download();
      if (act === "copy-cli" && state.last) PAN.copy(state.last.cli + (state.last.fwText ? "\n\n# ===== Côté pare-feu =====\n" + state.last.fwText : ""));
      if (act === "all-done" && state.last) {
        const m = doneMap(def.id), steps = state.last.steps, all = steps.every((s, i) => isDone(def.id, s, i));
        steps.forEach((s, i) => { if (all) delete m[stepKey(s, i)]; else m[stepKey(s, i)] = true; });
        save(true); renderView(); renderStepper();
        if (!all) { PAN.toast("Toutes les étapes sont validées 🎉"); PAN.confetti && PAN.confetti(b); }
      }
    });
    function generate() {
      const { ok, first } = validateAll(true);
      if (!ok) { if (first) { first.focus(); first.scrollIntoView({ behavior: "smooth", block: "center" }); } PAN.toast("Corrige les champs en rouge"); return; }
      renderOutput(); const o = main.querySelector(".cfg-outwrap"); o && o.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    /* ---- téléchargements / export ---- */
    function saveFile(name, txt, type) {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([txt], { type: type || "text/plain;charset=utf-8" }));
      a.download = name; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1500);
    }
    const slug = s => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase();
    const clientLine = () => PRJ.client ? [`# Client : ${PRJ.client}`] : [];
    function download() {
      if (!state.last) { PAN.toast("Complète d'abord les champs obligatoires"); return; }
      const txt = clientLine().join("\n") + (PRJ.client ? "\n" : "") + moduleText(state.def, state.values, state.last);
      saveFile(`${PRJ.client ? slug(PRJ.client) + "-" : ""}${state.def.id}.txt`, txt);
      PAN.toast("Fichier .txt téléchargé ⬇");
    }
    function scenarioItems(s) {
      return s._steps.map(id => { const def = byId[id], v = initialValues(def, s); let c = null, err = null;
        const er = errors(def, v); if (er.length) err = er.map(([f, e]) => `${f.label} : ${e}`).join(" ; ");
        if (!err) try { c = compute(def, v); } catch (e) { err = e.message; }
        return { def, v, c, err }; });
    }
    function downloadScenario() {
      const s = state.scn; if (!s) return download();
      const items = scenarioItems(s);
      const out = [`# Parcours : ${s.title}`, ...clientLine(), `# Généré par PANW Config Builder (${P.label}) — ${new Date().toLocaleString("fr-FR")}`,
        `# Étapes : ${items.map((x, i) => `${i + 1}. ${x.def.title}`).join(" | ")}`, ""];
      /* CLI consolidée : un seul configure / commit */
      const merged = ["configure"], raw = [], push = [], verify = [], fw = [];
      let needCommit = false;
      items.forEach((x, i) => {
        if (!x.c) { merged.push(`# !! Étape ${i + 1} (${x.def.title}) ignorée : ${x.err}`); return; }
        if (x.c.res.cliRaw) raw.push("", `# ===== Étape ${i + 1} · ${x.def.title} (à exécuter séparément) =====`, ...x.c.res.cliRaw);
        else { merged.push("", `# ===== Étape ${i + 1} · ${x.def.title} =====`, ...(x.c.res.cli || [])); if (!x.def.noCommit) needCommit = true; }
        if (x.c.push.length) push.push(`# Étape ${i + 1} · ${x.def.title}`, ...x.c.push);
        if (!x.c.res.cliRaw && x.c.res.verify && x.c.res.verify.length) verify.push(`# Étape ${i + 1} · ${x.def.title}`, ...x.c.res.verify);
        if (x.c.fwCli.length) fw.push(`# Étape ${i + 1} · ${x.def.title}`, ...x.c.fwCli);
      });
      if (needCommit) merged.push("", "commit");
      merged.push("exit");
      if (push.length) merged.push("", "# --- Push vers les pare-feux (mode opérationnel Panorama) ---", ...push);
      if (verify.length) merged.push("", "# --- Vérification (mode opérationnel) ---", ...verify);
      out.push(`######## CLI CONSOLIDÉE${isPano ? " (Panorama)" : ""} ########`, merged.join("\n"));
      if (raw.length) out.push("", "######## OPÉRATIONS SPÉCIFIQUES ########", raw.join("\n"));
      if (fw.length) out.push("", "######## CLI CÔTÉ PARE-FEU ########", ["configure", ...fw, "commit"].join("\n"));
      out.push("", "", "######## DÉTAIL ÉTAPE PAR ÉTAPE (GUI + CLI) ########");
      items.forEach((x, i) => { out.push("", `==================== ÉTAPE ${i + 1}/${items.length} — ${x.def.title} ====================`);
        out.push(x.c ? moduleText(x.def, x.v, x.c, false) : `(non générée : ${x.err})`); });
      saveFile(`${PRJ.client ? slug(PRJ.client) + "-" : ""}parcours-${s.id}.txt`, out.join("\n"));
      PAN.toast("CLI complète du parcours téléchargée ⬇");
    }

    function exportProject() {
      const data = { app: "PANW Config Builder", product: P.key, exported: new Date().toISOString(), client: PRJ.client, values: PRJ.values, done: PRJ.done, shared: PRJ.shared };
      saveFile(`projet-${slug(PRJ.client) || "client"}-${P.key}.json`, JSON.stringify(data, null, 2), "application/json");
      PAN.toast("Projet exporté (JSON) ⬇ — les mots de passe ne sont jamais enregistrés");
    }
    function importProject() {
      const inp = document.createElement("input"); inp.type = "file"; inp.accept = ".json,application/json";
      inp.onchange = () => {
        const f = inp.files[0]; if (!f) return;
        const r = new FileReader();
        r.onload = () => {
          try {
            const d = JSON.parse(r.result);
            if (!d || typeof d !== "object" || typeof d.values !== "object") throw new Error("format inattendu");
            if (d.product && d.product !== P.key && !confirm(`Ce projet a été créé pour ${d.product === "panorama" ? "Panorama" : "PAN-OS"}. L'importer quand même ?`)) return;
            PRJ = Object.assign(emptyProject(), { client: String(d.client || ""), values: d.values || {}, done: d.done || {}, shared: d.shared || {} });
            save(true); renderProject(); route(); PAN.toast(`Projet « ${PRJ.client || "sans nom"} » importé ✓`);
          } catch (e) { PAN.toast("Fichier JSON invalide : " + e.message); }
        };
        r.readAsText(f);
      };
      inp.click();
    }

    /* ---- lien de partage ---- */
    const diff = (def, v) => { const d = defaults(def, false), o = {}; def.fields.forEach(f => { if (f.type !== "password" && JSON.stringify(v[f.id]) !== JSON.stringify(d[f.id])) o[f.id] = v[f.id]; }); return o; };
    function shareLink() {
      let payload, base;
      if (state.scn) {
        payload = { c: PRJ.client || undefined, m: {} };
        state.scn._steps.forEach(id => { const def = byId[id]; payload.m[id] = diff(def, id === state.def.id ? state.values : initialValues(def, state.scn)); });
        base = `parcours=${state.scn.id}&step=${state.idx}`;
      } else if (state.def) { payload = { c: PRJ.client || undefined, m: { [state.def.id]: diff(state.def, state.values) } }; base = state.def.id; }
      else { PAN.toast("Ouvre un module ou un parcours pour le partager"); return; }
      const url = location.href.split("#")[0] + "#" + base + "&v=" + b64e(JSON.stringify(payload));
      PAN.copy(url).then(() => PAN.toast("🔗 Lien copié — il contient les valeurs saisies (sans mot de passe)"));
    }
    function applyShared(v) {
      try {
        const d = JSON.parse(b64d(v));
        if (d.c) PRJ.client = String(d.c);
        Object.keys(d.m || {}).forEach(id => { const def = byId[id]; if (!def) return;
          const base = defaults(def, false);
          def.fields.forEach(f => { if (f.id in d.m[id]) { const x = coerce(f, d.m[id][f.id]); if (x !== undefined) base[f.id] = x; } });
          PRJ.values[id] = storable(def, base);
          def.fields.forEach(f => { if (shareable(f) && f.id in d.m[id]) PRJ.shared[f.id] = base[f.id]; });
        });
        save(true); renderProject();
        setTimeout(() => PAN.toast("🔗 Valeurs du lien partagé chargées"), 300);
      } catch (e) { console.warn(e); PAN.toast("Lien de partage illisible"); }
    }

    /* ---- impression / PDF ---- */
    function reportHTML(title, items) {
      const date = new Date().toLocaleString("fr-FR");
      return `<header class="rp-h"><div class="rp-brand">PANW Config Builder · ${P.label}</div><h1>${PAN.esc(title)}</h1>
        <p>${PRJ.client ? `Client : <b>${PAN.esc(PRJ.client)}</b> · ` : ""}Généré le ${date}</p></header>
        ${items.length > 1 ? `<ol class="rp-toc">${items.map(x => `<li>${PAN.esc(x.def.title)}</li>`).join("")}</ol>` : ""}
        ${items.map((x, i) => `<section class="rp-mod">
          <h2>${items.length > 1 ? `Étape ${i + 1} · ` : ""}${PAN.esc(x.def.title)}</h2>
          ${x.def.desc ? `<p class="rp-desc">${PAN.esc(x.def.desc)}</p>` : ""}
          ${x.c ? `<h3>Paramètres</h3><table class="rp-t">${x.def.fields.filter(f => visible(f, x.v) && hasVal(x.v[f.id]) && f.type !== "password").map(f => `<tr><th>${PAN.esc(f.label)}</th><td>${PAN.esc(fmt(x.v[f.id]))}</td></tr>`).join("")}</table>
          ${(x.c.res.notes || []).map(n => `<div class="rp-note">${n.title ? `<b>${PAN.esc(n.title)}</b> ` : ""}${n.html || PAN.esc(n.text || "")}</div>`).join("")}
          <h3>Pas-à-pas WebUI</h3><ol class="rp-steps">${x.c.steps.map((s, k) => `<li><b>${PAN.esc(s.title)}</b> <span class="rp-done">${isDone(x.def.id, s, k) ? "☑" : "☐"}</span>
            <div class="rp-path">${PAN.esc((s.path || []).join(" › "))}${s.tab ? " › onglet " + PAN.esc(s.tab) : ""}</div>
            ${s.action ? `<div>${PAN.esc(s.action)}</div>` : ""}
            ${(s.fields || []).filter(([, v]) => hasVal(v)).length ? `<table class="rp-t">${s.fields.filter(([, v]) => hasVal(v)).map(([l, v]) => `<tr><th>${PAN.esc(l)}</th><td>${PAN.esc(fmt(v))}</td></tr>`).join("")}</table>` : ""}
            ${s.note ? `<div class="rp-note">${PAN.esc(s.note)}</div>` : ""}${s.warn ? `<div class="rp-note warn">⚠ ${PAN.esc(s.warn)}</div>` : ""}</li>`).join("")}</ol>
          <h3>CLI${isPano ? " (Panorama)" : ""}</h3><pre class="rp-cli">${PAN.esc(x.c.cli)}</pre>
          ${x.c.fwText ? `<h3>CLI côté pare-feu</h3><pre class="rp-cli">${PAN.esc(x.c.fwText)}</pre>` : ""}`
          : `<p class="rp-note warn">Module non généré : ${PAN.esc(x.err || "champs incomplets")}</p>`}
        </section>`).join("")}
        <footer class="rp-f">PANW Config Builder — outil non officiel. Relisez toujours la configuration avant de l'appliquer en production. Conçu par Dinèche RADJOU.</footer>`;
    }
    function printCurrent() {
      let html;
      if (state.scn) html = reportHTML("Parcours : " + state.scn.title, scenarioItems(state.scn));
      else if (state.def) {
        if (!state.last) { PAN.toast("Complète d'abord les champs obligatoires"); return; }
        html = reportHTML(state.def.title, [{ def: state.def, v: state.values, c: state.last }]);
      } else { window.print(); return; }
      let pr = document.getElementById("cfg-print");
      if (!pr) { pr = document.createElement("div"); pr.id = "cfg-print"; pr.className = "print-report"; document.body.append(pr); }
      pr.innerHTML = html;
      document.body.classList.add("printing-report");
      const done = () => { document.body.classList.remove("printing-report"); removeEventListener("afterprint", done); };
      addEventListener("afterprint", done);
      setTimeout(() => { window.print(); setTimeout(done, 1000); }, 50);
    }

    /* ---- routage ---- */
    function parseHash() {
      const o = {}; let h = location.hash.slice(1);
      try { h = decodeURIComponent(h); } catch { /* */ }
      h.split("&").forEach((p, i) => { const k = p.indexOf("="); if (k < 0) { if (i === 0 && p) o.mod = p; } else o[p.slice(0, k)] = p.slice(k + 1); });
      return o;
    }
    let lastView = "";
    function route(ev) {
      const h = parseHash();
      if (h.v) {
        applyShared(h.v);
        const clean = location.hash.replace(/&v=[^&]*/, "");
        try { history.replaceState(null, "", clean || location.pathname); } catch { /* file:// */ }
      }
      const key = h.parcours ? "s:" + h.parcours + ":" + (h.step || 0) : "m:" + (h.mod || "");
      const sameScn = !!h.parcours && lastView.startsWith("s:" + h.parcours + ":");
      lastView = key;
      const render = () => {
        if (h.parcours && scnById[h.parcours]) openScenario(h.parcours, h.step);
        else if (h.mod && byId[h.mod]) openModule(h.mod);
        else renderHome();
        const st = sameScn && document.getElementById("cfg-stepper");
        if (st) scrollTo({ top: Math.max(0, st.getBoundingClientRect().top + scrollY - 90) });
        else scrollTo({ top: 0 });
      };
      ev && ev.type === "hashchange" && PAN.transition ? PAN.transition(render) : render();
    }
    addEventListener("hashchange", route);
    route();
  }

  window.PAN = window.PAN || {};
  PAN.cfg = {
    register, category, scenario, list: reg, scenarios: scns, get: id => byId[id], getScenario: id => scnById[id],
    V, q, members, yn, MODNAMES, ORDER, modSort, mount, product, defaults, fieldErr, compute, moduleText, shareable,
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount); else setTimeout(mount, 0);
})();
