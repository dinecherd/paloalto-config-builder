/* Simulateur de règle de sécurité — assistant PAN-OS 11.0
   Vanilla JS, aucune dépendance, aucun appel réseau. Utilise window.PAN (common.js). */
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = window.PAN ? PAN.esc : s => String(s);
  const toast = m => window.PAN && PAN.toast(m);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const wait = ms => new Promise(r => setTimeout(r, reduce ? 0 : ms));

  /* ======================================================
     Données par défaut (topologie type Trust / Untrust / DMZ, VR « default »)
     ====================================================== */
  const ZONES = ["Trust", "Untrust", "DMZ"];
  const ZCLASS = { Trust: "inside", Untrust: "outside", DMZ: "dmz" };
  const ADDR = {
    "Trust-Net": { cidr: ["192.168.1.0/24"], desc: "LAN interne (ethernet1/2, zone Trust)" },
    "Admin-Net": { cidr: ["192.168.1.192/26"], desc: "Postes d'administration (zone Trust)" },
    "DMZ-Net": { cidr: ["172.16.1.0/24"], desc: "Réseau DMZ (ethernet1/3)" },
    "DMZ-Web": { cidr: ["172.16.1.10/32"], desc: "Serveur web DMZ (IP privée, post-NAT)" },
    "Web-Public-IP": { cidr: ["203.0.113.20/32"], desc: "IP publique du serveur web (pré-NAT, DNAT vers 172.16.1.10)" },
    "Public-DNS": { cidr: ["8.8.8.8/32", "1.1.1.1/32"], desc: "Résolveurs DNS publics autorisés" },
    "panw-highrisk-ip-list": { edl: true, cidr: ["198.51.100.77/32"], label: "Palo Alto Networks - High risk IP addresses" },
    "panw-known-ip-list": { edl: true, cidr: ["198.51.100.88/32"], label: "Palo Alto Networks - Known malicious IP addresses" },
  };
  const USERS = ["known-user", "unknown", "acme\\sales", "acme\\it-admins"];
  const FLOW_USERS = { unknown: { label: "aucun (unknown)", group: null }, "acme\\alice": { label: "acme\\alice (sales)", group: "acme\\sales" }, "acme\\bob": { label: "acme\\bob (it-admins)", group: "acme\\it-admins" } };
  // ports par défaut (application-default) — simplifiés d'après Applipedia
  const APPS = {
    "web-browsing": { tcp: [80], web: true }, ssl: { tcp: [443], web: true }, dns: { tcp: [53], udp: [53] },
    ping: { icmp: true }, ssh: { tcp: [22] }, "ms-rdp": { tcp: [3389], udp: [3389] },
    "facebook-base": { tcp: [80, 443], web: true }, ntp: { udp: [123] }, smtp: { tcp: [25] },
  };
  const SERVICES = { "application-default": null, any: null, "service-http": { tcp: [80, 8080] }, "service-https": { tcp: [443] } };
  const URLCATS = ["business-and-economy", "computer-and-internet-info", "social-networking", "news", "malware", "phishing"];
  const TAGS = { "Internet-Access": ["color3", "#2563EB"], "DMZ": ["color6", "#EA580C"], "Admin": ["color7", "#7C3AED"], "Block": ["color1", "#DC2626"], "Infra": ["color2", "#16A34A"] };
  const ACTIONS = { allow: "Allow", deny: "Deny", drop: "Drop", "reset-client": "Reset client", "reset-server": "Reset server", "reset-both": "Reset both client and server" };
  const ACT_HINT = {
    allow: "Autorise le trafic (action par défaut d'une nouvelle règle — pensez à la changer pour un blocage).",
    deny: "Bloque et applique l'action « deny » par défaut de l'application (voir Objects > Applications).",
    drop: "Abandonne silencieusement, sans reset TCP (option Send ICMP Unreachable possible en L3).",
    "reset-client": "Envoie un reset TCP au client (UDP : abandon).",
    "reset-server": "Envoie un reset TCP au serveur (UDP : abandon).",
    "reset-both": "Envoie un reset TCP au client et au serveur (UDP : abandon).",
  };
  const PROFILES = {
    av: { label: "Antivirus", cli: "virus", opts: ["default"] },
    as: { label: "Anti-Spyware", cli: "spyware", opts: ["default", "strict"] },
    vuln: { label: "Vulnerability Protection", cli: "vulnerability", opts: ["default", "strict"] },
    url: { label: "URL Filtering", cli: "url-filtering", opts: ["default"] },
    fb: { label: "File Blocking", cli: "file-blocking", opts: ["basic file blocking", "strict file blocking"] },
    wf: { label: "WildFire Analysis", cli: "wildfire-analysis", opts: ["default"] },
  };
  const GROUPS = ["Std-Profiles"];
  const LOGFWD = ["Log-Fwd-SIEM"];
  const TABS = [["general", "General"], ["source", "Source"], ["user", "User"], ["destination", "Destination"], ["application", "Application"], ["service", "Service/URL Category"], ["actions", "Actions"]];

  const blank = () => ({
    name: "", desc: "", tags: [], type: "universal", from: ["any"], to: ["any"], src: ["any"], user: ["any"], dst: ["any"],
    app: ["any"], svc: ["application-default"], url: ["any"], action: "allow", ptype: "none", group: GROUPS[0],
    prof: { av: "", as: "", vuln: "", url: "", fb: "", wf: "" }, logStart: false, logEnd: true, logFwd: "",
  });
  const mk = o => Object.assign(blank(), o);
  const clone = o => JSON.parse(JSON.stringify(o));

  const STD = { ptype: "group", logEnd: true, logFwd: "Log-Fwd-SIEM" };
  const PRESETS = [
    { k: "Accès Internet", sub: "Trust → Untrust, web (web-browsing, ssl) pour un groupe, application-default, Std-Profiles", rule: mk(Object.assign({ name: "Sales-to-Internet-Web", desc: "Navigation web du groupe Sales vers Internet (inclut facebook-base), profils Std-Profiles", tags: ["Internet-Access"], type: "interzone", from: ["Trust"], to: ["Untrust"], src: ["Trust-Net"], user: ["acme\\sales"], app: ["facebook-base", "ssl", "web-browsing"] }, STD)) },
    { k: "Publication DMZ", sub: "Untrust → DMZ, IP publique (pré-NAT) du serveur web, web-browsing + ssl", rule: mk(Object.assign({ name: "Publish-Web-DMZ", desc: "Publication du serveur web DMZ-Web depuis Internet (DNAT 203.0.113.20 -> 172.16.1.10)", tags: ["DMZ"], type: "interzone", from: ["Untrust"], to: ["DMZ"], dst: ["Web-Public-IP"], app: ["ssl", "web-browsing"] }, STD)) },
    { k: "Administration", sub: "Admin-Net → DMZ, ssh + ms-rdp, groupe it-admins (User-ID)", rule: mk(Object.assign({ name: "Admin-SSH-RDP-DMZ", desc: "Accès d'administration SSH/RDP aux serveurs DMZ depuis Admin-Net, groupe it-admins", tags: ["Admin"], type: "interzone", from: ["Trust"], to: ["DMZ"], src: ["Admin-Net"], user: ["acme\\it-admins"], dst: ["DMZ-Net"], app: ["ms-rdp", "ssh"] }, STD)) },
    { k: "DNS sortant", sub: "Trust + DMZ → résolveurs publics autorisés uniquement, app dns", rule: mk(Object.assign({ name: "DNS-Outbound", desc: "Résolution DNS vers les résolveurs publics autorisés (limite le tunneling DNS)", tags: ["Infra"], type: "interzone", from: ["DMZ", "Trust"], to: ["Untrust"], dst: ["Public-DNS"], app: ["dns"] }, STD)) },
    { k: "Anti-exemple", sub: "any / any / any, Service any, sans profils ni logs : à ne jamais faire", rule: mk({ name: "Allow-All", svc: ["any"], logEnd: false }) },
  ];
  const EDLS = ["panw-highrisk-ip-list", "panw-known-ip-list"];
  const seedRulebase = () => [
    mk({ name: "Block-Malicious-IPs-Out", desc: "Bloque le trafic sortant vers les IP malveillantes / à haut risque (EDL Palo Alto Networks)", tags: ["Block"], from: ["DMZ", "Trust"], to: ["Untrust"], dst: EDLS.slice(), svc: ["any"], action: "drop" }),
    mk({ name: "Block-Malicious-IPs-In", desc: "Bloque le trafic entrant depuis les IP malveillantes / à haut risque (EDL Palo Alto Networks)", tags: ["Block"], from: ["Untrust"], to: ["DMZ", "Trust"], src: EDLS.slice(), svc: ["any"], action: "drop" }),
    mk(Object.assign({ name: "LAN-to-Internet", desc: "Accès Internet standard du LAN : web, TLS, DNS, NTP, ping", tags: ["Internet-Access"], type: "interzone", from: ["Trust"], to: ["Untrust"], src: ["Trust-Net"], app: ["dns", "ntp", "ping", "ssl", "web-browsing"] }, STD)),
    mk(Object.assign({ name: "Allow-Web-DMZ", desc: "Accès des utilisateurs internes au serveur web DMZ", tags: ["DMZ"], type: "interzone", from: ["Trust"], to: ["DMZ"], src: ["Trust-Net"], dst: ["DMZ-Web"], app: ["ssl", "web-browsing"] }, STD)),
    mk({ name: "Deny-All-Log", desc: "Règle de nettoyage : refuse et journalise tout le trafic inter-zones non autorisé", tags: ["Block"], type: "interzone", svc: ["any"], action: "deny", logFwd: "Log-Fwd-SIEM" }),
  ].map(r => Object.assign(r, { uid: uid(), hits: 0 }));
  const seedDefaults = () => [
    mk({ name: "intrazone-default", type: "intrazone", action: "allow", logEnd: false, svc: ["any"], def: true, uid: uid(), hits: 0 }),
    mk({ name: "interzone-default", type: "interzone", action: "deny", logEnd: false, svc: ["any"], def: true, uid: uid(), hits: 0 }),
  ];
  let _u = 0; function uid() { return "r" + (++_u); }

  /* ======================================================
     Etat
     ====================================================== */
  let R = clone(PRESETS[0].rule);
  let RB = seedRulebase();
  let DEF = seedDefaults();
  let selected = null;
  let mineUid = null;            // règle "ma règle" insérée
  let mockTab = "general";
  let prevVals = {};
  let lastShadowKey = "";

  /* ======================================================
     Utilitaires IP / CIDR
     ====================================================== */
  const ipInt = s => s.split(".").reduce((a, o) => (a << 8) + +o, 0) >>> 0;
  const parseCidr = c => { const [a, m] = c.split("/"); const bits = m === undefined ? 32 : +m; const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0; return { net: (ipInt(a) & mask) >>> 0, mask, bits }; };
  const ipInCidr = (ip, c) => { const p = parseCidr(c); return ((ipInt(ip) & p.mask) >>> 0) === p.net; };
  const cidrIn = (inner, outer) => { const i = parseCidr(inner), o = parseCidr(outer); return i.bits >= o.bits && ((i.net & o.mask) >>> 0) === o.net; };
  const isAny = a => !a.length || a[0] === "any";
  const zoneForIp = ip => ipInCidr(ip, "192.168.1.0/24") ? "Trust" : ipInCidr(ip, "172.16.1.0/24") ? "DMZ" : "Untrust";
  const validIp = s => window.PAN ? PAN.ip.valid(s) : /^\d+\.\d+\.\d+\.\d+$/.test(s);
  const allRules = () => RB.concat(DEF);
  const byUid = id => allRules().find(r => r.uid === id);

  /* ======================================================
     Construction du formulaire
     ====================================================== */
  const MULTI = {
    tags: { el: "#c-tags", items: Object.keys(TAGS), any: false },
    from: { el: "#c-from", items: ZONES, any: true },
    src: { el: "#c-src", items: Object.keys(ADDR), any: true },
    user: { el: "#c-user", items: USERS, any: true },
    to: { el: "#c-to", items: ZONES, any: true },
    dst: { el: "#c-dst", items: Object.keys(ADDR), any: true },
    app: { el: "#c-app", items: Object.keys(APPS), any: true },
    svc: { el: "#c-svc", items: ["service-http", "service-https"], any: true, special: ["application-default"] },
    url: { el: "#c-url", items: URLCATS, any: true },
  };
  function buildChips() {
    Object.entries(MULTI).forEach(([key, m]) => {
      const box = $(m.el);
      const items = (m.special || []).concat(m.any ? ["any"] : [], m.items);
      box.innerHTML = items.map(v => {
        const a = ADDR[v];
        const cls = v === "any" ? "chip any" : "chip";
        const title = a ? (a.edl ? a.label + " (External Dynamic List prédéfinie)" : a.cidr[0] + " — " + a.desc) : "";
        return `<button type="button" class="${cls}" data-k="${key}" data-v="${esc(v)}" aria-pressed="false"${title ? ` title="${esc(title)}"` : ""}>${esc(v)}</button>`;
      }).join("");
    });
    const radios = (id, name, list) => { $(id).innerHTML = list.map(([v, l, c]) => `<label class="${c || ""}"><input type="radio" name="${name}" value="${v}"><span>${esc(l)}</span></label>`).join(""); };
    radios("#r-type", "rtype", [["universal", "universal (default)"], ["intrazone", "intrazone"], ["interzone", "interzone"]]);
    radios("#r-act", "ract", Object.keys(ACTIONS).map(a => [a, a, a === "allow" ? "a-allow" : "a-deny"]));
    radios("#r-ptype", "rptype", [["none", "None"], ["profiles", "Profiles"], ["group", "Group"]]);
    $("#f-group").innerHTML = GROUPS.map(g => `<option>${g}</option>`).join("");
    Object.entries(PROFILES).forEach(([k, p]) => { $("#p-" + k).innerHTML = `<option value="">None</option>` + p.opts.map(o => `<option>${o}</option>`).join(""); });
    $("#f-logfwd").innerHTML = `<option value="">None</option>` + LOGFWD.map(l => `<option>${l}</option>`).join("");
  }

  function syncText() { $("#f-name").value = R.name; $("#f-desc").value = R.desc; }
  function syncForm() {
    Object.keys(MULTI).forEach(key => {
      $$(`${MULTI[key].el} .chip`).forEach(b => {
        const v = b.dataset.v;
        let on = key === "svc" ? R.svc.includes(v) : (v === "any" ? isAny(R[key]) : R[key].includes(v));
        b.setAttribute("aria-pressed", String(on));
      });
    });
    const setR = (n, v) => { const i = $(`input[name="${n}"][value="${v}"]`); if (i) i.checked = true; };
    setR("rtype", R.type); setR("ract", R.action); setR("rptype", R.ptype);
    $("#f-group").value = R.group;
    Object.keys(PROFILES).forEach(k => { $("#p-" + k).value = R.prof[k]; });
    $("#f-logstart").checked = R.logStart; $("#f-logend").checked = R.logEnd; $("#f-logfwd").value = R.logFwd;
    // intrazone : la zone de destination = la zone source (grisée dans la WebUI)
    $$("#c-to .chip").forEach(b => { b.disabled = R.type === "intrazone"; });
    $("#w-group").style.display = R.ptype === "group" ? "" : "none";
    $("#w-prof").style.display = R.ptype === "profiles" ? "" : "none";
  }

  function onChip(b) {
    const key = b.dataset.k, v = b.dataset.v, m = MULTI[key];
    let arr = R[key].slice();
    if (key === "svc") {
      if (v === "application-default" || v === "any") arr = [v];
      else { arr = arr.filter(x => x !== "any" && x !== "application-default"); arr = arr.includes(v) ? arr.filter(x => x !== v) : arr.concat(v); if (!arr.length) arr = ["application-default"]; }
    } else if (v === "any") arr = ["any"];
    else {
      arr = arr.filter(x => x !== "any");
      arr = arr.includes(v) ? arr.filter(x => x !== v) : arr.concat(v);
      if (!arr.length && m.any) arr = ["any"];
    }
    R[key] = arr;
    if (R.type === "intrazone" && key === "from") R.to = R.from.slice();
    update();
  }

  function readForm(e) {
    const t = e.target;
    if (t.id === "f-name") R.name = t.value.trim();
    else if (t.id === "f-desc") R.desc = t.value;
    else if (t.name === "rtype") { R.type = t.value; if (R.type === "intrazone") R.to = R.from.slice(); }
    else if (t.name === "ract") R.action = t.value;
    else if (t.name === "rptype") R.ptype = t.value;
    else if (t.id === "f-group") R.group = t.value;
    else if (t.id && t.id.startsWith("p-")) R.prof[t.id.slice(2)] = t.value;
    else if (t.id === "f-logstart") R.logStart = t.checked;
    else if (t.id === "f-logend") R.logEnd = t.checked;
    else if (t.id === "f-logfwd") R.logFwd = t.value;
    else return;
    update(t.type === "text" || t.tagName === "TEXTAREA");
  }

  const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/;
  function nameError(n) {
    if (!n) return "Le nom est obligatoire.";
    if (!NAME_RE.test(n)) return "Commence par une lettre/un chiffre ; lettres, chiffres, espace, « _ », « - », « . » uniquement (63 car. max).";
    return "";
  }

  /* ======================================================
     Mock WebUI (Security Policy Rule)
     ====================================================== */
  function buildTabs() {
    $("#mock-tabs").innerHTML = TABS.map(([id, l]) => `<button type="button" role="tab" id="mt-${id}" data-tab="${id}" aria-selected="false">${l}</button>`).join("");
    $("#mock-tabs").addEventListener("click", e => { const b = e.target.closest("button[data-tab]"); if (b) { mockTab = b.dataset.tab; renderMock(true); } });
    $("#mock-tabs").addEventListener("keydown", e => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const i = TABS.findIndex(t => t[0] === mockTab), n = (i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length;
      mockTab = TABS[n][0]; renderMock(true); $("#mt-" + mockTab).focus();
    });
  }
  const tagPill = t => `<span class="tag-pill" style="background:${TAGS[t] ? TAGS[t][1] : "#64748B"}">${esc(t)}</span>`;
  const addrLabel = a => ADDR[a] && ADDR[a].edl ? ADDR[a].label : a;
  function vrow(label, key, html) { return `<div class="pan-row"><span>${label}</span><div class="pan-val" data-k="${key}">${html || "&nbsp;"}</div></div>`; }
  function plist(title, key, arr, opts) {
    opts = opts || {};
    const any = isAny(arr) && !opts.noAny;
    const items = any ? "" : arr.map(v => `<div class="pl-i">${esc(opts.map ? opts.map(v) : v)}</div>`).join("");
    const head = opts.select ? `<div class="pl-h">${opts.select}</div>` : `<div class="pl-h"><span class="pan-cb${any ? " on" : ""}"></span> Any</div>`;
    return `<div class="pan-sub">${title}</div><div class="pan-list" data-k="${key}">${head}<div class="pl-h" style="background:#F4F6F8">${title.toUpperCase()}</div>${items || (any ? "" : `<div class="pl-e">(vide)</div>`)}</div>`;
  }
  function mockHtml(tab) {
    const r = R;
    switch (tab) {
      case "general": return vrow("Name", "name", esc(r.name) || '<span style="color:#9AA5B1">(obligatoire)</span>') +
        vrow("Rule Type", "type", esc(r.type) + (r.type === "universal" ? " (default)" : "")) +
        vrow("Description", "desc", esc(r.desc)) +
        vrow("Tags", "tags", r.tags.map(tagPill).join("")) +
        vrow("Group Rules By Tag", "grp", "None") +
        vrow("Audit Comment", "audit", '<span style="color:#9AA5B1">(optionnel : qui, quoi, pourquoi)</span>') +
        `<p class="pan-hint">L'onglet Usage apparaît une fois la règle créée (hit count, apps vues, dates).</p>`;
      case "source": return plist("Source Zone", "from", r.from) + plist("Source Address", "src", r.src, { map: addrLabel }) +
        `<p class="pan-hint">☐ Negate (non coché) · Source Device : any</p>`;
      case "user": return plist("Source User", "user", r.user, { select: "<b>" + (isAny(r.user) ? "any" : "select") + "</b> ▾" }) +
        `<div class="pan-sub">Source HIP Profile</div><div class="pan-val">any</div>`;
      case "destination": {
        const to = r.type === "intrazone" ? r.from : r.to;
        return plist("Destination Zone", "to", to, { select: r.type === "intrazone" ? '<span class="pan-cb dis"></span> <i>désactivé : intrazone = zone source</i>' : `<b>${isAny(to) ? "any" : "select"}</b> ▾` }) +
          plist("Destination Address", "dst", r.dst, { map: addrLabel }) + `<p class="pan-hint">☐ Negate · Destination Device : any</p>`;
      }
      case "application": return plist("Applications", "app", r.app) +
        `<p class="pan-hint">${isAny(r.app) ? "Any coché : toutes les applications (App-ID ne filtre rien)." : "Value · Dependencies : vérifiées au commit."}</p>`;
      case "service": return plist("Service", "svc", r.svc, { noAny: true, select: `<b>${esc(r.svc.length > 1 || !["application-default", "any"].includes(r.svc[0]) ? "select" : r.svc[0])}</b> ▾` }) +
        plist("URL Category", "url", r.url);
      case "actions": {
        let prof = vrow("Profile Type", "ptype", { none: "None", profiles: "Profiles", group: "Group" }[r.ptype]);
        if (r.ptype === "group") prof += vrow("Group Profile", "group", esc(r.group));
        if (r.ptype === "profiles") prof += Object.entries(PROFILES).map(([k, p]) => vrow(p.label, "prof-" + k, esc(r.prof[k] || "None"))).join("");
        const cb = (on, l, k, dis) => `<div class="pan-row"><span>${l}</span><div class="pan-val" data-k="${k}" style="font-family:inherit"><span class="pan-cb${on ? " on" : ""}${dis ? " dis" : ""}"></span></div></div>`;
        return `<div class="pan-sub">Action Setting</div>` + vrow("Action", "action", esc(ACTIONS[r.action])) +
          cb(false, "Send ICMP Unreachable", "icmp", !["drop", "reset-client", "reset-server", "reset-both"].includes(r.action)) +
          `<div class="pan-sub">Profile Setting</div>` + prof +
          `<div class="pan-sub">Log Setting</div>` + cb(r.logStart, "Log at Session Start", "ls") + cb(r.logEnd, "Log at Session End", "le") +
          vrow("Log Forwarding", "lf", esc(r.logFwd || "None")) +
          `<div class="pan-sub">Other Settings</div>` + vrow("Schedule", "sch", "None") + vrow("QoS Marking", "qos", "None") + cb(false, "Disable Server Response Inspection", "dsri");
      }
    }
    return "";
  }
  function renderMock(tabOnly) {
    $$("#mock-tabs button").forEach(b => { const on = b.dataset.tab === mockTab; b.classList.toggle("on", on); b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
    const body = $("#mock-body");
    body.setAttribute("aria-labelledby", "mt-" + mockTab);
    body.innerHTML = mockHtml(mockTab);
    $("#mock-sub").textContent = R.name ? "— " + R.name : "— nouvelle règle";
    // surlignage des valeurs modifiées
    const cur = {};
    $$("[data-k]", body).forEach(el => { cur[el.dataset.k] = el.textContent; });
    if (!tabOnly) $$("[data-k]", body).forEach(el => {
      const k = el.dataset.k;
      if (prevVals[mockTab + k] !== undefined && prevVals[mockTab + k] !== cur[k]) { el.classList.add("hl"); if (el.classList.contains("pan-list")) { const last = el.querySelector(".pl-i:last-child"); if (last) last.classList.add("new"); } }
    });
    Object.keys(cur).forEach(k => { prevVals[mockTab + k] = cur[k]; });
  }
  // mémorise l'état de tous les onglets (pour ne surligner que ce qui change)
  function snapshotAll() { const keep = mockTab; TABS.forEach(([t]) => { mockTab = t; const d = document.createElement("div"); d.innerHTML = mockHtml(t); $$("[data-k]", d).forEach(el => { prevVals[t + el.dataset.k] = el.textContent; }); }); mockTab = keep; }

  /* ======================================================
     Score bonnes pratiques
     ====================================================== */
  function evaluate(r) {
    const L = []; // {s:'ok'|'warn'|'bad'|'info', t, d, p, max}
    const add = (s, t, d, p, max) => L.push({ s, t, d, p, max });
    const allow = r.action === "allow";
    const ne = nameError(r.name);
    if (ne) add("bad", "Nom de règle", ne, 0, 8);
    else if (/^(rule|r[eè]gle|test|new|copy|policy|regle)[\s_-]*\d*$/i.test(r.name)) add("warn", "Nom trop générique", "Un nom explicite décrit le flux (ex. LAN-to-Internet).", 3, 8);
    else add("ok", "Nom explicite", "« " + r.name + " »", 8, 8);
    const dl = r.desc.trim().length;
    add(dl >= 12 ? "ok" : dl ? "warn" : "warn", "Description", dl >= 12 ? "Présente : la règle se comprend sans l'ouvrir." : dl ? "Trop courte : précisez qui, quoi, pourquoi." : "Optionnelle mais fortement recommandée (audit, revue de règles).", dl >= 12 ? 7 : dl ? 3 : 0, 7);
    add(r.tags.length ? "ok" : "warn", "Tags", r.tags.length ? "Filtrage et groupage visuel (Tag-Based Rule Groups)." : "Ajoutez un tag pour filtrer/grouper la rulebase.", r.tags.length ? 5 : 0, 5);
    const fz = !isAny(r.from), tz = r.type === "intrazone" ? fz : !isAny(r.to);
    add(fz ? "ok" : "bad", "Source Zone précise", fz ? r.from.join(", ") : "Zone source « any » : la règle s'applique à toutes les zones.", fz ? 8 : 0, 8);
    add(tz ? "ok" : "bad", "Destination Zone précise", tz ? (r.type === "intrazone" ? "intrazone : " + r.from.join(", ") : r.to.join(", ")) : "Zone destination « any ».", tz ? 8 : 0, 8);
    const sa = !isAny(r.src), da = !isAny(r.dst);
    add(sa || da ? "ok" : "warn", "Adresses : pas de any/any", sa || da ? "Source et/ou destination restreintes par des objets." : "Restreignez la source (sous-réseau) ou la destination (serveurs précis, surtout DNS/SMTP).", sa || da ? 7 : 3, 7);
    add(isAny(r.user) ? "warn" : "ok", "User-ID", isAny(r.user) ? "Source User any : si User-ID est déployé, ciblez des groupes." : "Règle basée sur l'utilisateur : " + r.user.join(", "), isAny(r.user) ? 2 : 5, 5);
    if (isAny(r.app)) add(allow ? "bad" : "ok", "App-ID au lieu de « any »", allow ? "Application any : listez les applications réellement nécessaires (règles basées App-ID, pas port)." : "Acceptable pour un blocage (on bloque tout le trafic visé).", allow ? 0 : 15, 15);
    else add("ok", "App-ID précis", r.app.join(", "), 15, 15);
    const svc = r.svc[0];
    if (allow) {
      if (svc === "application-default") add("ok", "Service application-default", "Chaque application n'est autorisée que sur ses ports standard.", 12, 12);
      else if (svc === "any") add("bad", "Service any", "L'application est autorisée sur n'importe quel port (évasion, ex. SSH sur 80). Utilisez application-default.", 0, 12);
      else if (isAny(r.app)) add("bad", "Règle basée port", "Application any + " + r.svc.join(", ") + " : c'est une règle de firewall classique. Préférez App-ID + application-default.", 3, 12);
      else add("warn", "Service explicite", r.svc.join(", ") + " : acceptable seulement si plus restrictif que les ports standard de l'application.", 8, 12);
    } else {
      if (svc === "any") add("ok", "Service any sur un blocage", "Le blocage s'applique quel que soit le port.", 12, 12);
      else add("warn", "Service sur un blocage", "Avec " + r.svc.join(", ") + ", le trafic sur d'autres ports échappe au blocage.", 8, 12);
    }
    if (allow) {
      if (r.ptype === "group") add("ok", "Security Profile Group", r.group + " : inspection Content-ID (AV, spyware, vuln, URL, fichiers, WildFire).", 15, 15);
      else if (r.ptype === "profiles") {
        const n = Object.values(r.prof).filter(Boolean).length;
        add(n === 6 ? "ok" : n ? "warn" : "bad", "Security Profiles", n === 6 ? "Les 6 profils sont attachés." : n + "/6 profils attachés (AV default, Anti-Spyware strict, Vuln strict, URL default, File Blocking, WildFire default).", Math.round(15 * n / 6), 15);
      } else add("bad", "Aucun Security Profile", "Une règle allow sans profil laisse passer malwares et exploits. Attachez un Profile Group.", 0, 15);
    } else add("ok", "Profils non requis", "Pas d'inspection Content-ID sur du trafic bloqué.", 15, 15);
    add(r.logEnd ? "ok" : "bad", "Log at Session End", r.logEnd ? "Activé : visible dans Monitor > Logs > Traffic." : "Désactivé : aucune trace dans le Traffic log (vous serez aveugle en dépannage).", r.logEnd ? 8 : 0, 8);
    add(r.logStart ? "warn" : "ok", "Log at Session Start", r.logStart ? "Consomme plus de ressources : à réserver au dépannage / sessions longues (GRE, OT)." : "Désactivé (recommandé hors dépannage).", r.logStart ? 0 : 2, 2);
    // informations sans points
    add(r.logFwd ? "ok" : "info", "Log Forwarding", r.logFwd ? "Logs transférés (" + r.logFwd + ") vers SIEM/Panorama." : "Optionnel : un profil de Log Forwarding centralise les logs.", 0, 0);
    if (!isAny(r.url) && !isAny(r.app) && !r.app.some(a => APPS[a] && APPS[a].web)) add("warn", "URL Category inutile", "Une URL Category ne matche que le trafic web : aucune app web dans la règle.", 0, 0);
    if (r.type === "interzone" && !isAny(r.from) && r.from.length === 1 && r.to.length === 1 && r.from[0] === r.to[0]) add("warn", "Rule Type incohérent", "interzone avec la même zone source et destination ne matchera jamais.", 0, 0);
    if (r.app.includes("facebook-base")) add("info", "Dépendances applicatives", "Le commit signale les dépendances non résolues (Unresolved Dependencies) : vérifiez-les.", 0, 0);
    let score = L.reduce((a, x) => a + x.p, 0);
    const allowAll = allow && isAny(r.from) && isAny(r.to) && isAny(r.app) && (svc === "any" || svc === "application-default") && !sa && !da;
    if (allowAll) { score = Math.min(score, 15); L.unshift({ s: "bad", t: "Règle « allow any any »", d: "Tout est autorisé : score plafonné à 15. C'est l'inverse du principe du moindre privilège.", p: 0, max: 0 }); }
    return { score: Math.max(0, Math.min(100, score)), list: L };
  }
  function rulebaseChecks() {
    const L = [];
    const last = RB.filter(r => !r.disabled).slice(-1)[0];
    const cleanup = last && last.action !== "allow" && isAny(last.from) && isAny(last.to) && isAny(last.src) && isAny(last.dst) && isAny(last.app);
    const iz = DEF[1];
    if (cleanup && last.logEnd) L.push({ s: "ok", t: "Rulebase : deny explicite en bas", d: "« " + last.name + " » journalise le trafic refusé." });
    else if (iz.logEnd) L.push({ s: "ok", t: "Rulebase : trafic refusé journalisé", d: "interzone-default en Override avec Log at Session End " });
    else L.push({ s: "warn", t: "Rulebase : trafic refusé invisible", d: "Ajoutez une règle deny explicite avec log en bas, ou Override interzone-default + Log at Session End." });
    const mine = mineUid && byUid(mineUid);
    if (mine) {
      const sh = shadows().find(s => s.r.uid === mine.uid);
      L.push(sh ? { s: "bad", t: "Ma règle est masquée (shadow)", d: "« " + sh.by.name + " » au-dessus la couvre entièrement." } : { s: "ok", t: "Ma règle n'est pas masquée", d: "Position " + (RB.indexOf(mine) + 1) + " dans la rulebase." });
    }
    return L;
  }

  let shownScore = 0, scoreRaf = 0;
  function renderScore() {
    const { score, list } = evaluate(R);
    const all = list.concat(rulebaseChecks());
    const C = 326.73, arc = $("#g-arc");
    arc.style.strokeDashoffset = String(C * (1 - score / 100));
    arc.setAttribute("stroke", score >= 80 ? "#22C55E" : score >= 50 ? "#F59E0B" : "#EF4444");
    const g = $("#gauge");
    g.setAttribute("aria-label", "Score bonnes pratiques : " + score + " sur 100");
    if (score !== shownScore) { g.classList.remove("bump"); void g.offsetWidth; g.classList.add("bump"); }
    cancelAnimationFrame(scoreRaf);
    const from = shownScore, t0 = performance.now(), dur = reduce ? 1 : 700;
    const step = t => { const k = Math.min(1, (t - t0) / dur), v = Math.round(from + (score - from) * (1 - Math.pow(1 - k, 3))); $("#g-num").textContent = v; if (k < 1) scoreRaf = requestAnimationFrame(step); };
    scoreRaf = requestAnimationFrame(step); shownScore = score;
    $("#g-grade").textContent = score >= 90 ? "Excellente règle" : score >= 75 ? "Bonne règle, à peaufiner" : score >= 50 ? "Correcte mais risquée" : "Règle à risque";
    $("#g-grade").style.color = score >= 80 ? "#86EFAC" : score >= 50 ? "#FCD34D" : "#FCA5A5";
    const nb = s => all.filter(x => x.s === s).length;
    $("#g-sum").textContent = `${nb("ok")} ✓ · ${nb("warn")} ⚠ · ${nb("bad")} ✗ — best practices PAN-OS 11.0.`;
    const icon = { ok: "✓", warn: "!", bad: "✕", info: "i" }, sr = { ok: "conforme", warn: "à améliorer", bad: "problème", info: "information" };
    const order = { bad: 0, warn: 1, info: 2, ok: 3 };
    $("#recos").innerHTML = all.slice().sort((a, b) => order[a.s] - order[b.s]).map((x, i) =>
      `<li class="${x.s}" style="animation-delay:${reduce ? 0 : i * 25}ms"><i aria-hidden="true">${icon[x.s]}</i><span><span class="sr-only">${sr[x.s]} : </span><b>${esc(x.t)}</b><small>${esc(x.d)}</small></span>${x.max ? `<em>${x.p}/${x.max}</em>` : ""}</li>`).join("");
  }

  /* ======================================================
     Matching (test de flux) et shadowing
     ====================================================== */
  function matchRule(r, f) {
    if (r.disabled) return { ok: false, why: "règle désactivée (ignorée)" };
    const intra = f.from === f.to;
    if (r.type === "intrazone" && !intra) return { ok: false, why: "Rule Type intrazone : zones source et destination différentes" };
    if (r.type === "interzone" && intra) return { ok: false, why: "Rule Type interzone : même zone source et destination" };
    if (!isAny(r.from) && !r.from.includes(f.from)) return { ok: false, why: `Source Zone ${f.from} ∉ [${r.from.join(", ")}]` };
    const to = r.type === "intrazone" ? r.from : r.to;
    if (!isAny(to) && !to.includes(f.to)) return { ok: false, why: `Destination Zone ${f.to} ∉ [${to.join(", ")}]` };
    const inAddr = (list, ip) => isAny(list) || list.some(a => ADDR[a] && ADDR[a].cidr.some(c => ipInCidr(ip, c)));
    if (!inAddr(r.src, f.src)) return { ok: false, why: `Source ${f.src} hors de [${r.src.join(", ")}]` };
    if (!isAny(r.user)) {
      const u = FLOW_USERS[f.user] || FLOW_USERS.unknown;
      const okU = r.user.some(x => x === "known-user" ? !!u.group : x === "unknown" ? !u.group : x === u.group);
      if (!okU) return { ok: false, why: `Source User ${f.user} ne correspond pas à [${r.user.join(", ")}]` };
    }
    if (!inAddr(r.dst, f.dst)) return { ok: false, why: `Destination ${f.dst} hors de [${r.dst.join(", ")}]` };
    if (!isAny(r.app) && !r.app.includes(f.app)) return { ok: false, why: `Application ${f.app} ∉ [${r.app.join(", ")}]` };
    const proto = f.proto === "6" ? "tcp" : f.proto === "17" ? "udp" : "icmp";
    const svc = r.svc[0];
    if (svc === "application-default") {
      const a = APPS[f.app] || {};
      const ok = proto === "icmp" ? !!a.icmp : (a[proto] || []).includes(+f.port);
      if (!ok) return { ok: false, why: `application-default : ${f.app} n'utilise pas ${proto}/${proto === "icmp" ? "-" : f.port} par défaut` };
    } else if (svc !== "any") {
      const ok = proto !== "icmp" && r.svc.some(s => SERVICES[s] && (SERVICES[s][proto] || []).includes(+f.port));
      if (!ok) return { ok: false, why: `Service ${r.svc.join(", ")} ne couvre pas ${proto}/${f.port || "-"}` };
    }
    if (!isAny(r.url)) {
      if (!(APPS[f.app] && APPS[f.app].web) || f.url === "none" || !r.url.includes(f.url)) return { ok: false, why: `URL Category [${r.url.join(", ")}] : non correspondante` };
    }
    return { ok: true, why: "toutes les conditions correspondent" };
  }

  const coverSet = (S, X) => isAny(S) || (!isAny(X) && X.every(x => S.includes(x)));
  const coverAddr = (S, X) => isAny(S) || (!isAny(X) && X.every(x => ADDR[x].cidr.every(c => S.some(s => ADDR[s].cidr.some(o => cidrIn(c, o))))));
  const coverUser = (S, X) => isAny(S) || (!isAny(X) && X.every(x => S.includes(x) || (S.includes("known-user") && x !== "unknown")));
  const toZ = r => r.type === "intrazone" ? r.from : r.to;
  function covers(S, X) {
    if (S.type !== "universal" && S.type !== X.type) return false;
    if (!coverSet(S.from, X.from) || !coverSet(toZ(S), toZ(X))) return false;
    if (!coverAddr(S.src, X.src) || !coverAddr(S.dst, X.dst) || !coverUser(S.user, X.user)) return false;
    if (!coverSet(S.app, X.app) || !coverSet(S.url, X.url)) return false;
    const ss = S.svc[0], xs = X.svc[0];
    if (ss === "any") return true;
    if (ss === "application-default") return xs === "application-default";
    return xs !== "any" && xs !== "application-default" && X.svc.every(x => S.svc.includes(x));
  }
  function shadows() {
    const out = [];
    RB.forEach((r, i) => {
      if (r.disabled) return;
      for (let j = 0; j < i; j++) { const s = RB[j]; if (!s.disabled && covers(s, r)) { out.push({ r, by: s, i, j }); break; } }
    });
    return out;
  }

  /* ======================================================
     Rulebase (table)
     ====================================================== */
  const cell = (arr, map) => isAny(arr) ? "any" : `<span class="cell-list">${arr.map(v => esc(map ? map(v) : v)).join("<br>")}</span>`;
  const zoneCell = arr => isAny(arr) ? "any" : `<span class="cell-list">${arr.map(z => `<span class="zone ${ZCLASS[z] || ""}" style="font-size:10.5px;padding:1px 6px">${esc(z)}</span>`).join("<br>")}</span>`;
  const actCls = a => a === "allow" ? "allow" : a.startsWith("reset") ? "reset" : a;
  function renderRulebase(anim) {
    const tb = $("#rb-body");
    const before = {};
    if (anim && anim.flip && !reduce) $$("tr", tb).forEach(tr => { before[tr.dataset.uid] = tr.getBoundingClientRect().top; });
    const sh = shadows(), shMap = {}; sh.forEach(s => { shMap[s.r.uid] = s; });
    const rows = allRules();
    tb.innerHTML = rows.map((r, i) => {
      const cls = [r.def ? "def" : "", r.disabled ? "dis" : "", r.uid === mineUid ? "mine" : "", shMap[r.uid] ? "shadowed" : ""].join(" ");
      const prof = r.def ? "" : r.ptype === "group" ? `<span class="ico-s on" title="Group ${esc(r.group)}">🛡</span>` : r.ptype === "profiles" && Object.values(r.prof).some(Boolean) ? `<span class="ico-s on" title="Profiles">🛡</span>` : r.action === "allow" ? `<span class="ico-s" title="Aucun profil">—</span>` : "";
      const opts = (r.logStart ? `<span class="ico-s on" title="Log at Session Start">S</span>` : "") + (r.logEnd ? `<span class="ico-s on" title="Log at Session End">E</span>` : `<span class="ico-s" title="Pas de log">∅</span>`) + (shMap[r.uid] ? `<span class="ico-s warn" title="Masquée par ${esc(shMap[r.uid].by.name)}">!</span>` : "") + (r.def && r.overridden ? `<span class="ico-s on" title="Overridden">O</span>` : "");
      return `<tr data-uid="${r.uid}" class="${cls}" tabindex="0" aria-selected="${r.uid === selected}">
        <td>${i + 1}</td><td class="nm">${esc(r.name)}</td><td>${r.tags.map(tagPill).join("") || "none"}</td><td>${esc(r.type)}</td>
        <td>${zoneCell(r.from)}</td><td>${cell(r.src, addrLabel)}</td><td>${cell(r.user)}</td><td>${zoneCell(r.type === "intrazone" ? (isAny(r.from) ? ["any"] : r.from) : r.to)}${r.type === "intrazone" ? '<br><i style="font-size:10px">(intrazone)</i>' : ""}</td>
        <td>${cell(r.dst, addrLabel)}</td><td>${cell(r.app)}</td><td>${cell(r.svc)}</td><td>${cell(r.url)}</td>
        <td><span class="act ${actCls(r.action)}">${esc(ACTIONS[r.action].replace(" client and server", ""))}</span></td><td>${prof || "none"}</td><td>${opts}</td><td>${r.hits}</td></tr>`;
    }).join("");
    if (anim && anim.flip && !reduce) $$("tr", tb).forEach(tr => {
      const b = before[tr.dataset.uid]; if (b === undefined) return;
      const d = b - tr.getBoundingClientRect().top;
      if (d && tr.animate) tr.animate([{ transform: `translateY(${d}px)`, background: "#FFE7DB" }, { transform: "none", background: "transparent" }], { duration: 550, easing: "cubic-bezier(.2,.8,.2,1)" });
    });
    if (anim && anim.inserted) { const tr = $(`tr[data-uid="${anim.inserted}"]`, tb); if (tr) tr.classList.add("row-in"); }
    if (anim && anim.flash) { const tr = $(`tr[data-uid="${anim.flash}"]`, tb); if (tr) tr.classList.add("flash"); }
    renderShadowAlert(sh);
    renderTools();
    $("#po-sum").textContent = `${RB.length} règles · ${sh.length} masquée(s) · ${RB.filter(r => r.hits === 0).length} sans hit`;
  }
  function renderShadowAlert(sh) {
    const box = $("#rb-alert");
    const key = sh.map(s => s.r.uid + ">" + s.by.uid).join("|");
    if (!sh.length) { box.classList.remove("show"); box.innerHTML = ""; lastShadowKey = ""; return; }
    box.innerHTML = sh.map(s => `<div class="callout bad"><b>⚠ Rule Shadow — « ${esc(s.r.name)} » (ligne ${s.i + 1}) est masquée par « ${esc(s.by.name)} » (ligne ${s.j + 1})</b>
      Tout le trafic de « ${esc(s.r.name)} » correspond d'abord à « ${esc(s.by.name)} »${s.r.action !== s.by.action ? ` dont l'action est différente (<b>${esc(s.by.action)}</b> au lieu de <b>${esc(s.r.action)}</b>)` : ""} : elle ne sera jamais atteinte (hit count à 0).
      <div class="row" style="margin-top:8px"><button type="button" class="btn sm" data-fix="${s.r.uid}" data-above="${s.by.uid}">Placer « ${esc(s.r.name)} » au-dessus de « ${esc(s.by.name)} »</button></div></div>`).join("");
    if (key !== lastShadowKey) { box.classList.remove("show"); void box.offsetWidth; }
    box.classList.add("show");
    lastShadowKey = key;
  }
  function renderTools() {
    const r = selected && byUid(selected);
    const custom = r && !r.def, i = custom ? RB.indexOf(r) : -1;
    $("#t-edit").disabled = !custom; $("#t-del").disabled = !custom;
    $("#t-top").disabled = $("#t-up").disabled = !custom || i === 0;
    $("#t-bottom").disabled = $("#t-down").disabled = !custom || i === RB.length - 1;
    $("#t-toggle").disabled = !custom; $("#t-toggle").textContent = custom && r.disabled ? "Enable" : "Disable";
    $("#t-override").disabled = !(r && r.def);
    $("#t-override").textContent = r && r.def && r.overridden ? "Revert" : "Override";
    $("#t-reset").disabled = !r;
    $("#rb-sel").textContent = r ? `Sélection : ${r.name}${r.def ? " (règle par défaut : seul Override est possible)" : ""}` : "Cliquez sur une ligne pour la sélectionner (clavier : Tab puis Entrée).";
  }
  function addMine() {
    const ne = nameError(R.name);
    if (ne) { $("#name-err").textContent = ne; $("#f-name").classList.add("invalid"); $("#f-name").focus(); toast("Nom invalide : la règle n'a pas été ajoutée"); return; }
    const exist = allRules().find(x => x.name.toLowerCase() === R.name.toLowerCase());
    if (exist && (exist.def || exist.uid !== mineUid)) { toast("Le nom « " + R.name + " » existe déjà : il doit être unique"); $("#f-name").focus(); return; }
    let ins;
    if (exist) { const i = RB.indexOf(exist); ins = Object.assign(clone(R), { uid: exist.uid, hits: exist.hits }); RB[i] = ins; toast("Règle « " + R.name + " » mise à jour ✓"); }
    else {
      ins = Object.assign(clone(R), { uid: uid(), hits: 0 });
      const sel = selected && byUid(selected);
      const lastR = RB[RB.length - 1];
      const cleanup = lastR && lastR.action !== "allow" && isAny(lastR.from) && isAny(lastR.to) && isAny(lastR.src) && isAny(lastR.dst) && isAny(lastR.app);
      const at = sel && !sel.def ? RB.indexOf(sel) + 1 : cleanup ? RB.length - 1 : RB.length;
      RB.splice(at, 0, ins); mineUid = ins.uid;
      toast("Règle « " + R.name + " » ajoutée en position " + (at + 1));
    }
    selected = ins.uid;
    afterRulebaseChange({ inserted: ins.uid });
    $("#rulebase").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  }
  function move(how) {
    const r = byUid(selected); if (!r || r.def) return;
    const i = RB.indexOf(r); RB.splice(i, 1);
    const n = how === "top" ? 0 : how === "up" ? Math.max(0, i - 1) : how === "down" ? Math.min(RB.length, i + 1) : RB.length;
    RB.splice(n, 0, r);
    afterRulebaseChange({ flip: true });
  }
  function afterRulebaseChange(anim) { renderRulebase(anim); renderLane(); renderScore(); renderCli(); }

  function bindRulebase() {
    const tb = $("#rb-body");
    const pick = tr => { selected = selected === tr.dataset.uid ? null : tr.dataset.uid; $$("tr", tb).forEach(x => x.setAttribute("aria-selected", String(x.dataset.uid === selected))); renderTools(); };
    tb.addEventListener("click", e => { const tr = e.target.closest("tr"); if (tr) pick(tr); });
    tb.addEventListener("keydown", e => {
      const tr = e.target.closest("tr"); if (!tr) return;
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(tr); }
      else if (e.key === "ArrowDown" && tr.nextElementSibling) { e.preventDefault(); tr.nextElementSibling.focus(); }
      else if (e.key === "ArrowUp" && tr.previousElementSibling) { e.preventDefault(); tr.previousElementSibling.focus(); }
    });
    $("#t-add").addEventListener("click", addMine);
    $("#t-edit").addEventListener("click", () => {
      const r = byUid(selected); if (!r || r.def) return;
      R = clone(r); delete R.uid; delete R.hits; delete R.disabled;
      mineUid = r.uid; prevVals = {}; snapshotAll(); syncText(); update();
      toast("« " + r.name + " » chargée dans le constructeur");
      $("#builder").scrollIntoView({ behavior: reduce ? "auto" : "smooth" });
    });
    $("#t-del").addEventListener("click", () => {
      const r = byUid(selected); if (!r || r.def) return;
      RB.splice(RB.indexOf(r), 1); if (r.uid === mineUid) mineUid = null; selected = null;
      toast("Règle « " + r.name + " » supprimée"); afterRulebaseChange();
    });
    [["#t-top", "top"], ["#t-up", "up"], ["#t-down", "down"], ["#t-bottom", "bottom"]].forEach(([id, h]) => $(id).addEventListener("click", () => move(h)));
    $("#t-toggle").addEventListener("click", () => { const r = byUid(selected); if (!r || r.def) return; r.disabled = !r.disabled; toast(r.name + (r.disabled ? " désactivée (italique)" : " réactivée")); afterRulebaseChange(); });
    $("#t-override").addEventListener("click", () => {
      const r = byUid(selected); if (!r || !r.def) return;
      r.overridden = !r.overridden; r.logEnd = r.overridden;
      toast(r.overridden ? r.name + " : Override → Log at Session End activé" : r.name + " : Revert → valeurs par défaut (pas de log)");
      afterRulebaseChange({ flash: r.uid });
    });
    $("#t-reset").addEventListener("click", () => { const r = byUid(selected); if (!r) return; r.hits = 0; toast("Hit count remis à 0 : " + r.name); renderRulebase(); });
    $("#t-restore").addEventListener("click", () => { RB = seedRulebase(); DEF = seedDefaults(); mineUid = null; selected = null; toast("Rulebase initiale restaurée"); afterRulebaseChange(); });
    $("#rb-alert").addEventListener("click", e => {
      const b = e.target.closest("[data-fix]"); if (!b) return;
      const r = byUid(b.dataset.fix), above = byUid(b.dataset.above);
      RB.splice(RB.indexOf(r), 1); RB.splice(RB.indexOf(above), 0, r); selected = r.uid;
      toast("« " + r.name + " » déplacée au-dessus de « " + above.name + " »"); afterRulebaseChange({ flip: true });
    });
    $("#btn-commit").addEventListener("click", commit);
    $("#cli-commit").addEventListener("click", () => { $("#rulebase").scrollIntoView({ behavior: reduce ? "auto" : "smooth" }); commit(); });
    $("#commit-close").addEventListener("click", () => $("#commit-box").classList.remove("show"));
  }

  let committing = false;
  async function commit() {
    if (committing) return; committing = true;
    const box = $("#commit-box"), body = $("#commit-body");
    box.classList.add("show");
    body.innerHTML = `<div class="pan-row"><span>Operation</span><div class="pan-val">Commit</div></div><div class="pan-row"><span>Status</span><div class="pan-val" id="c-st">Active</div></div><div class="cbar"><i id="c-bar"></i></div>`;
    await wait(30); $("#c-bar").style.width = "100%";
    await wait(1450);
    const sh = shadows();
    const warn = sh.length;
    body.innerHTML = `<div class="pan-tabs small" role="tablist"><button type="button" class="on" aria-selected="true">General</button><button type="button" aria-selected="false" disabled>Rule Shadow${warn ? " (" + warn + ")" : ""}</button></div>
      <div class="pan-row"><span>Operation</span><div class="pan-val">Commit</div></div>
      <div class="pan-row"><span>Status</span><div class="pan-val">Completed</div></div>
      <div class="pan-row"><span>Result</span><div class="pan-val" style="color:#15803D;font-weight:700">Successful${warn ? " (with warnings)" : ""}</div></div>
      <div class="pan-sub">Rule Shadow</div>
      ${warn ? `<table><thead><tr><th>Rule</th><th>Shadowed by</th></tr></thead><tbody>${sh.map(s => `<tr><td>${esc(s.r.name)}</td><td>${esc(s.by.name)}</td></tr>`).join("")}</tbody></table>
      <p class="pan-hint">Le commit réussit malgré le shadowing : c'est un avertissement, à corriger en réordonnant ou en affinant les règles.</p>` : `<p class="pan-hint">Aucune règle masquée détectée.</p>`}`;
    toast(warn ? "Commit réussi avec " + warn + " avertissement(s) Rule Shadow" : "Commit réussi ✓");
    committing = false;
  }

  /* ======================================================
     Testeur de flux
     ====================================================== */
  const FLOWS = [
    { l: "LAN → web Internet (443)", f: { src: "192.168.1.50", dst: "93.184.216.34", app: "ssl", proto: "6", port: "443" } },
    { l: "LAN → DNS 8.8.8.8", f: { src: "192.168.1.50", dst: "8.8.8.8", app: "dns", proto: "17", port: "53" } },
    { l: "LAN → ping Internet", f: { src: "192.168.1.50", dst: "8.8.8.8", app: "ping", proto: "1", port: "" } },
    { l: "SSH sur port 80 (évasion)", f: { src: "192.168.1.50", dst: "203.0.113.99", app: "ssh", proto: "6", port: "80" } },
    { l: "Facebook (alice, sales)", f: { src: "192.168.1.50", dst: "157.240.1.35", app: "facebook-base", proto: "6", port: "443", user: "acme\\alice", url: "social-networking" } },
    { l: "LAN → IP malveillante", f: { src: "192.168.1.50", dst: "198.51.100.88", app: "ssl", proto: "6", port: "443" } },
    { l: "LAN → web DMZ", f: { src: "192.168.1.50", dst: "172.16.1.10", app: "web-browsing", proto: "6", port: "80" } },
    { l: "Admin RDP → DMZ (bob)", f: { src: "192.168.1.200", dst: "172.16.1.10", app: "ms-rdp", proto: "6", port: "3389", user: "acme\\bob" } },
    { l: "Internet → RDP LAN", f: { src: "198.51.100.200", dst: "192.168.1.50", app: "ms-rdp", proto: "6", port: "3389" } },
    { l: "Intrazone Trust", f: { src: "192.168.1.50", dst: "192.168.1.60", app: "ssh", proto: "6", port: "22" } },
    { l: "Internet → web publié (DNAT)", f: { src: "198.51.100.200", dst: "203.0.113.20", to: "DMZ", app: "web-browsing", proto: "6", port: "80" } },
  ];
  function buildTester() {
    const zo = ZONES.map(z => `<option>${z}</option>`).join("");
    $("#t-from").innerHTML = zo; $("#t-to").innerHTML = zo;
    $("#t-app").innerHTML = Object.keys(APPS).map(a => `<option>${a}</option>`).join("");
    $("#t-user").innerHTML = Object.entries(FLOW_USERS).map(([k, u]) => `<option value="${esc(k)}">${esc(u.label)}</option>`).join("");
    $("#t-url").innerHTML = `<option value="none">(aucune / non web)</option>` + URLCATS.map(c => `<option>${c}</option>`).join("");
    $("#flow-presets").innerHTML = FLOWS.map((x, i) => `<button type="button" class="chip" data-flow="${i}">${esc(x.l)}</button>`).join("");
    $("#flow-presets").addEventListener("click", e => { const b = e.target.closest("[data-flow]"); if (b) { setFlow(FLOWS[+b.dataset.flow].f); runTest(); } });
    $("#t-src").addEventListener("input", () => { const v = $("#t-src").value.trim(); if (validIp(v)) $("#t-from").value = zoneForIp(v); renderTestCli(); });
    $("#t-dst").addEventListener("input", () => { const v = $("#t-dst").value.trim(); if (validIp(v)) $("#t-to").value = zoneForIp(v); renderTestCli(); });
    $("#t-app").addEventListener("change", () => {
      const a = APPS[$("#t-app").value];
      if (a.icmp) { $("#t-proto").value = "1"; $("#t-port").value = ""; }
      else if (a.tcp) { $("#t-proto").value = "6"; $("#t-port").value = a.tcp[0]; }
      else if (a.udp) { $("#t-proto").value = "17"; $("#t-port").value = a.udp[0]; }
      syncProto(); renderTestCli();
    });
    $("#t-proto").addEventListener("change", () => { syncProto(); renderTestCli(); });
    $("#flowForm").addEventListener("input", () => renderTestCli());
    $("#flowForm").addEventListener("change", () => renderTestCli());
    $("#flowForm").addEventListener("submit", e => { e.preventDefault(); runTest(); });
    $("#try-dnat").addEventListener("click", () => { setFlow(FLOWS[10].f); $("#tester").scrollIntoView({ behavior: reduce ? "auto" : "smooth" }); setTimeout(runTest, reduce ? 0 : 500); });
    setFlow(FLOWS[2].f);
  }
  function syncProto() { const icmp = $("#t-proto").value === "1"; $("#t-port").disabled = icmp; if (icmp) $("#t-port").value = ""; }
  function setFlow(f) {
    $("#t-src").value = f.src; $("#t-dst").value = f.dst;
    $("#t-from").value = f.from || zoneForIp(f.src); $("#t-to").value = f.to || zoneForIp(f.dst);
    $("#t-app").value = f.app; $("#t-proto").value = f.proto; $("#t-port").value = f.port;
    $("#t-user").value = f.user || "unknown"; $("#t-url").value = f.url || "none";
    syncProto(); renderTestCli();
  }
  function readFlow() {
    return { src: $("#t-src").value.trim(), dst: $("#t-dst").value.trim(), from: $("#t-from").value, to: $("#t-to").value, app: $("#t-app").value, proto: $("#t-proto").value, port: $("#t-port").value.trim(), user: $("#t-user").value, url: $("#t-url").value };
  }
  function validateFlow(f) {
    let ok = true;
    const set = (id, msg) => { $("#" + id + "-err").textContent = msg; $("#" + id).classList.toggle("invalid", !!msg); if (msg) ok = false; };
    set("t-src", validIp(f.src) ? "" : "Adresse IPv4 invalide");
    set("t-dst", validIp(f.dst) ? "" : "Adresse IPv4 invalide");
    set("t-port", f.proto === "1" || (window.PAN ? PAN.ip.validPort(f.port) : +f.port > 0) ? "" : "Port 1-65535");
    return ok;
  }
  function testCmd(f) {
    let c = `test security-policy-match from ${f.from} to ${f.to} source ${f.src} destination ${f.dst} protocol ${f.proto}`;
    if (f.proto !== "1" && f.port) c += ` destination-port ${f.port}`;
    c += ` application ${f.app}`;
    if (f.user && f.user !== "unknown") c += ` source-user "${f.user}"`;
    return c;
  }
  function renderTestCli(result) {
    const f = readFlow();
    let out = `<span class="c"># Mode opérationnel (admin@firewall-a&gt;) — IP pré-NAT, zone de destination post-NAT</span>\n<span class="k">test security-policy-match</span> ${esc(testCmd(f).replace("test security-policy-match ", ""))}`;
    if (result && result.rule) {
      const r = result.rule, idx = allRules().indexOf(r) + 1;
      const list = a => isAny(a) ? "any" : a.length === 1 ? a[0] : "[ " + a.join(" ") + " ]";
      out += `\n\n<span class="c"># Sortie (format simplifié)</span>\n<span class="s">"${esc(r.name)}; index: ${idx}"</span> {\n        from ${esc(list(r.from))};\n        source ${esc(list(r.src))};\n        source-region none;\n        to ${esc(list(toZ(r)))};\n        destination ${esc(list(r.dst))};\n        destination-region none;\n        user ${esc(list(r.user))};\n        category ${esc(list(r.url))};\n        application/service ${esc(list(r.app))}/${esc(list(r.svc))};\n        action <span class="k">${esc(r.action)}</span>;\n        terminal yes;\n}`;
    }
    $("#test-cli").innerHTML = out;
  }
  function renderLane() {
    runId++; $("#t-run").disabled = false;
    $("#lane-rules").innerHTML = allRules().map((r, i) => `<div class="lr${r.def ? " def" : ""}" data-uid="${r.uid}"><span class="ix">${i + 1}</span><span class="nm" title="${esc(r.name)}">${esc(r.name)}</span><span class="act ${actCls(r.action)}" style="font-size:12px">${esc(r.action)}</span><span class="why"></span></div>`).join("");
    const p = $("#pkt"); p.className = "pkt"; p.style.top = "20px";
    $("#verdict").className = "verdict"; $("#verdict").innerHTML = "";
  }
  let runId = 0;
  async function runTest() {
    const f = readFlow();
    if (!validateFlow(f)) { toast("Corrigez les champs du flux"); return; }
    renderLane(); renderTestCli();
    const my = ++runId;
    const lane = $("#lane"), p = $("#pkt"), items = $$(".lr", lane);
    const rules = allRules();
    const btn = $("#t-run"); btn.disabled = true;
    p.classList.add("on");
    let hit = null;
    for (let i = 0; i < rules.length; i++) {
      if (my !== runId) return;
      const el = items[i], r = rules[i];
      p.style.top = (el.offsetTop + el.offsetHeight / 2 - 8) + "px";
      el.classList.add("eval");
      await wait(420);
      if (my !== runId) return;
      const m = matchRule(r, f);
      el.classList.remove("eval");
      el.querySelector(".why").textContent = (m.ok ? "✓ " : "✗ ") + m.why;
      if (m.ok) { hit = r; el.classList.add("match"); if (r.action !== "allow") el.classList.add("blk"); for (let j = i + 1; j < items.length; j++) items[j].classList.add("skip"); break; }
      el.classList.add("miss");
      await wait(120);
    }
    btn.disabled = false;
    if (!hit) return;
    hit.hits++;
    const allow = hit.action === "allow";
    p.classList.add(allow ? "ok" : "no");
    if (hit.def) {
      const after = $(`.lr[data-uid="${hit.uid}"]`);
      if (after) p.style.top = (after.offsetTop + after.offsetHeight / 2 - 8) + "px";
    }
    const v = $("#verdict");
    const logTxt = hit.logEnd ? `Entrée visible dans <b>Monitor &gt; Logs &gt; Traffic</b> (Log at Session End), règle « ${esc(hit.name)} »${hit.logStart ? " + entrée de début de session" : ""}.`
      : `<b>Aucun log</b> : « ${esc(hit.name)} » ne journalise pas${hit.def ? " (règle par défaut sans Override : le trafic refusé est invisible dans le Traffic log)" : ""}.`;
    let extra = "";
    if (allow && hit.ptype === "none" && !hit.def) extra = `<p class="small" style="margin-top:6px">⚠ Autorisé sans Security Profile : aucune inspection Content-ID.</p>`;
    if (allow && f.to === "Untrust" && /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(f.src)) extra += `<p class="small mut" style="margin-top:6px">Autorisé ≠ joignable : vérifiez qu'une règle de NAT source traduit ${esc(f.src)} vers une IP publique (ex. 203.0.113.10, ethernet1/1).</p>`;
    if (f.dst === "203.0.113.20" && f.to === "DMZ") extra += `<p class="small mut" style="margin-top:6px">DNAT : destination pré-NAT 203.0.113.20 (Web-Public-IP), zone post-NAT DMZ (serveur réel 172.16.1.10).</p>`;
    if (!allow && hit.name === "Deny-All-Log") extra += `<p class="small mut" style="margin-top:6px">Aucune règle allow ne couvre ce flux : il tombe sur la règle de nettoyage, journalisée.</p>`;
    v.className = "verdict show " + (allow ? "allow" : "block");
    v.innerHTML = `<h3>${allow ? "✅ Allow" : "⛔ " + esc(ACTIONS[hit.action])} <span class="badge ${allow ? "ok" : "bad"}">${esc(hit.name)}</span></h3>
      <p class="small">Première règle correspondante en position ${rules.indexOf(hit) + 1} : les règles suivantes ne sont pas évaluées. Hit count → ${hit.hits}.</p>
      <p class="small" style="margin-top:6px">${logTxt}</p>${extra}`;
    renderRulebase({ flash: hit.uid });
    renderTestCli({ rule: hit });
  }

  /* ======================================================
     CLI générée
     ====================================================== */
  const q = v => /[\s\\"]/.test(v) ? `"${v.replace(/"/g, '\\"')}"` : v;
  const L1 = a => a.length === 1 ? q(a[0]) : "[ " + a.map(q).join(" ") + " ]";
  function renderCli() {
    const r = R, n = q(r.name || "<nom-de-regle>"), base = `set rulebase security rules ${n}`;
    const lines = [];
    const c = t => lines.push(`<span class="c">${esc(t)}</span>`);
    const s = t => lines.push(hl(t));
    c("# ===== Mode configuration ====="); s("configure");
    const addrs = Array.from(new Set(r.src.concat(r.dst))).filter(a => a !== "any");
    const tags = r.tags;
    if (addrs.length || tags.length || (r.ptype === "group") || r.logFwd) { lines.push(""); c("# --- Objets nécessaires ---"); }
    addrs.forEach(a => {
      const o = ADDR[a];
      if (o.edl) c(`# ${a} : EDL prédéfinie « ${o.label} » (rien à créer)`);
      else { s(`set address ${q(a)} ip-netmask ${o.cidr[0]}`); s(`set address ${q(a)} description "${o.desc}"`); }
    });
    tags.forEach(t => s(`set tag ${q(t)} color ${TAGS[t][0]}`));
    if (r.ptype === "group") { c(`# Security Profile Group (Objects > Security Profile Groups) — contenu donné en exemple`); s(`set profile-group ${q(r.group)} virus default spyware strict vulnerability strict url-filtering default file-blocking "basic file blocking" wildfire-analysis default`); }
    if (r.logFwd) c(`# Prérequis : Objects > Log Forwarding > ${r.logFwd}`);
    if (!isAny(r.user)) c("# Source User : groupes issus du Group Mapping User-ID (Device > User Identification)");
    lines.push(""); c("# --- Règle de sécurité ---");
    const to = r.type === "intrazone" ? r.from : r.to;
    s(`${base} from ${L1(r.from)} to ${L1(to)} source ${L1(r.src)} destination ${L1(r.dst)} source-user ${L1(r.user)} application ${L1(r.app)} service ${L1(r.svc)} category ${L1(r.url)} action ${r.action}`);
    if (r.desc.trim()) s(`${base} description "${r.desc.trim().replace(/"/g, "'")}"`);
    if (tags.length) s(`${base} tag ${L1(tags)}`);
    s(`${base} rule-type ${r.type}`);
    if (r.ptype === "group") s(`${base} profile-setting group ${q(r.group)}`);
    else if (r.ptype === "profiles") {
      const p = Object.entries(PROFILES).filter(([k]) => r.prof[k]).map(([k, d]) => `${d.cli} ${q(r.prof[k])}`).join(" ");
      if (p) s(`${base} profile-setting profiles ${p}`); else c("# Profile Type « Profiles » sans aucun profil sélectionné");
    }
    s(`${base} log-start ${r.logStart ? "yes" : "no"} log-end ${r.logEnd ? "yes" : "no"}`);
    if (r.logFwd) s(`${base} log-setting ${q(r.logFwd)}`);
    lines.push(""); c("# --- Position dans la rulebase ---");
    const mine = mineUid && byUid(mineUid);
    if (mine && mine.name === r.name) {
      const i = RB.indexOf(mine);
      if (i === 0) s(`move rulebase security rules ${n} top`); else s(`move rulebase security rules ${n} after ${q(RB[i - 1].name)}`);
    } else c("# (nouvelle règle : ajoutée en bas des règles personnalisées, au-dessus des règles par défaut)");
    if (DEF[1].overridden || DEF[0].overridden) {
      lines.push(""); c("# --- Override des règles par défaut ---");
      if (DEF[1].overridden) s(`set rulebase default-security-rules rules interzone-default action deny log-end yes`);
      if (DEF[0].overridden) s(`set rulebase default-security-rules rules intrazone-default action allow log-end yes`);
    }
    lines.push(""); c("# --- Validation ---"); s("validate full"); s("commit");
    $("#cli-out").innerHTML = lines.join("\n");
  }
  function hl(t) {
    let h = esc(t);
    h = h.replace(/(&quot;[^&]*?&quot;)/g, '<span class="s">$1</span>');
    h = h.replace(/^(set|move|configure|commit|validate full)\b/, '<span class="k">$1</span>');
    h = h.replace(/\b(action) (allow|deny|drop|reset-client|reset-server|reset-both)\b/, '$1 <span class="n">$2</span>');
    return h;
  }

  /* ======================================================
     Hints & update global
     ====================================================== */
  function renderHints() {
    $("#type-hint").textContent = { universal: "universal : trafic intra- ET inter-zones (valeur par défaut).", intrazone: "intrazone : trafic à l'intérieur d'une même zone ; la zone de destination est celle de la source.", interzone: "interzone : uniquement le trafic entre zones différentes." }[R.type];
    $("#app-hint").textContent = isAny(R.app) ? "any : la règle ne tire aucun profit d'App-ID. Ajoutez les applications nécessaires (puis leurs dépendances)." : "Applications : " + R.app.join(", ") + ". Les ports par défaut sont ceux d'Applipedia (simplifiés ici).";
    const sv = R.svc[0];
    $("#svc-hint").textContent = sv === "application-default" ? "application-default : ex. web-browsing seulement sur TCP 80, ssl sur TCP 443." : sv === "any" ? "any : l'application est autorisée sur tous les ports." : "service-http (TCP 80, 8080) et service-https (TCP 443) sont les seuls services prédéfinis.";
    $("#act-hint").textContent = ACT_HINT[R.action];
    const ne = R.name ? nameError(R.name) : "";
    $("#name-err").textContent = ne; $("#f-name").classList.toggle("invalid", !!ne);
    const mine = mineUid && byUid(mineUid);
    $("#btn-add").textContent = mine && mine.name.toLowerCase() === R.name.toLowerCase() ? "🔄 Mettre à jour ma règle dans la rulebase" : "➕ Ajouter ma règle à la rulebase";
  }
  let typingT = 0;
  function update(typing) {
    syncForm(); renderHints(); renderMock();
    clearTimeout(typingT);
    const heavy = () => { renderScore(); renderCli(); };
    if (typing) typingT = setTimeout(heavy, 180); else heavy();
  }

  function buildPresets() {
    $("#presets").innerHTML = PRESETS.map((p, i) => `<button type="button" class="preset" data-p="${i}"><span class="badge ${p.k === "Anti-exemple" ? "bad" : p.k.includes("durci") ? "ok" : "or"}">${esc(p.k)}</span><b>${esc(p.rule.name)}</b><span>${esc(p.sub)}</span></button>`).join("");
    $("#presets").addEventListener("click", e => {
      const b = e.target.closest("[data-p]"); if (!b) return;
      const p = PRESETS[+b.dataset.p];
      R = clone(p.rule);
      const ex = RB.find(x => x.name === R.name);
      mineUid = ex ? ex.uid : null;
      $$(".preset").forEach(x => x.classList.toggle("loaded", x === b));
      mockTab = "general"; syncText(); update();
      toast("Exemple « " + p.rule.name + " » chargé");
    });
  }

  function init() {
    buildChips(); buildTabs(); buildPresets(); buildTester();
    const form = $("#ruleForm");
    form.addEventListener("click", e => { const b = e.target.closest(".chip"); if (b && !b.disabled) onChip(b); });
    form.addEventListener("input", e => { if (e.target.type === "text" || e.target.tagName === "TEXTAREA") readForm(e); });
    form.addEventListener("change", e => { if (e.target.type === "radio" || e.target.tagName === "SELECT" || e.target.type === "checkbox") readForm(e); });
    form.addEventListener("submit", e => e.preventDefault());
    form.addEventListener("focusin", e => {
      const fs = e.target.closest("fieldset[data-tab]"); if (!fs) return;
      $$("fieldset.fs").forEach(x => x.classList.toggle("active", x === fs));
      if (mockTab !== fs.dataset.tab) { mockTab = fs.dataset.tab; renderMock(true); }
    });
    $("#btn-add").addEventListener("click", addMine);
    $("#mock-ok").addEventListener("click", addMine);
    $("#mock-cancel").addEventListener("click", () => { R = blank(); mineUid = null; $$(".preset").forEach(x => x.classList.remove("loaded")); syncText(); update(); toast("Nouvelle règle vierge"); });
    $("#btn-reset").addEventListener("click", () => { R = blank(); mineUid = null; $$(".preset").forEach(x => x.classList.remove("loaded")); mockTab = "general"; syncText(); update(); toast("Formulaire réinitialisé (valeurs par défaut de la WebUI)"); });
    bindRulebase();
    snapshotAll();
    $(".preset[data-p='0']").classList.add("loaded");
    syncText(); update();
    renderRulebase(); renderLane();
  }
  init();
})();
