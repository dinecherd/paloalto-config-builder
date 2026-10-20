/* Assistant NAT + règle de sécurité — PAN-OS
   Vanilla JS, aucune dépendance, fonctionne en file:// (dépend de window.PAN de common.js). */
(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = PAN.esc, IP = PAN.ip;
  const REDUCE = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,62}$/;
  const APP_RE = /^[a-z0-9][a-z0-9_.\-]{0,62}$/i;
  const CPORT = 51515;   // port source éphémère du client (exemple)
  const XPORT = 25661;   // port source attribué par le DIPP (valeur d'exemple)
  const ZCOL = { inside: "#22C55E", outside: "#EF4444", dmz: "#F59E0B", users: "#38BDF8", extranet: "#A78BFA" };

  /* ================= SCÉNARIOS ================= */
  const ICON = {
    snat: '<svg viewBox="0 0 40 40" fill="none" stroke="#FF8A3D" stroke-width="2.2" stroke-linecap="round"><rect x="3" y="12" width="12" height="9" rx="2"/><path d="M6 25h6"/><circle cx="31" cy="17" r="7"/><path d="M24 17h14M31 10c-3 4-3 10 0 14M31 10c3 4 3 10 0 14"/><path class="mv" d="M16 31h10m-3-3 3 3-3 3"/></svg>',
    dip: '<svg viewBox="0 0 40 40" fill="none" stroke="#FF8A3D" stroke-width="2.2" stroke-linecap="round"><rect x="3" y="12" width="12" height="9" rx="2"/><rect x="25" y="6" width="12" height="6" rx="2"/><rect x="25" y="15" width="12" height="6" rx="2"/><rect x="25" y="24" width="12" height="6" rx="2"/><path class="mv" d="M14 33h8m-3-3 3 3-3 3"/></svg>',
    dnat: '<svg viewBox="0 0 40 40" fill="none" stroke="#FF8A3D" stroke-width="2.2" stroke-linecap="round"><circle cx="9" cy="16" r="6"/><path d="M3 16h12"/><rect x="26" y="7" width="11" height="22" rx="2"/><path d="M29 12h5M29 17h5"/><path class="mv" d="M12 32h10m-3-3 3 3-3 3"/></svg>',
    static: '<svg viewBox="0 0 40 40" fill="none" stroke="#FF8A3D" stroke-width="2.2" stroke-linecap="round"><rect x="3" y="9" width="11" height="20" rx="2"/><circle cx="31" cy="19" r="7"/><path d="M17 15h9m-3-3 3 3-3 3M26 24h-9m3 3-3-3 3-3"/></svg>',
    uturn: '<svg viewBox="0 0 40 40" fill="none" stroke="#FF8A3D" stroke-width="2.2" stroke-linecap="round"><rect x="3" y="24" width="11" height="8" rx="2"/><path d="M9 22V12a6 6 0 0 1 12 0v6"/><path d="m17 15 4 4 4-4"/><rect x="25" y="24" width="12" height="8" rx="2"/></svg>',
  };
  const SC = {
    snat: { t: "Source NAT sortant (DIPP)", k: "Source NAT · Dynamic IP And Port", d: "LAN → Internet : les clients privés sortent avec l'IP de l'interface egress, le port source est traduit (PAT).", mini: "192.168.1.50 → <b>203.0.113.10</b>:PAT" },
    dnat: { t: "Destination NAT entrant", k: "Destination NAT · Static IP (+ port)", d: "Publier un serveur : IP publique:port → IP privée:port, avec traduction de port optionnelle.", mini: "203.0.113.20 ⇒ <b>172.16.1.10</b>" },
    static: { t: "Static NAT 1:1 bidirectionnel", k: "Source NAT · Static IP · Bi-directional", d: "Une IP privée ↔ une IP publique fixe, dans les deux sens (sortant et entrant).", mini: "172.16.1.10 ⇄ <b>203.0.113.20</b>" },
    uturn: { t: "U-Turn NAT", k: "Destination NAT + Source NAT (U-Turn)", d: "Un utilisateur interne joint le serveur interne via son IP publique : le paquet « fait demi-tour » dans le pare-feu.", mini: "Trust → <b>IP publique</b> → DMZ" },
    dip: { t: "Source NAT Dynamic IP (pool)", k: "Source NAT · Dynamic IP / DIPP sur pool", d: "Les clients sortent avec une IP prise dans un pool d'adresses publiques (et non l'IP d'interface).", mini: "192.168.1.0/24 → <b>pool</b> 203.0.113.30-35" },
  };
  const ORDER = ["snat", "dnat", "static", "uturn", "dip"];
  const BADGE = { snat: "Sortant", dnat: "Entrant", static: "1:1", uturn: "Hairpin", dip: "Pool" };

  const TOPO_DEF = { "t1-zone": "Untrust", "t1-ip": "203.0.113.10/24", "t2-zone": "Trust", "t2-ip": "192.168.1.1/24", "t3-zone": "DMZ", "t3-ip": "172.16.1.1/24", "t-gw": "203.0.113.1" };
  const BASE = { src: "any", client: "192.168.1.50", srczone2: "", dst: "8.8.8.8", dstany: true, pool: "", diptype: "dynamic-ip", client2: "", pub: "", srv: "", uturnsnat: true, bidir: true, proto: "tcp", port: "80", tport: "", natsvc: "any", secsvc: "application-default", app: "any", natname: "", secname: "", secname2: "", useobj: false, objpfx: "Web" };
  const EX = {
    snat: { src: "192.168.1.0/24", port: "443", natname: "SNAT-LAN-Internet", secname: "LAN-to-Internet", useobj: true, objpfx: "LAN" },
    dip: { src: "192.168.1.0/24", pool: "203.0.113.30-203.0.113.35", port: "443", natname: "SNAT-LAN-Pool", secname: "LAN-to-Internet", useobj: true, objpfx: "LAN" },
    dnat: { client: "198.51.100.10", pub: "203.0.113.20", srv: "172.16.1.10", natsvc: "obj", app: "web-browsing", natname: "DNAT-Web-DMZ", secname: "Allow-Web-DMZ", useobj: true },
    dnatAlt: { client: "198.51.100.10", pub: "203.0.113.20", srv: "172.16.1.10", port: "443", tport: "8443", natsvc: "obj", secsvc: "obj", app: "ssl", natname: "DNAT-Web-DMZ-8443", secname: "Allow-Web-DMZ", useobj: true },
    static: { client2: "198.51.100.10", pub: "203.0.113.20", srv: "172.16.1.10", port: "443", app: "ssl", natname: "NAT-Static-Web-DMZ", secname: "Web-DMZ-to-Internet", secname2: "Allow-Web-DMZ", useobj: true },
    uturn: { src: "192.168.1.0/24", pub: "203.0.113.20", srv: "172.16.1.10", natsvc: "obj", natname: "UTurn-Web-DMZ", secname: "LAN-to-Web-DMZ-Public", useobj: true },
  };

  let scen = null, model = null;

  /* ================= TOPOLOGIE / ROUTAGE ================= */
  const val = id => { const e = document.getElementById(id); return e ? (e.type === "checkbox" ? e.checked : e.value.trim()) : ""; };
  const topo = () => [1, 2, 3].map(i => ({ ifc: "ethernet1/" + i, zone: val(`t${i}-zone`), cidr: val(`t${i}-ip`) }));
  const hostOf = c => String(c).split("/")[0];
  const maskOf = c => { const m = String(c).split("/")[1]; return m === undefined ? 32 : +m; };
  const maskInt = m => (m === 0 ? 0 : (~0 << (32 - m)) >>> 0);
  const inNet = (ip, cidr) => { const m = maskOf(cidr); return ((IP.toInt(ip) & maskInt(m)) >>> 0) === ((IP.toInt(hostOf(cidr)) & maskInt(m)) >>> 0); };
  const netOf = cidr => { const m = maskOf(cidr), n = (IP.toInt(hostOf(cidr)) & maskInt(m)) >>> 0; return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".") + "/" + m; };
  const zoneOfIf = ifc => (topo().find(t => t.ifc === ifc) || {}).zone || "";
  const ifIp = ifc => (topo().find(t => t.ifc === ifc) || {}).cidr || "";
  /** Route lookup simplifiée : réseau connecté le plus spécifique, sinon route par défaut (ethernet1/1). */
  function route(ip) {
    if (!IP.valid(ip)) return null;
    let best = null;
    for (const t of topo()) if (IP.validCidr(t.cidr) && t.cidr.includes("/") && inNet(ip, t.cidr) && (!best || maskOf(t.cidr) > maskOf(best.cidr))) best = t;
    if (best) return { ifc: best.ifc, zone: best.zone, why: `réseau connecté ${netOf(best.cidr)}` };
    return { ifc: "ethernet1/1", zone: zoneOfIf("ethernet1/1"), why: `route par défaut 0.0.0.0/0 → ${val("t-gw") || "next hop"}` };
  }
  /** Classe de couleur d'une zone (cohérente avec le design system). */
  function zcls(z) {
    const s = String(z).toLowerCase();
    if (/internet|untrust|outside|wan|extern/.test(s)) return "outside";
    if (/dmz/.test(s)) return "dmz";
    if (/extranet|server|srv/.test(s)) return "extranet";
    if (/trust|inside|lan|corp/.test(s)) return "inside";
    if (/user|client|guest/.test(s)) return "users";
    const i = topo().findIndex(t => t.zone === z);
    return ["outside", "inside", "dmz"][i] || "users";
  }
  const zchip = z => `<span class="zone ${zcls(z)}">${esc(z)}</span>`;

  /* ================= ÉTAPE 1 : cartes ================= */
  function renderCards() {
    $("#ns-scen").innerHTML = ORDER.map((k, i) => `
      <button type="button" class="card ns-card" data-scen="${k}" aria-pressed="false" style="--d:${i * 90}ms">
        <span class="ns-check" aria-hidden="true">✓</span>
        <span class="ns-ico" aria-hidden="true">${ICON[k]}</span>
        <span class="badge or">${BADGE[k]}</span>
        <span class="ns-h">${SC[k].t}</span>
        <span class="ns-p">${SC[k].d}</span>
        <span class="ns-mini">${SC[k].mini}</span>
      </button>`).join("");
    $("#ns-scen").addEventListener("click", e => {
      const c = e.target.closest(".ns-card"); if (!c) return;
      $$(".ns-card").forEach(x => x.setAttribute("aria-pressed", x === c));
      pickScenario(c.dataset.scen);
    });
  }
  function pickScenario(k) {
    const changed = scen !== k; scen = k;
    $("#ns-p2-kicker").textContent = SC[k].k;
    $("#ns-p2-title").textContent = SC[k].t;
    $("#ns-p2-desc").textContent = SC[k].d;
    $$("[data-for]").forEach(el => { el.hidden = !el.dataset.for.split(" ").includes(k); });
    $("#ns-leg-srv").textContent = k === "static" ? "① Le serveur et son IP publique fixe" : "② Le serveur publié";
    $("#ns-load-alt").hidden = k !== "dnat";
    if (changed) loadExample(k, true);
    setTimeout(() => go(2), REDUCE ? 0 : 260);
  }

  /* ================= ÉTAPE 2 : formulaire ================= */
  const AUTO = ["f-srczone", "f-ingress", "f-dstzone", "f-egress", "f-pubzone", "f-pubif", "f-srvzone"];
  function fillSelects() {
    const zones = [...new Set(topo().map(t => t.zone).filter(Boolean))];
    const ifs = topo().map(t => t.ifc);
    const set = (id, opts, extra) => {
      const s = document.getElementById(id), cur = s.value;
      s.innerHTML = (extra || "") + opts.map(o => `<option value="${esc(o)}">${esc(o)}</option>`).join("");
      if ([...s.options].some(o => o.value === cur)) s.value = cur;
    };
    ["f-srczone", "f-dstzone", "f-pubzone", "f-srvzone"].forEach(id => set(id, zones));
    set("f-srczone2", zones, '<option value="">(aucune)</option>');
    ["f-ingress", "f-egress", "f-pubif"].forEach(id => set(id, ifs));
  }
  function setAuto(id, value, why) {
    const s = document.getElementById(id), h = document.getElementById("h-" + id);
    if (s.dataset.manual === "1" || !value) return;
    if ([...s.options].some(o => o.value === value)) s.value = value;
    if (h) h.textContent = why ? "↳ " + why : "";
  }
  /** Déduit zones et interfaces à partir des IP saisies (comme le ferait la route lookup du pare-feu). */
  function autodetect() {
    const sIp = IP.valid(val("f-client")) ? val("f-client") : (IP.validCidr(val("f-src")) ? hostOf(val("f-src")) : "");
    const r = route(sIp);
    if (r) { setAuto("f-srczone", r.zone, `${r.why} → ${r.ifc} → zone ${r.zone}`); setAuto("f-ingress", r.ifc, "interface par laquelle arrive le client"); }
    const d = route(val("f-dst"));
    if (d) { setAuto("f-dstzone", d.zone, `${d.why} → zone ${d.zone}`); setAuto("f-egress", d.ifc, `sortie vers ${val("f-dst")} (IP ${ifIp(d.ifc)})`); }
    const p = route(val("f-pub"));
    if (p) { setAuto("f-pubzone", p.zone, `${p.why} → zone pré-NAT ${p.zone}`); setAuto("f-pubif", p.ifc, `route vers l'IP publique → ${p.ifc}`); }
    const v = route(val("f-srv"));
    if (v) setAuto("f-srvzone", v.zone, `${v.why} → ${v.ifc} → zone post-NAT ${v.zone}`);
  }
  function writeForm(o) {
    for (const [k, v] of Object.entries(o)) {
      const e = document.getElementById("f-" + k) || document.getElementById(k);
      if (!e) continue;
      if (e.type === "checkbox") e.checked = !!v; else e.value = v;
    }
  }
  function loadExample(k, silent) {
    writeForm(TOPO_DEF); fillSelects();
    AUTO.forEach(id => { const s = document.getElementById(id); delete s.dataset.manual; badge(id, false); });
    writeForm(Object.assign({}, BASE, EX[k] || {}));
    autodetect(); validate(false);
    if (!silent) PAN.toast("Exemple chargé ✓");
  }
  const badge = (id, man) => { const b = $(`[data-auto="${id}"]`); if (b) { b.textContent = man ? "manuel" : "auto"; b.classList.toggle("man", man); } };

  /* ---------- validation ---------- */
  const isRange = s => { const p = String(s).split("-"); return p.length === 2 && IP.valid(p[0]) && IP.valid(p[1]) && IP.toInt(p[0].trim()) <= IP.toInt(p[1].trim()); };
  const RULES = {
    "f-src": v => v.toLowerCase() === "any" || IP.validCidr(v) || "CIDR (192.168.1.0/24), IP ou any",
    "f-client": v => IP.valid(v) || "Adresse IPv4 invalide",
    "f-client2": v => IP.valid(v) || "Adresse IPv4 invalide",
    "f-dst": v => IP.valid(v) || "Adresse IPv4 invalide",
    "f-pub": v => IP.valid(v) || "Adresse IPv4 invalide",
    "f-srv": v => IP.valid(v) || "Adresse IPv4 invalide",
    "f-pool": v => isRange(v) || (IP.validCidr(v) && v.includes("/")) || "Plage a.b.c.d-a.b.c.e ou CIDR",
    "f-port": v => IP.validPort(v) || "Port 1-65535",
    "f-tport": v => v === "" || IP.validPort(v) || "Port 1-65535 (ou vide)",
    "f-app": v => v === "" || APP_RE.test(v) || "Nom d'application App-ID (ex. web-browsing)",
    "f-natname": v => NAME_RE.test(v) || "1-63 car. : lettres, chiffres, _ - . (sans espace)",
    "f-secname": v => NAME_RE.test(v) || "1-63 car. : lettres, chiffres, _ - . (sans espace)",
    "f-secname2": v => NAME_RE.test(v) || "1-63 car. : lettres, chiffres, _ - . (sans espace)",
    "f-objpfx": v => NAME_RE.test(v) || "Préfixe : lettres, chiffres, _ - .",
  };
  const visible = el => !el.closest("[hidden]");
  function validate(show) {
    let first = null;
    for (const [id, fn] of Object.entries(RULES)) {
      const el = document.getElementById(id), errEl = document.getElementById("e-" + id);
      if (!visible(el)) { el.classList.remove("invalid"); el.removeAttribute("aria-invalid"); if (errEl) errEl.textContent = ""; continue; }
      if (id === "f-objpfx" && !val("f-useobj") && val("f-natsvc") !== "obj" && val("f-secsvc") !== "obj") { el.classList.remove("invalid"); errEl.textContent = ""; continue; }
      const r = fn(el.value.trim()), bad = r !== true;
      const showIt = show || el.dataset.touched === "1";
      el.classList.toggle("invalid", bad && showIt);
      el.setAttribute("aria-invalid", bad && showIt ? "true" : "false");
      if (errEl) errEl.textContent = bad && showIt ? r : "";
      if (bad && !first) first = el;
    }
    // topologie
    let terr = "";
    topo().forEach((t, i) => {
      const zi = document.getElementById(`t${i + 1}-zone`), ii = document.getElementById(`t${i + 1}-ip`);
      const zb = !NAME_RE.test(t.zone), ib = !(IP.validCidr(t.cidr) && t.cidr.includes("/"));
      zi.classList.toggle("invalid", zb); ii.classList.toggle("invalid", ib);
      if (zb || ib) terr = "Topologie : zone (sans espace) et IP/masque requis pour chaque interface.";
      if ((zb || ib) && !first) first = zb ? zi : ii;
    });
    if (!IP.valid(val("t-gw"))) { terr = terr || "Next hop invalide."; if (!first) first = $("#t-gw"); }
    $("#t-gw").classList.toggle("invalid", !IP.valid(val("t-gw")));
    $("#t-err").textContent = terr;
    if (terr && show) $("#ns-topo").open = true;
    warnings();
    return first;
  }
  function warnings() {
    const w = [], k = scen;
    const c = val("f-client"), src = val("f-src");
    if (["snat", "dip", "dnat", "uturn"].includes(k) && IP.valid(c) && IP.validCidr(src) && src.toLowerCase() !== "any" && !inNet(c, src.includes("/") ? src : src + "/32"))
      w.push(`Le client de test ${esc(c)} n'appartient pas à la source ${esc(src)} : la règle ne le matchera pas.`);
    if (["snat", "dip", "uturn"].includes(k) && IP.valid(c) && !IP.isPrivate(c)) w.push("Le client source n'est pas une IP privée RFC 1918 : une source NAT est-elle vraiment nécessaire ?");
    if (["dnat", "uturn", "static"].includes(k)) {
      if (IP.valid(val("f-srv")) && val("f-srv") === val("f-pub")) w.push("IP publique et IP privée identiques : aucune traduction n'aurait lieu.");
      if (k !== "static" && val("f-pubzone") && val("f-pubzone") === val("f-srvzone")) w.push("Zone de l'IP publique = zone du serveur : vérifiez votre adressage (règle intrazone).");
      if (IP.valid(val("f-pub")) && topo().some(t => hostOf(t.cidr) === val("f-pub")) && k === "static") w.push("Static 1:1 sur l'IP de l'interface elle-même : à éviter, l'IP d'interface sert aussi au pare-feu (DIPP, VPN, management).");
    }
    if (k === "uturn" && val("f-srczone") === val("f-pubzone")) w.push("Le client est déjà dans la zone de l'IP publique : ce n'est pas un U-Turn mais une destination NAT classique.");
    if (k === "dip" && isRange(val("f-pool"))) {
      const eg = ifIp(val("f-egress")), a = val("f-pool").split("-")[0].trim();
      if (IP.validCidr(eg) && !inNet(a, eg)) w.push(`Le pool n'est pas dans le sous-réseau de ${esc(val("f-egress"))} (${esc(eg)}) : le routeur amont devra router ce pool vers le pare-feu (pas de proxy ARP).`);
    }
    const box = $("#ns-warn");
    box.hidden = !w.length;
    box.innerHTML = w.length ? "<b>À vérifier</b>" + w.map(x => "• " + x).join("<br>") : "";
  }

  /* ================= MODÈLE ================= */
  function read() {
    const d = {};
    ["src", "client", "srczone", "srczone2", "ingress", "dst", "dstany", "dstzone", "egress", "pool", "diptype", "client2", "pub", "pubzone", "pubif", "srv", "srvzone", "uturnsnat", "bidir", "proto", "port", "tport", "natsvc", "secsvc", "app", "natname", "secname", "secname2", "useobj", "objpfx"].forEach(k => (d[k] = val("f-" + k)));
    d.app = d.app || "any";
    if (d.src.toLowerCase() === "any") d.src = "any";
    return d;
  }
  function build(d) {
    const k = scen, objs = [], svcs = [];
    const P = d.objpfx;
    const addr = (value, name) => {
      if (value === "any") return "any";
      if (!d.useobj) return value;
      if (!objs.some(o => o.name === name)) objs.push({ name, type: value.includes("-") ? "ip-range" : "ip-netmask", value });
      return name;
    };
    const SP = (k === "snat" || k === "dip") ? P : "LAN";
    const srcName = v => v === "any" ? "any" : addr(v, maskOf(v) < 32 ? `Net-${SP}` : `Host-${SP}`);
    const svcObj = () => { const n = `${d.proto}-${d.port}`; if (!svcs.some(s => s.name === n)) svcs.push({ name: n, proto: d.proto, port: d.port }); return n; };
    const natSvc = d.natsvc === "obj" ? svcObj() : "any";
    const secSvc = d.secsvc === "obj" ? svcObj() : d.secsvc;
    const protoNum = d.proto === "udp" ? 17 : 6;
    const M = { k, d, objs, svcs, nat: null, sec: [], flows: [], moveTop: false };
    const none = { type: "none" };

    if (k === "snat" || k === "dip") {
      const from = [d.srczone].concat(d.srczone2 && d.srczone2 !== d.srczone ? [d.srczone2] : []);
      const src = srcName(d.src);
      const dstMatch = d.dstany ? "any" : addr(d.dst, `Dst-${P}`);
      let st, afterS, afterSp;
      if (k === "snat") {
        st = { type: "dynamic-ip-and-port", addrType: "interface-address", iface: d.egress, ip: ifIp(d.egress) };
        afterS = hostOf(ifIp(d.egress)); afterSp = XPORT;
      } else {
        const pool = addr(d.pool, `Pool-${P}`);
        st = { type: d.diptype, addrType: "translated-address", translated: [pool], poolRaw: d.pool };
        afterS = d.pool.includes("-") ? d.pool.split("-")[0].trim() : hostOf(d.pool);
        afterSp = d.diptype === "dynamic-ip" ? CPORT : XPORT;
      }
      M.nat = { name: d.natname, desc: `Source NAT ${from.join("+")} -> ${d.dstzone} via ${k === "snat" ? hostOf(ifIp(d.egress)) : d.pool}`, from, to: d.dstzone, toIf: d.egress, src: [src], dst: [dstMatch], svc: natSvc, st, dt: none };
      from.forEach((z, i) => M.sec.push({ name: i === 0 ? d.secname : `${z}_to_${d.dstzone}`, desc: `Autorise ${z} vers ${d.dstzone}`, from: [z], to: d.dstzone, src: [src], dst: [dstMatch], app: d.app, svc: secSvc }));
      M.flows.push({ label: "Flux sortant", srcLbl: "Client", dstLbl: "Internet", dstKind: "globe", ingress: d.ingress, egress: d.egress, zl: d.srczone, zr: d.dstzone,
        before: { s: d.client, sp: CPORT, d: d.dst, dp: d.port }, after: { s: afterS, sp: afterSp, d: d.dst, dp: d.port } });
      M.test = { from: d.srczone, to: d.dstzone, toIf: d.egress, src: d.client, dst: d.dst, port: d.port, proto: protoNum, secTo: d.dstzone };
      M.moveTop = k === "dip"; // doit passer avant une DIPP générale existante
    }

    if (k === "dnat" || k === "uturn") {
      const src = srcName(d.src), pub = addr(d.pub, `Pub-${P}`), srv = addr(d.srv, `Srv-${P}-${d.srvzone}`);
      const egr = route(d.srv).ifc;
      const st = k === "uturn" && d.uturnsnat ? { type: "dynamic-ip-and-port", addrType: "interface-address", iface: egr, ip: ifIp(egr) } : none;
      M.nat = { name: d.natname, desc: `${k === "uturn" ? "U-Turn : " : ""}${d.pub}${d.tport ? ":" + d.port : ""} -> ${d.srv}${d.tport ? ":" + d.tport : ""}`, from: [d.srczone], to: d.pubzone, toIf: d.pubif, src: [src], dst: [pub], svc: natSvc, st, dt: { type: "static-ip", addr: srv, port: d.tport } };
      M.sec.push({ name: d.secname, desc: `Autorise ${d.srczone} vers le serveur ${d.srv} publié en ${d.pub}`, from: [d.srczone], to: d.srvzone, src: [src], dst: [pub], app: d.app, svc: secSvc, gold: true });
      const tr = k === "uturn" && d.uturnsnat;
      M.flows.push({ label: k === "uturn" ? "Flux U-Turn" : "Flux entrant", srcLbl: "Client", dstLbl: "Serveur", dstKind: "server", ingress: d.ingress, egress: egr, zl: d.srczone, zr: d.srvzone, ghost: { ip: d.pub, zone: d.pubzone },
        before: { s: d.client, sp: CPORT, d: d.pub, dp: d.port }, after: { s: tr ? hostOf(ifIp(egr)) : d.client, sp: tr ? XPORT : CPORT, d: d.srv, dp: d.tport || d.port } });
      M.test = { from: d.srczone, to: d.pubzone, toIf: d.pubif, src: d.client, dst: d.pub, port: d.port, proto: protoNum, secTo: d.srvzone };
      M.moveTop = k === "uturn";
    }

    if (k === "static") {
      const srv = addr(d.srv, `Srv-${P}-${d.srvzone}`), pub = addr(d.pub, `Pub-${P}`);
      const ing = route(d.srv).ifc, out = route("8.8.8.8"), cz = route(d.client2);
      M.nat = { name: d.natname, desc: `Static 1:1 ${d.srv} <-> ${d.pub}`, from: [d.srvzone], to: d.pubzone, toIf: d.pubif, src: [srv], dst: ["any"], svc: natSvc, st: { type: "static-ip", addrType: "translated-address", translated: [pub], bidir: d.bidir }, dt: none };
      M.sec.push({ name: d.secname, desc: `Sortant : serveur ${d.srv} vers ${out.zone}`, from: [d.srvzone], to: out.zone, src: [srv], dst: ["any"], app: "any", svc: "application-default" });
      M.flows.push({ label: "Flux sortant (serveur → Internet)", srcLbl: "Serveur", srcKind: "server", dstLbl: "Internet", dstKind: "globe", ingress: ing, egress: out.ifc, zl: d.srvzone, zr: out.zone,
        before: { s: d.srv, sp: CPORT, d: "8.8.8.8", dp: 443 }, after: { s: d.pub, sp: CPORT, d: "8.8.8.8", dp: 443 } });
      if (d.bidir) {
        M.sec.push({ name: d.secname2, desc: `Entrant : ${cz.zone} vers le serveur publié en ${d.pub}`, from: [cz.zone], to: d.srvzone, src: ["any"], dst: [pub], app: d.app, svc: secSvc, gold: true });
        M.flows.push({ label: "Flux entrant (Internet → serveur)", srcLbl: "Client externe", dstLbl: "Serveur", dstKind: "server", ingress: cz.ifc, egress: ing, zl: cz.zone, zr: d.srvzone, ghost: { ip: d.pub, zone: d.pubzone },
          before: { s: d.client2, sp: CPORT, d: d.pub, dp: d.port }, after: { s: d.client2, sp: CPORT, d: d.srv, dp: d.port } });
      }
      M.test = { from: d.srvzone, to: d.pubzone, toIf: d.pubif, src: d.srv, dst: "8.8.8.8", port: 443, proto: 6, secTo: out.zone,
        inb: d.bidir ? { from: cz.zone, to: d.pubzone, src: d.client2, dst: d.pub, port: d.port, proto: protoNum, secTo: d.srvzone } : null };
      M.moveTop = true;
    }
    return M;
  }

  /* ================= LIBELLÉS WebUI ================= */
  const ST_LBL = { "none": "None", "dynamic-ip-and-port": "Dynamic IP And Port", "dynamic-ip": "Dynamic IP", "static-ip": "Static IP" };
  const list = a => a.join(", ");
  function natTabs(M) {
    const n = M.nat;
    const gen = [{ k: "Name", v: n.name }, { k: "Description", v: n.desc }, { k: "Group Rules By Tag", v: "None" }, { k: "NAT Type", v: "ipv4" },
      { note: "NAT Type ipv4 = traduction IPv4 ↔ IPv4 (nat64 / nptv6 servent à IPv6)." }];
    const orig = [{ k: "Source Zone", v: list(n.from), tag: "pre" }, { k: "Destination Zone", v: n.to, tag: "pre" }, { k: "Destination Interface", v: n.toIf }, { k: "Service", v: n.svc },
      { k: "Source Address", v: n.src[0] === "any" ? "☑ Any" : list(n.src), tag: "pre" }, { k: "Destination Address", v: n.dst[0] === "any" ? "☑ Any" : list(n.dst), tag: "pre" },
      { note: M.k === "dnat" || M.k === "uturn" ? `Original Packet = le paquet tel qu'il arrive. Destination Zone = <b>${esc(n.to)}</b> : la zone où « réside » l'IP ${esc(M.d.pub)} (route lookup sur l'IP d'origine), pas la zone du serveur.` : "Original Packet = le paquet tel qu'il arrive sur le pare-feu, avant toute traduction." }];
    const st = n.st, tr = [{ sec: "Source Address Translation" }, { k: "Translation Type", v: ST_LBL[st.type] }];
    if (st.type === "dynamic-ip-and-port" && st.addrType === "interface-address") tr.push({ k: "Address Type", v: "Interface Address" }, { k: "Interface", v: st.iface }, { k: "IP Address", v: st.ip });
    else if (st.type !== "none") {
      if (st.type === "dynamic-ip-and-port") tr.push({ k: "Address Type", v: "Translated Address" });
      tr.push({ k: "Translated Address", v: list(st.translated) });
      if (st.type === "static-ip") tr.push({ k: "Bi-directional", v: st.bidir ? "☑ Yes" : "☐ No" });
      if (st.type === "dynamic-ip") tr.push({ k: "Fallback", v: "None" });
    }
    tr.push({ sec: "Destination Address Translation" }, { k: "Translation Type", v: n.dt.type === "none" ? "None" : "Static IP" });
    if (n.dt.type !== "none") tr.push({ k: "Translated Address", v: n.dt.addr }, { k: "Translated Port", v: n.dt.port || "(vide : port inchangé)" });
    tr.push({ note: "Translated Packet = ce que deviendra le paquet à la sortie (egress). Les champs vides ne sont pas modifiés." });
    return [{ id: "gen", label: "General", rows: gen }, { id: "orig", label: "Original Packet", rows: orig }, { id: "tr", label: "Translated Packet", rows: tr }];
  }
  function secTabs(r) {
    const g = r.gold;
    return [
      { id: "gen", label: "General", rows: [{ k: "Name", v: r.name }, { k: "Rule Type", v: "universal (default)" }, { k: "Description", v: r.desc }, { k: "Tags", v: "" }] },
      { id: "src", label: "Source", rows: [{ k: "Source Zone", v: list(r.from), tag: "pre" }, { k: "Source Address", v: r.src[0] === "any" ? "☑ Any" : list(r.src), tag: "pre" }, { k: "Source User", v: "any" }, { k: "Source Device", v: "any" },
        { note: "Zone source = zone de l'interface d'entrée. Adresse source = IP d'origine (avant source NAT)." }] },
      { id: "dst", label: "Destination", rows: [{ k: "Destination Zone", v: r.to, tag: "post" }, { k: "Destination Address", v: r.dst[0] === "any" ? "☑ Any" : list(r.dst), tag: "pre" }, { k: "Destination Device", v: "any" },
        { note: g ? `<b>Règle d'or :</b> Destination Zone = <b>${esc(r.to)}</b> (zone finale, post-NAT, celle du serveur) mais Destination Address = <b>${esc(list(r.dst))}</b> (l'IP publique d'origine, pré-NAT).` : "Destination Zone = zone de sortie déterminée par la route lookup (post-NAT). Adresse = IP d'origine." }] },
      { id: "app", label: "Application", rows: [{ k: "Applications", v: r.app === "any" ? "☑ Any" : r.app }] },
      { id: "svc", label: "Service/URL Category", rows: [{ k: "Service", v: r.svc }, { k: "URL Category", v: "any" },
        { note: r.svc === "application-default" ? "application-default : l'application doit utiliser son port standard (ex. web-browsing → tcp/80). Le port vérifié est le port d'origine, jamais le port traduit." : "Le service correspond au port d'ORIGINE vu par le client, pas au port traduit." }] },
      { id: "act", label: "Actions", rows: [{ k: "Action", v: "Allow" }, { k: "Log Setting", v: "☑ Log at Session End" }, { k: "Profile Type", v: "None" }] },
    ];
  }

  /* ================= RENDU DES MOCKS ================= */
  function panRows(rows) {
    let i = 0;
    return rows.map(r => {
      if (r.sec) return `<div class="pan-sec">${esc(r.sec)}</div>`;
      if (r.note) return `<div class="pnote">${r.note}</div>`;
      const tag = r.tag ? `<span class="ptag ${r.tag}">${r.tag === "pre" ? "PRÉ-NAT" : "POST-NAT"}</span>` : "";
      return `<div class="pan-row"><span>${esc(r.k)}${tag}</span><span class="pan-val${r.v ? " hl" : ""}" style="--d:${(i++) * 90}ms">${esc(r.v)}</span></div>`;
    }).join("");
  }
  function panMock(id, top, title, tabs) {
    const T = ["Dashboard", "ACC", "Monitor", "Policies", "Objects", "Network", "Device"];
    return `<div class="pan ns-pan" id="${id}">
      <div class="pan-top" aria-hidden="true">${T.map(t => `<span class="${t === top ? "on" : ""}">${t}</span>`).join("")}</div>
      <div class="pan-title"><span>${esc(title)}</span><span class="pan-commit" aria-hidden="true">Commit</span></div>
      <div class="pan-tabs" role="tablist" aria-label="${esc(title)}">${tabs.map((t, i) => `<button type="button" role="tab" id="${id}-t-${t.id}" aria-controls="${id}-body" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}" class="${i === 0 ? "on" : ""}" data-tab="${t.id}">${esc(t.label)}</button>`).join("")}</div>
      <div class="pan-body" id="${id}-body" role="tabpanel" aria-labelledby="${id}-t-${tabs[0].id}">${panRows(tabs[0].rows)}</div>
      <div class="pan-foot"><button type="button" class="pan-btn pri" tabindex="-1" aria-hidden="true">OK</button><button type="button" class="pan-btn" tabindex="-1" aria-hidden="true">Cancel</button></div>
    </div>`;
  }
  function wirePan(id, tabs) {
    const root = document.getElementById(id), body = $(`#${id}-body`), btns = $$(".pan-tabs button", root);
    const show = (b, focus) => {
      btns.forEach(x => { const on = x === b; x.classList.toggle("on", on); x.setAttribute("aria-selected", on); x.tabIndex = on ? 0 : -1; });
      body.setAttribute("aria-labelledby", b.id);
      body.innerHTML = panRows(tabs.find(t => t.id === b.dataset.tab).rows);
      if (focus) b.focus();
    };
    btns.forEach((b, i) => {
      b.addEventListener("click", () => show(b));
      b.addEventListener("keydown", e => {
        const n = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (n) { e.preventDefault(); show(btns[(i + n + btns.length) % btns.length], true); }
      });
    });
  }

  /* ================= CLI ================= */
  const mem = a => (a.length > 1 ? `[ ${a.join(" ")} ]` : a[0]);
  const q = s => `"${String(s).replace(/"/g, "'")}"`;
  function cliConfig(M) {
    const n = M.nat, L = ["# ---- Mode configuration ----", "configure", ""];
    if (M.objs.length) { L.push("# Objets Address (Objects > Addresses)"); M.objs.forEach(o => L.push(`set address ${o.name} ${o.type} ${o.value}`)); L.push(""); }
    if (M.svcs.length) { L.push("# Objets Service (Objects > Services)"); M.svcs.forEach(s => L.push(`set service ${s.name} protocol ${s.proto} port ${s.port}`)); L.push(""); }
    L.push(`# Règle NAT (Policies > NAT)`);
    const base = `set rulebase nat rules ${n.name}`;
    L.push(`${base} nat-type ipv4 from ${mem(n.from)} to ${n.to} to-interface ${n.toIf} source ${mem(n.src)} destination ${mem(n.dst)} service ${n.svc}`);
    L.push(`${base} description ${q(n.desc)}`);
    const st = n.st;
    if (st.type === "dynamic-ip-and-port" && st.addrType === "interface-address") L.push(`${base} source-translation dynamic-ip-and-port interface-address interface ${st.iface} ip ${st.ip}`);
    else if (st.type === "dynamic-ip-and-port") L.push(`${base} source-translation dynamic-ip-and-port translated-address ${mem(st.translated)}`);
    else if (st.type === "dynamic-ip") L.push(`${base} source-translation dynamic-ip translated-address ${mem(st.translated)}`);
    else if (st.type === "static-ip") L.push(`${base} source-translation static-ip translated-address ${st.translated[0]} bi-directional ${st.bidir ? "yes" : "no"}`);
    if (n.dt.type === "static-ip") L.push(`${base} destination-translation translated-address ${n.dt.addr}${n.dt.port ? " translated-port " + n.dt.port : ""}`);
    if (M.moveTop) L.push(`# Placer la règle AU-DESSUS de la règle DIPP générale existante (ex. SNAT-LAN-Internet)`, `move rulebase nat rules ${n.name} top`);
    L.push("");
    M.sec.forEach(r => {
      L.push(`# Règle de sécurité (Policies > Security) — IP pré-NAT, zone post-NAT`);
      const b = `set rulebase security rules ${r.name}`;
      L.push(`${b} from ${mem(r.from)} to ${r.to} source ${mem(r.src)} destination ${mem(r.dst)} source-user any category any application ${r.app} service ${r.svc} action allow`);
      L.push(`${b} description ${q(r.desc)}`, "");
    });
    L.push("# Vérifier puis appliquer", "show rulebase nat rules " + n.name, "commit", "exit");
    return L.join("\n");
  }
  function cliVerify(M) {
    const t = M.test, L = ["# ---- Mode opérationnel (après le commit) ----"];
    const one = (x, lbl) => {
      L.push(`# ${lbl} : quelle règle NAT matche ? (valeurs PRÉ-NAT, zones pré-NAT)`);
      L.push(`test nat-policy-match from ${x.from} to ${x.to}${x.toIf ? " to-interface " + x.toIf : ""} source ${x.src} destination ${x.dst} destination-port ${x.port} protocol ${x.proto}`);
      L.push(`# ${lbl} : quelle règle de sécurité ? (IP PRÉ-NAT, zone de destination POST-NAT)`);
      L.push(`test security-policy-match from ${x.from} to ${x.secTo} source ${x.src} destination ${x.dst} destination-port ${x.port} protocol ${x.proto}${M.d.app !== "any" && lbl !== "Sortant" ? " application " + M.d.app : ""}`);
      L.push("");
    };
    one(t, M.k === "static" ? "Sortant" : "Flux");
    if (t.inb) one(t.inb, "Entrant");
    const s = t.inb || t;
    L.push("# Sessions actives (filtre sur le flux c2s, donc valeurs d'origine)");
    L.push(`show session all filter source ${s.src} destination ${s.dst} destination-port ${s.port}`);
    L.push(`show session all filter nat ${M.k === "dnat" || (M.k === "static" && t.inb) ? "destination" : M.k === "uturn" ? "both" : "source"}`);
    L.push("show session id <ID>          # comparer les flux c2s / s2c : la traduction y apparaît");
    L.push("show running nat-policy       # règles NAT réellement chargées");
    L.push("", "# Après une modification NAT : les sessions existantes gardent l'ancienne traduction", `clear session all filter source ${s.src}`);
    return L.join("\n");
  }
  function hl(txt) {
    return txt.split("\n").map(l => {
      const e = esc(l);
      if (/^\s*#/.test(l)) return `<span class="c">${e}</span>`;
      return e.replace(/#.*$/, m => `<span class="c">${m}</span>`)
        .replace(/^(set|test|show|configure|commit|exit|move|clear)\b/, '<span class="k">$1</span>')
        .replace(/\b(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\b/g, '<span class="n">$1</span>')
        .replace(/\b(from|to|to-interface|source|destination|service|application|action|destination-port|protocol|source-translation|destination-translation|translated-address|translated-port|bi-directional)\b(?![-\w])/g, '<span class="s">$1</span>');
    }).join("\n");
  }

  /* ================= PIÈGES ================= */
  function pitfalls(M) {
    const k = M.k, all = ["snat", "dnat", "static", "uturn", "dip"];
    const P = [
      { on: all, t: "Ordre des règles (top-down, première correspondance)", s: "NAT et sécurité sont évaluées de haut en bas ; la première règle qui matche gagne. Une règle DIPP « any → Internet » placée au-dessus capturera le trafic du serveur / du U-Turn." },
      { on: all, t: "Règle de sécurité : IP pré-NAT, zone post-NAT", s: "Ne mettez jamais l'IP traduite en adresse de destination d'une règle de sécurité pour un DNAT ; mettez l'IP publique d'origine et la zone finale du serveur." },
      { on: ["dnat", "uturn", "static"], t: "Règle NAT : zone de destination = zone de l'IP publique", s: "Dans Original Packet, la zone de destination est celle où réside l'IP publique (route lookup sur l'IP d'origine), pas la zone du serveur." },
      { on: ["dnat", "uturn"], t: "Service : port d'origine, jamais le port traduit", s: "Les règles NAT et sécurité utilisent le port vu par le client. Avec application-default, un port public non standard (ex. 8443 pour ssl) ne matchera pas : utilisez un objet service." },
      { on: all, t: "Commit !", s: "Rien n'est actif tant que la configuration candidate n'est pas commitée (bouton Commit / commande commit)." },
      { on: ["uturn"], t: "U-Turn : source NAT en plus du DNAT", s: "Si le serveur est dans la même zone/sous-réseau que le client, sans source NAT il répond directement au client : flux asymétrique, session cassée. La règle U-Turn doit aussi être au-dessus de la DIPP générale." },
      { on: ["dnat", "static", "uturn", "dip"], t: "Proxy ARP / routage de l'IP publique", s: "Si l'IP publique (ou le pool) est dans le sous-réseau de l'interface, le pare-feu répond en ARP pour elle. Sinon, le routeur amont doit router cette IP vers le pare-feu." },
      { on: ["snat", "dip"], t: "Capacité du pool", s: "Dynamic IP = une IP par client simultané : pool épuisé → nouvelles sessions refusées (prévoir un fallback). DIPP partage une IP via les ports (oversubscription 1/2/4/8 selon la plateforme)." },
      { on: all, t: "Routage = zone de destination", s: "Le pare-feu doit avoir une route vers l'IP d'origine ET vers l'IP traduite : c'est la route vers l'IP traduite qui donne la zone post-NAT utilisée par la sécurité." },
      { on: ["static"], t: "Bi-directional ne crée pas de règle de sécurité", s: "L'option crée seulement la traduction inverse implicite. Il faut toujours une règle de sécurité entrante (zone source Internet → zone du serveur, destination = IP publique)." },
      { on: all, t: "Sessions existantes", s: "Une session déjà établie garde sa traduction : après modification, faites clear session (ou attendez l'expiration) avant de retester." },
      { on: ["dnat", "uturn", "static"], t: "Logs : Destination = IP d'origine", s: "Dans Monitor > Logs > Traffic, la colonne Destination affiche l'IP publique ; l'IP traduite est dans NAT Destination IP (détail du log)." },
    ];
    return P.map(p => Object.assign({}, p, { rel: p.on.includes(k) })).sort((a, b) => b.rel - a.rel);
  }

  /* ================= RENDU ÉTAPE 3 ================= */
  function renderResult(M) {
    const n = M.nat, d = M.d, r0 = M.sec.find(s => s.gold) || M.sec[0];
    $("#ns-p3-kicker").textContent = SC[M.k].k;
    $("#ns-p3-title").textContent = n.name;
    $("#ns-sum").innerHTML = `<span class="badge or">${esc(SC[M.k].t)}</span>${M.flows[0].zl ? zchip(M.flows[0].zl) : ""}<span class="mut">→</span>${zchip(M.flows[0].zr)}<span class="badge">${esc(d.proto.toUpperCase())}/${esc(d.port)}${d.tport && n.dt.type !== "none" ? " → " + esc(d.tport) : ""}</span><span class="badge ok">${M.sec.length} règle${M.sec.length > 1 ? "s" : ""} de sécurité</span>`;

    const cmpRow = (lbl, a, ta, b, tb) => `<tr><th scope="row">${lbl}</th><td><code>${esc(a)}</code>${ta ? `<span class="ns-tag ${ta}">${ta === "pre" ? "PRÉ-NAT" : "POST-NAT"}</span>` : ""}</td><td><code>${esc(b)}</code>${tb ? `<span class="ns-tag ${tb}">${tb === "pre" ? "PRÉ-NAT" : "POST-NAT"}</span>` : ""}</td></tr>`;
    const goldTxt = (M.k === "dnat" || M.k === "uturn" || (M.k === "static" && r0.gold))
      ? `Dans la règle NAT, la zone de destination est <b>${esc(n.to)}</b> (là où vit l'IP ${esc(d.pub)}). Dans la règle de sécurité, la zone de destination devient <b>${esc(r0.to)}</b> (zone réelle du serveur, post-NAT) mais l'adresse reste <b>${esc(d.pub)}</b> (pré-NAT).`
      : `Pour une source NAT, la zone de destination est la même dans les deux règles (${esc(r0.to)}) ; la règle de sécurité garde l'adresse source privée d'origine (<b>${esc(list(r0.src))}</b>), jamais ${esc(M.flows[0].after.s)}.`;

    const flowsTabs = M.flows.length > 1 ? `<div class="ns-flowtabs" role="group" aria-label="Choix du flux">${M.flows.map((f, i) => `<button type="button" class="btn sm" data-flow="${i}" aria-pressed="${i === (M.flows.length - 1)}">${esc(f.label)}</button>`).join("")}</div>` : "";
    const secPick = M.sec.length > 1 ? `<div class="ns-secpick" role="group" aria-label="Choix de la règle de sécurité">${M.sec.map((s, i) => `<button type="button" class="btn sm" data-sec="${i}" aria-pressed="${i === 0}">${esc(s.name)}</button>`).join("")}</div>` : "";
    const old = M.k === "snat" ? "" : `<tr class="old"><td>${M.moveTop ? 2 : 1}</td><td>SNAT-LAN-Internet <i>(existante)</i></td><td>Trust</td><td>Untrust</td><td>ethernet1/1</td><td>any</td><td>any</td><td>any</td><td>dynamic-ip-and-port ethernet1/1</td><td>none</td></tr>`;
    const stTxt = n.st.type === "none" ? "none" : n.st.type + " " + (n.st.addrType === "interface-address" ? n.st.iface : list(n.st.translated)) + (n.st.bidir ? " (bi-dir)" : "");
    const dtTxt = n.dt.type === "none" ? "none" : `${n.dt.addr}${n.dt.port ? ":" + n.dt.port : ""}`;
    const tview = M.test.inb || M.test;

    $("#ns-res").innerHTML = `
      <div class="ns-gold fade-up" role="note">
        <span class="kicker">Règle d'or NAT ↔ Sécurité</span>
        <h3 style="margin-top:6px">La règle de sécurité utilise les <span class="grad">adresses IP pré-NAT</span> et la <span class="grad">zone post-NAT</span></h3>
        <p class="mut">${goldTxt}</p>
        <div class="ns-cmpwrap"><table class="ns-cmp">
          <thead><tr><th scope="col">Champ</th><th scope="col">Règle NAT · ${esc(n.name)}</th><th scope="col">Règle sécurité · ${esc(r0.name)}</th></tr></thead>
          <tbody>
            ${cmpRow("Zone source", list(n.from), "pre", list(r0.from), "pre")}
            ${cmpRow("Zone destination", n.to, "pre", r0.to, "post")}
            ${cmpRow("Adresse source", list(n.src), "pre", list(r0.src), "pre")}
            ${cmpRow("Adresse destination", list(n.dst), "pre", list(r0.dst), "pre")}
            ${cmpRow("Service", n.svc, "", r0.svc, "")}
          </tbody></table></div>
      </div>

      <div class="ns-block panel ns-stage">
        <h3><span class="ns-num">1</span> Le paquet traverse le pare-feu</h3>
        <p class="mut small" style="margin-bottom:12px">Le paquet arrive avec ses valeurs d'origine ; la traduction n'est appliquée qu'à la sortie (egress). La réponse suit la même session, traduite en sens inverse.</p>
        ${flowsTabs}
        <div class="ns-svgwrap" id="ns-svgwrap"></div>
        <div class="ns-caption" aria-live="polite"><span class="dot" aria-hidden="true"></span><span id="ns-cap">—</span></div>
        <div class="ns-hdrs">
          <div class="ns-hdr" id="ns-h1"></div><div class="ns-arrow" aria-hidden="true">➜</div><div class="ns-hdr" id="ns-h2"></div>
        </div>
        <div class="row" style="margin-top:14px"><button type="button" class="btn sm primary" id="ns-replay">▶ Rejouer l'animation</button></div>
      </div>

      <div class="ns-block">
        <h3><span class="ns-num">2</span> La règle NAT · <span class="mut" style="font-weight:600">Policies › NAT › Add</span></h3>
        <p class="mut small" style="margin-bottom:12px">Cliquez sur les onglets comme dans la WebUI. Les étiquettes <span class="ns-tag pre">PRÉ-NAT</span> rappellent que la NAT se décrit avec le paquet d'origine.</p>
        ${panMock("ns-natmock", "Policies", "NAT Policy Rule", natTabs(M))}
        <div class="pan ns-pan" style="margin-top:14px"><div class="pan-title"><span>Policies › NAT — vue de la rulebase</span></div><div class="ns-tablewrap"><table>
          <thead><tr><th>#</th><th>Name</th><th>Source Zone</th><th>Destination Zone</th><th>Destination Interface</th><th>Source Address</th><th>Destination Address</th><th>Service</th><th>Source Translation</th><th>Destination Translation</th></tr></thead>
          <tbody>${M.moveTop || !old ? "" : old}<tr class="new"><td>${M.moveTop || !old ? 1 : 2}</td><td><b>${esc(n.name)}</b></td><td>${esc(list(n.from))}</td><td>${esc(n.to)}</td><td>${esc(n.toIf)}</td><td>${esc(list(n.src))}</td><td>${esc(list(n.dst))}</td><td>${esc(n.svc)}</td><td>${esc(stTxt)}</td><td>${esc(dtTxt)}</td></tr>${M.moveTop ? old : ""}</tbody>
        </table></div></div>
        ${M.moveTop ? `<div class="callout warn"><b>Ordre</b>Placez cette règle au-dessus de toute règle DIPP générale (ex. SNAT-LAN-Internet), sinon c'est celle-ci qui matchera en premier.</div>` : ""}
        ${M.k === "dnat" && n.to === n.from[0] ? `<div class="callout"><b>IP NAT dans un sous-réseau interne</b>L'IP NAT ${esc(d.pub)} appartient au réseau de ${esc(n.toIf)} : source et destination zone sont toutes deux ${esc(n.to)} dans la règle NAT. La règle de sécurité utilise pourtant la zone post-NAT ${esc(M.sec[0].to)}.</div>` : ""}
      </div>

      <div class="ns-block">
        <h3><span class="ns-num">3</span> La règle de sécurité associée · <span class="mut" style="font-weight:600">Policies › Security › Add</span></h3>
        <p class="mut small" style="margin-bottom:12px">Onglet <b>Destination</b> : c'est là que se joue la règle d'or.</p>
        ${secPick}
        <div id="ns-secwrap"></div>
      </div>

      <div class="ns-block">
        <h3><span class="ns-num">4</span> Commandes CLI équivalentes</h3>
        <div class="code ns-code" id="ns-cli"><button type="button" class="btn sm copy-btn" data-copy-target="#ns-cli-txt" aria-label="Copier les commandes de configuration">Copier</button><div id="ns-cli-txt">${hl(cliConfig(M))}</div></div>
      </div>

      <div class="ns-block">
        <h3><span class="ns-num">5</span> Vérifier que ça marche</h3>
        <div class="code ns-code" id="ns-ver"><button type="button" class="btn sm copy-btn" data-copy-target="#ns-ver-txt" aria-label="Copier les commandes de vérification">Copier</button><div id="ns-ver-txt">${hl(cliVerify(M))}</div></div>
        <div class="callout ok"><b>Monitor › Logs › Traffic</b>Filtre : <code>( addr.src in ${esc(tview.src)} ) and ( addr.dst in ${esc(tview.dst)} )</code>. Les colonnes Source / Destination montrent les IP <b>d'origine</b> ; ouvrez le détail du log (loupe) ou ajoutez les colonnes <b>NAT Source IP / NAT Destination IP</b> (et ports) pour voir la traduction. Vérifiez aussi la colonne <b>Rule</b> : elle doit afficher <code>${esc((M.sec.find(s => s.gold) || M.sec[0]).name)}</code>.</div>
      </div>

      <div class="ns-block">
        <h3><span class="ns-num">6</span> Pièges fréquents · checklist</h3>
        <div class="ns-progress" aria-hidden="true"><i id="ns-pbar"></i></div>
        <p class="mut small" id="ns-pcount" aria-live="polite"></p>
        <ul class="ns-pit" id="ns-pit">${pitfalls(M).map((p, i) => `<li class="${p.rel ? "rel" : ""}"><label><input type="checkbox" data-pit="${i}"><span>${esc(p.t)} ${p.rel ? '<span class="badge warn" style="margin-left:6px">ce scénario</span>' : ""}<small>${esc(p.s)}</small></span></label></li>`).join("")}</ul>
      </div>`;

    wirePan("ns-natmock", natTabs(M));
    const showSec = i => { $("#ns-secwrap").innerHTML = panMock("ns-secmock", "Policies", "Security Policy Rule", secTabs(M.sec[i])); wirePan("ns-secmock", secTabs(M.sec[i])); };
    showSec(0);
    $$("[data-sec]").forEach(b => b.addEventListener("click", () => { $$("[data-sec]").forEach(x => x.setAttribute("aria-pressed", x === b)); showSec(+b.dataset.sec); }));
    $$("[data-flow]").forEach(b => b.addEventListener("click", () => { $$("[data-flow]").forEach(x => x.setAttribute("aria-pressed", x === b)); playFlow(M.flows[+b.dataset.flow]); }));
    $("#ns-replay").addEventListener("click", () => { const b = $("[data-flow][aria-pressed=true]"); playFlow(M.flows[b ? +b.dataset.flow : 0]); });
    const upd = () => { const c = $$("#ns-pit input"), on = c.filter(x => x.checked).length; $("#ns-pbar").style.width = (on / c.length * 100) + "%"; $("#ns-pcount").textContent = `${on} / ${c.length} points vérifiés`; c.forEach(x => x.closest("li").classList.toggle("ok", x.checked)); };
    $("#ns-pit").addEventListener("change", upd); upd();
    playFlow(M.flows[M.flows.length - 1]);
  }

  /* ================= SCHÉMA SVG ANIMÉ ================= */
  const NODE = {
    pc: (x, y) => `<g transform="translate(${x - 34} ${y - 30})" fill="none" stroke="#E2E8F0" stroke-width="3" stroke-linejoin="round"><rect x="0" y="0" width="68" height="46" rx="6" fill="#0B1224"/><path d="M24 56h20M34 46v10"/></g>`,
    server: (x, y) => `<g transform="translate(${x - 26} ${y - 38})" fill="#0B1224" stroke="#E2E8F0" stroke-width="3"><rect x="0" y="0" width="52" height="24" rx="5"/><rect x="0" y="28" width="52" height="24" rx="5"/><rect x="0" y="56" width="52" height="20" rx="5"/><circle cx="12" cy="12" r="3" fill="#22C55E" stroke="none"/><circle cx="12" cy="40" r="3" fill="#22C55E" stroke="none"/></g>`,
    globe: (x, y) => `<g transform="translate(${x} ${y})" fill="none" stroke="#E2E8F0" stroke-width="3"><circle r="34" fill="#0B1224"/><ellipse rx="14" ry="34"/><path d="M-34 0h68M-29-17h58M-29 17h58"/></g>`,
  };
  let anim = null;
  function hdr(title, p, chg) {
    const row = (k, v, c) => `<div class="r"><span>${k}</span><span class="v${c ? " chg" : ""}" data-f="${k}">${esc(v)}</span></div>`;
    return `<h4>${title}</h4>${row("Src IP", p.s, chg && chg.s)}${row("Src Port", p.sp, chg && chg.sp)}${row("Dst IP", p.d, chg && chg.d)}${row("Dst Port", p.dp, chg && chg.dp)}`;
  }
  /** Effet « morphing » : brouillage de caractères puis valeur finale. */
  function morph(el, to) {
    const from = el.textContent, chars = "0123456789.:";
    if (from === String(to) || REDUCE) { el.textContent = to; return; }
    const t0 = performance.now(), D = 650, str = String(to);
    const step = now => {
      const k = Math.min(1, (now - t0) / D), keep = Math.floor(str.length * k);
      el.textContent = str.slice(0, keep) + Array.from(str.slice(keep), c => (c === "." ? "." : chars[Math.random() * 10 | 0])).join("");
      if (k < 1) requestAnimationFrame(step); else el.textContent = str;
    };
    requestAnimationFrame(step);
  }
  function playFlow(f) {
    if (anim) cancelAnimationFrame(anim.raf);
    const cl = ZCOL[zcls(f.zl)], cr = ZCOL[zcls(f.zr)], gh = f.ghost;
    const lbl = p => [`S ${p.s}:${p.sp}`, `D ${p.d}:${p.dp}`];
    const W = 960, X1 = 160, XF = 480, X2 = 800, Y = 200;
    $("#ns-svgwrap").innerHTML = `
    <svg viewBox="0 0 ${W} 330" role="img" aria-labelledby="ns-svg-t ns-svg-d">
      <title id="ns-svg-t">${esc(f.label)} : ${esc(f.before.s)} vers ${esc(f.before.d)}</title>
      <desc id="ns-svg-d">Avant NAT : source ${esc(f.before.s)}:${f.before.sp}, destination ${esc(f.before.d)}:${f.before.dp}. Après NAT : source ${esc(f.after.s)}:${f.after.sp}, destination ${esc(f.after.d)}:${f.after.dp}.</desc>
      <defs><filter id="ns-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="8"/></filter></defs>
      <rect x="12" y="92" width="330" height="226" rx="20" fill="${cl}" fill-opacity=".08" stroke="${cl}" stroke-opacity=".55" stroke-width="2"/>
      <text x="32" y="304" fill="${cl}" font-size="17" font-weight="800">Zone ${esc(f.zl)}</text>
      <rect x="618" y="92" width="330" height="226" rx="20" fill="${cr}" fill-opacity=".08" stroke="${cr}" stroke-opacity=".55" stroke-width="2"/>
      <text x="928" y="304" fill="${cr}" font-size="17" font-weight="800" text-anchor="end">Zone ${esc(f.zr)}</text>
      <line x1="${X1 + 45}" y1="${Y}" x2="${XF - 72}" y2="${Y}" stroke="${cl}" stroke-width="3" class="flow-line"/>
      <line x1="${XF + 72}" y1="${Y}" x2="${X2 - 45}" y2="${Y}" stroke="${cr}" stroke-width="3" class="flow-line"/>
      ${gh ? `<g><rect x="${XF - 150}" y="14" width="300" height="52" rx="14" fill="${ZCOL[zcls(gh.zone)]}" fill-opacity=".1" stroke="${ZCOL[zcls(gh.zone)]}" stroke-dasharray="7 6" stroke-width="2"/>
        <text x="${XF}" y="37" text-anchor="middle" fill="#F1F5F9" font-size="15" font-weight="800">IP NAT ${esc(gh.ip)}</text>
        <text x="${XF}" y="56" text-anchor="middle" fill="${ZCOL[zcls(gh.zone)]}" font-size="12.5" font-weight="700">zone pré-NAT ${esc(gh.zone)} · n'existe que dans la règle</text>
        <line x1="${XF}" y1="66" x2="${XF}" y2="${Y - 60}" stroke="${ZCOL[zcls(gh.zone)]}" stroke-dasharray="4 5" stroke-width="2"/></g>` : ""}
      <circle id="ns-fwglow" cx="${XF}" cy="${Y}" r="70" fill="#FA582D" opacity="0" filter="url(#ns-glow)"/>
      <rect x="${XF - 72}" y="${Y - 60}" width="144" height="120" rx="22" fill="#0B1224" stroke="#FA582D" stroke-width="3"/>
      <g transform="translate(${XF - 20} ${Y - 44})" fill="none" stroke="#FF8A3D" stroke-width="3.2" stroke-linecap="round"><path d="M20 2 4 9v10c0 9 7 16 16 18 9-2 16-9 16-18V9z"/><path d="m13 19 5 5 9-9"/></g>
      <text x="${XF}" y="${Y + 18}" text-anchor="middle" fill="#F1F5F9" font-size="15" font-weight="800">PA-FW</text>
      <text x="${XF}" y="${Y + 40}" text-anchor="middle" fill="#94A3B8" font-size="12.5" id="ns-fwtxt">NAT · Security</text>
      <text x="${XF - 80}" y="${Y + 28}" text-anchor="end" fill="${cl}" font-size="13" font-weight="700">${esc(f.ingress)}</text>
      <text x="${XF + 80}" y="${Y + 28}" fill="${cr}" font-size="13" font-weight="700">${esc(f.egress)}</text>
      ${NODE[f.srcKind || "pc"](X1, Y)}
      <text x="${X1}" y="${Y + 66}" text-anchor="middle" fill="#F1F5F9" font-size="15" font-weight="800">${esc(f.srcLbl)}</text>
      <text x="${X1}" y="${Y + 86}" text-anchor="middle" fill="#CBD5E1" font-size="14" font-family="ui-monospace,Menlo,monospace">${esc(f.before.s)}</text>
      ${NODE[f.dstKind](X2, Y)}
      <text x="${X2}" y="${Y + 66}" text-anchor="middle" fill="#F1F5F9" font-size="15" font-weight="800">${esc(f.dstLbl)}</text>
      <text x="${X2}" y="${Y + 86}" text-anchor="middle" fill="#CBD5E1" font-size="14" font-family="ui-monospace,Menlo,monospace">${esc(f.after.d)}</text>
      <g id="ns-pk" transform="translate(${X1} ${Y - 76})">
        <rect x="-100" y="-24" width="200" height="48" rx="12" fill="#050913" stroke="#FA582D" stroke-width="2.5"/>
        <text id="ns-pk1" x="0" y="-4" text-anchor="middle" fill="#F1F5F9" font-size="13" font-family="ui-monospace,Menlo,monospace"></text>
        <text id="ns-pk2" x="0" y="15" text-anchor="middle" fill="#F1F5F9" font-size="13" font-family="ui-monospace,Menlo,monospace"></text>
      </g>
    </svg>`;
    const chg = { s: f.before.s !== f.after.s, sp: f.before.sp !== f.after.sp, d: f.before.d !== f.after.d, dp: String(f.before.dp) !== String(f.after.dp) };
    const h1 = $("#ns-h1"), h2 = $("#ns-h2"), pk = $("#ns-pk"), pk1 = $("#ns-pk1"), pk2 = $("#ns-pk2"), glow = $("#ns-fwglow"), fwt = $("#ns-fwtxt"), cap = $("#ns-cap");
    h1.innerHTML = hdr(`Avant NAT · ingress ${esc(f.ingress)} · ${esc(f.zl)}`, f.before);
    h2.innerHTML = hdr(`Après NAT · egress ${esc(f.egress)} · ${esc(f.zr)}`, { s: "…", sp: "…", d: "…", dp: "…" });
    const setPk = (p, col) => { const [a, b] = lbl(p); pk1.textContent = a; pk2.textContent = b; pk.querySelector("rect").setAttribute("stroke", col || "#FA582D"); };
    const rev = p => ({ s: p.d, sp: p.dp, d: p.s, dp: p.sp });
    const what = [chg.s && "IP source", chg.sp && "port source", chg.d && "IP destination", chg.dp && "port destination"].filter(Boolean).join(", ") || "rien";
    const C = [
      `① Le ${f.srcLbl.toLowerCase()} envoie le paquet : ${f.before.s}:${f.before.sp} → ${f.before.d}:${f.before.dp}. Il entre par ${f.ingress} (zone ${f.zl}).`,
      `② Le pare-feu évalue la NAT (calcul), la route vers ${f.after.d} donne la zone ${f.zr}, puis la sécurité valide avec IP pré-NAT + zone post-NAT. À l'egress, il réécrit : ${what}.`,
      `③ Le paquet traduit sort par ${f.egress} : ${f.after.s}:${f.after.sp} → ${f.after.d}:${f.after.dp}.`,
      `④ La réponse revient : ${f.after.d}:${f.after.dp} → ${f.after.s}:${f.after.sp}. Elle matche la session existante (flux s2c).`,
      `⑤ Traduction inverse automatique : le ${f.srcLbl.toLowerCase()} reçoit ${f.before.d}:${f.before.dp} → ${f.before.s}:${f.before.sp}. Aucune règle supplémentaire n'est nécessaire pour le retour.`,
    ];
    const finish = () => {
      h2.innerHTML = hdr(`Après NAT · egress ${esc(f.egress)} · ${esc(f.zr)}`, f.after, chg);
      h1.classList.remove("live"); h2.classList.remove("live");
    };
    if (REDUCE) {
      pk.setAttribute("transform", `translate(${X2} ${Y - 76})`); setPk(f.after, ZCOL[zcls(f.zr)]); finish();
      cap.textContent = C[1] + " " + C[2] + " " + C[4];
      return;
    }
    // Timeline : [durée, x départ, x arrivée, action au démarrage]
    const PH = [
      [1300, X1, XF, () => { setPk(f.before, cl); cap.textContent = C[0]; h1.classList.add("live"); }],
      [900, XF, XF, () => { glow.setAttribute("opacity", ".55"); fwt.textContent = "Évaluation NAT…"; cap.textContent = C[1]; }],
      [1300, XF, X2, () => {
        glow.setAttribute("opacity", "0"); fwt.textContent = "Traduction appliquée ✓"; setPk(f.after, cr);
        h1.classList.remove("live"); h2.classList.add("live");
        h2.innerHTML = hdr(`Après NAT · egress ${esc(f.egress)} · ${esc(f.zr)}`, f.before, chg);
        ["s", "sp", "d", "dp"].forEach((k, i) => { const el = $$(".v", h2)[i]; morph(el, f.after[k]); });
        cap.textContent = C[2];
      }],
      [700, X2, X2, () => { h2.classList.remove("live"); }],
      [1300, X2, XF, () => { setPk(rev(f.after), cr); cap.textContent = C[3]; fwt.textContent = "Session s2c"; }],
      [700, XF, XF, () => { glow.setAttribute("opacity", ".4"); fwt.textContent = "Traduction inverse"; }],
      [1300, XF, X1, () => { glow.setAttribute("opacity", "0"); setPk(rev(f.before), cl); cap.textContent = C[4]; fwt.textContent = "NAT · Security"; }],
    ];
    let i = -1, t0 = 0;
    const ease = t => (t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);
    anim = { raf: 0 };
    const tick = now => {
      if (i < 0 || now - t0 >= PH[i][0]) {
        i++; t0 = now;
        if (i >= PH.length) { finish(); fwt.textContent = "Session établie ✓"; return; }
        PH[i][3]();
      }
      const [dur, xa, xb] = PH[i], t = ease(Math.min(1, (now - t0) / dur));
      const x = xa + (xb - xa) * t, lift = xa === xb ? 0 : Math.sin(t * Math.PI) * -10;
      pk.setAttribute("transform", `translate(${x.toFixed(1)} ${(Y - 76 + lift).toFixed(1)})`);
      anim.raf = requestAnimationFrame(tick);
    };
    anim.raf = requestAnimationFrame(tick);
  }

  /* ================= EXPORT .TXT ================= */
  function exportTxt(M) {
    const n = M.nat, line = "=".repeat(64), L = [];
    L.push(line, `Assistant NAT PAN-OS — configuration générée`, `Scénario : ${SC[M.k].t}`, `Généré le : ${new Date().toLocaleString("fr-FR")}`, line, "");
    L.push("RÈGLE D'OR : la règle de sécurité utilise les IP PRÉ-NAT et la ZONE POST-NAT.", "");
    M.flows.forEach(f => L.push(`[${f.label}]`, `  Avant NAT (ingress ${f.ingress}, zone ${f.zl}) : ${f.before.s}:${f.before.sp} -> ${f.before.d}:${f.before.dp}`, `  Après NAT (egress ${f.egress}, zone ${f.zr})  : ${f.after.s}:${f.after.sp} -> ${f.after.d}:${f.after.dp}`, ""));
    L.push("--- Policies > NAT > Add ---");
    natTabs(M).forEach(t => { L.push(`[${t.label}]`); t.rows.forEach(r => { if (r.sec) L.push(`  -- ${r.sec}`); else if (r.k) L.push(`  ${r.k.padEnd(22)} ${r.v}${r.tag ? "   (" + (r.tag === "pre" ? "pré-NAT" : "post-NAT") + ")" : ""}`); }); });
    L.push("");
    M.sec.forEach(r => {
      L.push(`--- Policies > Security > Add : ${r.name} ---`);
      secTabs(r).forEach(t => { L.push(`[${t.label}]`); t.rows.forEach(x => { if (x.k) L.push(`  ${x.k.padEnd(22)} ${x.v}${x.tag ? "   (" + (x.tag === "pre" ? "pré-NAT" : "POST-NAT") + ")" : ""}`); }); });
      L.push("");
    });
    L.push("--- CLI : configuration ---", cliConfig(M), "", "--- CLI : vérification ---", cliVerify(M), "", "--- Pièges fréquents ---");
    pitfalls(M).forEach(p => L.push(`[ ] ${p.t}${p.rel ? " (ce scénario)" : ""}`, `    ${p.s}`));
    L.push("", "Outil pédagogique non officiel — vérifiez avec la documentation Palo Alto Networks.");
    const blob = new Blob([L.join("\r\n")], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = `nat-${M.k}-${n.name}.txt`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    PAN.toast("Fichier .txt exporté ✓");
  }

  /* ================= NAVIGATION ================= */
  function go(step) {
    if (step >= 2 && !scen) return;
    if (step === 3 && !model) return;
    $$("#ns-steps .st").forEach(b => {
      const s = +b.dataset.go;
      b.classList.toggle("on", s === step); b.classList.toggle("done", s < step);
      b.disabled = (s === 2 && !scen) || (s === 3 && !model);
      if (s === step) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
    });
    $$(".ns-pane").forEach((p, i) => p.classList.toggle("on", i + 1 === step));
    if (step !== 3 && anim) cancelAnimationFrame(anim.raf);
    const top = $("#ns-steps").getBoundingClientRect().top + scrollY - 84;
    if (scrollY > top + 40 || step > 1) scrollTo({ top, behavior: REDUCE ? "auto" : "smooth" });
    if (step === 3) $("#ns-p3").focus({ preventScroll: true });
  }

  /* ================= TIMELINE « LOGIQUE » ================= */
  const TL = [
    { i: "⇥", t: "Ingress", d: "Interface d'entrée → <b>zone source</b>." },
    { i: "⌕", t: "Session lookup", d: "Session existante → fast path, traduction déjà connue (le retour n'a besoin d'aucune règle). Sinon : slow path." },
    { i: "⛨", t: "Zone / DoS", d: "Zone Protection et DoS Protection sur la zone source." },
    { i: "⇄", t: "Forwarding lookup", d: "PBF / route sur l'IP de destination <b>d'origine</b> → zone de destination <b>pré-NAT</b> (Original Packet)." },
    { i: "⚙", t: "NAT policy (calcul)", key: true, d: "Rulebase NAT évaluée top-down avec les valeurs d'origine. En DNAT, route lookup sur l'IP traduite → zone <b>post-NAT</b>. Rien n'est encore réécrit." },
    { i: "✔", t: "Security policy", key: true, d: "Match sur <b>IP pré-NAT</b> + <b>zone post-NAT</b>. Si allow → création de session, puis App-ID / Content-ID." },
    { i: "⇤", t: "Egress + traduction", d: "Réécriture IP/ports <b>appliquée à la sortie</b>. Le retour (s2c) est dé-traduit via la session." },
  ];

  let tlTimer = null, tlCur = 0;
  function renderTL() {
    const box = $("#ns-tl");
    box.innerHTML = '<span class="bar" aria-hidden="true"></span>' + TL.map((s, i) => `<button type="button" role="tab" id="ns-tl-${i}" aria-controls="ns-tldet" aria-selected="false" class="${s.key ? "key" : ""}" data-i="${i}"><i aria-hidden="true">${s.i}</i><span>${i + 1}. ${s.t}</span></button>`).join("");
    box.addEventListener("click", e => { const b = e.target.closest("button"); if (b) { stopTL(); showTL(+b.dataset.i); } });
    box.addEventListener("keydown", e => {
      const n = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
      if (n) { e.preventDefault(); stopTL(); showTL((tlCur + n + TL.length) % TL.length); $("#ns-tl-" + tlCur).focus(); }
    });
    showTL(0);
    $("#ns-tl-play").addEventListener("click", () => (tlTimer ? stopTL() : playTL()));
    let played = false;
    $("#ns-logic").addEventListener("toggle", e => {
      if (e.target.open) { showTL(tlCur); if (!played && !REDUCE) { played = true; playTL(); } } else stopTL();
    });
  }
  function showTL(i) {
    tlCur = i;
    $$("#ns-tl button").forEach((b, j) => { b.classList.toggle("on", j === i); b.classList.toggle("past", j < i); b.setAttribute("aria-selected", j === i); b.tabIndex = j === i ? 0 : -1; });
    const bar = $("#ns-tl .bar"), pct = (i / (TL.length - 1)) * 92;
    if (matchMedia("(max-width:860px)").matches) { bar.style.width = ""; bar.style.height = `calc(${(i / (TL.length - 1)) * 100}% - 20px)`; }
    else { bar.style.height = ""; bar.style.width = pct + "%"; }
    const s = TL[i], det = $("#ns-tldet");
    det.setAttribute("aria-labelledby", "ns-tl-" + i);
    det.innerHTML = `<h3><span class="ns-num">${i + 1}</span>${s.t}${s.key ? ' <span class="badge or">clé NAT</span>' : ""}</h3><p class="fade-up">${s.d}</p>`;
  }
  function playTL() {
    stopTL(); $("#ns-tl-play").textContent = "⏸ Pause";
    showTL(0);
    tlTimer = setInterval(() => { if (tlCur >= TL.length - 1) return stopTL(); showTL(tlCur + 1); }, 2600);
  }
  function stopTL() { clearInterval(tlTimer); tlTimer = null; $("#ns-tl-play").textContent = "▶ Lecture automatique"; }

  /* ================= INIT ================= */
  function init() {
    renderCards(); renderTL();
    writeForm(TOPO_DEF); fillSelects();
    AUTO.forEach(id => {
      const s = document.getElementById(id);
      s.insertAdjacentHTML("afterend", `<div class="hint" id="h-${id}" aria-live="polite"></div>`);
      s.setAttribute("aria-describedby", "h-" + id);
      s.addEventListener("change", () => { s.dataset.manual = "1"; badge(id, true); const h = $("#h-" + id); if (h) h.textContent = "↳ valeur choisie manuellement"; validate(false); });
    });
    const form = $("#ns-form");
    form.addEventListener("input", e => {
      if (e.target.id) e.target.dataset.touched = "1";
      if (/^t\d?-/.test(e.target.id)) fillSelects();
      autodetect(); validate(false);
    });
    form.addEventListener("change", e => { if (e.target.type === "checkbox" || e.target.tagName === "SELECT") validate(false); });
    form.addEventListener("submit", e => {
      e.preventDefault();
      const bad = validate(true);
      if (bad) { bad.focus(); PAN.toast("Corrigez les champs en rouge"); return; }
      model = build(read());
      renderResult(model); go(3);
    });
    $("#ns-load-lab").addEventListener("click", () => loadExample(scen));
    $("#ns-load-alt").addEventListener("click", () => {
      loadExample("dnat", true); writeForm(EX.dnatAlt); autodetect(); validate(false); PAN.toast("Variante port translation chargée");
    });
    $$("[data-go]").forEach(b => b.addEventListener("click", () => go(+b.dataset.go)));
    $("#ns-export").addEventListener("click", () => model && exportTxt(model));
    $("#ns-reset").addEventListener("click", () => {
      if (anim) cancelAnimationFrame(anim.raf);
      scen = null; model = null; $("#ns-res").innerHTML = "";
      $$(".ns-card").forEach(x => x.setAttribute("aria-pressed", "false"));
      go(1); PAN.toast("Assistant réinitialisé");
    });
    PAN.reveal && PAN.reveal();
  }
  init();
})();
