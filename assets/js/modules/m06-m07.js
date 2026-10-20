/* Modules M06 (politiques de sécurité : objets, tags, règles, règles par défaut) et M07 (NAT) */
(function () {
  const { register, q, members, yn, V } = PAN.cfg;

  /* =========================================================
     Helpers communs
     ========================================================= */
  const SIM_SEC = '<a href="simulateur-securite.html">Simulateur de règle de sécurité</a>';
  const SIM_NAT = '<a href="simulateur-nat.html">Simulateur NAT</a>';
  const toInt = s => PAN.ip.toInt(s);
  const isIp = s => PAN.ip.valid(s);
  const isCidr = s => String(s).includes("/") && PAN.ip.validCidr(s);
  const rangeParts = s => { const m = /^([\d.]+)-([\d.]+)$/.exec(String(s)); return m && isIp(m[1]) && isIp(m[2]) ? [m[1], m[2]] : null; };
  const isRange = s => { const r = rangeParts(s); return !!(r && toInt(r[0]) <= toInt(r[1])); };
  const isLit = s => isIp(s) || isCidr(s) || isRange(s);
  const hostOf = c => String(c).split("/")[0];
  const maskOf = c => { const m = String(c).split("/")[1]; return m === undefined ? 32 : +m; };
  const maskInt = m => (m === 0 ? 0 : (~0 << (32 - m)) >>> 0);
  const inNet = (ip, cidr) => { const m = maskOf(cidr); return ((toInt(ip) & maskInt(m)) >>> 0) === ((toInt(hostOf(cidr)) & maskInt(m)) >>> 0); };
  const anyL = a => !a || !a.length || (a.length === 1 && a[0] === "any");
  const disp = a => (anyL(a) ? "☑ Any" : a);
  const proto = p => (p === "udp" ? 17 : 6);
  /** Nombre d'IP couvertes par un littéral (null si objet). */
  const ipCount = s => { if (isRange(s)) { const r = rangeParts(s); return toInt(r[1]) - toInt(r[0]) + 1; } if (isIp(s)) return 1; if (isCidr(s)) return 2 ** (32 - maskOf(s)); return null; };
  /** Une IP appartient-elle à un littéral (IP, CIDR, plage) ? null si indéterminable (objet). */
  const covers = (tok, ip) => { if (tok === "any") return true; if (isRange(tok)) { const r = rangeParts(tok), n = toInt(ip); return n >= toInt(r[0]) && n <= toInt(r[1]); } if (isIp(tok)) return tok === ip; if (isCidr(tok)) return inNet(ip, tok); return null; };
  const coversAny = (list, ip) => { const r = list.map(t => covers(t, ip)); return r.includes(true) ? true : r.includes(null) ? null : false; };

  /* ---------- validateurs de listes ---------- */
  const noAnyMix = a => (a.length > 1 && a.includes("any") ? "« any » ne se combine pas avec d'autres valeurs" : null);
  const zonesV = a => noAnyMix(a) || V.listOf("name")(a);
  const addrV = a => {
    const e = noAnyMix(a); if (e) return e;
    for (const x of a) {
      if (x === "any" || isLit(x)) continue;
      if (/^[\d.\/-]+$/.test(x)) return `« ${x} » : IP, IP/masque ou plage (a.b.c.d-e.f.g.h) invalide`;
      if (V.name(x)) return `« ${x} » : ni une IP/CIDR/plage, ni un nom d'objet valide`;
    }
    return null;
  };
  const appsV = a => noAnyMix(a) || (a.find(x => !/^[a-z0-9][a-z0-9._-]{0,62}$/i.test(x)) ? `« ${a.find(x => !/^[a-z0-9][a-z0-9._-]{0,62}$/i.test(x))} » : nom d'application invalide (ex. web-browsing, ssl)` : null);
  const usersV = a => noAnyMix(a) || (a.find(x => /[\s"',;]/.test(x)) ? "Utilisateur/groupe invalide (ex. any, known-user, acme\\jdoe, cn=vpn,...)" : null);
  const catV = a => noAnyMix(a) || (a.find(x => !/^[a-z0-9][a-z0-9._-]*$/i.test(x)) ? "Catégorie URL invalide (ex. any, social-networking)" : null);
  const usersCli = a => { a = anyL(a) ? ["any"] : a; const m = a.map(u => (/[\\\s]/.test(u) ? `"${u}"` : u)); return m.length > 1 ? `[ ${m.join(" ")} ]` : m[0]; };

  /* ---------- objets adresse ---------- */
  const ADDR_LBL = { "ip-netmask": "IP Netmask", "ip-range": "IP Range", fqdn: "FQDN" };
  const litType = s => (isRange(s) ? "ip-range" : isIp(s) || isCidr(s) ? "ip-netmask" : null);
  const autoName = s => (isRange(s) ? "R-" + s : isCidr(s) && maskOf(s) < 32 ? `N-${hostOf(s)}-${maskOf(s)}` : "H-" + hostOf(s));
  /** Résout un jeton saisi : littéral → objet créé (si create) ; nom → objet existant. */
  function resolver(create, objs, tags) {
    return (tok, name, desc) => {
      if (tok === "any") return "any";
      const type = litType(tok);
      if (!type || !create) return tok;
      const ex = objs.find(o => o.value === tok);
      if (ex) return ex.name;
      objs.push({ name: name || autoName(tok), type, value: tok, desc: desc || "", tags: tags || [] });
      return objs[objs.length - 1].name;
    };
  }
  function addrStep(o) {
    return { title: `Créer l'objet adresse « ${o.name} »`, path: ["Objects", "Addresses"], action: "Cliquer sur Add.", window: "Address",
      fields: [["Name", o.name], ["Description", o.desc], ["Type", ADDR_LBL[o.type]], [ADDR_LBL[o.type], o.value], ["Tags", o.tags]] };
  }
  function addrCli(o) {
    return [`set address ${q(o.name)} ${o.type} ${o.value}`, o.desc && `set address ${q(o.name)} description ${q(o.desc)}`,
      o.tags && o.tags.length && `set address ${q(o.name)} tag ${members(o.tags)}`].filter(Boolean);
  }
  /* ---------- objets service ---------- */
  function svcStep(s) {
    return { title: `Créer l'objet service « ${s.name} »`, path: ["Objects", "Services"], action: "Cliquer sur Add.", window: "Service",
      fields: [["Name", s.name], ["Description", s.desc], ["Protocol", s.proto.toUpperCase()], ["Destination Port", s.port], ["Source Port", s.sport], ["Tags", s.tags]] };
  }
  function svcCli(s) {
    return [`set service ${q(s.name)} protocol ${s.proto} port ${s.port}${s.sport ? " source-port " + s.sport : ""}`,
      s.desc && `set service ${q(s.name)} description ${q(s.desc)}`, s.tags && s.tags.length && `set service ${q(s.name)} tag ${members(s.tags)}`].filter(Boolean);
  }

  /* ---------- profils ---------- */
  const PROF = [["virus", "Antivirus", "av"], ["spyware", "Anti-Spyware", "as"], ["vulnerability", "Vulnerability Protection", "vuln"],
    ["url-filtering", "URL Filtering", "url"], ["file-blocking", "File Blocking", "fb"], ["wildfire-analysis", "WildFire Analysis", "wf"]];
  const PROF_PREDEF = { av: "default", as: "strict", vuln: "strict", url: "default", fb: "basic file blocking", wf: "default" };
  const profNameV = v => (/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/.test(v) ? null : "Nom de profil invalide");

  /* ---------- déplacement de règle ---------- */
  const POS_OPTS = [["bottom", "En bas (Move Bottom)"], ["top", "En haut (Move Top)"], ["before", "Avant la règle…"], ["after", "Après la règle…"]];
  function moveRule(kind, name, pos, ref) {
    const path = ["Policies", kind === "nat" ? "NAT" : "Security"];
    const base = `move rulebase ${kind} rules ${q(name)}`;
    if (pos === "top" || pos === "bottom") {
      const lbl = pos === "top" ? "Move Top" : "Move Bottom";
      return { step: { title: `Positionner la règle (${lbl})`, path, action: `Sélectionner la ligne « ${name} » sans l'ouvrir → bouton Move (en bas) → ${lbl}.`, fields: [] }, cli: [`${base} ${pos}`] };
    }
    return { step: { title: `Positionner la règle ${pos === "before" ? "avant" : "après"} « ${ref} »`, path,
      action: `Glisser-déposer la ligne « ${name} » juste ${pos === "before" ? "au-dessus" : "en dessous"} de « ${ref} » (ou Move > Move Up / Move Down).`, fields: [] },
      cli: [`${base} ${pos} ${q(ref)}`] };
  }

  /* ---------- règle de sécurité (générique) ---------- */
  /* r = { name, desc, tags[], type, from[], to[], src[], dst[], user[], app[], svc[], cat[], action, prof:{mode, group, p:{av..wf}},
           logStart, logEnd, logFwd, pos, ref } ; o = { compact, gold:{zone, addr} } */
  function secRule(r, o = {}) {
    const intra = r.type === "intrazone", allow = r.action === "allow";
    const to = intra ? r.from : r.to;
    const prof = allow ? r.prof || { mode: "none" } : { mode: "none" };
    const W = "Security Policy Rule", P = ["Policies", "Security"];
    const steps = [
      { title: `Règle « ${r.name} » — onglet General`, path: P, tab: "General", window: W, action: "Cliquer sur Add (en bas de la fenêtre).",
        fields: [["Name", r.name], ["Rule Type", r.type + (r.type === "universal" ? " (default)" : "")], ["Description", r.desc], ["Tags", r.tags]] },
      { title: "Onglet Source", path: P, tab: "Source", window: W,
        fields: [["Source Zone", anyL(r.from) ? "☑ Any" : r.from], ["Source Address", disp(r.src)]],
        note: o.compact ? "Adresse source = IP d'origine (avant source NAT)." : "" },
    ];
    if (!o.compact || !anyL(r.user)) steps.push({ title: "Onglet User", path: P, tab: "User", window: W, fields: [["Source User", anyL(r.user) ? "any" : r.user]] });
    steps.push({ title: "Onglet Destination", path: P, tab: "Destination", window: W,
      fields: [["Destination Zone", intra ? "(grisé : intrazone = zone source)" : anyL(to) ? "☑ Any" : to], ["Destination Address", disp(r.dst)]],
      note: o.gold ? `Règle NAT : Destination Zone = ${o.gold.zone} (zone POST-NAT, celle du serveur) ; Destination Address = ${o.gold.addr} (IP PRÉ-NAT, publique).` : "" });
    const appF = ["Applications", disp(r.app)], svcF = [["Service", r.svc], ["URL Category", anyL(r.cat) ? "☑ Any" : r.cat]];
    if (o.compact) steps.push({ title: "Onglets Application et Service/URL Category", path: P, tab: "Application · Service/URL Category", window: W, fields: [appF, ...svcF],
      note: "Le service est évalué sur le port d'ORIGINE (avant traduction de port)." });
    else steps.push({ title: "Onglet Application", path: P, tab: "Application", window: W, fields: [appF] },
      { title: "Onglet Service/URL Category", path: P, tab: "Service/URL Category", window: W, fields: svcF });
    const pf = prof.mode === "group" ? [["Profile Type", "Group"], ["Group Profile", prof.group]]
      : prof.mode === "profiles" ? [["Profile Type", "Profiles"], ...PROF.map(([, l, k]) => [l, prof.p[k] || "None"])] : [["Profile Type", "None"]];
    steps.push({ title: "Onglet Actions puis OK", path: P, tab: "Actions", window: W, action: "Renseigner l'onglet Actions puis cliquer sur OK.",
      fields: [["Action", { allow: "Allow", deny: "Deny", drop: "Drop", "reset-client": "Reset client", "reset-server": "Reset server", "reset-both": "Reset both client and server" }[r.action]],
        ...pf, ["Log at Session Start", !!r.logStart], ["Log at Session End", r.logEnd ? true : "☐ décoché"], ["Log Forwarding", r.logFwd]] });

    const base = `set rulebase security rules ${q(r.name)}`;
    const cli = [`${base} from ${members(anyL(r.from) ? ["any"] : r.from)} to ${members(anyL(to) ? ["any"] : to)} source ${members(anyL(r.src) ? ["any"] : r.src)} destination ${members(anyL(r.dst) ? ["any"] : r.dst)} source-user ${usersCli(r.user)} category ${members(anyL(r.cat) ? ["any"] : r.cat)} application ${members(anyL(r.app) ? ["any"] : r.app)} service ${members(r.svc)} action ${r.action}`];
    if (r.desc) cli.push(`${base} description ${q(r.desc)}`);
    if (r.tags && r.tags.length) cli.push(`${base} tag ${members(r.tags)}`);
    if (r.type !== "universal") cli.push(`${base} rule-type ${r.type}`);
    if (prof.mode === "group") cli.push(`${base} profile-setting group ${q(prof.group)}`);
    if (prof.mode === "profiles") { const p = PROF.filter(([, , k]) => prof.p[k]).map(([c, , k]) => `${c} ${q(prof.p[k])}`).join(" "); if (p) cli.push(`${base} profile-setting profiles ${p}`); }
    cli.push(`${base} log-start ${yn(r.logStart)} log-end ${yn(r.logEnd)}`);
    if (r.logFwd) cli.push(`${base} log-setting ${q(r.logFwd)}`);
    if (r.pos && r.pos !== "none") { const m = moveRule("security", r.name, r.pos, r.ref); steps.push(m.step); cli.push(...m.cli); }
    return { steps, cli };
  }
  const secTest = t => `test security-policy-match from ${t.from} to ${t.to} source ${t.src} destination ${t.dst}${t.port ? " destination-port " + t.port : ""} protocol ${t.proto}${t.app && t.app !== "any" ? " application " + t.app : ""}${t.user && t.user !== "any" ? " source-user " + (/[\\\s]/.test(t.user) ? `"${t.user}"` : t.user) : ""}`;
  const natTest = t => `test nat-policy-match from ${t.from} to ${t.to}${t.toIf ? " to-interface " + t.toIf : ""} source ${t.src} destination ${t.dst} destination-port ${t.port} protocol ${t.proto}`;

  /* ---------- règle NAT (générique) ---------- */
  /* n = { name, desc, from[], to, toIf, svc, src[], dst[], st:{type:none|dipp-if|dipp-tr|dynamic-ip|static-ip, iface, ip, translated[], bidir, fb:{type, iface, ip, addr}}, dt:{addr, port}|null, pos, ref } */
  function natRule(n) {
    const W = "NAT Policy Rule", P = ["Policies", "NAT"], st = n.st, base = `set rulebase nat rules ${q(n.name)}`;
    const tr = [];
    const ST = { none: "None", "dipp-if": "Dynamic IP And Port", "dipp-tr": "Dynamic IP And Port", "dynamic-ip": "Dynamic IP", "static-ip": "Static IP" };
    tr.push(["Source Address Translation — Translation Type", ST[st.type]]);
    if (st.type === "dipp-if") tr.push(["Address Type", "Interface Address"], ["Interface", st.iface], ["IP Address", st.ip]);
    if (st.type === "dipp-tr") tr.push(["Address Type", "Translated Address"], ["Translated Address", st.translated]);
    if (st.type === "dynamic-ip") {
      tr.push(["Translated Address", st.translated]);
      if (st.fb && st.fb.type !== "none") tr.push(["Advanced (Dynamic IP/Port Fallback)", "Dynamic IP And Port"], ["Fallback — Address Type", st.fb.type === "interface" ? "Interface Address" : "Translated Address"],
        ...(st.fb.type === "interface" ? [["Fallback — Interface", st.fb.iface], ["Fallback — IP Address", st.fb.ip]] : [["Fallback — Translated Address", st.fb.addr]]));
    }
    if (st.type === "static-ip") tr.push(["Translated Address", st.translated[0]], ["Bi-directional", st.bidir ? true : "☐ No"]);
    tr.push(["Destination Address Translation — Translation Type", n.dt ? "Static IP" : "None"]);
    if (n.dt) tr.push(["Translated Address", n.dt.addr], ["Translated Port", n.dt.port || "(vide : port inchangé)"]);
    const steps = [
      { title: `Règle NAT « ${n.name} » — onglet General`, path: P, tab: "General", window: W, action: "Cliquer sur Add.",
        fields: [["Name", n.name], ["Description", n.desc], ["Tags", n.tags], ["NAT Type", "ipv4"]] },
      { title: "Onglet Original Packet (valeurs PRÉ-NAT)", path: P, tab: "Original Packet", window: W,
        fields: [["Source Zone", n.from], ["Destination Zone", n.to], ["Destination Interface", n.toIf || "any"], ["Service", n.svc], ["Source Address", disp(n.src)], ["Destination Address", disp(n.dst)]],
        note: n.dt ? `Destination Zone = zone où « vit » l'IP d'origine ${n.dstRaw || ""} (route lookup sur l'IP pré-NAT), pas la zone du serveur.` : "" },
      { title: "Onglet Translated Packet puis OK", path: P, tab: "Translated Packet", window: W, action: "Renseigner les sections Source / Destination Address Translation puis cliquer sur OK.", fields: tr },
    ];
    const cli = [`${base} nat-type ipv4 from ${members(n.from)} to ${q(n.to)}${n.toIf ? " to-interface " + n.toIf : ""} source ${members(anyL(n.src) ? ["any"] : n.src)} destination ${members(anyL(n.dst) ? ["any"] : n.dst)} service ${q(n.svc)}`];
    if (n.desc) cli.push(`${base} description ${q(n.desc)}`);
    if (n.tags && n.tags.length) cli.push(`${base} tag ${members(n.tags)}`);
    if (st.type === "dipp-if") cli.push(`${base} source-translation dynamic-ip-and-port interface-address interface ${st.iface} ip ${st.ip}`);
    if (st.type === "dipp-tr") cli.push(`${base} source-translation dynamic-ip-and-port translated-address ${members(st.translated)}`);
    if (st.type === "dynamic-ip") {
      cli.push(`${base} source-translation dynamic-ip translated-address ${members(st.translated)}`);
      if (st.fb && st.fb.type === "interface") cli.push(`${base} source-translation dynamic-ip fallback interface-address interface ${st.fb.iface} ip ${st.fb.ip}`);
      if (st.fb && st.fb.type === "translated") cli.push(`${base} source-translation dynamic-ip fallback translated-address ${q(st.fb.addr)}`);
    }
    if (st.type === "static-ip") cli.push(`${base} source-translation static-ip translated-address ${q(st.translated[0])} bi-directional ${yn(st.bidir)}`);
    if (n.dt) cli.push(`${base} destination-translation translated-address ${q(n.dt.addr)}${n.dt.port ? " translated-port " + n.dt.port : ""}`);
    if (n.pos) { const m = moveRule("nat", n.name, n.pos, n.ref); steps.push(m.step); cli.push(...m.cli); }
    return { steps, cli };
  }

  /* ---------- champs partagés des modules NAT ---------- */
  const NAT_POS = [["top", "En haut (Move Top) — recommandé"], ["bottom", "En bas (Move Bottom)"], ["before", "Avant la règle…"], ["after", "Après la règle…"]];
  const posRefField = (id, g) => ({ id, label: "Règle de référence", type: "text", validate: "name", required: true, show: v => v[id.replace("ref", "pos")] === "before" || v[id.replace("ref", "pos")] === "after", group: g });
  function secFields(d, svcOpts) {
    const G = "Règle de sécurité associée", on = v => v.mksec;
    return [
      { id: "mksec", label: "Créer la règle de sécurité associée", type: "checkbox", default: true, group: G },
      { id: "secname", label: "Nom de la règle de sécurité", type: "text", validate: "name", required: true, default: d.name, show: on, group: G },
      { id: "secapps", label: "Applications", type: "list", validate: appsV, required: true, default: d.apps, show: on, group: G, hint: "any ou App-ID (web-browsing, ssl, dns…)" },
      { id: "secsvc", label: "Service", type: "select", default: "application-default", options: svcOpts || [["application-default", "application-default"], ["any", "any"]], show: on, group: G },
      { id: "secprof", label: "Profils de sécurité", type: "select", default: "group", show: on, group: G,
        options: [["group", "Profile Group"], ["profiles", "Profils prédéfinis (default / strict)"], ["none", "Aucun"]] },
      { id: "secgroup", label: "Nom du Profile Group", type: "text", validate: "name", required: true, default: "Std-Profiles", show: v => v.mksec && v.secprof === "group", group: G, hint: "Doit exister (Objects > Security Profile Groups)." },
    ];
  }
  const secProf = v => (v.secprof === "group" ? { mode: "group", group: v.secgroup } : v.secprof === "profiles" ? { mode: "profiles", p: PROF_PREDEF } : { mode: "none" });
  const natRelSec = (v, r, gold) => secRule({ name: v.secname, desc: r.desc, tags: [], type: "universal", from: r.from, to: [r.to], src: r.src, dst: r.dst, user: ["any"],
    app: v.secapps, svc: [r.svc], cat: ["any"], action: "allow", prof: secProf(v), logStart: false, logEnd: true, logFwd: "", pos: "none" }, { compact: true, gold });
  const secNotes = v => {
    const n = [];
    if (v.mksec && v.secprof === "none") n.push({ type: "warn", text: "Règle allow sans profil de sécurité : le trafic autorisé n'est pas inspecté (AV, vulnérabilités, WildFire)." });
    if (v.mksec && anyL(v.secapps) && v.secsvc === "any") n.push({ type: "warn", text: "Application any + service any : la règle ouvre tous les ports. Préférer des App-ID avec application-default." });
    return n;
  };
  const natVerifyTail = (t, natKind) => [
    "# Sessions (valeurs d'origine, flux c2s)",
    `show session all filter source ${t.src} destination ${t.dst}${t.port ? " destination-port " + t.port : ""}`,
    `show session all filter nat ${natKind}`,
    "show session id <ID>          # flux c2s / s2c : la traduction y apparaît",
    "show running nat-policy",
  ];
  const tagsV = a => V.listOf("name")(a);

  /* =========================================================
     M06 · Objets adresse
     ========================================================= */
  const parseKV = s => { const i = s.indexOf("="); return i < 0 ? null : [s.slice(0, i).trim(), s.slice(i + 1).trim()]; };
  const addrKind = val => (isRange(val) ? "ip-range" : isIp(val) || isCidr(val) ? "ip-netmask" : V.fqdn(val) === null ? "fqdn" : null);
  register({
    id: "m06-address-objects", module: "M06", title: "Objets adresse & groupe", icon: "📇",
    desc: "Créer plusieurs objets adresse (IP Netmask, IP Range, FQDN) en une fois, avec tags et groupe d'adresses statique optionnel.",
    tags: "address objet adresse fqdn range netmask groupe address-group",
    fields: [
      { id: "entries", label: "Objets (nom=valeur)", type: "list", required: true, wide: true, group: "Objets",
        default: ["Net-LAN=192.168.1.0/24", "Srv-Web-DMZ=172.16.1.10", "Range-DHCP-LAN=192.168.1.100-192.168.1.200", "FQDN-Updates=updates.paloaltonetworks.com"],
        hint: "Séparés par des virgules. Type déduit : 10.0.0.1 ou 10.0.0.0/24 → IP Netmask ; 10.0.0.10-10.0.0.20 → IP Range ; nom DNS → FQDN.",
        validate: arr => {
          const seen = new Set();
          for (const e of arr) {
            const kv = parseKV(e); if (!kv) return `« ${e} » : format nom=valeur attendu`;
            const [n, val] = kv; const en = V.name(n); if (en) return `« ${n} » : ${en}`;
            if (seen.has(n.toLowerCase())) return `Nom en double : ${n}`; seen.add(n.toLowerCase());
            if (rangeParts(val) && !isRange(val)) return `« ${val} » : la plage doit être croissante`;
            if (!addrKind(val)) return `« ${val} » : IP, IP/masque, plage ou FQDN attendu`;
          }
          return null;
        } },
      { id: "desc", label: "Description (commune)", type: "text", default: "", placeholder: "Serveurs exposés en DMZ" },
      { id: "tags", label: "Tags", type: "list", validate: tagsV, default: [], placeholder: "DMZ, Prod" },
      { id: "mktags", label: "Créer ces tags (s'ils n'existent pas)", type: "checkbox", default: true, show: v => v.tags.length > 0 },
      { id: "tagcolor", label: "Couleur des tags créés", type: "select", default: "color3", show: v => v.tags.length > 0 && v.mktags, options: [] },
      { id: "mkgrp", label: "Créer un groupe d'adresses statique", type: "checkbox", default: true, group: "Groupe d'adresses" },
      { id: "grpname", label: "Nom du groupe", type: "text", validate: (x, v) => V.name(x) || (v.entries.some(e => (parseKV(e) || [])[0] === x) ? "Nom déjà utilisé par un objet" : null), required: true, default: "Grp-Internal", show: v => v.mkgrp },
      { id: "grpmembers", label: "Membres (vide = tous les objets ci-dessus)", type: "list", validate: tagsV, default: ["Net-LAN", "Srv-Web-DMZ"], show: v => v.mkgrp, hint: "Noms d'objets ci-dessus ou existants." },
    ],
    build(v) {
      const objs = v.entries.map(e => { const [name, value] = parseKV(e); return { name, value, type: addrKind(value), desc: v.desc, tags: v.tags }; });
      const steps = [], cli = [];
      if (v.tags.length && v.mktags) v.tags.forEach(t => { steps.push(tagStep(t, v.tagcolor, "")); cli.push(tagCli(t, v.tagcolor, "")); });
      objs.forEach(o => { steps.push(addrStep(o)); cli.push(...addrCli(o)); });
      const mem = v.grpmembers.length ? v.grpmembers : objs.map(o => o.name);
      if (v.mkgrp) {
        steps.push({ title: `Créer le groupe « ${v.grpname} »`, path: ["Objects", "Address Groups"], action: "Cliquer sur Add, puis Add sous la liste des adresses pour chaque membre.", window: "Address Group",
          fields: [["Name", v.grpname], ["Description", v.desc], ["Type", "Static"], ["Addresses", mem], ["Tags", v.tags]] });
        cli.push(`set address-group ${q(v.grpname)} static ${members(mem)}`);
        if (v.desc) cli.push(`set address-group ${q(v.grpname)} description ${q(v.desc)}`);
        if (v.tags.length) cli.push(`set address-group ${q(v.grpname)} tag ${members(v.tags)}`);
      }
      const notes = [];
      const unknown = v.mkgrp ? v.grpmembers.filter(m => !objs.some(o => o.name === m)) : [];
      if (unknown.length) notes.push({ type: "warn", text: `Membres non définis ici, ils doivent déjà exister : ${unknown.join(", ")}.` });
      if (objs.some(o => o.type === "fqdn")) notes.push({ type: "or", text: "Objets FQDN : le pare-feu résout le nom via ses serveurs DNS (Device > Setup > Services) et rafraîchit périodiquement." });
      const badNet = objs.filter(o => o.type === "ip-netmask" && isCidr(o.value) && maskOf(o.value) < 32 && (toInt(hostOf(o.value)) & ~maskInt(maskOf(o.value))) !== 0);
      if (badNet.length) notes.push({ type: "warn", text: `Bits d'hôte non nuls (${badNet.map(o => o.value).join(", ")}) : accepté, mais vérifie s'il s'agit d'un réseau ou d'un hôte.` });
      return { steps, cli, notes,
        verify: [...objs.map(o => `show config running | match "${o.name}"`), ...(objs.some(o => o.type === "fqdn") ? ["request system fqdn show"] : [])] };
    },
  });

  /* =========================================================
     M06 · Tags
     ========================================================= */
  const COLORS = [["color1", "Red"], ["color2", "Green"], ["color3", "Blue"], ["color4", "Yellow"], ["color5", "Copper"], ["color6", "Orange"], ["color7", "Purple"],
    ["color8", "Gray"], ["color9", "Light Green"], ["color10", "Cyan"], ["color11", "Light Gray"], ["color12", "Blue Gray"], ["color13", "Lime"], ["color14", "Black"],
    ["color15", "Gold"], ["color16", "Brown"], ["color17", "Olive"], ["color19", "Maroon"], ["color20", "Red-Orange"], ["color21", "Yellow-Orange"], ["color22", "Forest Green"],
    ["color23", "Turquoise Blue"], ["color24", "Azure Blue"], ["color25", "Cerulean Blue"], ["color26", "Midnight Blue"], ["color27", "Medium Blue"], ["color28", "Cobalt Blue"],
    ["color29", "Violet Blue"], ["color30", "Blue Violet"], ["color31", "Medium Violet"], ["color32", "Medium Rose"], ["color33", "Lavender"], ["color34", "Orchid"],
    ["color35", "Thistle"], ["color36", "Peach"], ["color37", "Salmon"], ["color38", "Magenta"], ["color39", "Red Violet"], ["color40", "Mahogany"], ["color41", "Burnt Sienna"], ["color42", "Chestnut"]];
  const colorOf = s => { s = String(s || "").trim().toLowerCase(); if (!s) return null; const c = COLORS.find(([k, l]) => k === s || l.toLowerCase() === s); return c ? c[0] : undefined; };
  const colorLbl = k => (COLORS.find(c => c[0] === k) || [k, "None"])[1];
  function tagStep(name, color, comments) {
    return { title: `Créer le tag « ${name} »`, path: ["Objects", "Tags"], action: "Cliquer sur Add.", window: "Tag", fields: [["Name", name], ["Color", color ? colorLbl(color) : "None"], ["Comments", comments]] };
  }
  const tagCli = (name, color, comments) => `set tag ${q(name)}${color ? " color " + color : ""}${comments ? " comments " + q(comments) : ""}`;

  register({
    id: "m06-tags", module: "M06", title: "Tags", icon: "🏷️",
    desc: "Créer des tags colorés pour classer règles et objets (filtrage, Group Rules By Tag).",
    tags: "tag couleur color étiquette",
    fields: [
      { id: "entries", label: "Tags (nom=couleur)", type: "list", required: true, wide: true,
        default: ["Internet-Access=Blue", "DMZ=Orange", "Block=Red", "Prod=Green"],
        hint: "Couleur par nom anglais (Red, Green, Blue, Yellow, Orange, Purple, Gray, Cyan, Gold, Brown…) ou colorN ; « =» vide → sans couleur.",
        validate: arr => {
          const seen = new Set();
          for (const e of arr) {
            const kv = parseKV(e) || [e, ""]; const [n, c] = kv; const en = V.name(n); if (en) return `« ${n} » : ${en}`;
            if (n.length > 127) return "Nom trop long";
            if (seen.has(n.toLowerCase())) return `Tag en double : ${n}`; seen.add(n.toLowerCase());
            if (c && colorOf(c) === undefined) return `Couleur inconnue : ${c}`;
          }
          return null;
        } },
      { id: "comments", label: "Commentaire (commun)", type: "text", default: "" },
    ],
    build(v) {
      const tags = v.entries.map(e => { const [n, c] = parseKV(e) || [e, ""]; return { n, c: colorOf(c) }; });
      return {
        steps: tags.map(t => tagStep(t.n, t.c, v.comments)),
        cli: tags.map(t => tagCli(t.n, t.c, v.comments)),
        verify: ["show config running | match color"],
        notes: [{ type: "or", text: "Policies > Security : activer « Group Rules By Tag » (en bas) pour regrouper visuellement les règles ; le premier tag d'une règle détermine son groupe." }],
      };
    },
  });

  /* =========================================================
     M06 · Objets service
     ========================================================= */
  const SVC_RE = /^([^=]+)=\s*(tcp|udp)\/([\d,-]+)(?:\s+src\s*=?\s*([\d,-]+))?$/i;
  register({
    id: "m06-service-objects", module: "M06", title: "Objets service & groupe", icon: "🔌",
    desc: "Créer des objets service TCP/UDP (port destination, port source optionnel) et un groupe de services.",
    tags: "service port tcp udp service-group",
    fields: [
      { id: "entries", label: "Services (nom=proto/port)", type: "textarea", required: true, wide: true,
        default: "tcp-8080=tcp/8080\ntcp-8443=tcp/8443\nWeb-Alt-Range=tcp/8000-8090\nudp-syslog=udp/514",
        hint: "Un service par ligne : nom=tcp/8080 · plage tcp/8000-8090 · liste tcp/80,8080 · port source optionnel : nom=udp/514 src 1024-65535.",
        validate: txt => {
          const seen = new Set();
          for (const l of txt.split("\n").map(s => s.trim()).filter(Boolean)) {
            const m = SVC_RE.exec(l); if (!m) return `« ${l} » : format nom=tcp/port attendu`;
            const n = m[1].trim(), en = V.name(n); if (en) return `« ${n} » : ${en}`;
            if (seen.has(n.toLowerCase())) return `Nom en double : ${n}`; seen.add(n.toLowerCase());
            if (V.portrange(m[3])) return `« ${m[3]} » : ${V.portrange(m[3])}`;
            if (m[4] && V.portrange(m[4])) return `Port source « ${m[4]} » : ${V.portrange(m[4])}`;
          }
          return null;
        } },
      { id: "desc", label: "Description (commune)", type: "text", default: "" },
      { id: "tags", label: "Tags", type: "list", validate: tagsV, default: [], hint: "Les tags doivent exister (module Tags)." },
      { id: "mkgrp", label: "Créer un groupe de services", type: "checkbox", default: true, group: "Groupe de services" },
      { id: "grpname", label: "Nom du groupe", type: "text", validate: "name", required: true, default: "Grp-Web-Services", show: v => v.mkgrp },
      { id: "grpmembers", label: "Membres (vide = tous les services ci-dessus)", type: "list", validate: tagsV, default: ["tcp-8080", "tcp-8443", "service-https"], show: v => v.mkgrp,
        hint: "service-http et service-https sont prédéfinis." },
    ],
    build(v) {
      const svcs = v.entries.split("\n").map(s => s.trim()).filter(Boolean).map(l => { const m = SVC_RE.exec(l); return { name: m[1].trim(), proto: m[2].toLowerCase(), port: m[3], sport: m[4] || "", desc: v.desc, tags: v.tags }; });
      const steps = svcs.map(svcStep), cli = svcs.flatMap(svcCli);
      const mem = v.grpmembers.length ? v.grpmembers : svcs.map(s => s.name);
      if (v.mkgrp) {
        steps.push({ title: `Créer le groupe « ${v.grpname} »`, path: ["Objects", "Service Groups"], action: "Cliquer sur Add, puis Add pour chaque service membre.", window: "Service Group",
          fields: [["Name", v.grpname], ["Services", mem], ["Tags", v.tags]] });
        cli.push(`set service-group ${q(v.grpname)} members ${members(mem)}`);
        if (v.tags.length) cli.push(`set service-group ${q(v.grpname)} tag ${members(v.tags)}`);
      }
      const notes = [{ type: "or", text: "Dans une règle de sécurité, un service personnalisé remplace application-default : l'App-ID est alors autorisé uniquement sur ces ports." }];
      if (svcs.some(s => s.sport)) notes.push({ type: "warn", text: "Port source renseigné : la plupart des clients utilisent un port source éphémère aléatoire ; ne le restreindre que si l'application l'impose." });
      const unknown = v.mkgrp ? v.grpmembers.filter(m => !svcs.some(s => s.name === m) && !/^service-https?$/.test(m)) : [];
      if (unknown.length) notes.push({ type: "warn", text: `Membres non définis ici, ils doivent déjà exister : ${unknown.join(", ")}.` });
      return { steps, cli, notes, verify: svcs.map(s => `show config running | match "${s.name}"`) };
    },
  });

  /* =========================================================
     M06 · Règle de sécurité
     ========================================================= */
  register({
    id: "m06-security-rule", module: "M06", title: "Règle de sécurité", icon: "🛡️",
    desc: "Source, destination, application/port → règle de sécurité complète : objets, onglets WebUI, profils, logs, position et test.",
    tags: "security policy règle rule allow deny application-default profile log",
    fields: [
      { id: "name", label: "Nom de la règle", type: "text", validate: "name", required: true, default: "Allow-Web-DMZ", group: "General" },
      { id: "desc", label: "Description", type: "text", default: "Accès LAN vers le serveur web DMZ" },
      { id: "tags", label: "Tags", type: "list", validate: tagsV, default: [], hint: "Doivent exister (module Tags)." },
      { id: "type", label: "Rule Type", type: "select", default: "universal", options: [["universal", "universal (défaut)"], ["interzone", "interzone"], ["intrazone", "intrazone"]] },
      { id: "from", label: "Zone(s) source", type: "list", validate: zonesV, required: true, default: ["Trust"], group: "Source" },
      { id: "src", label: "Adresse(s) source", type: "list", validate: addrV, required: true, default: ["192.168.1.0/24"], hint: "any, IP, IP/masque, plage ou nom d'objet existant." },
      { id: "user", label: "Source User", type: "list", validate: usersV, required: true, default: ["any"], hint: "any, known-user, unknown, domaine\\groupe…" },
      { id: "to", label: "Zone(s) destination", type: "list", validate: (a, v) => zonesV(a) || (v.type === "interzone" && a.some(z => v.from.includes(z)) ? "interzone : zones source et destination doivent différer" : null),
        required: true, default: ["DMZ"], show: v => v.type !== "intrazone", group: "Destination" },
      { id: "dst", label: "Adresse(s) destination", type: "list", validate: addrV, required: true, default: ["172.16.1.10"] },
      { id: "mkobj", label: "Créer des objets adresse pour les IP saisies", type: "checkbox", default: true, hint: "Noms générés : N-192.168.1.0-24, H-172.16.1.10, R-…" },
      { id: "app", label: "Applications", type: "list", validate: appsV, required: true, default: ["web-browsing", "ssl"], group: "Application & service" },
      { id: "svcmode", label: "Service", type: "select", default: "application-default",
        options: [["application-default", "application-default (recommandé)"], ["any", "any"], ["custom", "Ports personnalisés (objet service créé)"], ["existing", "Objet(s) service existant(s)"]] },
      { id: "svcproto", label: "Protocole", type: "select", default: "tcp", options: [["tcp", "TCP"], ["udp", "UDP"]], show: v => v.svcmode === "custom" },
      { id: "svcports", label: "Port(s) destination", type: "text", validate: "portrange", required: true, default: "8080", show: v => v.svcmode === "custom" },
      { id: "svcname", label: "Nom de l'objet service", type: "text", validate: "name", default: "", placeholder: "auto : tcp-8080", show: v => v.svcmode === "custom" },
      { id: "svcexist", label: "Objet(s) service", type: "list", validate: tagsV, required: true, default: ["service-https"], show: v => v.svcmode === "existing" },
      { id: "cat", label: "URL Category", type: "list", validate: catV, required: true, default: ["any"] },
      { id: "action", label: "Action", type: "select", default: "allow", group: "Actions",
        options: [["allow", "Allow"], ["deny", "Deny"], ["drop", "Drop"], ["reset-client", "Reset client"], ["reset-server", "Reset server"], ["reset-both", "Reset both"]] },
      { id: "profmode", label: "Profile Type", type: "select", default: "group", show: v => v.action === "allow",
        options: [["group", "Group (Profile Group)"], ["profiles", "Profiles (individuels)"], ["none", "None"]] },
      { id: "group", label: "Group Profile", type: "text", validate: "name", required: true, default: "Std-Profiles", show: v => v.action === "allow" && v.profmode === "group", hint: "Doit exister (Objects > Security Profile Groups)." },
      ...PROF.map(([, l, k]) => ({ id: "p_" + k, label: l, type: "text", validate: profNameV, default: PROF_PREDEF[k], show: v => v.action === "allow" && v.profmode === "profiles", hint: k === "av" ? "Vide = None. Prédéfinis : default / strict." : "" })),
      { id: "logStart", label: "Log at Session Start", type: "checkbox", default: false },
      { id: "logEnd", label: "Log at Session End", type: "checkbox", default: true },
      { id: "logFwd", label: "Log Forwarding (profil)", type: "text", validate: "name", default: "", placeholder: "Std-Log-Forwarding" },
      { id: "pos", label: "Position", type: "select", default: "bottom", options: POS_OPTS, group: "Position" },
      { id: "ref", label: "Règle de référence", type: "text", validate: "name", required: true, default: "", show: v => v.pos === "before" || v.pos === "after" },
      { id: "tsrc", label: "IP source de test", type: "ip", required: true, default: "192.168.1.50", group: "Test (test security-policy-match)" },
      { id: "tdst", label: "IP destination de test", type: "ip", required: true, default: "172.16.1.10" },
      { id: "tproto", label: "Protocole", type: "select", default: "tcp", options: [["tcp", "TCP (6)"], ["udp", "UDP (17)"]] },
      { id: "tport", label: "Port destination", type: "port", required: true, default: "443" },
    ],
    build(v) {
      const objs = [], R = resolver(v.mkobj, objs, []);
      const src = anyL(v.src) ? ["any"] : v.src.map(t => R(t));
      const dst = anyL(v.dst) ? ["any"] : v.dst.map(t => R(t));
      const steps = [], cli = [], svcs = [];
      objs.forEach(o => { steps.push(addrStep(o)); cli.push(...addrCli(o)); });
      let svc = [v.svcmode];
      if (v.svcmode === "custom") { const s = { name: v.svcname || `${v.svcproto}-${v.svcports.replace(/,/g, "_")}`, proto: v.svcproto, port: v.svcports, sport: "", desc: "", tags: [] }; svcs.push(s); svc = [s.name]; }
      if (v.svcmode === "existing") svc = v.svcexist;
      svcs.forEach(s => { steps.push(svcStep(s)); cli.push(...svcCli(s)); });
      const intra = v.type === "intrazone";
      const r = secRule({ name: v.name, desc: v.desc, tags: v.tags, type: v.type, from: v.from, to: intra ? v.from : v.to, src, dst, user: v.user, app: v.app, svc, cat: v.cat,
        action: v.action, prof: { mode: v.profmode, group: v.group, p: { av: v.p_av, as: v.p_as, vuln: v.p_vuln, url: v.p_url, fb: v.p_fb, wf: v.p_wf } },
        logStart: v.logStart, logEnd: v.logEnd, logFwd: v.logFwd, pos: v.pos, ref: v.ref });
      steps.push(...r.steps); cli.push(...r.cli);

      const notes = [{ type: "or", html: `Visualiser le matching, le shadowing et la position dans la rulebase : ${SIM_SEC}.` }];
      const allow = v.action === "allow";
      if (allow && anyL(v.app)) notes.push({ type: "warn", text: "Applications any : la règle ne tire pas parti d'App-ID. Lister les applications (et leurs dépendances)." });
      if (allow && v.svcmode === "any" && !anyL(v.app)) notes.push({ type: "warn", text: "Service any : les applications sont autorisées sur tous les ports. Préférer application-default." });
      if (!allow && v.svcmode === "application-default") notes.push({ type: "warn", text: "Règle de blocage : utiliser Service = any, sinon l'application est bloquée uniquement sur ses ports par défaut." });
      if (allow && v.profmode === "none") notes.push({ type: "warn", text: "Allow sans profil : aucune inspection AV / vulnérabilités / WildFire sur ce trafic." });
      if (!v.logEnd) notes.push({ type: "warn", text: "Log at Session End désactivé : la règle n'apparaîtra pas dans le Traffic log." });
      if (v.logStart) notes.push({ type: "or", text: "Log at Session Start : à réserver au dépannage (volume de logs élevé)." });
      if (!v.desc) notes.push({ type: "or", text: "Ajouter une description : elle facilite les audits et le nettoyage de la rulebase." });
      if (v.pos === "bottom") notes.push({ type: "or", text: "Les règles sont évaluées de haut en bas (first match) : placer les règles spécifiques au-dessus des règles larges." });
      const inS = coversAny(v.src, v.tsrc), inD = coversAny(v.dst, v.tdst);
      if (inS === false || inD === false) notes.push({ type: "warn", text: `Les IP de test (${v.tsrc} → ${v.tdst}) ne correspondent pas aux adresses de la règle : le test ne la matchera pas.` });
      const toT = intra ? v.from[0] : (anyL(v.to) ? "<zone>" : v.to[0]);
      return { steps, cli, notes,
        verify: [secTest({ from: anyL(v.from) ? "<zone>" : v.from[0], to: toT, src: v.tsrc, dst: v.tdst, port: v.tport, proto: proto(v.tproto), app: anyL(v.app) ? "" : v.app[0], user: anyL(v.user) ? "" : v.user[0] }),
          `show running security-policy | match "${v.name}"`, `show rule-hit-count vsys vsys-name vsys1 rule-base security rules rule-name "${v.name}"`] };
    },
  });

  /* =========================================================
     M06 · Override des règles par défaut
     ========================================================= */
  register({
    id: "m06-default-rules-override", module: "M06", title: "Règles par défaut (intrazone / interzone)", icon: "📜",
    desc: "Override de intrazone-default et interzone-default : activer la journalisation (Log at Session End), action, profils.",
    tags: "default rule intrazone-default interzone-default override log",
    fields: [
      { id: "ovInter", label: "Override interzone-default", type: "checkbox", default: true, group: "interzone-default (deny)" },
      { id: "interAction", label: "Action", type: "select", default: "deny", show: v => v.ovInter,
        options: [["deny", "Deny (défaut)"], ["drop", "Drop"], ["reset-both", "Reset both"], ["allow", "Allow (déconseillé)"]] },
      { id: "interLogStart", label: "Log at Session Start", type: "checkbox", default: false, show: v => v.ovInter },
      { id: "interLogEnd", label: "Log at Session End", type: "checkbox", default: true, show: v => v.ovInter },
      { id: "ovIntra", label: "Override intrazone-default", type: "checkbox", default: true, group: "intrazone-default (allow)",
        validate: (x, v) => (!x && !v.ovInter ? "Coche au moins une des deux règles" : null) },
      { id: "intraAction", label: "Action", type: "select", default: "allow", show: v => v.ovIntra,
        options: [["allow", "Allow (défaut)"], ["deny", "Deny"], ["drop", "Drop"]] },
      { id: "intraLogEnd", label: "Log at Session End", type: "checkbox", default: true, show: v => v.ovIntra },
      { id: "intraGroup", label: "Profile Group (si allow)", type: "text", validate: "name", default: "Std-Profiles", show: v => v.ovIntra && v.intraAction === "allow", hint: "Vide = aucun profil." },
      { id: "logFwd", label: "Log Forwarding (commun)", type: "text", validate: "name", default: "", group: "Commun", placeholder: "Std-Log-Forwarding" },
    ],
    build(v) {
      const steps = [], cli = [];
      const one = (rule, action, ls, le, group) => {
        steps.push({ title: `Override de « ${rule} »`, path: ["Policies", "Security"], tab: "Actions", window: "Security Policy Rule",
          action: `Sélectionner la ligne « ${rule} » (sans l'ouvrir) → bouton Override (en bas) → onglet Actions → OK.`,
          fields: [["Action", action.charAt(0).toUpperCase() + action.slice(1).replace("-both", " both client and server")], ...(group ? [["Profile Type", "Group"], ["Group Profile", group]] : []),
            ["Log at Session Start", !!ls], ["Log at Session End", le ? true : "☐ décoché"], ["Log Forwarding", v.logFwd]] });
        const b = `set rulebase default-security-rules rules ${rule}`;
        cli.push(`${b} action ${action} log-start ${yn(ls)} log-end ${yn(le)}`);
        if (group) cli.push(`${b} profile-setting group ${q(group)}`);
        if (v.logFwd) cli.push(`${b} log-setting ${q(v.logFwd)}`);
      };
      if (v.ovInter) one("interzone-default", v.interAction, v.interLogStart, v.interLogEnd, "");
      if (v.ovIntra) one("intrazone-default", v.intraAction, false, v.intraLogEnd, v.intraAction === "allow" ? v.intraGroup : "");
      const notes = [{ type: "or", text: "Sans override, le trafic refusé par interzone-default n'apparaît pas dans le Traffic log. Revenir aux valeurs d'origine : sélectionner la règle → Revert." },
        { type: "or", html: `Voir l'effet sur la rulebase : ${SIM_SEC}.` }];
      if (v.ovInter && v.interAction === "allow") notes.push({ type: "bad", text: "interzone-default en allow : tout le trafic entre zones non couvert par une règle est autorisé. À proscrire." });
      if (v.ovIntra && v.intraAction !== "allow") notes.push({ type: "warn", text: "intrazone-default en blocage : tout trafic intra-zone devra être explicitement autorisé." });
      return { steps, cli, notes,
        verify: ["show running security-policy", "test security-policy-match from Trust to Untrust source 192.168.1.50 destination 198.51.100.10 protocol 1 application ping",
          "show log traffic rule equal interzone-default   # entrées journalisées après l'override"] };
    },
  });

  /* =========================================================
     M07 · Source NAT DIPP
     ========================================================= */
  const ifaceIpV = (x) => (maskOf(x) >= 31 || maskOf(x) < 8 ? "Masque de /8 à /30 attendu" : null);
  register({
    id: "m07-snat-dipp", module: "M07", title: "Source NAT — Dynamic IP and Port", icon: "↗️",
    desc: "NAT sortant (PAT) : les clients privés sortent avec l'IP de l'interface ou une IP traduite. Règle de sécurité associée incluse.",
    tags: "nat source snat dipp pat dynamic ip port interface overload",
    fields: [
      { id: "name", label: "Nom de la règle NAT", type: "text", validate: "name", required: true, default: "SNAT-LAN-Internet", group: "Règle NAT" },
      { id: "desc", label: "Description", type: "text", default: "PAT du LAN vers Internet via l'IP de ethernet1/1" },
      { id: "from", label: "Zone(s) source", type: "list", validate: zonesV, required: true, default: ["Trust"] },
      { id: "src", label: "Adresse(s) source", type: "list", validate: addrV, required: true, default: ["192.168.1.0/24"] },
      { id: "to", label: "Zone destination (sortie)", type: "text", validate: (x, v) => V.name(x) || (v.from.includes(x) ? "Zone de sortie identique à une zone source" : null), required: true, default: "Untrust" },
      { id: "egress", label: "Interface de sortie", type: "text", validate: "iface", required: true, default: "ethernet1/1" },
      { id: "ifip", label: "IP/masque de l'interface de sortie", type: "cidr", required: true, validate: ifaceIpV, default: "203.0.113.10/24", hint: "Telle qu'affichée dans la liste déroulante IP Address." },
      { id: "dst", label: "Adresse(s) destination", type: "list", validate: addrV, required: true, default: ["any"] },
      { id: "addrtype", label: "Address Type", type: "select", default: "interface", group: "Traduction",
        options: [["interface", "Interface Address (IP de l'interface)"], ["translated", "Translated Address (IP/pool dédié)"]] },
      { id: "pool", label: "Translated Address", type: "list", required: true, default: ["203.0.113.11"], show: v => v.addrtype === "translated",
        validate: (a, v) => addrV(a) || (a.includes("any") ? "any interdit" : null) || (a.some(t => covers(t, hostOf(v.ifip)) === true) ? `Le pool ne doit pas contenir l'IP de l'interface (${hostOf(v.ifip)}) : utiliser Interface Address` : null) },
      { id: "mkobj", label: "Créer des objets adresse pour les IP saisies", type: "checkbox", default: true },
      { id: "pos", label: "Position de la règle NAT", type: "select", default: "bottom", options: [["bottom", "En bas (règle générale)"], ["top", "En haut"], ["before", "Avant la règle…"], ["after", "Après la règle…"]] },
      posRefField("ref"),
      ...secFields({ name: "LAN-to-Internet", apps: ["web-browsing", "ssl", "dns"] }),
      { id: "tsrc", label: "IP client de test", type: "ip", required: true, default: "192.168.1.50", group: "Test" },
      { id: "tdst", label: "IP destination de test", type: "ip", required: true, default: "8.8.8.8" },
      { id: "tport", label: "Port destination", type: "port", required: true, default: "443" },
    ],
    build(v) {
      const objs = [], R = resolver(v.mkobj, objs, []);
      const src = anyL(v.src) ? ["any"] : v.src.map(t => R(t));
      const dst = anyL(v.dst) ? ["any"] : v.dst.map(t => R(t));
      const pool = v.addrtype === "translated" ? v.pool.map(t => R(t, `SNAT-Pool-${hostOf(t.split("-")[0])}`)) : [];
      const steps = [], cli = [];
      objs.forEach(o => { steps.push(addrStep(o)); cli.push(...addrCli(o)); });
      const n = natRule({ name: v.name, desc: v.desc, from: v.from, to: v.to, toIf: v.egress, svc: "any", src, dst,
        st: v.addrtype === "interface" ? { type: "dipp-if", iface: v.egress, ip: v.ifip } : { type: "dipp-tr", translated: pool }, dt: null, pos: v.pos, ref: v.ref });
      steps.push(...n.steps); cli.push(...n.cli);
      if (v.mksec) { const s = natRelSec(v, { desc: `Autorise ${v.from.join("+")} vers ${v.to} (source NAT ${v.name})`, from: v.from, to: v.to, src, dst, svc: v.secsvc }); steps.push(...s.steps); cli.push(...s.cli); }
      const notes = [
        { type: "or", html: `Règle NAT : zones PRÉ-NAT. Règle de sécurité : IP d'origine + zone de destination POST-NAT (ici identique : ${PAN.esc(v.to)}). Vue animée : ${SIM_NAT}.` },
        ...secNotes(v),
      ];
      if (v.addrtype === "translated") {
        const out = v.pool.filter(t => covers(t, hostOf(v.ifip)) === null ? false : !(isLit(t) && (isRange(t) ? inNet(rangeParts(t)[0], v.ifip) : inNet(hostOf(t), v.ifip))));
        notes.push(out.length ? { type: "warn", text: `${out.join(", ")} hors du sous-réseau de ${v.egress} (${v.ifip}) : le routeur amont doit router ces IP vers le pare-feu.` }
          : { type: "ok", text: `Pool dans le sous-réseau de ${v.egress} : le pare-feu répond automatiquement aux requêtes ARP (proxy ARP) pour ces IP.` });
      }
      if (coversAny(v.src, v.tsrc) === false) notes.push({ type: "warn", text: `Le client de test ${v.tsrc} n'appartient pas à la source de la règle.` });
      if (v.pos === "bottom") notes.push({ type: "or", text: "Règle générale : la laisser sous les règles NAT spécifiques (static, DNAT, U-Turn) — la rulebase NAT est first match." });
      const t = { from: v.from[0], to: v.to, toIf: v.egress, src: v.tsrc, dst: v.tdst, port: v.tport, proto: 6 };
      return { steps, cli, notes,
        verify: [natTest(t), v.mksec ? secTest({ ...t, app: anyL(v.secapps) ? "" : v.secapps.includes("ssl") ? "ssl" : v.secapps[0] }) : "", ...natVerifyTail(t, "source"), "show running ippool"].filter(Boolean) };
    },
  });

  /* =========================================================
     M07 · Source NAT Dynamic IP (pool)
     ========================================================= */
  register({
    id: "m07-snat-dynamic-ip", module: "M07", title: "Source NAT — Dynamic IP (pool)", icon: "🎱",
    desc: "Chaque client reçoit une IP du pool (1:1 dynamique, port conservé), avec fallback DIPP optionnel en cas d'épuisement.",
    tags: "nat source dynamic ip pool fallback",
    fields: [
      { id: "name", label: "Nom de la règle NAT", type: "text", validate: "name", required: true, default: "SNAT-LAN-Pool", group: "Règle NAT" },
      { id: "desc", label: "Description", type: "text", default: "NAT dynamique du LAN sur le pool public" },
      { id: "from", label: "Zone(s) source", type: "list", validate: zonesV, required: true, default: ["Trust"] },
      { id: "src", label: "Adresse(s) source", type: "list", validate: addrV, required: true, default: ["192.168.1.0/24"] },
      { id: "to", label: "Zone destination (sortie)", type: "text", validate: (x, v) => V.name(x) || (v.from.includes(x) ? "Zone de sortie identique à une zone source" : null), required: true, default: "Untrust" },
      { id: "egress", label: "Interface de sortie", type: "text", validate: "iface", required: true, default: "ethernet1/1" },
      { id: "ifip", label: "IP/masque de l'interface de sortie", type: "cidr", required: true, validate: ifaceIpV, default: "203.0.113.10/24" },
      { id: "pool", label: "Pool (Translated Address)", type: "list", required: true, default: ["203.0.113.30-203.0.113.40"], group: "Traduction",
        validate: (a, v) => addrV(a) || (a.includes("any") ? "any interdit" : null) || (a.some(t => covers(t, hostOf(v.ifip)) === true) ? `Le pool ne doit pas contenir l'IP de l'interface (${hostOf(v.ifip)})` : null),
        hint: "IP, plage ou IP/masque (ou objet existant)." },
      { id: "fb", label: "Fallback (pool épuisé)", type: "select", default: "interface",
        options: [["none", "Aucun"], ["interface", "DIPP sur l'IP de l'interface de sortie"], ["translated", "DIPP sur une IP dédiée"]] },
      { id: "fbaddr", label: "IP de fallback", type: "ip", required: true, default: "203.0.113.41", show: v => v.fb === "translated",
        validate: (x, v) => (v.pool.some(t => covers(t, x) === true) ? "L'IP de fallback ne doit pas faire partie du pool" : null) },
      { id: "mkobj", label: "Créer des objets adresse pour les IP saisies", type: "checkbox", default: true },
      { id: "pos", label: "Position de la règle NAT", type: "select", default: "top", options: NAT_POS },
      posRefField("ref"),
      ...secFields({ name: "LAN-to-Internet", apps: ["web-browsing", "ssl", "dns"] }),
      { id: "tsrc", label: "IP client de test", type: "ip", required: true, default: "192.168.1.50", group: "Test" },
      { id: "tdst", label: "IP destination de test", type: "ip", required: true, default: "8.8.8.8" },
      { id: "tport", label: "Port destination", type: "port", required: true, default: "443" },
    ],
    build(v) {
      const objs = [], R = resolver(v.mkobj, objs, []);
      const src = anyL(v.src) ? ["any"] : v.src.map(t => R(t));
      const pool = v.pool.map(t => R(t, `SNAT-Pool-${hostOf(t.split("-")[0])}`));
      const fbObj = v.fb === "translated" ? R(v.fbaddr, `SNAT-Fallback-${v.fbaddr}`) : "";
      const steps = [], cli = [];
      objs.forEach(o => { steps.push(addrStep(o)); cli.push(...addrCli(o)); });
      const n = natRule({ name: v.name, desc: v.desc, from: v.from, to: v.to, toIf: v.egress, svc: "any", src, dst: ["any"],
        st: { type: "dynamic-ip", translated: pool, fb: { type: v.fb, iface: v.egress, ip: v.ifip, addr: fbObj } }, dt: null, pos: v.pos, ref: v.ref });
      steps.push(...n.steps); cli.push(...n.cli);
      if (v.mksec) { const s = natRelSec(v, { desc: `Autorise ${v.from.join("+")} vers ${v.to} (NAT pool ${v.name})`, from: v.from, to: v.to, src, dst: ["any"], svc: v.secsvc }); steps.push(...s.steps); cli.push(...s.cli); }
      const notes = [{ type: "or", html: `Dynamic IP = 1 IP du pool par client (port source conservé). Vue animée : ${SIM_NAT}.` }, ...secNotes(v)];
      const pc = v.pool.map(ipCount), sc = v.src.map(ipCount);
      if (!pc.includes(null) && !sc.includes(null) && !anyL(v.src)) {
        const P = pc.reduce((a, b) => a + b, 0), S = sc.reduce((a, b) => a + b, 0);
        if (S > P) notes.push({ type: v.fb === "none" ? "bad" : "warn", text: `${S} adresses sources pour ${P} IP de pool : ${v.fb === "none" ? "sans fallback, les nouvelles sessions échouent une fois le pool épuisé." : "le fallback DIPP prendra le relais à l'épuisement."}` });
      } else if (v.fb === "none") notes.push({ type: "warn", text: "Sans fallback, les nouvelles sessions échouent une fois le pool épuisé." });
      const out = v.pool.filter(t => isLit(t) && !inNet(isRange(t) ? rangeParts(t)[0] : hostOf(t), v.ifip));
      notes.push(out.length ? { type: "warn", text: `${out.join(", ")} hors du sous-réseau de ${v.egress} : le routeur amont doit router le pool vers ${hostOf(v.ifip)}.` }
        : { type: "ok", text: `Pool dans le sous-réseau de ${v.egress} : réponse ARP automatique (proxy ARP) par le pare-feu.` });
      if (v.pos !== "top") notes.push({ type: "warn", text: "Placer cette règle au-dessus de toute règle DIPP générale couvrant les mêmes sources, sinon elle ne sera jamais atteinte." });
      const t = { from: v.from[0], to: v.to, toIf: v.egress, src: v.tsrc, dst: v.tdst, port: v.tport, proto: 6 };
      return { steps, cli, notes, verify: [natTest(t), v.mksec ? secTest(t) : "", ...natVerifyTail(t, "source"), "show running ippool"].filter(Boolean) };
    },
  });

  /* =========================================================
     M07 · Static NAT 1:1 bidirectionnel
     ========================================================= */
  register({
    id: "m07-static-bidir", module: "M07", title: "Static NAT 1:1 bidirectionnel", icon: "⇄",
    desc: "Une IP privée ↔ une IP publique fixe : sortant (source NAT static) et entrant (option Bi-directional), avec les règles de sécurité des deux sens.",
    tags: "nat static 1:1 bidirectional bi-directional one-to-one",
    fields: [
      { id: "name", label: "Nom de la règle NAT", type: "text", validate: "name", required: true, default: "NAT-Static-Web-DMZ", group: "Règle NAT" },
      { id: "desc", label: "Description", type: "text", default: "1:1 172.16.1.10 <-> 203.0.113.20" },
      { id: "srv", label: "IP privée du serveur", type: "ip", required: true, default: "172.16.1.10" },
      { id: "srvzone", label: "Zone du serveur", type: "text", validate: "name", required: true, default: "DMZ" },
      { id: "srvname", label: "Nom du serveur (préfixe des objets)", type: "text", validate: "name", required: true, default: "Srv-Web-DMZ" },
      { id: "pub", label: "IP publique", type: "ip", required: true, default: "203.0.113.20",
        validate: (x, v) => (x === v.srv ? "IP publique = IP privée" : v.ifip && PAN.ip.validCidr(v.ifip) && x === hostOf(v.ifip) ? "Ne pas réutiliser l'IP de l'interface pour un 1:1 (elle porterait aussi la gestion, le VPN…)" : null) },
      { id: "pubzone", label: "Zone publique", type: "text", validate: (x, v) => V.name(x) || (x === v.srvzone ? "Zone publique identique à la zone du serveur" : null), required: true, default: "Untrust" },
      { id: "pubif", label: "Interface publique", type: "text", validate: "iface", required: true, default: "ethernet1/1" },
      { id: "ifip", label: "IP/masque de l'interface publique", type: "cidr", validate: ifaceIpV, required: true, default: "203.0.113.10/24" },
      { id: "bidir", label: "Bi-directional (autoriser les connexions entrantes)", type: "checkbox", default: true },
      { id: "mkobj", label: "Créer les objets adresse", type: "checkbox", default: true },
      { id: "pos", label: "Position de la règle NAT", type: "select", default: "top", options: NAT_POS },
      posRefField("ref"),
      { id: "mksecout", label: "Règle de sécurité sortante (serveur → Internet)", type: "checkbox", default: true, group: "Règles de sécurité" },
      { id: "secoutname", label: "Nom (sortant)", type: "text", validate: "name", required: true, default: "Web-DMZ-to-Internet", show: v => v.mksecout },
      { id: "secoutapps", label: "Applications (sortant)", type: "list", validate: appsV, required: true, default: ["dns", "ssl", "web-browsing"], show: v => v.mksecout },
      { id: "mksecin", label: "Règle de sécurité entrante (Internet → serveur)", type: "checkbox", default: true, show: v => v.bidir },
      { id: "secinname", label: "Nom (entrant)", type: "text", validate: "name", required: true, default: "Allow-Web-DMZ", show: v => v.bidir && v.mksecin },
      { id: "secinapps", label: "Applications (entrant)", type: "list", validate: appsV, required: true, default: ["web-browsing", "ssl"], show: v => v.bidir && v.mksecin },
      { id: "secprof", label: "Profils de sécurité", type: "select", default: "group", options: [["group", "Profile Group"], ["profiles", "Profils prédéfinis"], ["none", "Aucun"]] },
      { id: "secgroup", label: "Nom du Profile Group", type: "text", validate: "name", required: true, default: "Std-Profiles", show: v => v.secprof === "group" },
      { id: "ext", label: "IP cliente externe de test", type: "ip", required: true, default: "198.51.100.10", group: "Test", show: v => v.bidir },
      { id: "tport", label: "Port entrant de test", type: "port", required: true, default: "443", show: v => v.bidir },
    ],
    build(v) {
      const objs = [], R = resolver(v.mkobj, objs, []);
      const priv = R(v.srv, v.srvname + "-Private"), pub = R(v.pub, v.srvname + "-Public");
      const steps = [], cli = [];
      objs.forEach(o => { steps.push(addrStep(o)); cli.push(...addrCli(o)); });
      const n = natRule({ name: v.name, desc: v.desc, from: [v.srvzone], to: v.pubzone, toIf: v.pubif, svc: "any", src: [priv], dst: ["any"],
        st: { type: "static-ip", translated: [pub], bidir: v.bidir }, dt: null, pos: v.pos, ref: v.ref });
      steps.push(...n.steps); cli.push(...n.cli);
      const prof = secProf(v), mk = (name, desc, from, to, src, dst, app, gold) => {
        const s = secRule({ name, desc, tags: [], type: "universal", from, to: [to], src, dst, user: ["any"], app, svc: ["application-default"], cat: ["any"], action: "allow", prof, logStart: false, logEnd: true, logFwd: "", pos: "none" }, { compact: true, gold });
        steps.push(...s.steps); cli.push(...s.cli);
      };
      if (v.mksecout) mk(v.secoutname, `Sortant : ${v.srv} vers ${v.pubzone}`, [v.srvzone], v.pubzone, [priv], ["any"], v.secoutapps);
      if (v.bidir && v.mksecin) mk(v.secinname, `Entrant : ${v.pubzone} vers ${v.srv} publié en ${v.pub}`, [v.pubzone], v.srvzone, ["any"], [pub], v.secinapps, { zone: v.srvzone, addr: pub });
      const notes = [{ type: "or", html: `Entrant : règle de sécurité = IP publique (PRÉ-NAT) + zone du serveur (POST-NAT). Vue animée : ${SIM_NAT}.` }];
      notes.push(inNet(v.pub, v.ifip) ? { type: "ok", text: `${v.pub} est dans le sous-réseau de ${v.pubif} : proxy ARP automatique.` }
        : { type: "warn", text: `${v.pub} hors du sous-réseau de ${v.pubif} (${v.ifip}) : le routeur amont doit router ${v.pub} vers ${hostOf(v.ifip)}.` });
      if (!v.bidir) notes.push({ type: "or", text: "Sans Bi-directional, seules les connexions initiées par le serveur sont traduites ; pour l'entrant, créer une règle de Destination NAT (#m07-dnat)." });
      if (v.secprof === "none") notes.push({ type: "warn", text: "Serveur exposé sans profil de sécurité : ajouter au moins Vulnerability Protection et Antivirus." });
      if (v.pos !== "top") notes.push({ type: "warn", text: "La règle 1:1 doit précéder la règle DIPP générale, sinon le serveur sortira avec l'IP de l'interface." });
      const out = { from: v.srvzone, to: v.pubzone, toIf: v.pubif, src: v.srv, dst: "8.8.8.8", port: 443, proto: 6 };
      const verify = ["# Sortant", natTest(out), v.mksecout ? secTest(out) : ""];
      if (v.bidir) { const inb = { from: v.pubzone, to: v.pubzone, src: v.ext, dst: v.pub, port: v.tport, proto: 6 };
        verify.push("# Entrant (IP publique, zone pré-NAT pour le NAT ; zone serveur pour la sécurité)", natTest(inb), v.mksecin ? secTest({ ...inb, to: v.srvzone }) : ""); }
      verify.push(...natVerifyTail(v.bidir ? { src: v.ext, dst: v.pub, port: v.tport } : out, v.bidir ? "destination" : "source"));
      return { steps, cli, notes, verify: verify.filter(Boolean) };
    },
  });

  /* =========================================================
     M07 · Destination NAT  /  U-Turn (logique commune)
     ========================================================= */
  function dnatFields(u) {
    return [
      { id: "name", label: "Nom de la règle NAT", type: "text", validate: "name", required: true, default: u ? "UTurn-Web-DMZ" : "DNAT-Web-DMZ", group: "Règle NAT" },
      { id: "desc", label: "Description", type: "text", default: u ? "Accès LAN au serveur web DMZ via son IP publique" : "Publication du serveur web DMZ" },
      { id: "from", label: "Zone(s) source (clients)", type: "list", validate: zonesV, required: true, default: [u ? "Trust" : "Untrust"] },
      { id: "src", label: "Adresse(s) source", type: "list", validate: addrV, required: true, default: [u ? "192.168.1.0/24" : "any"] },
      { id: "pub", label: "IP publique (destination d'origine)", type: "ip", required: true, default: "203.0.113.20", group: "Adresse publiée",
        validate: (x, v) => (x === v.srv ? "IP publique = IP du serveur" : v.pubifip && PAN.ip.validCidr(v.pubifip) && x === hostOf(v.pubifip) && !v.oport ? "IP de l'interface : préciser un port d'origine, sinon tout le trafic vers le pare-feu (gestion, VPN…) est redirigé" : null) },
      { id: "pubzone", label: "Zone de l'IP publique (pré-NAT)", type: "text", validate: "name", required: true, default: "Untrust", hint: "Zone de l'interface qui porte le réseau de l'IP publique (route lookup)." },
      { id: "pubif", label: "Interface de l'IP publique", type: "text", validate: "iface", required: true, default: "ethernet1/1" },
      { id: "pubifip", label: "IP/masque de cette interface", type: "cidr", validate: ifaceIpV, required: true, default: "203.0.113.10/24" },
      { id: "proto", label: "Protocole", type: "select", default: "tcp", options: [["tcp", "TCP"], ["udp", "UDP"]] },
      { id: "oport", label: "Port d'origine (vide = tous)", type: "port", default: "443", hint: "Crée un objet service et restreint la règle NAT à ce port." },
      { id: "xport", label: "Port traduit (vide = inchangé)", type: "port", default: "",
        validate: (x, v) => (!v.oport ? "Un port traduit nécessite un port d'origine" : x === v.oport ? "Identique au port d'origine : laisser vide" : null) },
      { id: "srv", label: "IP privée du serveur", type: "ip", required: true, default: "172.16.1.10", group: "Serveur" },
      { id: "srvzone", label: "Zone du serveur (post-NAT)", type: "text", validate: "name", required: true, default: "DMZ" },
      { id: "srvname", label: "Nom du serveur (préfixe des objets)", type: "text", validate: "name", required: true, default: "Srv-Web-DMZ" },
      ...(u ? [
        { id: "snat", label: "Source NAT (DIPP) vers l'interface du serveur", type: "checkbox", default: true, group: "Source NAT (U-Turn)",
          validate: (x, v) => (!x && v.from.includes(v.srvzone) ? "Client et serveur dans la même zone : le source NAT est obligatoire (sinon routage asymétrique)" : null) },
        { id: "snatif", label: "Interface côté serveur", type: "text", validate: "iface", required: true, default: "ethernet1/3", show: v => v.snat },
        { id: "snatifip", label: "IP/masque de cette interface", type: "cidr", validate: ifaceIpV, required: true, default: "172.16.1.1/24", show: v => v.snat },
      ] : []),
      { id: "mkobj", label: "Créer les objets adresse", type: "checkbox", default: true, group: "Options" },
      { id: "pos", label: "Position de la règle NAT", type: "select", default: "top", options: NAT_POS },
      posRefField("ref"),
      ...secFields({ name: u ? "LAN-to-Web-DMZ-Public" : "Allow-Web-DMZ", apps: ["ssl", "web-browsing"] },
        [["application-default", "application-default"], ["orig", "Port d'origine (objet service)"], ["any", "any"]]),
      { id: "tsrc", label: "IP client de test", type: "ip", required: true, default: u ? "192.168.1.50" : "198.51.100.10", group: "Test" },
      { id: "tport", label: "Port de test", type: "port", required: true, default: "443", show: v => !v.oport },
    ];
  }
  function dnatBuild(v, u) {
    const objs = [], R = resolver(v.mkobj, objs, []);
    const src = anyL(v.src) ? ["any"] : v.src.map(t => R(t));
    const pub = R(v.pub, v.srvname + "-Public"), priv = R(v.srv, v.srvname + "-Private");
    const steps = [], cli = [], svcs = [];
    objs.forEach(o => { steps.push(addrStep(o)); cli.push(...addrCli(o)); });
    let svc = "any";
    if (v.oport) { const s = { name: `${v.proto}-${v.oport}`, proto: v.proto, port: v.oport, sport: "", desc: "", tags: [] }; svcs.push(s); svc = s.name; }
    svcs.forEach(s => { steps.push(svcStep(s)); cli.push(...svcCli(s)); });
    const snat = u && v.snat;
    const n = natRule({ name: v.name, desc: v.desc, from: v.from, to: v.pubzone, toIf: v.pubif, svc, src, dst: [pub], dstRaw: v.pub,
      st: snat ? { type: "dipp-if", iface: v.snatif, ip: v.snatifip } : { type: "none" }, dt: { addr: priv, port: v.xport }, pos: v.pos, ref: v.ref });
    steps.push(...n.steps); cli.push(...n.cli);
    const secSvc = v.secsvc === "orig" ? (v.oport ? svc : "application-default") : v.secsvc;
    if (v.mksec) { const s = natRelSec(v, { desc: `Autorise ${v.from.join("+")} vers ${v.srv} publié en ${v.pub}${v.oport ? ":" + v.oport : ""}`, from: v.from, to: v.srvzone, src, dst: [pub], svc: secSvc }, { zone: v.srvzone, addr: pub });
      steps.push(...s.steps); cli.push(...s.cli); }

    const notes = [{ type: "or", html: `Règle d'or : NAT = zones PRÉ-NAT (destination ${PAN.esc(v.pubzone)}) ; sécurité = IP PRÉ-NAT (${PAN.esc(v.pub)}) + zone POST-NAT (${PAN.esc(v.srvzone)}) ; service = port d'origine. Vue animée : ${SIM_NAT}.` }, ...secNotes(v)];
    if (v.pub !== hostOf(v.pubifip)) notes.push(inNet(v.pub, v.pubifip) ? { type: "ok", text: `${v.pub} ≠ IP de ${v.pubif} mais dans son sous-réseau : le pare-feu répond automatiquement à l'ARP (proxy ARP) pour cette IP.` }
      : { type: "warn", text: `${v.pub} hors du sous-réseau de ${v.pubif} (${v.pubifip}) : pas de proxy ARP possible, le routeur amont doit router ${v.pub} vers ${hostOf(v.pubifip)}.` });
    if (v.xport && v.mksec && v.secsvc === "application-default") notes.push({ type: "warn", text: `Port traduit ${v.xport} : la sécurité évalue le port d'origine ${v.oport}. Vérifier qu'il s'agit du port par défaut des applications, sinon choisir « Port d'origine ».` });
    if (!v.oport) notes.push({ type: "warn", text: "Service any : tous les ports vers l'IP publique sont redirigés vers le serveur. Restreindre avec un port d'origine si possible." });
    if (!u && v.from.includes(v.srvzone)) notes.push({ type: "warn", text: "Clients dans la zone du serveur : configuration U-Turn, source NAT requis → module U-Turn NAT (#m07-uturn)." });
    if (u && snat && !inNet(v.srv, v.snatifip)) notes.push({ type: "warn", text: `${v.srv} n'est pas dans le sous-réseau de ${v.snatif} (${v.snatifip}) : vérifier l'interface de sortie vers le serveur.` });
    if (u && !snat) notes.push({ type: "or", text: "Sans source NAT, le serveur répond directement au client s'ils partagent un segment : à réserver aux zones/sous-réseaux distincts routés par le pare-feu." });
    if (u) notes.push({ type: "or", text: "Une règle DNAT entrante (depuis Untrust) pour le même serveur reste nécessaire pour les clients externes (#m07-dnat)." });
    if (v.pos !== "top") notes.push({ type: "warn", text: u ? "La règle U-Turn doit précéder la règle DIPP sortante (même zones source / destination), sinon le trafic part en source NAT vers Internet." : "Placer la règle au-dessus des règles NAT générales qui pourraient matcher le même trafic." });
    if (coversAny(v.src, v.tsrc) === false) notes.push({ type: "warn", text: `Le client de test ${v.tsrc} n'appartient pas à la source de la règle.` });
    const port = v.oport || v.tport;
    const t = { from: v.from[0], to: v.pubzone, toIf: v.pubif, src: v.tsrc, dst: v.pub, port, proto: proto(v.proto) };
    return { steps, cli, notes,
      verify: ["# NAT : zones pré-NAT", natTest(t), ...(v.mksec ? ["# Sécurité : IP pré-NAT, zone de destination post-NAT", secTest({ ...t, to: v.srvzone })] : []), ...natVerifyTail({ src: v.tsrc, dst: v.pub, port }, u ? (snat ? "both" : "destination") : "destination")] };
  }
  register({
    id: "m07-dnat", module: "M07", title: "Destination NAT (publication de serveur)", icon: "↘️",
    desc: "IP publique[:port] → IP privée[:port] avec traduction de port optionnelle, règle de sécurité pré-NAT IP / post-NAT zone.",
    tags: "nat destination dnat port forwarding publication translated port proxy arp",
    fields: dnatFields(false),
    build: v => dnatBuild(v, false),
  });
  register({
    id: "m07-uturn", module: "M07", title: "U-Turn NAT (hairpin)", icon: "↩️",
    desc: "Des clients internes joignent un serveur interne via son IP publique : destination NAT + source NAT combinés.",
    tags: "nat uturn u-turn hairpin loopback dnat snat",
    fields: dnatFields(true),
    build: v => dnatBuild(v, true),
  });

  /* options couleur du module objets adresse (définies après COLORS) */
  const am = PAN.cfg.get("m06-address-objects");
  if (am) am.fields.find(f => f.id === "tagcolor").options = COLORS.map(([k, l]) => [k, `${l} (${k})`]);
})();
