/* Modules M08 (App-ID), M09 (Security Profiles), M10 (URL Filtering) — PAN-OS 11.0 */
(function () {
  const { register, q, members } = PAN.cfg;

  /* ================= helpers communs ================= */
  const each = (fn, msg) => arr => { for (const x of [].concat(arr)) if (!fn(x)) return `« ${x} » : ${msg}`; return null; };
  const objName = s => /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/.test(s);
  const appName = s => /^[a-z0-9][a-z0-9._+-]{0,62}$/i.test(s);
  const catName = s => /^[a-z0-9][a-z0-9-]{0,62}$/.test(s);
  const addrOk = s => s === "any" || PAN.ip.validCidr(s) || /^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$/.test(s) || objName(s);
  const V_OBJS = each(objName, "nom d'objet PAN-OS invalide");
  const V_APPS = each(appName, "nom d'application invalide (minuscules, chiffres, - _ .)");
  const V_ADDR = each(addrOk, "IP, IP/masque, plage ou nom d'objet attendu");
  const qm = a => { a = [].concat(a).filter(Boolean); return a.length > 1 ? `[ ${a.map(qq).join(" ")} ]` : qq(a[0] ?? "any"); };
  const qq = s => (/[\s"';|*^?]/.test(String(s)) ? `"${String(s).replace(/"/g, '\\"')}"` : String(s)); // quote aussi les jokers
  const uniq = a => [...new Set(a)];
  const dup = (a, b) => a.filter(x => b.includes(x));

  const ACT = [["allow", "Allow"], ["deny", "Deny"], ["drop", "Drop"], ["reset-client", "Reset client"], ["reset-server", "Reset server"], ["reset-both", "Reset both client and server"]];
  const actLabel = a => (ACT.find(x => x[0] === a) || [a, a])[1];
  const THR_ACT = [["default", "default"], ["allow", "allow"], ["alert", "alert"], ["drop", "drop"], ["reset-client", "reset-client"], ["reset-server", "reset-server"], ["reset-both", "reset-both"]];
  const PCAP = [["disable", "disable"], ["single-packet", "single-packet"], ["extended-capture", "extended-capture"]];

  /* Règle de sécurité : étapes GUI (un onglet = une étape) */
  function ruleSteps(r) {
    const t = `Règle « ${r.name} »`, p = ["Policies", "Security"], w = "Security Policy Rule";
    const prof = r.group ? [["Profile Type", "Group"], ["Group Profile", r.group]] : [];
    return [
      { title: `${t} — General`, path: p, tab: "General", window: w, action: r.edit ? `Cliquer sur la règle ${r.name} pour l'éditer.` : "Cliquer sur Add en bas de la liste.",
        fields: [["Name", r.name], ["Rule Type", r.edit ? "" : "universal (default)"], ["Description", r.desc]] },
      { title: `${t} — Source`, path: p, tab: "Source", window: w, fields: [["Source Zone", r.from], ["Source Address", r.src && r.src.length && r.src[0] !== "any" ? r.src : "Any"]] },
      { title: `${t} — Destination`, path: p, tab: "Destination", window: w, fields: [["Destination Zone", r.to], ["Destination Address", r.dst && r.dst.length && r.dst[0] !== "any" ? r.dst : "Any"]] },
      { title: `${t} — Application`, path: p, tab: "Application", window: w, action: r.appAction, fields: [["Applications", r.app && r.app.length ? r.app : "Any"]], note: r.appNote },
      { title: `${t} — Service/URL Category`, path: p, tab: "Service/URL Category", window: w,
        fields: [["Service", r.svc || "application-default"], ["URL Category", r.cat && r.cat.length ? r.cat : "Any"]] },
      { title: `${t} — Actions`, path: p, tab: "Actions", window: w, action: "Cliquer sur OK pour fermer la règle.",
        fields: [["Action", actLabel(r.action || "allow")], ["Log at Session End", true], ...prof], warn: r.actWarn },
    ];
  }
  /* Règle de sécurité : CLI */
  function ruleCli(r) {
    const n = q(r.name);
    return [
      `set rulebase security rules ${n} from ${members(r.from)} to ${members(r.to)} source ${qm(r.src && r.src.length ? r.src : "any")} destination ${qm(r.dst && r.dst.length ? r.dst : "any")} source-user any`,
      `set rulebase security rules ${n} application ${qm(r.app && r.app.length ? r.app : "any")} service ${qm(r.svc || "application-default")} category ${qm(r.cat && r.cat.length ? r.cat : "any")}`,
      `set rulebase security rules ${n} action ${r.action || "allow"} log-end yes`,
      r.desc && `set rulebase security rules ${n} description ${q(r.desc)}`,
      r.group && `set rulebase security rules ${n} profile-setting group ${q(r.group)}`,
      r.move === "top" && `move rulebase security rules ${n} top`,
      r.move && r.move !== "top" && `move rulebase security rules ${n} before ${q(r.move)}`,
    ].filter(Boolean);
  }
  const moveStep = (name, where) => where ? [{ title: `Positionner la règle « ${name} »`, path: ["Policies", "Security"],
    action: where === "top" ? `Sélectionner la ligne ${name} (sans l'ouvrir) → Move → Move Top.` : `Sélectionner la ligne ${name} → Move → Move Up / glisser-déposer juste au-dessus de « ${where} ».`,
    fields: [], note: "Ordre des règles = premier match. Vérifier l'onglet Rule Shadow au commit." }] : [];

  /* Application d'un profil à un groupe ou à une règle existante */
  const PROFKEY = { virus: ["Antivirus Profile", "Antivirus"], spyware: ["Anti-Spyware Profile", "Anti-Spyware"], vulnerability: ["Vulnerability Protection Profile", "Vulnerability Protection"],
    "url-filtering": ["URL Filtering Profile", "URL Filtering"], "file-blocking": ["File Blocking Profile", "File Blocking"], "data-filtering": ["Data Filtering Profile", "Data Filtering"], "wildfire-analysis": ["WildFire Analysis Profile", "WildFire Analysis"] };
  const applyFields = (grpDefault) => [
    { id: "apply", label: "Appliquer le profil", type: "select", default: "group", group: "Application du profil",
      options: [["group", "Dans un Security Profile Group existant"], ["rule", "Directement sur une règle existante"], ["none", "Ne pas appliquer maintenant"]] },
    { id: "applyGroup", label: "Nom du groupe de profils", type: "text", default: grpDefault || "Std-Profiles", validate: "name", required: true, show: v => v.apply === "group",
      hint: "Groupe créé avec le module « Security Profile Group » (#m09-profile-group)." },
    { id: "applyRules", label: "Règles de sécurité (séparées par des virgules)", type: "list", default: ["LAN-to-Internet"], required: true, validate: V_OBJS, show: v => v.apply === "rule" },
  ];
  function applyOut(v, key, prof) {
    const [gl, rl] = PROFKEY[key];
    if (v.apply === "group") return {
      steps: [{ title: `Ajouter le profil au groupe « ${v.applyGroup} »`, path: ["Objects", "Security Profile Groups"], window: "Security Profile Group",
        action: `Cliquer sur ${v.applyGroup} pour l'éditer.`, fields: [[gl, prof]], note: "Toutes les règles qui utilisent ce groupe héritent du profil au prochain commit." }],
      cli: [`set profile-group ${q(v.applyGroup)} ${key} ${q(prof)}`] };
    if (v.apply === "rule") return {
      steps: v.applyRules.map(r => ({ title: `Appliquer le profil à la règle « ${r} »`, path: ["Policies", "Security"], tab: "Actions", window: "Security Policy Rule",
        action: `Cliquer sur ${r} → onglet Actions → Profile Setting.`, fields: [["Profile Type", "Profiles"], [rl, prof]],
        warn: "Si la règle utilisait un groupe (Profile Type = Group), le passer en « Profiles » retire tous les profils du groupe : resélectionner les autres profils." })),
      cli: v.applyRules.map(r => `set rulebase security rules ${q(r)} profile-setting profiles ${key} ${q(prof)}`) };
    return { steps: [], cli: [] };
  }

  /* ================= M08 · App-ID ================= */
  const APP_CATS = { "business-systems": ["auth-service", "database", "erp-crm", "general-business", "management", "office-programs", "software-development", "software-update", "storage-backup"],
    collaboration: ["email", "instant-messaging", "internet-conferencing", "social-business", "social-networking", "voip-video", "web-posting"],
    "general-internet": ["file-sharing", "internet-utility"], media: ["audio-streaming", "gaming", "photo-video"],
    networking: ["encrypted-tunnel", "infrastructure", "ip-protocol", "proxy", "remote-access", "routing"], unknown: [] };
  const ALL_SUBS = Object.values(APP_CATS).flat();
  const TECHS = ["browser-based", "client-server", "network-protocol", "peer-to-peer"];
  const CHARS = [["evasive", "Evasive"], ["excessive-bandwidth-use", "Excessive Bandwidth"], ["used-by-malware", "Used by Malware"], ["transfers-files", "Capable of File Transfer"],
    ["has-known-vulnerabilities", "Has Known Vulnerabilities"], ["tunnels-other-apps", "Tunnels Other Apps"], ["prone-to-misuse", "Prone to Misuse"], ["pervasive", "Widely Used"], ["is-saas", "SaaS"], ["new-appid", "New App-ID"]];

  register({
    id: "m08-app-filter", module: "M08", title: "Application Filter (filtre dynamique)", icon: "🧪",
    desc: "Filtre d'applications par catégorie, sous-catégorie, technologie, risque et caractéristiques, puis règle de sécurité qui l'utilise.",
    tags: "app-id application filter filtre risk risque category characteristics",
    fields: [
      { id: "name", label: "Nom du filtre", type: "text", required: true, validate: "name", default: "Risky-File-Sharing" },
      { id: "cats", label: "Category", type: "list", default: ["general-internet"], validate: each(x => x in APP_CATS, "catégorie inconnue (business-systems, collaboration, general-internet, media, networking, unknown)") },
      { id: "subs", label: "Subcategory", type: "list", default: ["file-sharing"], validate: (a, v) => {
        const e = each(x => ALL_SUBS.includes(x), "sous-catégorie inconnue")(a); if (e) return e;
        if (v.cats.length) { const ok = v.cats.flatMap(c => APP_CATS[c] || []); const bad = a.find(s => !ok.includes(s)); if (bad) return `« ${bad} » n'appartient pas aux catégories choisies`; }
        return null; } },
      { id: "techs", label: "Technology", type: "list", default: [], validate: each(x => TECHS.includes(x), "browser-based, client-server, network-protocol ou peer-to-peer") },
      { id: "risk", label: "Risk (1 à 5)", type: "list", default: ["4", "5"], validate: each(x => /^[1-5]$/.test(x), "risque entre 1 et 5") },
      ...CHARS.map(([id, l], i) => ({ id: "ch_" + id, label: l, type: "checkbox", default: false, group: "Characteristics (toutes doivent correspondre)" })),
      { id: "tags", label: "Tags d'application (optionnel)", type: "list", default: [], group: "Tags", validate: V_OBJS, hint: "Ex. « Sanctioned » ou tags prédéfinis (Web App, Enterprise VoIP…)." },
      { id: "useRule", label: "Créer une règle de sécurité utilisant le filtre", type: "checkbox", default: true, group: "Règle de sécurité" },
      { id: "rule", label: "Nom de la règle", type: "text", default: "Block-Risky-File-Sharing", validate: "name", required: true, show: v => v.useRule },
      { id: "from", label: "Zone source", type: "text", default: "Trust", validate: "name", required: true, show: v => v.useRule },
      { id: "to", label: "Zone destination", type: "text", default: "Untrust", validate: "name", required: true, show: v => v.useRule },
      { id: "src", label: "Source Address", type: "list", default: ["any"], validate: V_ADDR, show: v => v.useRule },
      { id: "action", label: "Action", type: "select", default: "deny", options: ACT, show: v => v.useRule },
      { id: "svc", label: "Service", type: "select", default: "any", show: v => v.useRule,
        options: [["any", "any (recommandé pour une règle de blocage)"], ["application-default", "application-default"]] },
      { id: "move", label: "Placer la règle en tête (Move Top)", type: "checkbox", default: true, show: v => v.useRule },
      { id: "testApp", label: "Application de test (vérification)", type: "text", default: "bittorrent", validate: (x) => appName(x) ? null : "Nom d'application invalide", show: v => v.useRule },
    ],
    build(v) {
      const chars = CHARS.filter(([id]) => v["ch_" + id]);
      if (!v.cats.length && !v.subs.length && !v.techs.length && !v.risk.length && !chars.length && !v.tags.length)
        return { notes: [{ type: "bad", title: "Filtre vide", text: "Sélectionner au moins un attribut (catégorie, risque, caractéristique…) : un filtre vide correspond à toutes les applications." }] };
      const n = q(v.name);
      const steps = [{ title: "Créer le filtre d'applications", path: ["Objects", "Application Filters"], window: "Application Filter",
        action: "Cliquer sur Add, saisir le nom puis cliquer sur les valeurs voulues dans chaque colonne (la liste des applications correspondantes se réduit en bas).",
        fields: [["Name", v.name], ["Category", v.cats], ["Subcategory", v.subs], ["Technology", v.techs], ["Risk", v.risk],
          ["Characteristics", chars.map(c => c[1])], ["Tags", v.tags]],
        note: "Filtre dynamique : les nouvelles App-ID correspondant aux critères y entrent automatiquement à chaque mise à jour de contenu. Plusieurs valeurs d'une même colonne = OU ; entre colonnes = ET." }];
      const cli = [
        `set application-filter ${n}` + (v.cats.length ? ` category ${members(v.cats)}` : "") + (v.subs.length ? ` subcategory ${members(v.subs)}` : "")
          + (v.techs.length ? ` technology ${members(v.techs)}` : "") + (v.risk.length ? ` risk ${members(v.risk)}` : ""),
        ...chars.map(([id]) => `set application-filter ${n} ${id} yes`),
        v.tags.length && `set application-filter ${n} tagging tag ${qm(v.tags)}`,
      ].filter(x => x && !/^set application-filter \S+$/.test(x));
      const verify = [];
      if (v.useRule) {
        const r = { name: v.rule, desc: `Contrôle des applications du filtre ${v.name}`, from: v.from, to: v.to, src: v.src, app: [v.name], svc: v.svc, action: v.action, move: v.move ? "top" : "",
          appAction: "Décocher Any → Add → taper le nom du filtre (les filtres et groupes apparaissent en fin de liste)." };
        steps.push(...ruleSteps(r), ...moveStep(v.rule, r.move));
        cli.push(...ruleCli(r));
        verify.push(`test security-policy-match from ${v.from} to ${v.to} source 192.168.1.50 destination 198.51.100.10 protocol 6 destination-port 6881 application ${v.testApp}`);
      }
      verify.push(`show running security-policy`);
      return { steps, cli, verify, notes: [{ type: "or", text: "Contrôler la liste « applications correspondantes » dans la fenêtre du filtre avant de l'utiliser dans une règle de blocage." }] };
    },
  });

  register({
    id: "m08-app-group", module: "M08", title: "Application Group + règle", icon: "🗂️",
    desc: "Groupe d'applications statique, règle de sécurité qui l'utilise et résolution des dépendances (Depends On).",
    tags: "app-id application group groupe dependencies dépendances depends on",
    fields: [
      { id: "name", label: "Nom du groupe", type: "text", required: true, validate: "name", default: "Collab-Apps" },
      { id: "apps", label: "Applications / filtres / groupes membres", type: "list", required: true, default: ["ms-office365", "ms-teams", "zoom", "webex"], validate: V_APPS, wide: true },
      { id: "useRule", label: "Créer la règle de sécurité utilisant le groupe", type: "checkbox", default: true, group: "Règle de sécurité" },
      { id: "rule", label: "Nom de la règle", type: "text", default: "LAN-Collab-Apps", validate: "name", required: true, show: v => v.useRule },
      { id: "desc", label: "Description", type: "text", default: "Applications de collaboration autorisées", show: v => v.useRule },
      { id: "from", label: "Zone source", type: "text", default: "Trust", validate: "name", required: true, show: v => v.useRule },
      { id: "src", label: "Source Address", type: "list", default: ["192.168.1.0/24"], validate: V_ADDR, show: v => v.useRule },
      { id: "to", label: "Zone destination", type: "text", default: "Untrust", validate: "name", required: true, show: v => v.useRule },
      { id: "deps", label: "Dépendances à ajouter (colonne « Depends On »)", type: "list", default: ["ssl", "web-browsing", "stun"], validate: V_APPS, show: v => v.useRule, wide: true,
        hint: "Recopier la liste affichée par la WebUI ; elle varie selon la version de contenu." },
      { id: "group", label: "Security Profile Group (optionnel)", type: "text", default: "Std-Profiles", validate: "name", show: v => v.useRule },
      { id: "before", label: "Placer avant la règle (optionnel)", type: "text", default: "LAN-to-Internet", validate: "name", show: v => v.useRule,
        hint: "Évite qu'une règle plus large (ex. application any) masque celle-ci (Rule Shadow)." },
    ],
    build(v) {
      const deps = (v.deps || []).filter(d => !v.apps.includes(d));
      const steps = [{ title: "Créer le groupe d'applications", path: ["Objects", "Application Groups"], window: "Application Group",
        action: "Cliquer sur Add, saisir le nom, puis Add (ou Browse) pour chaque application.", fields: [["Name", v.name], ["Applications", v.apps]] }];
      const cli = [`set application-group ${q(v.name)} members ${qm(v.apps)}`];
      if (v.useRule) {
        const r = { name: v.rule, desc: v.desc, from: v.from, to: v.to, src: v.src, app: [v.name, ...deps], group: v.group, move: v.before,
          appAction: "Décocher Any → Add → sélectionner le groupe. Dans la colonne « Depends On », cocher l'en-tête (tout sélectionner) → Add To Current Rule.",
          appNote: deps.length ? `Dépendances ajoutées à la règle : ${deps.join(", ")}.` : "" };
        steps.push(...ruleSteps(r), ...moveStep(v.rule, v.before));
        cli.push(...ruleCli(r));
      }
      steps.push({ title: "Contrôler les dépendances au commit", path: ["Commit"], action: "Après le commit, ouvrir l'onglet « App Dependency » de la fenêtre de commit (ou Tasks → Commit) : cliquer sur le compteur puis sur le nom de la règle pour ajouter les applications manquantes.",
        fields: [], note: "Aucun avertissement App Dependency ni Rule Shadow ne doit subsister." });
      return { steps, cli,
        verify: v.useRule ? [`test security-policy-match from ${v.from} to ${v.to} source 192.168.1.50 destination 52.112.0.10 protocol 6 destination-port 443 application ${v.apps[0]}`, "show running security-policy"] : [],
        notes: [{ type: "or", text: "Groupe statique : un nouvel App-ID n'y entre pas automatiquement (utiliser un Application Filter pour un regroupement dynamique)." }] };
    },
  });

  const CTX = [["http-req-host-header", "http-req-host-header"], ["http-req-uri-path", "http-req-uri-path"], ["http-req-user-agent-header", "http-req-user-agent-header"],
    ["ssl-req-chello-sni", "ssl-req-chello-sni"], ["ssl-rsp-certificate", "ssl-rsp-certificate"]];
  register({
    id: "m08-custom-app", module: "M08", title: "Application personnalisée (+ Application Override)", icon: "🧩",
    desc: "Application maison (catégorie, risque, port, signature) pour sortir le trafic interne de unknown-tcp, règle associée et Application Override optionnel.",
    tags: "custom application personnalisée signature unknown-tcp override application override",
    fields: [
      { id: "name", label: "Nom de l'application", type: "text", required: true, default: "crm-interne", validate: x => appName(x) ? null : "Minuscules, chiffres, - _ . (31 car. conseillés)" },
      { id: "desc", label: "Description", type: "text", default: "CRM interne hébergé en DMZ" },
      { id: "cat", label: "Category", type: "select", default: "business-systems", options: Object.keys(APP_CATS).filter(c => c !== "unknown").map(c => [c, c]) },
      { id: "sub", label: "Subcategory", type: "select", default: "erp-crm", options: ALL_SUBS.map(s => [s, s]),
        validate: (s, v) => (APP_CATS[v.cat] || []).includes(s) ? null : `Sous-catégorie incompatible avec ${v.cat} (${(APP_CATS[v.cat] || []).join(", ")})` },
      { id: "tech", label: "Technology", type: "select", default: "client-server", options: TECHS.map(t => [t, t]) },
      { id: "risk", label: "Risk", type: "select", default: "2", options: [["1"], ["2"], ["3"], ["4"], ["5"]] },
      { id: "ports", label: "Port(s) par défaut", type: "list", required: true, default: ["tcp/8443"], group: "Advanced",
        validate: each(x => /^(tcp|udp)\/(dynamic|\d+(-\d+)?(,\d+(-\d+)?)*)$/.test(x) && x.split("/")[1].split(/[,-]/).every(p => p === "dynamic" || (+p >= 1 && +p <= 65535)), "format tcp/8443, udp/5000-5010 ou tcp/dynamic") },
      { id: "sig", label: "Ajouter une signature", type: "checkbox", default: true, group: "Signature" },
      { id: "sigName", label: "Signature Name", type: "text", default: "crm-host", validate: "name", required: true, show: v => v.sig },
      { id: "scope", label: "Scope", type: "select", default: "protocol-data-unit", options: [["protocol-data-unit", "Transaction"], ["session", "Session"]], show: v => v.sig },
      { id: "ctx", label: "Context", type: "select", default: "http-req-host-header", options: CTX, show: v => v.sig },
      { id: "pattern", label: "Pattern (regex)", type: "text", default: "crm\\.example\\.local", required: true, show: v => v.sig,
        validate: x => x.replace(/\\./g, "x").replace(/[.*+?()[\]{}|^$]/g, "").length >= 7 ? null : "Au moins 7 octets fixes consécutifs requis dans le motif",
        hint: "Échapper les points (\\.) ; au moins 7 caractères fixes." },
      { id: "useRule", label: "Créer la règle de sécurité", type: "checkbox", default: true, group: "Règle de sécurité" },
      { id: "rule", label: "Nom de la règle", type: "text", default: "Allow-CRM-DMZ", validate: "name", required: true, show: v => v.useRule },
      { id: "from", label: "Zone source", type: "text", default: "Trust", validate: "name", required: true, show: v => v.useRule || v.ao },
      { id: "to", label: "Zone destination", type: "text", default: "DMZ", validate: "name", required: true, show: v => v.useRule || v.ao },
      { id: "dst", label: "Adresse du serveur", type: "list", default: ["172.16.1.10"], validate: V_ADDR, show: v => v.useRule || v.ao },
      { id: "group", label: "Security Profile Group (optionnel)", type: "text", default: "Std-Profiles", validate: "name", show: v => v.useRule },
      { id: "ao", label: "Créer aussi une règle Application Override", type: "checkbox", default: false, group: "Application Override (optionnel)" },
      { id: "aoName", label: "Nom de la règle d'override", type: "text", default: "AO-CRM", validate: "name", required: true, show: v => v.ao },
      { id: "aoProto", label: "Protocol", type: "select", default: "tcp", options: [["tcp"], ["udp"]], show: v => v.ao },
      { id: "aoPort", label: "Port", type: "text", default: "8443", validate: "portrange", required: true, show: v => v.ao },
    ],
    build(v) {
      const n = q(v.name);
      const steps = [
        { title: "Créer l'application — Configuration", path: ["Objects", "Applications"], tab: "Configuration", window: "Application",
          action: "Cliquer sur Add (en bas de la liste des applications).",
          fields: [["Name", v.name], ["Description", v.desc], ["Category", v.cat], ["Subcategory", v.sub], ["Technology", v.tech], ["Risk", v.risk]] },
        { title: "Créer l'application — Advanced", path: ["Objects", "Applications"], tab: "Advanced", window: "Application",
          fields: [["Defaults", "Port"], ["Port", v.ports]], note: "Le port par défaut sert à « application-default » dans les règles." },
      ];
      const cli = [`set application ${n} category ${v.cat} subcategory ${v.sub} technology ${v.tech} risk ${v.risk}`,
        v.desc && `set application ${n} description ${q(v.desc)}`, `set application ${n} default port ${members(v.ports)}`];
      if (v.sig) {
        steps.push({ title: "Créer l'application — Signatures", path: ["Objects", "Applications"], tab: "Signatures", window: "Signature",
          action: "Add → saisir le nom → Add And Condition → Add Or Condition dans « And Condition 1 ».",
          fields: [["Signature Name", v.sigName], ["Scope", v.scope === "session" ? "Session" : "Transaction"], ["Ordered Condition Match", true],
            ["Operator", "Pattern Match"], ["Context", v.ctx], ["Pattern", v.pattern]],
          note: v.ctx.startsWith("ssl") ? "Contexte SSL : visible sans déchiffrement (SNI / certificat)." : "Contexte HTTP : le trafic doit être en clair ou déchiffré.",
        });
        cli.push(`set application ${n} signature ${q(v.sigName)} scope ${v.scope} order-free no`,
          `set application ${n} signature ${q(v.sigName)} and-condition "And Condition 1" or-condition "Or Condition 1" operator pattern-match context ${v.ctx} pattern "${v.pattern.replace(/"/g, '\\"')}"`);
      }
      if (v.useRule) {
        const r = { name: v.rule, desc: `Accès à ${v.name}`, from: v.from, to: v.to, dst: v.dst, app: [v.name], group: v.group };
        steps.push(...ruleSteps(r)); cli.push(...ruleCli(r));
      }
      if (v.ao) {
        const p = ["Policies", "Application Override"], w = "Application Override Policy Rule";
        steps.push(
          { title: `Override « ${v.aoName} » — General`, path: p, tab: "General", window: w, action: "Cliquer sur Add.", fields: [["Name", v.aoName]] },
          { title: `Override « ${v.aoName} » — Source`, path: p, tab: "Source", window: w, fields: [["Source Zone", v.from], ["Source Address", "Any"]] },
          { title: `Override « ${v.aoName} » — Destination`, path: p, tab: "Destination", window: w, fields: [["Destination Zone", v.to], ["Destination Address", v.dst]] },
          { title: `Override « ${v.aoName} » — Protocol/Application`, path: p, tab: "Protocol/Application", window: w, fields: [["Protocol", v.aoProto.toUpperCase()], ["Port", v.aoPort], ["Application", v.name]],
            warn: "Le trafic overridé n'est plus inspecté (ni App-ID ni Content-ID / profils de menaces). Réserver aux flux internes de confiance." });
        cli.push(`set rulebase application-override rules ${q(v.aoName)} from ${q(v.from)} to ${q(v.to)} source any destination ${qm(v.dst)} protocol ${v.aoProto} port ${v.aoPort} application ${n}`);
      }
      return { steps, cli: cli.filter(Boolean),
        verify: [`show running application-override-policy`, v.useRule ? `test security-policy-match from ${v.from} to ${v.to} source 192.168.1.50 destination ${PAN.ip.validCidr(v.dst[0]) ? v.dst[0].split("/")[0] : "172.16.1.10"} protocol 6 destination-port ${(v.ports[0].split("/")[1] || "443").split(/[,-]/)[0]} application ${v.name}` : ""].filter(Boolean),
        notes: [{ type: "or", text: "Contrôle : Monitor > Logs > Traffic, filtre ( app eq " + v.name + " ). Le trafic ne doit plus apparaître en unknown-tcp." }] };
    },
  });

  register({
    id: "m08-policy-optimizer", module: "M08", title: "Policy Optimizer : port-based → App-ID", icon: "🔁",
    desc: "Conversion guidée d'une règle basée sur les ports (service-http/https…) en règle App-ID via Policy Optimizer.",
    tags: "policy optimizer no app specified unused apps clone match usage migration port-based",
    fields: [
      { id: "old", label: "Règle port-based à convertir", type: "text", required: true, validate: "name", default: "LAN-Web-Ports" },
      { id: "from", label: "Zone source de la règle", type: "text", required: true, validate: "name", default: "Trust" },
      { id: "to", label: "Zone destination de la règle", type: "text", required: true, validate: "name", default: "Untrust" },
      { id: "src", label: "Source Address de la règle", type: "list", default: ["192.168.1.0/24"], validate: V_ADDR },
      { id: "method", label: "Méthode", type: "select", default: "clone",
        options: [["clone", "Create Cloned Rule (recommandé : conserve la règle d'origine dessous)"], ["add", "Add To This Rule (modifie la règle d'origine)"], ["match", "Match Usage (remplace par les Apps Seen)"]] },
      { id: "apps", label: "Applications vues à autoriser (Apps Seen)", type: "list", required: true, default: ["web-browsing", "ssl", "google-base", "ms-office365"], validate: V_APPS, wide: true },
      { id: "newRule", label: "Nom de la règle clonée", type: "text", default: "LAN-Web-Apps", validate: "name", required: true, show: v => v.method === "clone" },
      { id: "container", label: "Add container app", type: "checkbox", default: true, show: v => v.method === "clone" },
      { id: "appDefault", label: "Passer le service en application-default", type: "checkbox", default: true },
      { id: "disableOld", label: "Désactiver ensuite la règle port-based (après période d'observation)", type: "checkbox", default: false, show: v => v.method === "clone" },
    ],
    build(v) {
      const P = ["Policies", "Security", "Policy Optimizer", "No App Specified"];
      const target = v.method === "clone" ? v.newRule : v.old;
      const steps = [
        { title: "Identifier la règle port-based", path: P, action: `Trier par « Traffic (Bytes, 30 days) » ou « Apps Seen », repérer ${v.old} puis cliquer sur Compare (ou sur le nombre d'Apps Seen).`, fields: [],
          note: "Apps Seen est mis à jour environ toutes les heures et ne compte que les sessions journalisées en fin de session (Log at Session End)." },
        { title: "Sélectionner les applications vues", path: P, window: "Applications & Usage", action: "Régler Timeframe (Anytime ou 30 days), cocher les applications à autoriser dans Apps Seen.",
          fields: [["Timeframe", "Anytime"], ["Apps Seen (cochées)", v.apps]] },
      ];
      if (v.method === "clone") steps.push({ title: "Créer la règle clonée App-ID", path: P, window: "Create Cloned Rule", action: "Cliquer sur Create Cloned Rule, nommer la règle, vérifier les dépendances, OK.",
        fields: [["Name", v.newRule], ["Add container app", v.container]], note: `La règle clonée est insérée au-dessus de ${v.old} ; celle-ci reste en filet de sécurité.` });
      else steps.push({ title: v.method === "add" ? "Ajouter les applications à la règle" : "Faire correspondre l'usage", path: P, window: "Applications & Usage",
        action: v.method === "add" ? "Cliquer sur Add To This Rule." : "Cliquer sur Match Usage : les Apps Seen remplacent les applications de la règle.", fields: [] });
      if (v.appDefault) steps.push({ title: `Restreindre « ${target} » aux ports par défaut`, path: ["Policies", "Security"], tab: "Service/URL Category", window: "Security Policy Rule",
        action: `Cliquer sur ${target} → onglet Service/URL Category → supprimer les services port-based.`, fields: [["Service", "application-default"]] });
      steps.push({ title: "Nettoyer les applications inutilisées (après quelques semaines)", path: ["Policies", "Security", "Policy Optimizer", "Unused Apps"],
        action: `Cliquer sur Compare pour ${target} : retirer les applications jamais vues (Delete) ou Match Usage.`, fields: [], note: "Tenir compte des usages périodiques (trimestriels, annuels) avant suppression." });
      if (v.method === "clone" && v.disableOld) steps.push({ title: `Désactiver « ${v.old} »`, path: ["Policies", "Security"], action: `Lorsque ${v.old} ne reçoit plus de trafic (Hit Count stable), la sélectionner → Disable.`, fields: [] });

      const cli = ["# Équivalent CLI de l'action Policy Optimizer"];
      if (v.method === "clone") {
        cli.push(...ruleCli({ name: v.newRule, desc: `Clone App-ID de ${v.old}`, from: v.from, to: v.to, src: v.src, app: v.apps, svc: v.appDefault ? "application-default" : "any", move: v.old }));
        if (v.disableOld) cli.push(`set rulebase security rules ${q(v.old)} disabled yes`);
      } else {
        cli.push(`delete rulebase security rules ${q(v.old)} application`, `set rulebase security rules ${q(v.old)} application ${qm(v.apps)}`);
        if (v.appDefault) cli.push(`delete rulebase security rules ${q(v.old)} service`, `set rulebase security rules ${q(v.old)} service application-default`);
      }
      return { steps, cli,
        verify: ["show rule-hit-count vsys vsys-name vsys1 rule-base security rules all", `test security-policy-match from ${v.from} to ${v.to} source 192.168.1.50 destination 142.250.0.10 protocol 6 destination-port 443 application ssl`],
        notes: [{ type: "warn", text: "Après conversion, une application non listée bascule sur la règle suivante (ou interzone-default). Surveiller les refus dans Monitor > Logs > Traffic ( action neq allow )." }] };
    },
  });

  register({
    id: "m08-app-update", module: "M08", title: "Mise à jour de contenu & nouvelles App-ID", icon: "🔄",
    desc: "Applications and Threats : vérification, revue des nouvelles App-ID, installation (option « Disable new apps ») et planification.",
    tags: "dynamic updates content update app-id new apps disable new apps schedule threshold review policies",
    noCommit: true,
    fields: [
      { id: "now", label: "Installer maintenant la dernière version", type: "checkbox", default: true, group: "Installation immédiate" },
      { id: "disableNow", label: "Disable new apps in content update", type: "checkbox", default: false, show: v => v.now,
        hint: "Les nouvelles App-ID sont installées désactivées : protection contre les menaces à jour, classification inchangée." },
      { id: "sched", label: "Planifier les mises à jour", type: "checkbox", default: true, group: "Planification (Schedule)" },
      { id: "rec", label: "Recurrence", type: "select", default: "daily", show: v => v.sched,
        options: [["every-30-mins", "Every 30 Minutes"], ["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"]] },
      { id: "dow", label: "Day", type: "select", default: "wednesday", show: v => v.sched && v.rec === "weekly",
        options: ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"].map(d => [d, d]) },
      { id: "at", label: "Time (HH:MM)", type: "text", default: "01:15", show: v => v.sched && (v.rec === "daily" || v.rec === "weekly"), required: true,
        validate: x => /^([01]\d|2[0-3]):[0-5]\d$/.test(x) ? null : "Format HH:MM" },
      { id: "min", label: "Minutes past hour", type: "number", default: "15", min: 0, max: 59, show: v => v.sched && (v.rec === "hourly" || v.rec === "every-30-mins"), required: true,
        validate: (x, v) => v.rec === "every-30-mins" && +x > 29 ? "0 à 29 pour Every 30 Minutes" : null },
      { id: "act", label: "Action", type: "select", default: "download-and-install", show: v => v.sched, options: [["download-and-install", "download-and-install"], ["download-only", "download-only"]] },
      { id: "thr", label: "Threshold (hours)", type: "number", default: "24", min: 1, max: 336, show: v => v.sched,
        hint: "Délai avant installation d'une version (évite d'installer une version retirée)." },
      { id: "newThr", label: "New App-ID Threshold (hours, optionnel)", type: "number", default: "", min: 1, max: 336, show: v => v.sched },
      { id: "schedDisable", label: "Disable new apps in content update (planification)", type: "checkbox", default: false, show: v => v.sched },
    ],
    build(v) {
      const P = ["Device", "Dynamic Updates"];
      const steps = [{ title: "Rechercher les nouvelles versions", path: P, action: "Cliquer sur Check Now en bas de la page.", fields: [] }];
      if (v.now) steps.push(
        { title: "Télécharger la dernière version Applications and Threats", path: P, action: "Section Applications and Threats → colonne Action → Download sur la version la plus récente.", fields: [] },
        { title: "Revoir les nouvelles App-ID", path: P, action: "Colonne Features : cliquer sur Review Apps (App-ID nouvelles / modifiées), puis colonne Action : Review Policies pour voir les règles impactées.", fields: [],
          note: "Dans Review Policies, sélectionner une App-ID puis Add app to selected policies pour l'ajouter aux règles qui autorisaient l'ancienne classification." },
        { title: "Installer la version", path: P, window: "Install", action: "Colonne Action → Install.", fields: [["Disable new apps in content update", v.disableNow]],
          note: v.disableNow ? "Réactiver plus tard : Objects > Applications → sélectionner les applications → Enable." : "" });
      let sched = "";
      if (v.sched) {
        const fr = v.rec === "weekly" ? `weekly day-of-week ${v.dow} at ${v.at}` : v.rec === "daily" ? `daily at ${v.at}` : `${v.rec} at ${v.min}`;
        sched = fr;
        steps.push({ title: "Planifier Applications and Threats", path: P, window: "Applications and Threats Update Schedule", action: "Section Applications and Threats → cliquer sur le lien Schedule.",
          fields: [["Recurrence", { "every-30-mins": "Every 30 Minutes", hourly: "Hourly", daily: "Daily", weekly: "Weekly" }[v.rec]], ["Day", v.rec === "weekly" ? v.dow : ""],
            ["Time", v.rec === "daily" || v.rec === "weekly" ? v.at : ""], ["Minutes Past Hour", v.rec === "hourly" || v.rec === "every-30-mins" ? v.min : ""],
            ["Action", v.act], ["Disable new apps in content update", v.schedDisable], ["Threshold (hours)", v.thr], ["New App-ID Threshold (hours)", v.newThr]] });
      }
      const fr = sched.split(" ")[0];
      const cliRaw = [
        "# --- Mode opérationnel ---", "request content upgrade check", "request content upgrade info",
        ...(v.now ? ["request content upgrade download latest", "show jobs processed", `request content upgrade install${v.disableNow ? " disable-new-content yes" : ""} version latest`, "show jobs processed"] : []),
      ];
      if (v.sched) cliRaw.push(...["", "configure",
        `set deviceconfig system update-schedule threats recurring ${sched} action ${v.act}`,
        v.schedDisable && `set deviceconfig system update-schedule threats recurring ${fr} disable-new-content yes`,
        v.thr ? `set deviceconfig system update-schedule threats recurring threshold ${v.thr}` : null,
        v.newThr ? `set deviceconfig system update-schedule threats recurring new-app-threshold ${v.newThr}` : null,
        "commit", "exit"].filter(x => typeof x === "string"));
      cliRaw.push("", "# --- Vérification ---", "show system info | match app-version");
      if (v.sched) steps.push({ title: "Valider la planification (Commit)", path: ["Commit"], action: "Commit → Commit (la planification est un paramètre de configuration).", fields: [] });
      return { steps, cliRaw: cliRaw.filter(x => typeof x === "string"),
        notes: [{ type: "or", text: "Alternative aux App-ID désactivées : règle Allow avec un Application Filter « New App-ID » (Apply to New App-IDs only) pour les applications critiques." }] };
    },
  });

  /* ================= M09 · Security Profiles ================= */
  const DECODERS = ["ftp", "http", "http2", "imap", "pop3", "smb", "smtp"];
  const ML_MODELS = ["Windows Executables", "PowerShell Script 1", "PowerShell Script 2", "Executable Linked Format", "MSOffice", "Shell"];
  const profNameField = (def) => ({ id: "name", label: "Nom du profil", type: "text", required: true, validate: "name", default: def });
  const descField = (def) => ({ id: "desc", label: "Description", type: "text", default: def });
  const excField = { id: "exc", label: "Exceptions (Threat ID, optionnel)", type: "list", default: [], validate: each(x => /^\d{4,9}$/.test(x), "Threat ID numérique attendu"), group: "Exceptions" };

  register({
    id: "m09-antivirus", module: "M09", title: "Profil Antivirus", icon: "🦠",
    desc: "Actions par décodeur (signature, WildFire, WildFire Inline ML), modèles ML, exceptions et application au groupe ou à la règle.",
    tags: "antivirus av virus decoder wildfire inline ml security profile",
    fields: [
      profNameField("Std-AV"), descField("Profil antivirus standard"),
      ...DECODERS.map(d => ({ id: "d_" + d, label: d, type: "select", default: "reset-both", options: THR_ACT, group: "Signature Action par décodeur" })),
      { id: "wf", label: "WildFire Signature Action", type: "select", default: "same", group: "WildFire & Inline ML", options: [["same", "Identique à Signature Action"], ...THR_ACT] },
      { id: "ml", label: "WildFire Inline ML Action", type: "select", default: "same", options: [["same", "Identique à Signature Action"], ...THR_ACT] },
      { id: "mlModels", label: "Modèles Inline ML", type: "select", default: "enable", options: [["enable", "enable"], ["enable(alert-only)", "enable (alert-only)"], ["disable", "disable"], ["skip", "Ne pas modifier"]],
        hint: "Nécessite la licence WildFire / Advanced WildFire." },
      { id: "pcap", label: "Packet Capture", type: "checkbox", default: false },
      excField,
      ...applyFields(),
    ],
    build(v) {
      const n = q(v.name), P = ["Objects", "Security Profiles", "Antivirus"], W = "Antivirus Profile";
      const wfa = d => v.wf === "same" ? v["d_" + d] : v.wf, mla = d => v.ml === "same" ? v["d_" + d] : v.ml;
      const steps = [
        { title: "Créer le profil — Action", path: P, tab: "Action", window: W, action: "Cliquer sur Add, puis régler chaque ligne du tableau Decoders.",
          fields: [["Name", v.name], ["Description", v.desc], ["Packet Capture", v.pcap], ...DECODERS.map(d => [`${d} (Signature / WildFire / ML)`, `${v["d_" + d]} / ${wfa(d)} / ${mla(d)}`])],
          note: "Bonne pratique : reset-both sur tous les décodeurs (y compris smtp, imap, pop3 qui sont en alert dans le profil default)." },
      ];
      if (v.mlModels !== "skip") steps.push({ title: "Créer le profil — WildFire Inline ML", path: P, tab: "WildFire Inline ML", window: W,
        fields: ML_MODELS.map(m => [m, v.mlModels]), note: "La liste des modèles dépend de la version de contenu ; appliquer la même action à tous les modèles affichés." });
      if (v.exc.length) steps.push({ title: "Créer le profil — Signature Exceptions", path: P, tab: "Signature Exceptions", window: W, fields: [["Threat ID", v.exc]] });
      const cli = [v.desc && `set profiles virus ${n} description ${q(v.desc)}`,
        ...DECODERS.map(d => `set profiles virus ${n} decoder ${d} action ${v["d_" + d]} wildfire-action ${wfa(d)} mlav-action ${mla(d)}`),
        v.mlModels !== "skip" && ML_MODELS.map(m => `set profiles virus ${n} mlav-engine-filebased-enabled ${q(m)} mlav-policy-action ${v.mlModels.includes("(") ? `"${v.mlModels}"` : v.mlModels}`),
        `set profiles virus ${n} packet-capture ${v.pcap ? "yes" : "no"}`,
        ...v.exc.map(t => `set profiles virus ${n} threat-exception ${t}`)].flat().filter(Boolean);
      const a = applyOut(v, "virus", v.name);
      return { steps: [...steps, ...a.steps], cli: [...cli, ...a.cli],
        verify: ["show system info | match av-version", "show system info | match wildfire-version"],
        notes: [{ type: "or", text: "Test : télécharger le fichier EICAR en HTTP (https://www.eicar.org) depuis un poste ; en HTTPS, le déchiffrement est requis. Monitor > Logs > Threat ( subtype eq virus )." }] };
    },
  });

  const sevRules = (pfx) => [
    { id: pfx + "ch", label: "critical + high : Action", type: "select", default: "reset-both", options: THR_ACT, group: "Règles par sévérité" },
    { id: pfx + "chp", label: "critical + high : Packet Capture", type: "select", default: "single-packet", options: PCAP },
    { id: pfx + "med", label: "medium : Action", type: "select", default: "reset-both", options: THR_ACT },
    { id: pfx + "low", label: "low + informational : Action", type: "select", default: "default", options: THR_ACT },
  ];
  const sevList = v => [
    { rn: "Std-Critical-High", sev: ["critical", "high"], act: v.r_ch, pcap: v.r_chp },
    { rn: "Std-Medium", sev: ["medium"], act: v.r_med, pcap: "disable" },
    { rn: "Std-Low-Info", sev: ["low", "informational"], act: v.r_low, pcap: "disable" },
  ];

  register({
    id: "m09-anti-spyware", module: "M09", title: "Profil Anti-Spyware + DNS sinkhole", icon: "🕵️",
    desc: "Règles par sévérité, DNS Policies (signatures Palo Alto, DNS Security, EDL de domaines), adresses de sinkhole et règle de détection des hôtes infectés.",
    tags: "anti-spyware spyware dns sinkhole dns policies dns security edl c2 command and control",
    fields: [
      profNameField("Std-AS"), descField("Profil anti-spyware standard"),
      ...sevRules("r_"),
      { id: "pandns", label: "default-paloalto-dns : Policy Action", type: "select", default: "sinkhole", group: "DNS Policies",
        options: [["sinkhole", "sinkhole"], ["block", "block"], ["alert", "alert"], ["allow", "allow"]] },
      { id: "pandnsPcap", label: "default-paloalto-dns : Packet Capture", type: "select", default: "single-packet", options: PCAP },
      { id: "dnsSec", label: "Licence DNS Security : sinkhole C2, malware, phishing", type: "checkbox", default: false },
      { id: "edl", label: "Ajouter une EDL de domaines", type: "checkbox", default: false },
      { id: "edlName", label: "Nom de l'EDL (Domain List)", type: "text", default: "Malicious-Domains-EDL", validate: "name", required: true, show: v => v.edl,
        hint: "EDL créée avec le module « External Dynamic List » (#m10-edl)." },
      { id: "edlAct", label: "Action EDL", type: "select", default: "sinkhole", show: v => v.edl, options: [["sinkhole", "sinkhole"], ["block", "block"], ["alert", "alert"]] },
      { id: "v4", label: "Sinkhole IPv4", type: "select", default: "pan", group: "DNS Sinkhole Settings",
        options: [["pan", "Palo Alto Networks Sinkhole IP (sinkhole.paloaltonetworks.com)"], ["lo", "IPv4 Loopback IP (127.0.0.1)"], ["custom", "Adresse personnalisée"]] },
      { id: "v4ip", label: "Adresse sinkhole IPv4", type: "ip", default: "172.16.1.250", required: true, show: v => v.v4 === "custom",
        hint: "IP inexistante joignable via le pare-feu (ex. DMZ) : le trafic vers elle traverse le pare-feu et identifie l'hôte infecté." },
      { id: "v6", label: "Sinkhole IPv6", type: "text", default: "::1", required: true, validate: x => /^[0-9a-fA-F:]+$/.test(x) && x.includes(":") ? null : "Adresse IPv6 attendue" },
      { id: "allowDom", label: "DNS Exceptions — domaines autorisés (optionnel)", type: "list", default: [], validate: each(x => /^[A-Za-z0-9.*-]+$/.test(x), "domaine invalide") },
      { id: "sinkRule", label: "Créer une règle qui bloque et journalise le trafic vers le sinkhole", type: "checkbox", default: true, group: "Détection des hôtes infectés" },
      { id: "sinkFrom", label: "Zone des clients", type: "text", default: "Trust", validate: "name", required: true, show: v => v.sinkRule },
      { id: "sinkTo", label: "Zone vers le sinkhole", type: "text", default: "Untrust", validate: "name", required: true, show: v => v.sinkRule, hint: "Untrust pour l'IP Palo Alto ; zone de l'IP personnalisée sinon." },
      ...applyFields(),
    ],
    build(v) {
      const n = q(v.name), P = ["Objects", "Security Profiles", "Anti-Spyware"], W = "Anti-Spyware Profile";
      const rules = sevList(v);
      const v4 = v.v4 === "pan" ? "pan-sinkhole-default-ip" : v.v4 === "lo" ? "127.0.0.1" : v.v4ip;
      const v4l = v.v4 === "pan" ? "Palo Alto Networks Sinkhole IP" : v.v4 === "lo" ? "IPv4 Loopback IP" : v.v4ip;
      const dnsCats = v.dnsSec ? ["pan-dns-sec-cc", "pan-dns-sec-malware", "pan-dns-sec-phishing"] : [];
      const steps = [
        { title: "Créer le profil — Signature Policies", path: P, tab: "Signature Policies", window: W, action: "Cliquer sur Add, nommer le profil, puis Add une règle par ligne ci-dessous (Threat Name any, Category any).",
          fields: [["Name", v.name], ["Description", v.desc], ...rules.map(r => [`${r.rn} (${r.sev.join(", ")})`, `${r.act} — pcap ${r.pcap}`])],
          note: "Équivaut au profil prédéfini strict (alternative : cocher strict → Clone → renommer)." },
        { title: "Créer le profil — DNS Policies", path: P, tab: "DNS Policies", window: W,
          fields: [["Palo Alto Networks Content › default-paloalto-dns", `${v.pandns} — pcap ${v.pandnsPcap}`],
            ...dnsCats.map(c => [`DNS Security › ${c}`, "sinkhole"]),
            ["External Dynamic Lists", v.edl ? `${v.edlName} — ${v.edlAct}` : ""],
            ["Sinkhole IPv4", v4l], ["Sinkhole IPv6", v.v6]],
          note: v.edl ? "L'EDL n'apparaît dans DNS Policies que si elle est de type Domain List." : "" },
      ];
      if (v.allowDom.length) steps.push({ title: "Créer le profil — DNS Exceptions", path: P, tab: "DNS Exceptions", window: W, action: "Section DNS Domain/FQDN Allow List → Add.", fields: [["Name / FQDN", v.allowDom]] });
      const cli = [v.desc && `set profiles spyware ${n} description ${q(v.desc)}`,
        ...rules.map(r => `set profiles spyware ${n} rules ${r.rn} threat-name any category any severity ${members(r.sev)} action ${r.act} packet-capture ${r.pcap}`),
        `set profiles spyware ${n} botnet-domains lists default-paloalto-dns action ${v.pandns} packet-capture ${v.pandnsPcap}`,
        ...dnsCats.map(c => `set profiles spyware ${n} botnet-domains dns-security-categories ${c} action sinkhole log-level default packet-capture disable`),
        v.edl && `set profiles spyware ${n} botnet-domains lists ${q(v.edlName)} action ${v.edlAct} packet-capture disable`,
        `set profiles spyware ${n} botnet-domains sinkhole ipv4-address ${v4} ipv6-address ${v.v6}`,
        ...v.allowDom.map(d => `set profiles spyware ${n} botnet-domains whitelist ${q(d)}`)].filter(Boolean);
      if (v.sinkRule) {
        const obj = v.v4 === "custom" ? "Sinkhole-IP" : "Sinkhole-PANW";
        steps.push({ title: `Créer l'objet adresse « ${obj} »`, path: ["Objects", "Addresses"], window: "Address", action: "Cliquer sur Add.",
          fields: [["Name", obj], ["Type", v.v4 === "custom" ? "IP Netmask" : "FQDN"], ["Value", v.v4 === "custom" ? v.v4ip : "sinkhole.paloaltonetworks.com"]] });
        cli.push(`set address ${obj} ${v.v4 === "custom" ? "ip-netmask " + v.v4ip : "fqdn sinkhole.paloaltonetworks.com"}`);
        const r = { name: "Block-Sinkhole", desc: "Hôtes infectés : trafic vers l'adresse de sinkhole", from: v.sinkFrom, to: v.sinkTo, dst: [obj], svc: "any", action: "deny", move: "top" };
        steps.push(...ruleSteps(r), ...moveStep(r.name, "top")); cli.push(...ruleCli(r));
      }
      const a = applyOut(v, "spyware", v.name);
      return { steps: [...steps, ...a.steps], cli: [...cli, ...a.cli],
        verify: ["show system info | match threat-version", "show rule-hit-count vsys vsys-name vsys1 rule-base security rules all"],
        notes: [
          { type: "warn", text: "Le sinkhole n'agit que si la requête DNS traverse le pare-feu. Avec un DNS interne, le Threat log montre le serveur DNS : identifier l'hôte infecté via la règle Block-Sinkhole (Traffic log)." },
          { type: "or", text: "Contrôle : Monitor > Logs > Threat ( action eq sinkhole ) ; Monitor > Logs > Traffic ( rule eq 'Block-Sinkhole' )." }] };
    },
  });

  register({
    id: "m09-vulnerability", module: "M09", title: "Profil Vulnerability Protection", icon: "🛡️",
    desc: "Règles par sévérité (reset-both / default), packet capture, type d'hôte et exceptions.",
    tags: "vulnerability protection vuln exploit ips security profile",
    fields: [
      profNameField("Std-VP"), descField("Profil de protection contre les vulnérabilités standard"),
      ...sevRules("r_"),
      { id: "host", label: "Host Type", type: "select", default: "any", options: [["any"], ["client"], ["server"]] },
      excField,
      ...applyFields(),
    ],
    build(v) {
      const n = q(v.name), P = ["Objects", "Security Profiles", "Vulnerability Protection"], W = "Vulnerability Protection Profile";
      const rules = sevList(v);
      const steps = [{ title: "Créer le profil — Rules", path: P, tab: "Rules", window: W, action: "Cliquer sur Add, nommer le profil, puis Add une règle par ligne (Threat Name any, CVE any, Vendor ID any, Category any).",
        fields: [["Name", v.name], ["Description", v.desc], ["Host Type", v.host], ...rules.map(r => [`${r.rn} (${r.sev.join(", ")})`, `${r.act} — pcap ${r.pcap}`])],
        note: "Équivaut au profil prédéfini strict (alternative : cocher strict → Clone → renommer)." }];
      if (v.exc.length) steps.push({ title: "Créer le profil — Exceptions", path: P, tab: "Exceptions", window: W, action: "Cocher Show all signatures, rechercher l'ID, cocher Enable et choisir l'action.", fields: [["Threat ID", v.exc]] });
      const cli = [v.desc && `set profiles vulnerability ${n} description ${q(v.desc)}`,
        ...rules.map(r => `set profiles vulnerability ${n} rules ${r.rn} threat-name any cve any vendor-id any category any host ${v.host} severity ${members(r.sev)} action ${r.act} packet-capture ${r.pcap}`),
        ...v.exc.map(t => `set profiles vulnerability ${n} threat-exception ${t} action default`)].filter(Boolean);
      const a = applyOut(v, "vulnerability", v.name);
      return { steps: [...steps, ...a.steps], cli: [...cli, ...a.cli], verify: ["show system info | match threat-version"],
        notes: [{ type: "or", text: "Contrôle : Monitor > Logs > Threat ( subtype eq vulnerability )." }] };
    },
  });

  const FT = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
  register({
    id: "m09-file-blocking", module: "M09", title: "Profil File Blocking", icon: "📁",
    desc: "Blocage / continue / alerte par type de fichier, application et direction.",
    tags: "file blocking fichiers exe dll block continue alert",
    fields: [
      profNameField("Std-FB"), descField("Profil de blocage de fichiers standard"),
      { id: "block", label: "Types bloqués", type: "list", required: true, group: "Règles", wide: true,
        default: ["7z", "bat", "chm", "class", "cpl", "dll", "hlp", "hta", "jar", "ocx", "pif", "scr", "torrent", "vbe", "wsf"], validate: each(x => FT.test(x), "type de fichier invalide") },
      { id: "blockApp", label: "Applications (règle de blocage)", type: "list", default: ["any"], validate: V_APPS },
      { id: "dir", label: "Direction (règle de blocage)", type: "select", default: "both", options: [["both"], ["download"], ["upload"]] },
      { id: "enc", label: "Bloquer les archives chiffrées (encrypted-rar, encrypted-zip)", type: "checkbox", default: true },
      { id: "cont", label: "Types en « continue » (page de confirmation, optionnel)", type: "list", default: ["exe", "msi"], validate: each(x => FT.test(x), "type de fichier invalide"), wide: true },
      { id: "alertAll", label: "Journaliser tous les autres types (alert any)", type: "checkbox", default: true },
      ...applyFields(),
    ],
    build(v) {
      const d = dup(v.block, v.cont);
      if (d.length) return { notes: [{ type: "bad", title: "Doublon", text: `Type(s) présent(s) à la fois en block et continue : ${d.join(", ")}.` }] };
      const n = q(v.name), P = ["Objects", "Security Profiles", "File Blocking"], W = "File Blocking Profile";
      const rules = [{ rn: "Block-Risky-Types", app: v.blockApp, ft: v.block, dir: v.dir, act: "block" }];
      if (v.enc) rules.push({ rn: "Block-Encrypted", app: ["any"], ft: ["encrypted-rar", "encrypted-zip"], dir: "both", act: "block" });
      if (v.cont.length) rules.push({ rn: "Continue-Executables", app: ["any"], ft: v.cont, dir: "download", act: "continue" });
      if (v.alertAll) rules.push({ rn: "Alert-All", app: ["any"], ft: ["any"], dir: "both", act: "alert" });
      const steps = [{ title: "Créer le profil File Blocking", path: P, window: W, action: "Cliquer sur Add, nommer le profil, puis Add une règle par ligne, dans cet ordre.",
        fields: [["Name", v.name], ["Description", v.desc], ...rules.map(r => [r.rn, `Applications ${r.app.join(", ")} · File Types ${r.ft.join(", ")} · Direction ${r.dir} · Action ${r.act}`])],
        note: "Alternative : cloner le profil prédéfini « strict file blocking » puis l'adapter." }];
      const cli = [v.desc && `set profiles file-blocking ${n} description ${q(v.desc)}`,
        ...rules.map(r => `set profiles file-blocking ${n} rules ${r.rn} application ${members(r.app)} file-type ${members(r.ft)} direction ${r.dir} action ${r.act}`)].filter(Boolean);
      const a = applyOut(v, "file-blocking", v.name);
      const notes = [{ type: "or", text: "Contrôle : Monitor > Logs > Data Filtering (les blocages de fichiers y sont journalisés)." }];
      if (v.cont.length) notes.push({ type: "warn", text: "« continue » ne fonctionne qu'en HTTP (ou HTTPS déchiffré) et requiert Response Pages sur l'Interface Management Profile de l'interface côté client (#m10-response-pages)." });
      return { steps: [...steps, ...a.steps], cli: [...cli, ...a.cli], notes };
    },
  });

  register({
    id: "m09-profile-group", module: "M09", title: "Security Profile Group", icon: "🧰",
    desc: "Regroupe les profils (AV, AS, VP, URL, FB, DF, WildFire) et l'applique aux règles de sécurité. Option « default » pour les nouvelles règles.",
    tags: "security profile group groupe profils default profile-setting",
    fields: [
      { id: "isDefault", label: "Nommer le groupe « default » (appliqué automatiquement aux nouvelles règles)", type: "checkbox", default: false },
      { id: "name", label: "Nom du groupe", type: "text", required: true, validate: "name", default: "Std-Profiles", show: v => !v.isDefault },
      { id: "virus", label: "Antivirus Profile", type: "text", default: "Std-AV", validate: "name", group: "Profils (vide = None)" },
      { id: "spyware", label: "Anti-Spyware Profile", type: "text", default: "Std-AS", validate: "name" },
      { id: "vulnerability", label: "Vulnerability Protection Profile", type: "text", default: "Std-VP", validate: "name" },
      { id: "url-filtering", label: "URL Filtering Profile", type: "text", default: "Std-URL", validate: "name" },
      { id: "file-blocking", label: "File Blocking Profile", type: "text", default: "Std-FB", validate: "name" },
      { id: "data-filtering", label: "Data Filtering Profile", type: "text", default: "", validate: "name" },
      { id: "wildfire-analysis", label: "WildFire Analysis Profile", type: "text", default: "default", validate: "name" },
      { id: "rules", label: "Règles de sécurité auxquelles appliquer le groupe", type: "list", default: ["LAN-to-Internet", "LAN-to-DMZ", "Allow-Web-DMZ"], validate: V_OBJS, group: "Application aux règles", wide: true,
        hint: "Uniquement les règles Allow. Vide = ne pas appliquer." },
    ],
    build(v) {
      const keys = Object.keys(PROFKEY), name = v.isDefault ? "default" : v.name, set = keys.filter(k => v[k]);
      if (!set.length) return { notes: [{ type: "bad", text: "Renseigner au moins un profil." }] };
      const link = { virus: "m09-antivirus", spyware: "m09-anti-spyware", vulnerability: "m09-vulnerability", "url-filtering": "m10-url-profile", "file-blocking": "m09-file-blocking" };
      const steps = [{ title: "Créer le groupe de profils", path: ["Objects", "Security Profile Groups"], window: "Security Profile Group", action: "Cliquer sur Add, puis choisir chaque profil dans les listes déroulantes.",
        fields: [["Name", name], ...keys.map(k => [PROFKEY[k][0], v[k] || "None"])] }];
      const cli = [`set profile-group ${q(name)} ` + set.map(k => `${k} ${q(v[k])}`).join(" ")];
      v.rules.forEach(r => {
        steps.push({ title: `Appliquer le groupe à « ${r} »`, path: ["Policies", "Security"], tab: "Actions", window: "Security Policy Rule", action: `Cliquer sur ${r} → onglet Actions → Profile Setting.`,
          fields: [["Profile Type", "Group"], ["Group Profile", name]] });
        cli.push(`set rulebase security rules ${q(r)} profile-setting group ${q(name)}`);
      });
      const notes = [{ type: "or", text: "Profils prérequis : modules " + set.filter(k => link[k] && v[k] !== "default").map(k => `« ${PROFKEY[k][1]} » (#${link[k]})`).join(", ") + ". Le WildFire Analysis « default » est prédéfini." }];
      if (v.isDefault) notes.push({ type: "warn", text: "Le groupe « default » est appliqué automatiquement aux règles créées ensuite ; les règles existantes ne sont pas modifiées." });
      return { steps, cli, notes, verify: [`show running security-policy`] };
    },
  });

  /* ================= M10 · URL Filtering ================= */
  const URL_CATS = ["abortion", "abused-drugs", "adult", "alcohol-and-tobacco", "auctions", "business-and-economy", "command-and-control", "computer-and-internet-info",
    "content-delivery-networks", "copyright-infringement", "cryptocurrency", "dating", "dynamic-dns", "educational-institutions", "entertainment-and-arts", "extremism",
    "financial-services", "gambling", "games", "government", "grayware", "hacking", "health-and-medicine", "high-risk", "home-and-garden", "hunting-and-fishing",
    "insufficient-content", "internet-communications-and-telephony", "internet-portals", "job-search", "legal", "low-risk", "malware", "medium-risk", "military",
    "motor-vehicles", "music", "newly-registered-domain", "news", "not-resolved", "nudity", "online-storage-and-backup", "parked", "peer-to-peer",
    "personal-sites-and-blogs", "philosophy-and-political-advocacy", "phishing", "private-ip-addresses", "proxy-avoidance-and-anonymizers", "questionable",
    "real-estate", "recreation-and-hobbies", "reference-and-research", "religion", "search-engines", "sex-education", "shareware-and-freeware", "shopping",
    "social-networking", "society", "sports", "stock-advice-and-tools", "streaming-media", "swimsuits-and-intimate-apparel", "training-and-tools", "translation",
    "travel", "unknown", "weapons", "web-advertisements", "web-based-email", "web-hosting"];
  /* catégories plus récentes : acceptées en saisie, non incluses automatiquement dans « alert » */
  const URL_CATS_RECENT = ["ransomware", "scanning-activity", "encrypted-dns", "real-time-detection", "remote-access", "artificial-intelligence", "compromised-website"];
  const V_URLCAT = each(x => URL_CATS.includes(x) || URL_CATS_RECENT.includes(x), "catégorie PAN-DB inconnue (orthographe exacte, ex. proxy-avoidance-and-anonymizers)");
  const BAD_CATS = ["adult", "command-and-control", "copyright-infringement", "dynamic-dns", "extremism", "grayware", "hacking", "high-risk", "malware", "nudity", "parked",
    "peer-to-peer", "phishing", "proxy-avoidance-and-anonymizers", "questionable", "unknown"];

  const V_URLENTRY = each(x => {
    if (/^[a-z]+:\/\//i.test(x) || /\s/.test(x)) return false;
    if (!/^[A-Za-z0-9*^.\-\/_?=&%~+:]+$/.test(x)) return false;
    return x.split(/[./?=&;+]/).every(t => !t.includes("*") && !t.includes("^") || t === "*" || t === "^");
  }, "sans http(s)://, joker * ou ^ uniquement comme jeton entier entre séparateurs (ex. *.example.com, example.com/)");

  register({
    id: "m10-custom-url-category", module: "M10", title: "Custom URL Category", icon: "🔖",
    desc: "Catégorie d'URL personnalisée (URL List avec jokers ou Category Match) et utilisation dans un profil URL ou une règle.",
    tags: "custom url category catégorie personnalisée url list category match wildcard",
    fields: [
      { id: "name", label: "Nom", type: "text", required: true, validate: "name", default: "Custom-Block-List" },
      { id: "desc", label: "Description", type: "text", default: "Sites bloqués par la politique de l'entreprise" },
      { id: "type", label: "Type", type: "select", default: "URL List", options: [["URL List", "URL List"], ["Category Match", "Category Match"]] },
      { id: "sites", label: "Sites (URL List)", type: "list", required: true, show: v => v.type === "URL List", wide: true,
        default: ["*.badsite.example", "badsite.example/", "www.example.org/forbidden/"], validate: V_URLENTRY },
      { id: "cats", label: "Catégories (toutes doivent correspondre)", type: "list", required: true, show: v => v.type === "Category Match", default: ["high-risk", "newly-registered-domain"], validate: V_URLCAT },
      { id: "use", label: "Utilisation", type: "select", default: "profile", group: "Utilisation",
        options: [["profile", "Action dans un profil URL Filtering existant"], ["rule", "URL Category d'une règle de sécurité existante"], ["none", "Aucune pour l'instant"]] },
      { id: "prof", label: "Profil URL Filtering", type: "text", default: "Std-URL", validate: "name", required: true, show: v => v.use === "profile", hint: "Module « URL Filtering Profile » (#m10-url-profile)." },
      { id: "profAct", label: "Site Access", type: "select", default: "block", show: v => v.use === "profile",
        options: [["block"], ["alert"], ["allow"], ["continue"], ["override"]] },
      { id: "rule", label: "Règle de sécurité", type: "text", default: "Block-URL-Categories", validate: "name", required: true, show: v => v.use === "rule", hint: "Module « Règle avec URL Category » (#m10-url-in-rule)." },
    ],
    build(v) {
      const n = q(v.name), list = v.type === "URL List" ? v.sites : v.cats;
      const steps = [{ title: "Créer la catégorie personnalisée", path: ["Objects", "Custom Objects", "URL Category"], window: "Custom URL Category",
        action: "Cliquer sur Add. Au message « Append ending token to entries », choisir selon le besoin (OK ajoute « / » aux entrées sans jeton de fin).",
        fields: [["Name", v.name], ["Description", v.desc], ["Type", v.type], [v.type === "URL List" ? "Sites" : "Categories", list]] }];
      const cli = [`set profiles custom-url-category ${n} type ${q(v.type)} list ${qm(list)}`, v.desc && `set profiles custom-url-category ${n} description ${q(v.desc)}`];
      if (v.use === "profile") {
        steps.push({ title: `Définir l'action dans « ${v.prof} »`, path: ["Objects", "Security Profiles", "URL Filtering"], tab: "Categories", window: "URL Filtering Profile",
          action: `Cliquer sur ${v.prof} ; la catégorie apparaît dans la section Custom URL Categories (marquée *).`, fields: [[`${v.name} — Site Access`, v.profAct]] });
        cli.push(`set profiles url-filtering ${q(v.prof)} ${v.profAct} ${n}`);
      } else if (v.use === "rule") {
        steps.push({ title: `Ajouter la catégorie à « ${v.rule} »`, path: ["Policies", "Security"], tab: "Service/URL Category", window: "Security Policy Rule",
          action: `Cliquer sur ${v.rule} → onglet Service/URL Category → URL Category : Add.`, fields: [["URL Category", v.name]] });
        cli.push(`set rulebase security rules ${q(v.rule)} category ${n}`);
      }
      const notes = [];
      if (v.type === "URL List") {
        const miss = v.sites.filter(s => s.startsWith("*.")).map(s => s.slice(2).split("/")[0]).filter(b => !v.sites.some(s => s.replace(/\/.*$/, "") === b));
        if (miss.length) notes.push({ type: "warn", text: `« *.domaine » ne couvre pas le domaine nu : ajouter aussi ${miss.map(m => m + "/").join(", ")} si nécessaire.` });
        notes.push({ type: "or", text: "« example.com » sans « / » correspond aussi à example.com.evil.net : terminer les entrées par « / » pour un domaine exact." });
      }
      if (v.use === "rule") notes.push({ type: "warn", text: "Si la règle avait URL Category = any, le remplacement restreint la règle à cette seule catégorie." });
      return { steps, cli: cli.filter(Boolean), notes, verify: v.type === "URL List" ? [`test url ${v.sites[0].replace(/^\*\./, "www.").replace(/\/.*$/, "")}`] : [] };
    },
  });

  register({
    id: "m10-url-profile", module: "M10", title: "URL Filtering Profile", icon: "🌐",
    desc: "Actions par catégorie (Site Access et User Credential Submission), safe search, journalisation des en-têtes HTTP, inline categorization et application.",
    tags: "url filtering profile pan-db block alert continue override credential safe search header logging",
    fields: [
      profNameField("Std-URL"), descField("Profil de filtrage URL standard"),
      { id: "alertOthers", label: "Toutes les autres catégories en alert (Set All Actions › alert)", type: "checkbox", default: true, group: "Site Access" },
      { id: "block", label: "block", type: "list", default: BAD_CATS, validate: V_URLCAT, wide: true },
      { id: "cont", label: "continue", type: "list", default: ["newly-registered-domain"], validate: V_URLCAT, wide: true },
      { id: "ovr", label: "override", type: "list", default: [], validate: V_URLCAT, wide: true },
      { id: "allow", label: "allow (sans journalisation)", type: "list", default: [], validate: V_URLCAT, wide: true },
      { id: "custom", label: "Catégories personnalisées / EDL URL à bloquer", type: "list", default: [], validate: V_OBJS, wide: true,
        hint: "Créées avec « Custom URL Category » (#m10-custom-url-category) ou « External Dynamic List » (#m10-edl)." },
      { id: "ucd", label: "User Credential Detection", type: "select", default: "disabled", group: "User Credential Submission",
        options: [["disabled", "Disabled"], ["ip-user", "IP User"], ["domain-credentials", "Domain Credential Filter"]] },
      { id: "ucdBlock", label: "Bloquer la soumission d'identifiants sur toutes les catégories sauf celles autorisées", type: "checkbox", default: true, show: v => v.ucd !== "disabled" },
      { id: "ucdAllow", label: "Catégories où la soumission est autorisée", type: "list", default: ["business-and-economy", "financial-services", "government"], validate: V_URLCAT, show: v => v.ucd !== "disabled" && v.ucdBlock },
      { id: "container", label: "Log container page only", type: "checkbox", default: true, group: "URL Filtering Settings" },
      { id: "safe", label: "Safe Search Enforcement", type: "checkbox", default: false },
      { id: "ua", label: "HTTP Header Logging : User-Agent", type: "checkbox", default: true },
      { id: "ref", label: "HTTP Header Logging : Referer", type: "checkbox", default: true },
      { id: "xff", label: "HTTP Header Logging : X-Forwarded-For", type: "checkbox", default: false },
      { id: "cloudInline", label: "Enable cloud inline categorization (Advanced URL Filtering)", type: "checkbox", default: false, group: "Inline Categorization" },
      { id: "localInline", label: "Enable local inline categorization", type: "checkbox", default: false },
      ...applyFields(),
    ],
    build(v) {
      const lists = { block: v.block, continue: v.cont, override: v.ovr, allow: v.allow };
      const all = [].concat(...Object.values(lists));
      const d = all.filter((x, i) => all.indexOf(x) !== i);
      if (d.length) return { notes: [{ type: "bad", title: "Catégorie en double", text: `Une catégorie ne peut avoir qu'une action : ${uniq(d).join(", ")}.` }] };
      const alert = v.alertOthers ? URL_CATS.filter(c => !all.includes(c)) : [];
      const n = q(v.name), P = ["Objects", "Security Profiles", "URL Filtering"], W = "URL Filtering Profile";
      const steps = [
        { title: "Créer le profil — Overview", path: P, tab: "Overview", window: W, action: "Cliquer sur Add.", fields: [["Name", v.name], ["Description", v.desc]] },
        { title: "Créer le profil — Categories (Site Access)", path: P, tab: "Categories", window: W,
          action: (v.alertOthers ? "Cliquer sur la flèche de l'en-tête SITE ACCESS → Set All Actions → alert. " : "") + "Puis sélectionner les catégories de chaque ligne et définir leur action.",
          fields: [["Site Access : alert", v.alertOthers ? "toutes les autres catégories" : ""], ["Site Access : block", v.block], ["Site Access : continue", v.cont], ["Site Access : override", v.ovr],
            ["Site Access : allow", v.allow], ["Custom URL Categories / EDL : block", v.custom]] },
      ];
      let ucsCli = [];
      if (v.ucd !== "disabled") {
        const ub = v.ucdBlock ? uniq([...URL_CATS.filter(c => !v.ucdAllow.includes(c))]) : [];
        steps.push({ title: "Créer le profil — User Credential Detection", path: P, tab: "User Credential Detection", window: W,
          fields: [["User Credential Detection", { "ip-user": "IP User", "domain-credentials": "Domain Credential Filter" }[v.ucd]], ["Valid Username Detected Log Severity", "medium"]],
          note: "Nécessite User-ID (et le déchiffrement SSL pour voir les formulaires HTTPS)." });
        if (v.ucdBlock) steps.push({ title: "Créer le profil — Categories (User Credential Submission)", path: P, tab: "Categories", window: W,
          action: "Flèche de l'en-tête USER CREDENTIAL SUBMISSION → Set All Actions → block, puis allow pour les catégories ci-dessous.",
          fields: [["User Credential Submission : allow", v.ucdAllow], ["User Credential Submission : block", "toutes les autres"]] });
        ucsCli = [`set profiles url-filtering ${n} credential-enforcement mode ${v.ucd}`,
          ub.length && `set profiles url-filtering ${n} credential-enforcement block ${members(ub)}`,
          v.ucdAllow.length && v.ucdBlock && `set profiles url-filtering ${n} credential-enforcement allow ${members(v.ucdAllow)}`];
      }
      steps.push({ title: "Créer le profil — URL Filtering Settings", path: P, tab: "URL Filtering Settings", window: W,
        fields: [["Log container page only", v.container], ["Safe Search Enforcement", v.safe], ["User-Agent", v.ua], ["Referer", v.ref], ["X-Forwarded-For", v.xff]],
        note: v.safe ? "Safe Search exige le déchiffrement SSL du trafic des moteurs de recherche." : "" });
      if (v.cloudInline || v.localInline) steps.push({ title: "Créer le profil — Inline Categorization", path: P, tab: "Inline Categorization", window: W,
        fields: [["Enable cloud inline categorization", v.cloudInline], ["Enable local inline categorization", v.localInline]] });
      const cli = [v.desc && `set profiles url-filtering ${n} description ${q(v.desc)}`,
        alert.length && `set profiles url-filtering ${n} alert ${members(alert)}`,
        ...Object.entries(lists).filter(([, a]) => a.length).map(([k, a]) => `set profiles url-filtering ${n} ${k} ${members(a)}`),
        v.custom.length && `set profiles url-filtering ${n} block ${qm(v.custom)}`,
        ...ucsCli,
        `set profiles url-filtering ${n} log-container-page-only ${v.container ? "yes" : "no"} safe-search-enforcement ${v.safe ? "yes" : "no"}`,
        `set profiles url-filtering ${n} log-http-hdr-user-agent ${v.ua ? "yes" : "no"} log-http-hdr-referer ${v.ref ? "yes" : "no"} log-http-hdr-xff ${v.xff ? "yes" : "no"}`,
        v.cloudInline && `set profiles url-filtering ${n} cloud-inline-cat yes`, v.localInline && `set profiles url-filtering ${n} local-inline-cat yes`].filter(Boolean);
      const a = applyOut(v, "url-filtering", v.name);
      const notes = [
        { type: "warn", text: `En CLI, une catégorie non listée est en allow (non journalisée). Catégories récentes à vérifier selon la version de contenu : ${URL_CATS_RECENT.join(", ")} (Set All Actions en WebUI les inclut).` },
        { type: "or", text: "Contrôle : Monitor > Logs > URL Filtering ( action eq block-url ). Le profil n'agit que sur les règles Allow ; HTTPS : catégorisation via SNI/certificat, page de blocage seulement si déchiffré." }];
      if (v.cont.length || v.ovr.length) notes.push({ type: "warn", text: "continue / override : activer Response Pages sur l'Interface Management Profile côté client (#m10-response-pages). override requiert aussi Device > Setup > Content-ID > URL Admin Override (mot de passe)." });
      return { steps: [...steps, ...a.steps], cli: [...cli, ...a.cli], notes, verify: ["test url www.hacker9.com", "show system setting url-database"] };
    },
  });

  register({
    id: "m10-url-in-rule", module: "M10", title: "Règle avec URL Category (blocage)", icon: "⛔",
    desc: "Règle de sécurité Deny dont le critère est la catégorie d'URL (prédéfinie, personnalisée ou EDL), placée en tête de politique.",
    tags: "url category rule règle deny block catégorie security policy",
    fields: [
      { id: "name", label: "Nom de la règle", type: "text", required: true, validate: "name", default: "Block-URL-Categories" },
      { id: "desc", label: "Description", type: "text", default: "Blocage des catégories d'URL à risque" },
      { id: "from", label: "Zone source", type: "text", required: true, validate: "name", default: "Trust" },
      { id: "src", label: "Source Address", type: "list", default: ["any"], validate: V_ADDR },
      { id: "to", label: "Zone destination", type: "text", required: true, validate: "name", default: "Untrust" },
      { id: "cats", label: "Catégories PAN-DB", type: "list", default: BAD_CATS.filter(c => !["copyright-infringement", "unknown", "dynamic-dns", "grayware"].includes(c)), validate: V_URLCAT, wide: true },
      { id: "custom", label: "Catégories personnalisées / EDL URL", type: "list", default: [], validate: V_OBJS, wide: true,
        hint: "Modules « Custom URL Category » (#m10-custom-url-category) / « External Dynamic List » (#m10-edl)." },
      { id: "action", label: "Action", type: "select", default: "deny", options: ACT.filter(a => a[0] !== "allow") },
      { id: "top", label: "Placer la règle en tête (Move Top)", type: "checkbox", default: true },
      { id: "disabled", label: "Créer la règle désactivée", type: "checkbox", default: false },
    ],
    build(v) {
      if (!v.cats.length && !v.custom.length) return { notes: [{ type: "bad", text: "Ajouter au moins une catégorie : sans catégorie, la règle bloquerait tout le trafic web." }] };
      const r = { name: v.name, desc: v.desc, from: v.from, to: v.to, src: v.src, cat: [...v.cats, ...v.custom], svc: "application-default", action: v.action, move: v.top ? "top" : "" };
      const steps = [...ruleSteps(r), ...moveStep(v.name, r.move)];
      const cli = ruleCli(r);
      if (v.disabled) { steps.push({ title: "Désactiver la règle", path: ["Policies", "Security"], action: `Sélectionner ${v.name} (sans l'ouvrir) → Disable.`, fields: [] }); cli.push(`set rulebase security rules ${q(v.name)} disabled yes`); }
      return { steps, cli,
        verify: [`test security-policy-match from ${v.from} to ${v.to} source 192.168.1.50 destination 198.51.100.10 protocol 6 destination-port 80 application web-browsing category ${v.cats[0] || v.custom[0]}`, "test url www.hacker9.com"],
        notes: [{ type: "or", text: "Une règle Deny par catégorie affiche la page « Application Blocked » et journalise peu d'informations (Traffic log, catégorie sans URL complète). Pour la page « Web Page Blocked » et un journal URL détaillé, préférer un profil URL Filtering (#m10-url-profile)." }] };
    },
  });

  register({
    id: "m10-edl", module: "M10", title: "External Dynamic List (IP / Domain / URL)", icon: "📜",
    desc: "Liste dynamique externe hébergée sur un serveur web, rafraîchie sans commit, et son utilisation (règle, Anti-Spyware ou profil URL).",
    tags: "edl external dynamic list ip domain url liste dynamique externe blocklist",
    fields: [
      { id: "name", label: "Nom", type: "text", required: true, validate: "name", default: "Malicious-URLs-EDL" },
      { id: "type", label: "Type", type: "select", default: "url", options: [["ip", "IP List"], ["domain", "Domain List"], ["url", "URL List"]] },
      { id: "desc", label: "Description", type: "text", default: "Liste d'URL malveillantes (flux interne)" },
      { id: "src", label: "Source", type: "text", required: true, validate: "url", default: "https://feeds.example.com/edl/malicious-urls.txt", wide: true },
      { id: "cert", label: "Certificate Profile (source HTTPS)", type: "text", default: "", validate: "name", show: v => /^https:/.test(v.src), hint: "Recommandé : profil contenant la CA du serveur." },
      { id: "expand", label: "Automatically expand to include subdomains", type: "checkbox", default: true, show: v => v.type === "domain" },
      { id: "rec", label: "Check for updates", type: "select", default: "five-minute", options: [["five-minute", "Every five minutes"], ["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["monthly", "Monthly"]] },
      { id: "dow", label: "Jour", type: "select", default: "monday", show: v => v.rec === "weekly", options: ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"].map(d => [d, d]) },
      { id: "dom", label: "Jour du mois", type: "number", default: "1", min: 1, max: 31, show: v => v.rec === "monthly", required: true },
      { id: "at", label: "Heure (00-23)", type: "text", default: "03", show: v => ["daily", "weekly", "monthly"].includes(v.rec), required: true, validate: x => /^([01]\d|2[0-3])$/.test(x) ? null : "Heure sur 2 chiffres (00-23)" },
      { id: "exc", label: "Manual Exceptions (optionnel)", type: "list", default: [], validate: each(x => !/\s/.test(x), "sans espace") },
      { id: "use", label: "Utilisation", type: "select", default: "auto", group: "Utilisation",
        options: [["auto", "Selon le type (règle / Anti-Spyware / URL)"], ["none", "Aucune pour l'instant"]] },
      { id: "ipDir", label: "Règle IP : sens", type: "select", default: "dst", show: v => v.use === "auto" && v.type === "ip",
        options: [["dst", "Bloquer les destinations (sortant)"], ["src", "Bloquer les sources (entrant)"]] },
      { id: "ipRule", label: "Nom de la règle", type: "text", default: "Block-EDL-IPs", validate: "name", required: true, show: v => v.use === "auto" && v.type === "ip" },
      { id: "inZone", label: "Zone interne", type: "text", default: "Trust", validate: "name", required: true, show: v => v.use === "auto" && v.type === "ip" },
      { id: "outZone", label: "Zone externe", type: "text", default: "Untrust", validate: "name", required: true, show: v => v.use === "auto" && v.type === "ip" },
      { id: "asProf", label: "Profil Anti-Spyware", type: "text", default: "Std-AS", validate: "name", required: true, show: v => v.use === "auto" && v.type === "domain" },
      { id: "asAct", label: "Policy Action", type: "select", default: "sinkhole", show: v => v.use === "auto" && v.type === "domain", options: [["sinkhole"], ["block"], ["alert"]] },
      { id: "urlUse", label: "Liste URL : utilisation", type: "select", default: "profile", show: v => v.use === "auto" && v.type === "url",
        options: [["profile", "Block dans un profil URL Filtering"], ["rule", "URL Category d'une règle Deny existante"]] },
      { id: "urlProf", label: "Profil URL Filtering", type: "text", default: "Std-URL", validate: "name", required: true, show: v => v.use === "auto" && v.type === "url" && v.urlUse === "profile" },
      { id: "urlRule", label: "Règle Deny", type: "text", default: "Block-URL-Categories", validate: "name", required: true, show: v => v.use === "auto" && v.type === "url" && v.urlUse === "rule" },
    ],
    build(v) {
      const n = q(v.name), T = { ip: "IP List", domain: "Domain List", url: "URL List" }[v.type], base = `set external-list ${n} type ${v.type}`;
      const rec = v.rec === "daily" ? `daily at ${v.at}` : v.rec === "weekly" ? `weekly day-of-week ${v.dow} at ${v.at}` : v.rec === "monthly" ? `monthly day-of-month ${v.dom} at ${v.at}` : v.rec;
      const recL = { "five-minute": "Every five minutes", hourly: "Hourly", daily: "Daily", weekly: "Weekly", monthly: "Monthly" }[v.rec];
      const steps = [
        { title: "Créer la liste dynamique externe", path: ["Objects", "External Dynamic Lists"], tab: "Create List", window: "External Dynamic Lists",
          action: "Cliquer sur Add" + (v.type !== "ip" ? " (au message « Append ending token to entries », choisir selon le besoin)." : "."),
          fields: [["Name", v.name], ["Type", T], ["Description", v.desc], ["Source", v.src], ["Certificate Profile", v.cert],
            ["Automatically expand to include subdomains", v.type === "domain" && v.expand], ["Check for updates", recL + (["daily", "weekly", "monthly"].includes(v.rec) ? ` (${v.rec === "weekly" ? v.dow + " " : v.rec === "monthly" ? "jour " + v.dom + " " : ""}${v.at}h)` : "")]] },
      ];
      if (v.exc.length) steps.push({ title: "Exceptions manuelles", path: ["Objects", "External Dynamic Lists"], tab: "List Entries And Exceptions", window: "External Dynamic Lists", fields: [["Manual Exceptions", v.exc]] });
      steps.push({ title: "Tester la source", path: ["Objects", "External Dynamic Lists"], action: `Rouvrir ${v.name} → Test Source URL : le message doit indiquer que la source est accessible.`, fields: [],
        note: "Le pare-feu récupère la liste via l'interface de management (ou la service route « External Dynamic Lists »)." });
      const cli = [`${base} url ${q(v.src)}`, `${base} recurring ${rec}`, v.desc && `${base} description ${q(v.desc)}`,
        v.cert && /^https:/.test(v.src) && `${base} certificate-profile ${q(v.cert)}`, v.type === "domain" && `${base} expand-domain ${v.expand ? "yes" : "no"}`,
        v.exc.length && `${base} exception-list ${qm(v.exc)}`].filter(Boolean);
      const notes = [];
      if (v.use === "auto") {
        if (v.type === "ip") {
          const r = v.ipDir === "dst" ? { name: v.ipRule, desc: `Blocage des IP de ${v.name}`, from: v.inZone, to: v.outZone, dst: [v.name], svc: "any", action: "deny", move: "top" }
            : { name: v.ipRule, desc: `Blocage des IP de ${v.name}`, from: v.outZone, to: "any", src: [v.name], svc: "any", action: "deny", move: "top" };
          steps.push(...ruleSteps(r), ...moveStep(r.name, "top")); cli.push(...ruleCli(r));
        } else if (v.type === "domain") {
          steps.push({ title: `Utiliser l'EDL dans « ${v.asProf} »`, path: ["Objects", "Security Profiles", "Anti-Spyware"], tab: "DNS Policies", window: "Anti-Spyware Profile",
            action: `Cliquer sur ${v.asProf} → DNS Policies → section External Dynamic Lists.`, fields: [[v.name + " — Policy Action", v.asAct]] });
          cli.push(`set profiles spyware ${q(v.asProf)} botnet-domains lists ${n} action ${v.asAct} packet-capture disable`);
          notes.push({ type: "or", text: "Profil Anti-Spyware : module #m09-anti-spyware. Une Domain List ne s'utilise pas directement dans une règle de sécurité." });
        } else if (v.urlUse === "profile") {
          steps.push({ title: `Bloquer l'EDL dans « ${v.urlProf} »`, path: ["Objects", "Security Profiles", "URL Filtering"], tab: "Categories", window: "URL Filtering Profile",
            action: `Cliquer sur ${v.urlProf} ; l'EDL apparaît dans External Dynamic URL Lists (marquée +).`, fields: [[v.name + " — Site Access", "block"]] });
          cli.push(`set profiles url-filtering ${q(v.urlProf)} block ${n}`);
        } else {
          steps.push({ title: `Ajouter l'EDL à « ${v.urlRule} »`, path: ["Policies", "Security"], tab: "Service/URL Category", window: "Security Policy Rule",
            action: `Cliquer sur ${v.urlRule} → Service/URL Category → URL Category : Add.`, fields: [["URL Category", v.name]] });
          cli.push(`set rulebase security rules ${q(v.urlRule)} category ${n}`);
        }
      }
      notes.push({ type: "or", text: "Après le commit initial, les mises à jour de la liste sont prises en compte sans commit." });
      if (/^http:/.test(v.src)) notes.push({ type: "warn", text: "Source en HTTP : contenu non authentifié. Préférer HTTPS avec Certificate Profile." });
      return { steps, cli, notes, verify: [`request system external-list refresh type ${v.type} name ${v.name}`, `request system external-list show type ${v.type} name ${v.name}`] };
    },
  });

  register({
    id: "m10-response-pages", module: "M10", title: "Response Pages (pages de blocage)", icon: "🪧",
    desc: "Personnalisation des pages de blocage (URL, continue/override, application, fichier) et activation sur l'Interface Management Profile.",
    tags: "response pages page de blocage block page continue override application block interface management profile",
    fields: [
      { id: "url", label: "Personnaliser « URL Filtering and Category Match Block Page »", type: "checkbox", default: true, group: "Pages" },
      { id: "cont", label: "Personnaliser « URL Filtering Continue and Override Page »", type: "checkbox", default: false },
      { id: "file", label: "Personnaliser « File Blocking Block Page »", type: "checkbox", default: false },
      { id: "app", label: "Activer « Application Block Page »", type: "checkbox", default: true },
      { id: "html", label: "Fichier HTML importé (nom)", type: "text", default: "block-page-entreprise.html", show: v => v.url || v.cont || v.file,
        validate: x => /\.html?$/i.test(x) ? null : "Fichier .html attendu" },
      { id: "contact", label: "Contact support affiché", type: "text", default: "support@example.com", show: v => v.url || v.cont || v.file },
      { id: "prof", label: "Interface Management Profile", type: "text", default: "Allow-Response-Pages", validate: "name", required: true, group: "Interface Management Profile" },
      { id: "ping", label: "Autoriser aussi Ping", type: "checkbox", default: true },
      { id: "iface", label: "Interface côté utilisateurs", type: "text", default: "ethernet1/2", validate: "iface", required: true },
    ],
    build(v) {
      const steps = [], cli = [];
      const pages = [v.url && "URL Filtering and Category Match Block Page", v.cont && "URL Filtering Continue and Override Page", v.file && "File Blocking Block Page"].filter(Boolean);
      if (pages.length) {
        steps.push({ title: "Exporter la page par défaut (modèle)", path: ["Device", "Response Pages"], action: `Cliquer sur le nom de la page → Predefined → Export, pour partir du modèle.`, fields: [["Pages", pages]],
          note: `Conserver les variables (<user/>, <url/>, <category/>, et <pan_form/> sur la page continue/override). Ajouter le contact ${v.contact}.` });
        pages.forEach(p => steps.push({ title: `Importer « ${p} »`, path: ["Device", "Response Pages"], window: "Import File", action: `Cliquer sur ${p} → Import.`,
          fields: [["Import File", v.html], ["Destination", "shared"]] }));
      }
      if (v.app) {
        steps.push({ title: "Activer l'Application Block Page", path: ["Device", "Response Pages"], window: "Application Block Page", action: "Ligne Application Block Page → colonne Action : cliquer sur Disabled.",
          fields: [["Enable Application Block Page", true]] });
        cli.push("set deviceconfig setting application notify-user yes");
      }
      const sub = /\./.test(v.iface), phys = v.iface.split(".")[0];
      steps.push(
        { title: "Créer l'Interface Management Profile", path: ["Network", "Network Profiles", "Interface Mgmt"], window: "Interface Management Profile", action: "Cliquer sur Add (ou éditer le profil déjà appliqué à l'interface).",
          fields: [["Name", v.prof], ["Ping", v.ping], ["Response Pages", true]] },
        { title: `Appliquer le profil à ${v.iface}`, path: ["Network", "Interfaces", "Ethernet"], tab: "Advanced", window: "Ethernet Interface", action: `Cliquer sur ${v.iface} → Advanced → Other Info.`,
          fields: [["Management Profile", v.prof]], warn: "Un seul profil par interface : si un profil existe déjà, y cocher Response Pages plutôt que le remplacer." });
      cli.push(`set network profiles interface-management-profile ${q(v.prof)} response-pages yes${v.ping ? " ping yes" : ""}`,
        sub ? `set network interface ethernet ${phys} layer3 units ${v.iface} interface-management-profile ${q(v.prof)}` : `set network interface ethernet ${v.iface} layer3 interface-management-profile ${q(v.prof)}`);
      if (pages.length) cli.unshift("# Import des pages HTML : WebUI uniquement (Device > Response Pages > Import)");
      return { steps, cli, verify: [`show interface ${v.iface}`],
        notes: [{ type: "warn", text: "En HTTPS, la page de blocage ne s'affiche que si la session est déchiffrée ; sinon la connexion est simplement réinitialisée." },
          { type: "or", text: "Les pages continue / override s'appuient sur Response Pages de l'interface côté client (requis pour les actions continue et override des profils URL et File Blocking)." }] };
    },
  });
})();
