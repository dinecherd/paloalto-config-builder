/* Modules M02 (paramètres initiaux), M03 (gestion des configurations), M04 (comptes administrateurs) */
(function () {
  const { register, q, members, yn } = PAN.cfg;

  /* ---------- M02 · Hostname, domaine, DNS, NTP, fuseau horaire, bannière ---------- */
  register({
    id: "m02-general",
    module: "M02",
    title: "Hostname, DNS, NTP & fuseau horaire",
    icon: "🏷️",
    desc: "Identité du pare-feu : nom d'hôte, domaine, bannière de connexion, serveurs DNS et NTP, fuseau horaire.",
    tags: "hostname domaine dns ntp timezone banner",
    fields: [
      { id: "hostname", label: "Hostname", type: "text", required: true, validate: "hostname", default: "PA-FW-01", placeholder: "fw-paris-01" },
      { id: "domain", label: "Domaine", type: "text", validate: "fqdn", placeholder: "corp.local", default: "" },
      { id: "timezone", label: "Fuseau horaire", type: "select", default: "Europe/Paris",
        options: [["Europe/Paris"], ["Europe/Brussels"], ["Europe/Zurich"], ["Europe/London"], ["America/Montreal"], ["Indian/Reunion"], ["America/Martinique"], ["Africa/Casablanca"], ["UTC"]] },
      { id: "banner", label: "Bannière de connexion (login banner)", type: "textarea", placeholder: "Accès réservé au personnel autorisé." },
      { id: "dns1", label: "DNS primaire", type: "ip", required: true, default: "8.8.8.8", group: "Services" },
      { id: "dns2", label: "DNS secondaire", type: "ip", default: "8.8.4.4" },
      { id: "ntp1", label: "NTP primaire", type: "text", validate: "host", default: "0.pool.ntp.org" },
      { id: "ntp2", label: "NTP secondaire", type: "text", validate: "host", default: "1.pool.ntp.org" },
    ],
    build(v) {
      const steps = [
        { title: "Modifier les paramètres généraux", path: ["Device", "Setup", "Management"], window: "General Settings",
          action: "Dans le cadre « General Settings », cliquer sur l'icône ⚙ (engrenage).",
          fields: [["Hostname", v.hostname], ["Domain", v.domain], ["Login Banner", v.banner], ["Time Zone", v.timezone]],
          note: "Le hostname apparaît dans l'invite CLI (admin@" + v.hostname + ">) et dans les logs transférés." },
        { title: "Configurer les serveurs DNS", path: ["Device", "Setup", "Services"], tab: "Services", window: "Services",
          action: "Dans le cadre « Services », cliquer sur l'icône ⚙.",
          fields: [["DNS", "Servers"], ["Primary DNS Server", v.dns1], ["Secondary DNS Server", v.dns2]] },
      ];
      if (v.ntp1 || v.ntp2) steps.push({ title: "Configurer les serveurs NTP", path: ["Device", "Setup", "Services"], tab: "NTP", window: "Services",
        action: "Toujours dans la fenêtre Services, ouvrir l'onglet NTP.",
        fields: [["Primary NTP Server Address", v.ntp1], ["Secondary NTP Server Address", v.ntp2], ["Authentication Type", "None"]] });

      const cli = [
        `set deviceconfig system hostname ${q(v.hostname)}`,
        v.domain && `set deviceconfig system domain ${q(v.domain)}`,
        `set deviceconfig system timezone ${v.timezone}`,
        v.banner && `set deviceconfig system login-banner ${q(v.banner.replace(/\n/g, " "))}`,
        `set deviceconfig system dns-setting servers primary ${v.dns1}`,
        v.dns2 && `set deviceconfig system dns-setting servers secondary ${v.dns2}`,
        v.ntp1 && `set deviceconfig system ntp-servers primary-ntp-server ntp-server-address ${v.ntp1}`,
        v.ntp2 && `set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address ${v.ntp2}`,
      ].filter(Boolean);

      return {
        steps, cli,
        verify: ["show system info | match hostname", "show ntp", `ping host ${v.ntp1 && !PAN.ip.valid(v.ntp1) ? v.ntp1 : "updates.paloaltonetworks.com"}`],
      };
    },
  });

  /* =====================================================================
     Helpers communs M02-M04
     ===================================================================== */
  const toInt = s => PAN.ip.toInt(String(s).trim());
  const maskLen = m => {
    if (!PAN.ip.valid(m)) return -1;
    const n = toInt(m), inv = (~n) >>> 0;
    if (((inv & (inv + 1)) >>> 0) !== 0) return -1;
    let c = 0; for (let i = 31; i >= 0; i--) if ((n >>> i) & 1) c++;
    return c;
  };
  const sameNet = (a, b, len) => len === 0 || ((toInt(a) ^ toInt(b)) >>> (32 - len)) === 0;
  const inCidr = (ip, cidr) => { const [n, l] = String(cidr).split("/"); return sameNet(ip, n, l === undefined ? 32 : +l); };
  const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };
  const hhmm = v => /^([01]\d|2[0-3]):[0-5]\d$/.test(v) ? null : "Heure au format HH:MM (24 h), ex. 02:30";
  const fileXml = v => /^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.xml$/.test(v) ? null : "Nom de fichier .xml (lettres, chiffres, . _ -), ex. PA-FW-01-2026-01-15.xml";
  const MASKED = "•••••••• (valeur saisie)";
  const strongPwd = v => (v.length >= 8 && /[A-Z]/.test(v) && /[a-z]/.test(v) && /\d/.test(v) && /[^A-Za-z0-9]/.test(v)) ? null
    : "8 caractères min. avec majuscule, minuscule, chiffre et caractère spécial";
  const DAYS = [["sunday", "Sunday"], ["monday", "Monday"], ["tuesday", "Tuesday"], ["wednesday", "Wednesday"], ["thursday", "Thursday"], ["friday", "Friday"], ["saturday", "Saturday"]];
  const scpTarget = v => `${v.scpUser}@${v.scpHost}:${v.scpPath}`;

  /* =====================================================================
     M02 · Interface de management
     ===================================================================== */
  register({
    id: "m02-mgmt-interface",
    module: "M02",
    title: "Interface de management",
    icon: "🖧",
    desc: "Adressage du port MGT, services autorisés (HTTPS, SSH, Ping, SNMP, User-ID…) et restriction par Permitted IP Addresses.",
    tags: "management mgt interface permitted ip https ssh ping snmp mtu passerelle",
    fields: [
      { id: "iptype", label: "Type d'adressage", type: "select", default: "static", options: [["static", "Statique"], ["dhcp", "Client DHCP"]], group: "Adressage" },
      { id: "ip", label: "Adresse IP MGT", type: "ip", required: true, default: "192.168.1.254", show: v => v.iptype === "static" },
      { id: "mask", label: "Masque", type: "text", required: true, default: "255.255.255.0", show: v => v.iptype === "static",
        validate: v => maskLen(v) < 0 ? "Masque décimal pointé attendu (ex. 255.255.255.0)" : null },
      { id: "gw", label: "Passerelle par défaut", type: "ip", required: true, default: "192.168.1.1", show: v => v.iptype === "static",
        validate: (g, v) => {
          const l = maskLen(v.mask); if (!PAN.ip.valid(v.ip) || l < 0) return null;
          if (g === v.ip) return "La passerelle doit être différente de l'IP MGT";
          return sameNet(g, v.ip, l) ? null : "La passerelle n'est pas dans le sous-réseau de l'IP MGT";
        } },
      { id: "mtu", label: "MTU (optionnel)", type: "number", min: 576, max: 1500, placeholder: "1500", hint: "Laisser vide = 1500 par défaut." },
      { id: "https", label: "HTTPS", type: "checkbox", default: true, group: "Services d'administration" },
      { id: "ssh", label: "SSH", type: "checkbox", default: true },
      { id: "ping", label: "Ping", type: "checkbox", default: true },
      { id: "http", label: "HTTP (non chiffré — déconseillé)", type: "checkbox", default: false },
      { id: "telnet", label: "Telnet (non chiffré — déconseillé)", type: "checkbox", default: false },
      { id: "snmp", label: "SNMP", type: "checkbox", default: false },
      { id: "userid", label: "User-ID (agent / redistribution)", type: "checkbox", default: false },
      { id: "sslssl", label: "User-ID Syslog Listener-SSL", type: "checkbox", default: false },
      { id: "ssludp", label: "User-ID Syslog Listener-UDP", type: "checkbox", default: false },
      { id: "ocsp", label: "HTTP OCSP", type: "checkbox", default: false },
      { id: "permitted", label: "Permitted IP Addresses (séparées par des virgules)", type: "list", validate: "ipcidr", default: ["192.168.1.0/24"], group: "Restriction d'accès",
        hint: "Vide = accès depuis toute adresse. Réseaux d'admin uniquement." },
      { id: "permDesc", label: "Description", type: "text", default: "Reseaux d'administration", show: v => v.permitted.length > 0 },
      { id: "adminIp", label: "IP de ton poste d'administration (contrôle)", type: "ip", default: "192.168.1.50",
        hint: "Sert uniquement à vérifier que tu ne te bloques pas toi-même.",
        validate: (a, v) => v.permitted.length && v.permitted.every(c => PAN.ip.validCidr(c)) && !v.permitted.some(c => inCidr(a, c))
          ? "Ce poste n'est couvert par aucune Permitted IP : tu perdras l'accès après le commit" : null },
    ],
    build(v) {
      const st = v.iptype === "static";
      const svc = [["HTTP", v.http], ["HTTPS", v.https], ["Telnet", v.telnet], ["SSH", v.ssh]];
      const net = [["HTTP OCSP", v.ocsp], ["Ping", v.ping], ["SNMP", v.snmp], ["User-ID", v.userid], ["User-ID Syslog Listener-SSL", v.sslssl], ["User-ID Syslog Listener-UDP", v.ssludp]];
      const on = a => a.filter(x => x[1]).map(x => x[0]);
      const steps = [
        { title: "Ouvrir les paramètres de l'interface de management", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
          action: "Dans l'onglet Interfaces, cliquer sur le lien « Management ».",
          fields: [["IP Type", st ? "Static" : "DHCP Client"], ["IP Address", st && v.ip], ["Netmask", st && v.mask], ["Default Gateway", st && v.gw], ["MTU", v.mtu]],
          note: st ? null : "En DHCP, cocher au besoin « Send Hostname » / « Send Client ID ». Réserver l'adresse sur le serveur DHCP." },
        { title: "Choisir les services de management autorisés", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
          action: "Dans la même fenêtre, cadre « Administrative Management Services » puis « Network Services » : cocher uniquement ce qui suit, décocher le reste.",
          fields: [["Administrative Management Services", on(svc).join(", ") || "(aucun)"], ["Network Services", on(net).join(", ") || "(aucun)"]],
          warn: (v.http || v.telnet) ? "HTTP/Telnet transmettent les identifiants en clair : à désactiver en production." : null },
      ];
      if (v.permitted.length) steps.push({ title: "Restreindre les adresses autorisées", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
        action: "Cadre « Permitted IP Addresses » : cliquer Add pour chaque réseau, puis OK.",
        fields: v.permitted.map(c => ["Permitted IP Address", c]).concat([["Description", v.permDesc]]),
        warn: "Vérifie que ton poste d'admin est dans la liste : sinon accès perdu dès le commit." });
      steps.push({ title: "Vérifier DNS / passerelle de service", path: ["Device", "Setup", "Services"], action: "Les serveurs DNS utilisés par le MGT se règlent dans Services (voir module « Hostname, DNS, NTP & fuseau horaire »).", fields: [] });

      const dis = (b) => yn(!b);
      const cli = [
        st ? "set deviceconfig system type static" : "set deviceconfig system type dhcp-client send-hostname yes send-client-id no accept-dhcp-hostname no accept-dhcp-domain no",
        st && `set deviceconfig system ip-address ${v.ip} netmask ${v.mask} default-gateway ${v.gw}`,
        v.mtu && `set deviceconfig system mtu ${v.mtu}`,
        `set deviceconfig system service disable-https ${dis(v.https)} disable-ssh ${dis(v.ssh)} disable-icmp ${dis(v.ping)} disable-http ${dis(v.http)} disable-telnet ${dis(v.telnet)}`,
        `set deviceconfig system service disable-snmp ${dis(v.snmp)} disable-userid-service ${dis(v.userid)} disable-userid-syslog-listener-ssl ${dis(v.sslssl)} disable-userid-syslog-listener-udp ${dis(v.ssludp)} disable-http-ocsp ${dis(v.ocsp)}`,
        ...v.permitted.map(c => `set deviceconfig system permitted-ip ${c}${v.permDesc ? " description " + q(v.permDesc) : ""}`),
      ].filter(Boolean);

      const notes = [];
      if (st) notes.push({ type: "warn", title: "Changement d'IP MGT", text: `Si l'adresse change, le commit coupe ta session WebUI/SSH : reconnecte-toi sur https://${v.ip}.` });
      if (!v.https && !v.ssh) notes.push({ type: "bad", title: "Aucun accès d'administration", text: "HTTPS et SSH sont désactivés : seul le port console permettra d'administrer le pare-feu." });
      if (!v.permitted.length) notes.push({ type: "or", text: "Aucune Permitted IP : l'interface MGT accepte les connexions de n'importe quelle source." });
      return { steps, cli, notes, verify: ["show interface management", "show system info | match \"ip-address|netmask|default-gateway\"", "ping host updates.paloaltonetworks.com"] };
    },
  });

  /* =====================================================================
     M02 · Mises à jour dynamiques
     ===================================================================== */
  const recFields = (p, label, recs, def) => {
    const minMax = { "every-30-mins": 29, "hourly": 59, "every-15-mins": 14 };
    return [
      { id: p + "Rec", label: "Récurrence", type: "select", default: def.rec, options: recs, group: label },
      { id: p + "Min", label: "Minutes après le début de période", type: "number", min: 0, required: true, default: def.min ?? 5,
        show: v => v[p + "Rec"] in minMax,
        validate: (m, v) => +m > minMax[v[p + "Rec"]] ? `Maximum ${minMax[v[p + "Rec"]]} pour cette récurrence` : null },
      { id: p + "Day", label: "Jour", type: "select", default: "sunday", options: DAYS, show: v => v[p + "Rec"] === "weekly" },
      { id: p + "Time", label: "Heure (HH:MM)", type: "text", required: true, default: def.time || "02:00", validate: hhmm, show: v => ["daily", "weekly"].includes(v[p + "Rec"]) },
      { id: p + "Act", label: "Action", type: "select", default: "download-and-install", options: [["download-and-install", "Download and Install"], ["download-only", "Download Only"]],
        show: v => !["none", "real-time"].includes(v[p + "Rec"]) },
    ];
  };
  const RECGUI = { "none": "None", "real-time": "Real-time", "every-min": "Every Minute", "every-15-mins": "Every 15 Minutes", "every-30-mins": "Every 30 Minutes", hourly: "Hourly", daily: "Daily", weekly: "Weekly" };

  register({
    id: "m02-dynamic-updates",
    module: "M02",
    title: "Mises à jour dynamiques & licences",
    icon: "🔄",
    desc: "Planification Applications and Threats, Antivirus et WildFire, seuil de sécurité, serveur de mise à jour et récupération des licences.",
    tags: "dynamic updates content applications threats antivirus wildfire schedule licence license update server",
    fields: [
      ...recFields("thr", "Applications and Threats", [["every-30-mins", "Every 30 Minutes"], ["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["none", "None"]], { rec: "daily", time: "01:15" }),
      { id: "thrThr", label: "Threshold (heures, optionnel)", type: "number", min: 1, max: 336, default: "24", show: v => !["none"].includes(v.thrRec),
        hint: "Délai avant installation d'un contenu publié (laisse le temps à Palo Alto de retirer un contenu défectueux)." },
      ...recFields("av", "Antivirus", [["every-30-mins", "Every 30 Minutes"], ["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["none", "None"]], { rec: "hourly", min: 20 }),
      { id: "avThr", label: "Threshold (heures, optionnel)", type: "number", min: 1, max: 336, show: v => v.avRec !== "none" },
      ...recFields("wf", "WildFire", [["real-time", "Real-time"], ["every-min", "Every Minute"], ["every-15-mins", "Every 15 Minutes"], ["every-30-mins", "Every 30 Minutes"], ["hourly", "Hourly"], ["none", "None"]], { rec: "every-min", min: 2 }),
      { id: "updServer", label: "Update Server", type: "text", validate: "fqdn", required: true, default: "updates.paloaltonetworks.com", group: "Serveur de mise à jour & licences" },
      { id: "verifyId", label: "Verify Update Server Identity", type: "checkbox", default: true },
      { id: "fetchLic", label: "Récupérer les licences depuis le serveur (Retrieve license keys)", type: "checkbox", default: true },
    ],
    build(v) {
      const schedFields = (p) => {
        const r = v[p + "Rec"];
        return [["Recurrence", RECGUI[r]],
          ["Minutes Past " + (r === "hourly" ? "Hour" : "Period"), r in { "every-30-mins": 1, hourly: 1, "every-15-mins": 1 } ? String(v[p + "Min"]) : ""],
          ["Day", r === "weekly" ? DAYS.find(d => d[0] === v[p + "Day"])[1] : ""],
          ["Time", ["daily", "weekly"].includes(r) ? v[p + "Time"] : ""],
          ["Action", ["none", "real-time"].includes(r) ? "" : (v[p + "Act"] === "download-only" ? "Download Only" : "Download and Install")]];
      };
      const schedCli = (node, p, thr) => {
        const r = v[p + "Rec"], base = `set deviceconfig system update-schedule ${node} recurring`;
        const act = `action ${v[p + "Act"]}`;
        const l = [];
        if (r === "none" || r === "real-time") l.push(`${base} ${r}`);
        else if (r === "every-min") l.push(`${base} every-min ${act}`);
        else if (r === "daily") l.push(`${base} daily at ${v[p + "Time"]} ${act}`);
        else if (r === "weekly") l.push(`${base} weekly day-of-week ${v[p + "Day"]} at ${v[p + "Time"]} ${act}`);
        else l.push(`${base} ${r} at ${v[p + "Min"]} ${act}`);
        if (thr && r !== "none") l.push(`${base} threshold ${thr}`);
        return l;
      };
      const steps = [
        { title: "Vérifier le serveur de mise à jour", path: ["Device", "Setup", "Services"], window: "Services",
          action: "Cadre « Services » → icône ⚙.",
          fields: [["Update Server", v.updServer], ["Verify Update Server Identity", v.verifyId]],
          note: "Le pare-feu doit résoudre ce FQDN : DNS configurés et sortie HTTPS (tcp/443) autorisée depuis le MGT ou la service route." },
      ];
      if (v.fetchLic) steps.push({ title: "Récupérer les licences", path: ["Device", "Licenses"],
        action: "Cliquer « Retrieve license keys from license server » et vérifier les dates d'expiration (Threat Prevention, WildFire, Advanced URL Filtering…).", fields: [] });
      steps.push(
        { title: "Interroger le serveur de mises à jour", path: ["Device", "Dynamic Updates"], action: "Cliquer « Check Now » en bas de page : la liste des contenus disponibles s'affiche.", fields: [] },
        { title: "Planifier Applications and Threats", path: ["Device", "Dynamic Updates"], window: "Applications and Threats Update Schedule",
          action: "Section « Applications and Threats » → cliquer le lien à droite de « Schedule ».",
          fields: [...schedFields("thr"), ["Threshold (hours)", v.thrRec !== "none" && v.thrThr]] },
        { title: "Planifier Antivirus", path: ["Device", "Dynamic Updates"], window: "Antivirus Update Schedule",
          action: "Section « Antivirus » → lien « Schedule ».",
          fields: [...schedFields("av"), ["Threshold (hours)", v.avRec !== "none" && v.avThr]] },
        { title: "Planifier WildFire", path: ["Device", "Dynamic Updates"], window: "WildFire Update Schedule",
          action: "Section « WildFire » → lien « Schedule ».",
          fields: schedFields("wf"), note: "Nécessite une licence WildFire active." },
      );

      const cli = [
        `set deviceconfig system update-server ${v.updServer}`,
        `set deviceconfig system server-verification ${yn(v.verifyId)}`,
        ...schedCli("threats", "thr", v.thrThr),
        ...schedCli("anti-virus", "av", v.avThr),
        ...schedCli("wildfire", "wf"),
      ];
      const notes = [
        { type: "or", text: "Installe Applications and Threats avant Antivirus lors de la première mise en service (l'antivirus dépend de la version de contenu)." },
        { type: "or", text: "URL Filtering (PAN-DB / Advanced URL Filtering) est interrogé en temps réel dans le cloud : aucune planification à configurer." },
      ];
      if (v.thrRec === "every-30-mins" || v.thrRec === "hourly") notes.push({ type: "warn", text: "Applications and Threats ne publie en général qu'une fois par semaine (nouvelles App-ID) et quelques fois par semaine (menaces) : une récurrence quotidienne avec threshold suffit." });
      if (v.thrAct === "download-and-install" && v.thrRec !== "none" && !v.thrThr) notes.push({ type: "warn", text: "Sans threshold, une nouvelle App-ID peut modifier immédiatement la correspondance des règles en production." });
      return { steps, cli, notes,
        verify: [v.fetchLic && "request license fetch", "request license info", "request content upgrade check", "request anti-virus upgrade check", "request wildfire upgrade check",
          "show system info | match \"app-version|threat-version|av-version|wildfire-version\""].filter(Boolean) };
    },
  });

  /* =====================================================================
     M02 · Sécurisation initiale de l'accès admin
     ===================================================================== */
  register({
    id: "m02-admin-password",
    module: "M02",
    title: "Sécurisation initiale (mot de passe admin)",
    icon: "🔐",
    desc: "Remplacer le mot de passe par défaut du compte admin, désactiver HTTP/Telnet, timeout d'inactivité et verrouillage après échecs.",
    tags: "admin password mot de passe defaut http telnet idle timeout lockout hardening",
    fields: [
      { id: "user", label: "Compte administrateur", type: "text", required: true, validate: "name", default: "admin", group: "Mot de passe" },
      { id: "pwd", label: "Nouveau mot de passe", type: "password", required: true, default: "Ch@ngeMe-2026!", validate: strongPwd },
      { id: "pwd2", label: "Confirmation", type: "password", required: true, default: "Ch@ngeMe-2026!", validate: (p, v) => p !== v.pwd ? "Les deux mots de passe diffèrent" : null },
      { id: "noHttp", label: "Désactiver HTTP sur le MGT", type: "checkbox", default: true, group: "Durcissement" },
      { id: "noTelnet", label: "Désactiver Telnet sur le MGT", type: "checkbox", default: true },
      { id: "idle", label: "Idle Timeout (minutes)", type: "number", min: 1, max: 1440, default: "15" },
      { id: "fails", label: "Failed Attempts (0 = illimité)", type: "number", min: 0, max: 10, default: "5" },
      { id: "lock", label: "Lockout Time (minutes)", type: "number", min: 0, max: 60, default: "30", show: v => +v.fails > 0 },
    ],
    build(v) {
      const steps = [
        { title: `Changer le mot de passe de « ${v.user} »`, path: ["Device", "Administrators"], window: "Administrator",
          action: `Cliquer sur le nom « ${v.user} » dans la liste.`,
          fields: [["Password", MASKED], ["Confirm Password", MASKED]],
          note: "Alternative : cliquer sur le nom d'utilisateur en bas à gauche de la WebUI pour changer son propre mot de passe (ancien mot de passe demandé)." },
      ];
      if (v.noHttp || v.noTelnet) steps.push({ title: "Désactiver les protocoles en clair", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
        action: "Cliquer sur « Management » → cadre « Administrative Management Services ».",
        fields: [["HTTP", v.noHttp && "☐ décoché"], ["Telnet", v.noTelnet && "☐ décoché"], ["HTTPS", "✓ coché"], ["SSH", "✓ coché"]] });
      steps.push({ title: "Timeout et verrouillage des comptes", path: ["Device", "Setup", "Management"], window: "Authentication Settings",
        action: "Cadre « Authentication Settings » → icône ⚙.",
        fields: [["Idle Timeout (min)", v.idle], ["Failed Attempts", v.fails], ["Lockout Time (min)", +v.fails > 0 && v.lock]] });

      const sets = [
        v.noHttp && "set deviceconfig system service disable-http yes",
        v.noTelnet && "set deviceconfig system service disable-telnet yes",
        v.idle && `set deviceconfig setting management idle-timeout ${v.idle}`,
        v.fails !== "" && `set deviceconfig setting management admin-lockout failed-attempts ${v.fails}${+v.fails > 0 && v.lock !== "" ? " lockout-time " + v.lock : ""}`,
      ].filter(Boolean);
      const cliRaw = ["configure", ...sets, "",
        "# --- Ligne interactive : la coller SEULE, puis saisir le mot de passe deux fois ---",
        `set mgt-config users ${q(v.user)} password`,
        "# --- Puis ---", "commit", "exit", "", "# --- Vérification (mode opérationnel) ---", "show admins all", "show system info | match hostname"];
      return { steps, cli: [...sets, `set mgt-config users ${q(v.user)} password`], cliRaw,
        notes: [
          { type: "warn", title: "Commande interactive", text: "« set mgt-config users … password » demande le mot de passe au clavier : ne colle pas les lignes suivantes dans le même bloc, elles seraient prises comme mot de passe." },
          { type: "or", text: "En mode opérationnel, « set password » change le mot de passe du compte connecté sans commit." },
        ] };
    },
  });

  /* =====================================================================
     M03 · Snapshot nommé + export
     ===================================================================== */
  register({
    id: "m03-save-snapshot",
    module: "M03",
    title: "Sauvegarder & exporter la configuration",
    icon: "💾",
    desc: "Enregistrer la configuration candidate en snapshot nommé et l'exporter (navigateur, SCP ou TFTP).",
    tags: "save snapshot export backup sauvegarde configuration scp tftp running candidate",
    noCommit: true,
    fields: [
      { id: "src", label: "Configuration à sauvegarder", type: "select", default: "candidate",
        options: [["candidate", "Candidate → snapshot nommé"], ["running", "Running (running-config.xml, export direct)"]], group: "Sauvegarde" },
      { id: "name", label: "Nom du snapshot", type: "text", required: true, default: `PA-FW-01-${today()}.xml`, validate: (n) => fileXml(n) ||
        (["running-config.xml", "candidate-config.xml", ".snapshot.xml"].includes(n) ? "Nom réservé par PAN-OS" : null), show: v => v.src === "candidate" },
      { id: "exp", label: "Méthode d'export", type: "select", default: "browser",
        options: [["browser", "Téléchargement navigateur (WebUI)"], ["scp", "SCP (CLI)"], ["tftp", "TFTP (CLI)"], ["none", "Pas d'export"]], group: "Export" },
      { id: "scpUser", label: "Utilisateur SCP", type: "text", required: true, default: "backup", validate: "name", show: v => v.exp === "scp" },
      { id: "scpHost", label: "Serveur SCP / TFTP", type: "text", required: true, default: "192.168.1.20", validate: "host", show: v => v.exp === "scp" || v.exp === "tftp" },
      { id: "scpPath", label: "Répertoire distant", type: "text", required: true, default: "/backup/paloalto/", show: v => v.exp === "scp",
        validate: p => /^[~\/][^\s]*$/.test(p) ? null : "Chemin absolu sans espace (ex. /backup/paloalto/)" },
    ],
    build(v) {
      const file = v.src === "running" ? "running-config.xml" : v.name;
      const steps = [];
      if (v.src === "candidate") steps.push({ title: "Enregistrer un snapshot nommé", path: ["Device", "Setup", "Operations"], window: "Save Named Configuration",
        action: "Cadre « Configuration Management » → « Save named configuration snapshot ».",
        fields: [["Name", v.name]], note: "Enregistre la configuration CANDIDATE (y compris les modifications non commitées) sur le pare-feu." });
      if (v.exp === "browser") steps.push({ title: "Exporter vers le poste", path: ["Device", "Setup", "Operations"], window: "Export Named Configuration",
        action: "« Export named configuration snapshot » → choisir le fichier → OK : le navigateur télécharge le XML.",
        fields: [["Name", file]] });
      if (v.exp === "scp" || v.exp === "tftp") steps.push({ title: `Exporter par ${v.exp.toUpperCase()}`, path: ["CLI"],
        action: "L'export SCP/TFTP se fait uniquement en CLI (onglet CLI).", fields: [["Fichier", file], ["Destination", v.exp === "scp" ? scpTarget(v) : v.scpHost]] });

      const cliRaw = [];
      if (v.src === "candidate") cliRaw.push("configure", `save config to ${v.name}`, "exit");
      if (v.exp === "scp") cliRaw.push(`scp export configuration from ${file} to ${scpTarget(v)}`);
      if (v.exp === "tftp") cliRaw.push(`tftp export configuration from ${file} to ${v.scpHost}`);
      cliRaw.push("", "# --- Vérification ---", `show config saved ${file}`);
      if (v.exp === "browser") cliRaw.splice(cliRaw.length - 3, 0, "# Export navigateur : uniquement via la WebUI (Export named configuration snapshot)");
      return { steps, cli: cliRaw, cliRaw,
        notes: [
          { type: "or", text: "Le pare-feu crée aussi une version horodatée à chaque commit (Load configuration version), mais un export externe reste indispensable." },
          { type: "warn", text: "Les secrets du XML sont chiffrés avec la master key du pare-feu : conserve la master key si tu dois restaurer sur un autre boîtier." },
          v.exp === "tftp" && { type: "warn", text: "TFTP n'est ni authentifié ni chiffré : à réserver à un réseau d'administration isolé." },
        ].filter(Boolean) };
    },
  });

  /* =====================================================================
     M03 · Charger / restaurer
     ===================================================================== */
  register({
    id: "m03-load-revert",
    module: "M03",
    title: "Charger ou restaurer une configuration",
    icon: "⏪",
    desc: "Charger un snapshot nommé ou une version, importer un fichier, revenir à la running ou à la dernière sauvegarde.",
    tags: "load revert restore snapshot version import rollback restauration",
    noCommit: true,
    fields: [
      { id: "act", label: "Opération", type: "select", default: "load-named", options: [
        ["load-named", "Charger un snapshot nommé"], ["import", "Importer un fichier XML puis le charger"], ["load-version", "Charger une version horodatée (historique des commits)"],
        ["revert-running", "Annuler les modifications (revenir à la running)"], ["revert-saved", "Revenir à la dernière configuration sauvegardée"]] },
      { id: "name", label: "Nom du snapshot", type: "text", required: true, default: `PA-FW-01-${today()}.xml`, validate: fileXml, show: v => v.act === "load-named" || v.act === "import" },
      { id: "scpUser", label: "Utilisateur SCP (import CLI)", type: "text", required: true, default: "backup", validate: "name", show: v => v.act === "import" },
      { id: "scpHost", label: "Serveur SCP", type: "text", required: true, default: "192.168.1.20", validate: "host", show: v => v.act === "import" },
      { id: "scpPath", label: "Répertoire distant", type: "text", required: true, default: "/backup/paloalto/", show: v => v.act === "import",
        validate: p => /^[~\/][^\s]*\/$/.test(p) ? null : "Chemin absolu terminé par / (ex. /backup/paloalto/)" },
      { id: "ver", label: "Numéro de version", type: "number", min: 1, required: true, default: "10", show: v => v.act === "load-version",
        hint: "Visible dans Device > Setup > Operations > Load configuration version ou Device > Config Audit." },
      { id: "commit", label: "Commiter après chargement", type: "checkbox", default: true, show: v => v.act.startsWith("load") || v.act === "import" || v.act === "revert-saved" },
    ],
    build(v) {
      const steps = [], cliRaw = [];
      const loadStep = (link, win, fields) => steps.push({ title: "Charger dans la configuration candidate", path: ["Device", "Setup", "Operations"], window: win,
        action: `Cadre « Configuration Management » → « ${link} » → OK, puis Close.`, fields,
        warn: "Le chargement remplace TOUTE la configuration candidate (IP MGT, comptes admin compris)." });
      switch (v.act) {
        case "import":
          steps.push({ title: "Importer le fichier", path: ["Device", "Setup", "Operations"], window: "Import Named Configuration",
            action: "« Import named configuration snapshot » → Browse → sélectionner le fichier → OK.", fields: [["File", v.name]] });
          cliRaw.push(`scp import configuration from ${v.scpUser}@${v.scpHost}:${v.scpPath}${v.name}`);
          /* falls through */
        case "load-named":
          loadStep("Load named configuration snapshot", "Load Named Configuration", [["Name", v.name], ["Decryption Key", "(vide sauf master key différente)"]]);
          cliRaw.push("configure", `load config from ${v.name}`);
          break;
        case "load-version":
          loadStep("Load configuration version", "Load Configuration Version", [["Version", v.ver]]);
          cliRaw.push("configure", `load config version ${v.ver}`);
          break;
        case "revert-running":
          steps.push({ title: "Annuler les modifications non commitées", path: ["Device", "Setup", "Operations"],
            action: "« Revert to running configuration » → Yes. Alternative : bouton « Changes » en haut à droite → Revert Changes (choix par administrateur / périmètre).", fields: [] });
          cliRaw.push("configure", "revert config");
          break;
        case "revert-saved":
          loadStep("Revert to last saved configuration", "Revert to last saved configuration", []);
          cliRaw.push("configure", "load config last-saved");
          break;
      }
      const needCommit = v.act !== "revert-running" && v.commit;
      if (needCommit) {
        steps.push({ title: "Prévisualiser puis commiter", path: ["Commit"], window: "Commit",
          action: "Commit → « Preview Changes » pour contrôler l'écart avec la running → Commit.", fields: [["Lines of Context", "10"]] });
        cliRaw.push("commit");
      }
      cliRaw.push("exit", "", "# --- Vérification ---", "show config diff", "show jobs processed");
      const notes = [];
      if (v.act === "revert-running") notes.push({ type: "ok", text: "Pas de commit nécessaire : la candidate redevient identique à la running." });
      else if (!v.commit) notes.push({ type: "warn", text: "Sans commit, la configuration chargée reste en candidate : elle n'est pas appliquée." });
      if (v.act !== "revert-running") notes.push({ type: "warn", title: "Accès MGT", text: "Si le fichier provient d'un autre pare-feu, vérifie l'IP MGT, les Permitted IP et les comptes avant de commiter." });
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     M03 · Options de commit & verrous
     ===================================================================== */
  register({
    id: "m03-commit-options",
    module: "M03",
    title: "Commit : validation, partiel, description & verrous",
    icon: "✅",
    desc: "Prévisualiser et valider avant commit, commiter seulement ses changements, documenter le commit, poser un config/commit lock.",
    tags: "commit validate preview partial description lock config-lock commit-lock",
    noCommit: true,
    fields: [
      { id: "lock", label: "Verrou", type: "select", default: "config", options: [["none", "Aucun"], ["config", "Config Lock (bloque les modifications des autres)"], ["commit", "Commit Lock (bloque les commits des autres)"]], group: "Avant modification" },
      { id: "lockCmt", label: "Commentaire du verrou", type: "text", default: "Changement CHG-1234 en cours", show: v => v.lock !== "none" },
      { id: "preview", label: "Preview Changes (diff running / candidate)", type: "checkbox", default: true, group: "Commit" },
      { id: "validate", label: "Validate Commit avant le commit", type: "checkbox", default: true },
      { id: "partial", label: "Commit partiel (seulement les changements de certains admins)", type: "checkbox", default: false },
      { id: "admins", label: "Administrateurs inclus", type: "list", required: true, validate: "name", default: ["admin"], show: v => v.partial },
      { id: "desc", label: "Description du commit", type: "text", default: "CHG-1234 - ajout regles DMZ", validate: d => d.length > 512 ? "512 caractères max" : null },
      { id: "unlock", label: "Retirer le verrou après commit", type: "checkbox", default: true, show: v => v.lock !== "none" },
    ],
    build(v) {
      const lk = v.lock === "config" ? "Config Lock" : "Commit Lock", lkc = v.lock === "config" ? "config-lock" : "commit-lock";
      const steps = [];
      if (v.lock !== "none") steps.push({ title: "Poser le verrou", path: ["Icône cadenas (en haut à droite)"], window: "Locks",
        action: "Cliquer l'icône cadenas → « Take Lock ».", fields: [["Type", lk], ["Comment", v.lockCmt]] });
      steps.push({ title: "Effectuer les modifications", path: ["…"], action: "Réaliser les changements prévus (autres modules).", fields: [] });
      steps.push({ title: "Ouvrir la fenêtre de commit", path: ["Commit"], window: "Commit",
        action: "Cliquer Commit en haut à droite.",
        fields: [["Commit All Changes / Commit Changes Made By", v.partial ? "Commit Changes Made By : " + v.admins.join(", ") : "Commit All Changes"], ["Description", v.desc]],
        note: v.partial ? "Clique sur le lien des administrateurs pour cocher uniquement les comptes voulus." : null });
      if (v.preview) steps.push({ title: "Prévisualiser", path: ["Commit", "Preview Changes"], action: "Bouton « Preview Changes » → OK : vert = ajout, jaune = modifié, rouge = supprimé. « Change Summary » liste les objets touchés.", fields: [["Lines of Context", "10"]] });
      if (v.validate) steps.push({ title: "Valider", path: ["Commit", "Validate Commit"], action: "Bouton « Validate Commit » : corriger toute erreur avant de commiter.", fields: [] });
      steps.push({ title: "Commiter", path: ["Commit"], action: "Cliquer Commit, attendre « Configuration committed successfully ».", fields: [] });
      if (v.lock !== "none" && v.unlock) steps.push({ title: "Retirer le verrou", path: ["Icône cadenas"], action: "Sélectionner le verrou → « Remove Lock ».", fields: [] });

      const cliRaw = [];
      if (v.lock !== "none") cliRaw.push(`request ${lkc} add comment ${q(v.lockCmt || "lock")}`);
      if (v.preview) cliRaw.push("show config diff");
      cliRaw.push("configure", "# … modifications …");
      if (v.validate) cliRaw.push("validate full", "# puis : run show jobs id <job-id>");
      const dsc = v.desc ? ` description ${q(v.desc)}` : "";
      cliRaw.push(v.partial ? `commit${dsc} partial admin ${members(v.admins)}` : `commit${dsc}`, "exit");
      if (v.lock !== "none" && v.unlock) cliRaw.push(`request ${lkc} remove`);
      cliRaw.push("", "# --- Vérification ---", "show jobs processed", "show config-locks", "show commit-locks");
      const notes = [];
      if (v.partial) notes.push({ type: "warn", text: "Un commit partiel peut échouer si tes changements dépendent d'objets modifiés par un autre admin et non inclus." });
      if (v.lock === "config") notes.push({ type: "or", text: "Un Config Lock est levé automatiquement par un commit réussi si l'option correspondante est active ; sinon retire-le manuellement." });
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     M04 · Admin Role Profile
     ===================================================================== */
  const ROLE_TREE = {
    monitor: ["logs traffic", "logs threat", "logs url", "logs wildfire", "logs data-filtering", "logs configuration", "logs system", "logs authentication", "logs userid", "logs decryption", "session-browser", "block-ip-list", "botnet", "packet-capture"],
    policies: ["security-rulebase", "nat-rulebase", "qos-rulebase", "policy-based-forwarding-rulebase", "ssl-decryption-rulebase", "tunnel-inspect-rulebase", "application-override-rulebase", "authentication-rulebase", "dos-rulebase"],
    objects: ["addresses", "address-groups", "regions", "applications", "application-groups", "application-filters", "services", "service-groups", "tags", "dynamic-block-lists", "security-profile-groups", "log-forwarding", "authentication", "decryption-profile", "schedules",
      "security-profiles antivirus", "security-profiles anti-spyware", "security-profiles vulnerability-protection", "security-profiles url-filtering", "security-profiles file-blocking", "security-profiles wildfire-analysis", "security-profiles data-filtering", "security-profiles dos-protection"],
    network: ["interfaces", "zones", "vlans", "virtual-wires", "virtual-routers", "ipsec-tunnels", "dhcp", "dns-proxy", "qos", "lldp",
      "network-profiles ike-gateways", "network-profiles ipsec-crypto", "network-profiles ike-crypto", "network-profiles interface-mgmt", "network-profiles zone-protection"],
    device: ["setup", "config-audit", "admin-roles", "administrators", "high-availability", "password-profile", "authentication-profile", "authentication-sequence", "user-identification", "software", "dynamic-updates", "licenses", "support", "master-key",
      "server-profiles syslog", "server-profiles ldap", "server-profiles radius", "server-profiles tacplus", "local-user-database users", "local-user-database user-groups", "certificate-management certificates"],
  };
  const LEVEL = [["enable", "Enable"], ["read-only", "Read Only"], ["disable", "Disable"]];
  const LEVELGUI = { enable: "Enable (✓ vert)", "read-only": "Read Only (🔒)", disable: "Disable (⊘)" };
  const XMLAPI = [["report", "Report"], ["log", "Log"], ["config", "Configuration"], ["op", "Operational Requests"], ["commit", "Commit"], ["user-id", "User-ID Agent"], ["export", "Export"], ["import", "Import"]];

  register({
    id: "m04-admin-role",
    module: "M04",
    title: "Admin Role Profile",
    icon: "🎭",
    desc: "Profil de rôle personnalisé : droits par section de la WebUI, XML API et niveau CLI.",
    tags: "admin role profile rbac droits webui xml api cli superuser devicereader",
    fields: [
      { id: "name", label: "Nom du profil", type: "text", required: true, validate: "name", default: "SecOps-Policy-Admin", group: "Profil" },
      { id: "descr", label: "Description", type: "text", default: "Gestion des politiques et objets, reste en lecture seule" },
      { id: "dashboard", label: "Dashboard", type: "select", default: "enable", options: LEVEL.filter(l => l[0] !== "read-only"), group: "Web UI" },
      { id: "acc", label: "ACC", type: "select", default: "enable", options: LEVEL.filter(l => l[0] !== "read-only") },
      { id: "monitor", label: "Monitor", type: "select", default: "read-only", options: LEVEL },
      { id: "policies", label: "Policies", type: "select", default: "enable", options: LEVEL },
      { id: "objects", label: "Objects", type: "select", default: "enable", options: LEVEL },
      { id: "network", label: "Network", type: "select", default: "read-only", options: LEVEL },
      { id: "device", label: "Device", type: "select", default: "read-only", options: LEVEL },
      { id: "commitDev", label: "Commit > Device (autoriser le commit)", type: "checkbox", default: true },
      { id: "commitOthers", label: "Commit > Commit For Other Admins", type: "checkbox", default: false },
      { id: "xml", label: "XML API autorisées", type: "list", default: [], placeholder: "report, log, config, op, commit, user-id, export, import", group: "XML API & CLI",
        validate: a => { const ok = XMLAPI.map(x => x[0]); const bad = a.find(x => !ok.includes(x)); return bad ? `« ${bad} » inconnu — valeurs : ${ok.join(", ")}` : null; } },
      { id: "cli", label: "Command Line", type: "select", default: "devicereader",
        options: [["none", "None"], ["superuser", "superuser"], ["superreader", "superreader"], ["deviceadmin", "deviceadmin"], ["devicereader", "devicereader"]] },
    ],
    build(v) {
      const SECT = ["dashboard", "acc", "monitor", "policies", "objects", "network", "device"];
      const label = s => s === "acc" ? "ACC" : s[0].toUpperCase() + s.slice(1);
      const steps = [
        { title: "Créer le profil", path: ["Device", "Admin Roles"], window: "Admin Role Profile", action: "Cliquer Add.",
          fields: [["Name", v.name], ["Description", v.descr], ["Role", "Device"]] },
        { title: "Droits Web UI", path: ["Device", "Admin Roles"], tab: "Web UI", window: "Admin Role Profile",
          action: "Cliquer l'icône devant chaque section pour alterner Enable / Read Only / Disable (le choix s'applique aux sous-éléments, ajustables ensuite).",
          fields: [...SECT.map(s => [label(s), LEVELGUI[v[s]]]), ["Commit > Device", v.commitDev ? "Enable" : "Disable"], ["Commit > Commit For Other Admins", v.commitOthers ? "Enable" : "Disable"]] },
        { title: "Droits XML API", path: ["Device", "Admin Roles"], tab: "XML API", window: "Admin Role Profile",
          action: "Mettre en Enable uniquement les éléments listés, le reste en Disable.",
          fields: [["Enable", v.xml.length ? XMLAPI.filter(x => v.xml.includes(x[0])).map(x => x[1]) : "(aucun — tout en Disable)"]] },
        { title: "Accès CLI", path: ["Device", "Admin Roles"], tab: "Command Line", window: "Admin Role Profile",
          action: "Choisir le niveau CLI puis OK.", fields: [["Command Line", v.cli === "none" ? "None" : v.cli]] },
      ];
      const b = `set shared admin-role ${q(v.name)}`;
      const w = `${b} role device webui`;
      const cli = [v.descr && `${b} description ${q(v.descr)}`, `${w} dashboard ${v.dashboard}`, `${w} acc ${v.acc}`];
      ["monitor", "policies", "objects", "network", "device"].forEach(s => {
        cli.push(`# ${label(s)} : ${v[s]}`);
        ROLE_TREE[s].forEach(n => cli.push(`${w} ${s} ${n} ${v[s]}`));
      });
      cli.push(`${w} commit device ${v.commitDev ? "enable" : "disable"}`, `${w} commit commit-for-other-admins ${v.commitOthers ? "enable" : "disable"}`);
      XMLAPI.forEach(([k]) => cli.push(`${b} role device xmlapi ${k} ${v.xml.includes(k) ? "enable" : "disable"}`));
      if (v.cli !== "none") cli.push(`${b} role device cli ${v.cli}`);
      const notes = [{ type: "or", text: "Affectation à un compte : module « Administrateur local » (#m04-local-admin), type Role Based." }];
      if (v.cli === "superuser" && v.device !== "enable") notes.push({ type: "warn", text: "CLI superuser donne un accès complet : incohérent avec une WebUI restreinte." });
      if (v.policies === "enable" && !v.commitDev) notes.push({ type: "warn", text: "Le compte pourra modifier les politiques sans pouvoir les commiter." });
      notes.push({ type: "or", text: "En CLI, les sections Monitor/Policies/Objects/Network/Device sont des arborescences : les principaux sous-nœuds sont générés ; utilise « ? » pour lister les autres." });
      return { steps, cli: cli.filter(Boolean), notes, verify: [`show config running xpath shared/admin-role/entry[@name='${v.name}']`] };
    },
  });

  /* =====================================================================
     M04 · Administrateur local
     ===================================================================== */
  const DYN = [["superuser", "Superuser"], ["superreader", "Superuser (read-only)"], ["deviceadmin", "Device administrator"], ["devicereader", "Device administrator (read-only)"]];
  const dynCli = r => r === "superuser" || r === "superreader" ? `${r} yes` : `${r} localhost.localdomain`;

  register({
    id: "m04-local-admin",
    module: "M04",
    title: "Administrateur (compte local)",
    icon: "👤",
    desc: "Compte administrateur avec mot de passe local ou base locale (Local User Database), rôle dynamique ou personnalisé, password profile.",
    tags: "administrator admin compte local user database role dynamic superuser password profile",
    fields: [
      { id: "name", label: "Nom du compte", type: "text", required: true, validate: "name", default: "adm-jdupont", group: "Compte" },
      { id: "auth", label: "Authentification", type: "select", default: "local",
        options: [["local", "Mot de passe local (sur le compte admin)"], ["localdb", "Local User Database + Authentication Profile"], ["ext", "Authentication Profile existant (LDAP/RADIUS/TACACS+)"]] },
      { id: "dbProfile", label: "Nom de l'Authentication Profile local", type: "text", required: true, validate: "name", default: "Local-DB-Auth", show: v => v.auth === "localdb" },
      { id: "extProfile", label: "Authentication Profile", type: "text", required: true, validate: "name", default: "LDAP-Auth-Profile", show: v => v.auth === "ext",
        hint: "Créé avec le module « Authentification externe »." },
      { id: "pwd", label: "Mot de passe", type: "password", required: true, default: "Ch@ngeMe-2026!", validate: strongPwd, show: v => v.auth !== "ext" },
      { id: "pwd2", label: "Confirmation", type: "password", required: true, default: "Ch@ngeMe-2026!", show: v => v.auth !== "ext", validate: (p, v) => p !== v.pwd ? "Les deux mots de passe diffèrent" : null },
      { id: "type", label: "Administrator Type", type: "select", default: "dynamic", options: [["dynamic", "Dynamic"], ["role", "Role Based"]], group: "Droits" },
      { id: "dyn", label: "Rôle dynamique", type: "select", default: "superuser", options: DYN, show: v => v.type === "dynamic" },
      { id: "role", label: "Admin Role Profile", type: "text", required: true, validate: "name", default: "SecOps-Policy-Admin", show: v => v.type === "role",
        hint: "Créé avec le module « Admin Role Profile »." },
      { id: "pwProfile", label: "Password Profile (optionnel)", type: "text", validate: "name", show: v => v.auth === "local", placeholder: "Admin-90d" },
    ],
    build(v) {
      const steps = [];
      const ap = v.auth === "localdb" ? v.dbProfile : v.auth === "ext" ? v.extProfile : "";
      if (v.auth === "localdb") {
        steps.push({ title: "Créer l'utilisateur local", path: ["Device", "Local User Database", "Users"], window: "Local User", action: "Cliquer Add.",
          fields: [["Name", v.name], ["Mode", "Password"], ["Password", MASKED], ["Confirm Password", MASKED], ["Enable", true]] });
        steps.push({ title: "Créer l'Authentication Profile local", path: ["Device", "Authentication Profile"], tab: "Authentication", window: "Authentication Profile",
          action: "Cliquer Add.", fields: [["Name", v.dbProfile], ["Type", "Local Database"]] });
        steps.push({ title: "Allow List", path: ["Device", "Authentication Profile"], tab: "Advanced", window: "Authentication Profile",
          action: "Allow List → Add → all, puis OK.", fields: [["Allow List", "all"]] });
      }
      steps.push({ title: "Créer l'administrateur", path: ["Device", "Administrators"], window: "Administrator", action: "Cliquer Add.",
        fields: [["Name", v.name], ["Authentication Profile", ap || "None"], ["Password", v.auth === "local" && MASKED], ["Confirm Password", v.auth === "local" && MASKED],
          ["Administrator Type", v.type === "dynamic" ? "Dynamic" : "Role Based"],
          [v.type === "dynamic" ? "Role" : "Profile", v.type === "dynamic" ? DYN.find(d => d[0] === v.dyn)[1] : v.role],
          ["Password Profile", v.auth === "local" && v.pwProfile]],
        note: ap ? "Avec un Authentication Profile, le champ Password disparaît : le mot de passe est vérifié par le profil." : null });

      const u = `set mgt-config users ${q(v.name)}`;
      const sets = [
        v.auth === "localdb" && `set shared local-user-database user ${q(v.name)} disabled no`,
        v.auth === "localdb" && `set shared authentication-profile ${q(v.dbProfile)} method local-database`,
        v.auth === "localdb" && `set shared authentication-profile ${q(v.dbProfile)} allow-list all`,
        v.type === "dynamic" ? `${u} permissions role-based ${dynCli(v.dyn)}` : `${u} permissions role-based custom profile ${q(v.role)}`,
        ap && `${u} authentication-profile ${q(ap)}`,
        v.auth === "local" && v.pwProfile && `${u} password-profile ${q(v.pwProfile)}`,
      ].filter(Boolean);
      const inter = v.auth === "local" ? `${u} password` : v.auth === "localdb" ? `set shared local-user-database user ${q(v.name)} password` : null;
      const cliRaw = ["configure", ...sets];
      if (inter) cliRaw.push("", "# --- Ligne interactive : la coller SEULE, puis saisir le mot de passe deux fois ---", inter, "# --- Puis ---");
      cliRaw.push("commit", "exit", "", "# --- Vérification ---", "show admins all", ap ? `test authentication authentication-profile ${q(ap)} username ${q(v.name)} password` : "show system info | match hostname");
      const notes = [];
      if (inter) notes.push({ type: "warn", title: "Commande interactive", text: "La saisie du mot de passe en CLI est interactive : colle la ligne seule, sinon la ligne suivante serait prise comme mot de passe." });
      if (v.type === "dynamic" && v.dyn === "superuser") notes.push({ type: "or", text: "Superuser = tous les droits. Pour un accès restreint, préfère Role Based avec un Admin Role Profile (#m04-admin-role)." });
      if (v.pwProfile) notes.push({ type: "or", text: "Le Password Profile doit exister (module « Complexité des mots de passe », #m04-password-complexity)." });
      return { steps, cli: [...sets, inter].filter(Boolean), cliRaw, notes };
    },
  });

  /* =====================================================================
     M04 · Complexité des mots de passe + Password Profile
     ===================================================================== */
  register({
    id: "m04-password-complexity",
    module: "M04",
    title: "Complexité des mots de passe",
    icon: "🔑",
    desc: "Minimum Password Complexity pour les comptes locaux et Password Profile (expiration) à affecter aux administrateurs.",
    tags: "password complexity mot de passe expiration password profile longueur",
    fields: [
      { id: "enable", label: "Activer Minimum Password Complexity", type: "checkbox", default: true, group: "Minimum Password Complexity" },
      { id: "len", label: "Minimum Length", type: "number", min: 6, max: 15, required: true, default: "12", show: v => v.enable },
      { id: "up", label: "Minimum Uppercase Letters", type: "number", min: 0, max: 15, default: "1", show: v => v.enable },
      { id: "low", label: "Minimum Lowercase Letters", type: "number", min: 0, max: 15, default: "1", show: v => v.enable },
      { id: "num", label: "Minimum Numeric Letters", type: "number", min: 0, max: 15, default: "1", show: v => v.enable },
      { id: "spe", label: "Minimum Special Characters", type: "number", min: 0, max: 15, default: "1", show: v => v.enable,
        validate: (s, v) => (+v.up || 0) + (+v.low || 0) + (+v.num || 0) + (+s || 0) > +v.len ? "La somme des minimums dépasse la longueur minimale" : null },
      { id: "rep", label: "Block Repeated Characters", type: "number", min: 0, max: 15, default: "3", show: v => v.enable },
      { id: "blockUser", label: "Block Username Inclusion (including reversed)", type: "checkbox", default: true, show: v => v.enable },
      { id: "diff", label: "New Password Differs By Characters", type: "number", min: 0, max: 15, default: "3", show: v => v.enable },
      { id: "first", label: "Require Password Change on First Login", type: "checkbox", default: true, show: v => v.enable },
      { id: "reuse", label: "Prevent Password Reuse Limit", type: "number", min: 0, max: 50, default: "5", show: v => v.enable },
      { id: "blockPeriod", label: "Block Password Change Period (jours)", type: "number", min: 0, max: 365, default: "1", show: v => v.enable },
      { id: "prof", label: "Créer un Password Profile", type: "checkbox", default: true, group: "Password Profile" },
      { id: "pname", label: "Nom", type: "text", required: true, validate: "name", default: "Admin-90d", show: v => v.prof },
      { id: "exp", label: "Required Password Change Period (jours)", type: "number", min: 0, max: 365, required: true, default: "90", show: v => v.prof },
      { id: "warnD", label: "Expiration Warning Period (jours)", type: "number", min: 0, max: 30, default: "7", show: v => v.prof,
        validate: (w, v) => +v.exp && +w >= +v.exp ? "Doit être inférieur à la période d'expiration" : null },
      { id: "loginCnt", label: "Post Expiration Admin Login Count", type: "number", min: 0, max: 3, default: "0", show: v => v.prof },
      { id: "grace", label: "Post Expiration Grace Period (jours)", type: "number", min: 0, max: 30, default: "0", show: v => v.prof },
      { id: "admins", label: "Affecter le profil aux administrateurs (optionnel)", type: "list", validate: "name", default: ["adm-jdupont"], show: v => v.prof },
    ],
    build(v) {
      const steps = [];
      if (v.enable) steps.push({ title: "Minimum Password Complexity", path: ["Device", "Setup", "Management"], window: "Minimum Password Complexity",
        action: "Cadre « Minimum Password Complexity » → icône ⚙ → cocher Enabled.",
        fields: [["Enabled", true], ["Minimum Length", v.len], ["Minimum Uppercase Letters", v.up], ["Minimum Lowercase Letters", v.low], ["Minimum Numeric Letters", v.num],
          ["Minimum Special Characters", v.spe], ["Block Repeated Characters", v.rep], ["Block Username Inclusion (including reversed)", v.blockUser],
          ["New Password Differs By Characters", v.diff], ["Require Password Change on First Login", v.first], ["Prevent Password Reuse Limit", v.reuse], ["Block Password Change Period (days)", v.blockPeriod]],
        note: "S'applique aux comptes à mot de passe local (pas aux comptes LDAP/RADIUS/TACACS+). Les mots de passe existants ne sont contrôlés qu'au prochain changement." });
      if (v.prof) {
        steps.push({ title: "Créer le Password Profile", path: ["Device", "Password Profiles"], window: "Password Profile", action: "Cliquer Add.",
          fields: [["Name", v.pname], ["Required Password Change Period (days)", v.exp], ["Expiration Warning Period (days)", v.warnD],
            ["Post Expiration Admin Login Count", v.loginCnt], ["Post Expiration Grace Period (days)", v.grace]] });
        v.admins.forEach(a => steps.push({ title: `Affecter à ${a}`, path: ["Device", "Administrators"], window: "Administrator",
          action: `Cliquer sur « ${a} ».`, fields: [["Password Profile", v.pname]] }));
      }
      const c = "set mgt-config password-complexity";
      const cli = [];
      if (v.enable) cli.push(`${c} enabled yes minimum-length ${v.len}`,
        `${c} minimum-uppercase-letters ${v.up || 0} minimum-lowercase-letters ${v.low || 0} minimum-numeric-letters ${v.num || 0} minimum-special-characters ${v.spe || 0}`,
        `${c} block-repeated-characters ${v.rep || 0} block-username-inclusion ${yn(v.blockUser)} new-password-differs-by-characters ${v.diff || 0}`,
        `${c} password-change-on-first-login ${yn(v.first)} password-history-count ${v.reuse || 0} password-change-period-block ${v.blockPeriod || 0}`);
      else cli.push(`${c} enabled no`);
      if (v.prof) {
        cli.push(`set mgt-config password-profile ${q(v.pname)} password-change expiration-period ${v.exp} expiration-warning-period ${v.warnD || 0} post-expiration-admin-login-count ${v.loginCnt || 0} post-expiration-grace-period ${v.grace || 0}`);
        v.admins.forEach(a => cli.push(`set mgt-config users ${q(a)} password-profile ${q(v.pname)}`));
      }
      const notes = [];
      if (v.prof && v.admins.length) notes.push({ type: "or", text: "Les administrateurs listés doivent déjà exister et utiliser un mot de passe local (#m04-local-admin)." });
      if (v.enable && +v.len < 12) notes.push({ type: "warn", text: "Longueur minimale inférieure à 12 caractères : en deçà des recommandations courantes pour les comptes d'administration." });
      return { steps, cli, notes, verify: ["show admins all"] };
    },
  });

  /* =====================================================================
     M04 · Authentification externe (RADIUS / LDAP / TACACS+)
     ===================================================================== */
  const SRV = { ldap: "LDAP", radius: "RADIUS", tacplus: "TACACS+" };
  register({
    id: "m04-auth-profile",
    module: "M04",
    title: "Authentification externe (LDAP / RADIUS / TACACS+)",
    icon: "🗝️",
    desc: "Server Profile, Authentication Profile avec Allow List et verrouillage, puis rattachement aux administrateurs ou aux Authentication Settings.",
    tags: "authentication profile ldap radius tacacs server profile allow list active directory admin",
    fields: [
      { id: "kind", label: "Type de serveur", type: "select", default: "ldap", options: [["ldap", "LDAP / Active Directory"], ["radius", "RADIUS"], ["tacplus", "TACACS+"]], group: "Server Profile" },
      { id: "sp", label: "Nom du Server Profile", type: "text", required: true, validate: "name", default: "LDAP-Server-Profile" },
      { id: "srvName", label: "Nom du serveur", type: "text", required: true, validate: "name", default: "dc01" },
      { id: "srvIp", label: "Adresse du serveur", type: "text", required: true, validate: "host", default: "192.168.1.10" },
      { id: "srvPort", label: "Port", type: "port", required: true, default: "389",
        hint: "LDAP 389 / LDAPS 636 · RADIUS 1812 · TACACS+ 49." },
      { id: "ldapType", label: "Type LDAP", type: "select", default: "active-directory", show: v => v.kind === "ldap",
        options: [["active-directory", "active-directory"], ["e-directory", "e-directory"], ["sun", "sun"], ["other", "other"]] },
      { id: "base", label: "Base DN", type: "text", required: true, default: "DC=corp,DC=local", show: v => v.kind === "ldap",
        validate: d => /^([A-Za-z]+=[^,]+)(,[A-Za-z]+=[^,]+)*$/.test(d) ? null : "Format DN attendu (ex. DC=corp,DC=local), sans espace autour des virgules" },
      { id: "bind", label: "Bind DN", type: "text", required: true, default: "svc-paloalto@corp.local", show: v => v.kind === "ldap",
        hint: "Compte de service en lecture (UPN ou DN complet)." },
      { id: "secret", label: "Mot de passe Bind / Secret partagé", type: "password", required: true, default: "S3rv1ce-Secret!" },
      { id: "ssl", label: "Require SSL/TLS secured connection", type: "checkbox", default: false, show: v => v.kind === "ldap" },
      { id: "verifyCert", label: "Verify Server Certificate for SSL sessions", type: "checkbox", default: false, show: v => v.kind === "ldap" && v.ssl },
      { id: "radProto", label: "Authentication Protocol", type: "select", default: "PEAP-MSCHAPv2", show: v => v.kind === "radius",
        options: [["PEAP-MSCHAPv2", "PEAP-MSCHAPv2"], ["PEAP-with-GTC", "PEAP with GTC"], ["EAP-TTLS-with-PAP", "EAP-TTLS with PAP"], ["CHAP", "CHAP"], ["PAP", "PAP"]] },
      { id: "tacProto", label: "Authentication Protocol", type: "select", default: "CHAP", show: v => v.kind === "tacplus", options: [["CHAP", "CHAP"], ["PAP", "PAP"]] },
      { id: "timeout", label: "Timeout (s)", type: "number", min: 1, max: 30, default: "3", show: v => v.kind !== "ldap" },
      { id: "retries", label: "Retries", type: "number", min: 1, max: 5, default: "3", show: v => v.kind === "radius" },
      { id: "ap", label: "Nom de l'Authentication Profile", type: "text", required: true, validate: "name", default: "LDAP-Auth-Profile", group: "Authentication Profile" },
      { id: "loginAttr", label: "Login Attribute", type: "text", default: "sAMAccountName", show: v => v.kind === "ldap" },
      { id: "domain", label: "User Domain (optionnel)", type: "text", placeholder: "corp", validate: d => /^[A-Za-z0-9.-]+$/.test(d) ? null : "Nom de domaine NetBIOS ou DNS" },
      { id: "allow", label: "Allow List (utilisateurs/groupes, ou all)", type: "list", required: true, default: ["all"] },
      { id: "fails", label: "Failed Attempts (0 = pas de verrouillage)", type: "number", min: 0, max: 10, default: "5" },
      { id: "lock", label: "Lockout Time (minutes)", type: "number", min: 0, max: 60, default: "30", show: v => +v.fails > 0 },
      { id: "apply", label: "Utilisation", type: "select", default: "admins", group: "Rattachement",
        options: [["admins", "Comptes administrateurs déclarés sur le pare-feu"], ["global", "Authentication Settings (admins non déclarés, rôle via VSA)"], ["none", "Aucun pour l'instant"]] },
      { id: "admins", label: "Administrateurs à créer", type: "list", required: true, validate: "name", default: ["adm-jdupont", "adm-mmartin"], show: v => v.apply === "admins" },
      { id: "dyn", label: "Rôle dynamique de ces administrateurs", type: "select", default: "superuser", options: DYN, show: v => v.apply === "admins" },
    ],
    build(v) {
      const k = v.kind, sp = q(v.sp), ap = q(v.ap);
      const steps = [];
      const srvWin = `${SRV[k]} Server Profile`;
      if (k === "ldap") {
        steps.push({ title: "Créer le LDAP Server Profile", path: ["Device", "Server Profiles", "LDAP"], window: srvWin,
          action: "Cliquer Add → Server List → Add.",
          fields: [["Profile Name", v.sp], ["Name", v.srvName], ["LDAP Server", v.srvIp], ["Port", v.srvPort], ["Type", v.ldapType], ["Base DN", v.base], ["Bind DN", v.bind],
            ["Password / Confirm Password", MASKED], ["Require SSL/TLS secured connection", v.ssl ? true : "☐ décoché"], ["Verify Server Certificate for SSL sessions", v.ssl && v.verifyCert]],
          note: "Après saisie, le menu déroulant Base DN se remplit automatiquement si la connexion au serveur fonctionne." });
      } else if (k === "radius") {
        steps.push({ title: "Créer le RADIUS Server Profile", path: ["Device", "Server Profiles", "RADIUS"], window: srvWin,
          action: "Cliquer Add → Servers → Add.",
          fields: [["Profile Name", v.sp], ["Timeout (sec)", v.timeout], ["Retries", v.retries], ["Authentication Protocol", v.radProto.replace(/-/g, " ").replace("PEAP MSCHAPv2", "PEAP-MSCHAPv2")],
            ["Name", v.srvName], ["RADIUS Server", v.srvIp], ["Secret / Confirm Secret", MASKED], ["Port", v.srvPort]] });
      } else {
        steps.push({ title: "Créer le TACACS+ Server Profile", path: ["Device", "Server Profiles", "TACACS+"], window: srvWin,
          action: "Cliquer Add → Servers → Add.",
          fields: [["Profile Name", v.sp], ["Timeout (sec)", v.timeout], ["Authentication Protocol", v.tacProto],
            ["Name", v.srvName], ["TACACS+ Server", v.srvIp], ["Secret / Confirm Secret", MASKED], ["Port", v.srvPort]] });
      }
      steps.push({ title: "Créer l'Authentication Profile", path: ["Device", "Authentication Profile"], tab: "Authentication", window: "Authentication Profile",
        action: "Cliquer Add.",
        fields: [["Name", v.ap], ["Type", SRV[k]], ["Server Profile", v.sp], ["Login Attribute", k === "ldap" && v.loginAttr], ["User Domain", v.domain]] });
      steps.push({ title: "Allow List et verrouillage", path: ["Device", "Authentication Profile"], tab: "Advanced", window: "Authentication Profile",
        action: "Allow List → Add pour chaque entrée, puis OK.",
        fields: [["Allow List", v.allow], ["Failed Attempts", v.fails], ["Lockout Time (min)", +v.fails > 0 && v.lock]] });
      if (v.apply === "admins") v.admins.forEach(a => steps.push({ title: `Créer l'administrateur ${a}`, path: ["Device", "Administrators"], window: "Administrator",
        action: "Cliquer Add.", fields: [["Name", a], ["Authentication Profile", v.ap], ["Administrator Type", "Dynamic"], ["Role", DYN.find(d => d[0] === v.dyn)[1]]],
        note: "Le nom doit correspondre exactement au login sur le serveur d'authentification." }));
      if (v.apply === "global") steps.push({ title: "Profil par défaut des administrateurs", path: ["Device", "Setup", "Management"], window: "Authentication Settings",
        action: "Cadre « Authentication Settings » → icône ⚙.", fields: [["Authentication Profile", v.ap]],
        note: "Les comptes non déclarés localement obtiennent leur rôle via l'attribut VSA PaloAlto-Admin-Role (RADIUS/TACACS+/SAML)." });

      const S = `set shared server-profile ${k} ${sp}`;
      const cli = [];
      if (k === "ldap") cli.push(`${S} server ${q(v.srvName)} address ${v.srvIp} port ${v.srvPort}`,
        `${S} ldap-type ${v.ldapType} base ${q(v.base)} bind-dn ${q(v.bind)} bind-password ${q(v.secret)}`,
        `${S} ssl ${yn(v.ssl)}${v.ssl ? " verify-server-certificate " + yn(v.verifyCert) : ""}`);
      else if (k === "radius") cli.push(`${S} server ${q(v.srvName)} ip-address ${v.srvIp} port ${v.srvPort} secret ${q(v.secret)}`,
        `${S} timeout ${v.timeout || 3} retries ${v.retries || 3}`, `${S} protocol ${v.radProto}`);
      else cli.push(`${S} server ${q(v.srvName)} address ${v.srvIp} port ${v.srvPort} secret ${q(v.secret)}`,
        `${S} timeout ${v.timeout || 3}`, `${S} protocol ${v.tacProto}`);
      const A = `set shared authentication-profile ${ap}`;
      cli.push(`${A} method ${k} server-profile ${sp}${k === "ldap" && v.loginAttr ? " login-attribute " + q(v.loginAttr) : ""}`,
        v.domain && `${A} user-domain ${q(v.domain)}`,
        `${A} allow-list ${members(v.allow)}`,
        v.fails !== "" && `${A} lockout failed-attempts ${v.fails}${+v.fails > 0 && v.lock !== "" ? " lockout-time " + v.lock : ""}`);
      if (v.apply === "admins") v.admins.forEach(a => cli.push(`set mgt-config users ${q(a)} authentication-profile ${ap} permissions role-based ${dynCli(v.dyn)}`));
      if (v.apply === "global") cli.push(`set deviceconfig system authentication-profile ${ap}`);

      const notes = [
        { type: "or", text: "Le trafic d'authentification part de l'interface MGT par défaut (Device > Setup > Services > Service Route Configuration pour changer)." },
        { type: "or", text: "Pour enchaîner plusieurs profils (ex. LDAP puis RADIUS) : Device > Authentication Sequence → Add → profils dans l'ordre." },
      ];
      const stdPorts = { ldap: ["389", "636", "3268", "3269"], radius: ["1812", "1645"], tacplus: ["49"] };
      if (!stdPorts[k].includes(String(v.srvPort))) notes.push({ type: "warn", text: `Port ${v.srvPort} inhabituel pour ${SRV[k]} (standard : ${stdPorts[k].join(" / ")}).` });
      if (!v.sp.toUpperCase().includes(SRV[k].replace("+", "")) && /LDAP|RADIUS|TACACS/i.test(v.sp)) notes.push({ type: "warn", text: "Le nom du Server Profile ne correspond pas au type choisi : pense à le renommer." });
      if (k === "ldap" && !v.ssl) notes.push({ type: "warn", text: "LDAP sans SSL/TLS : le mot de passe des administrateurs transite en clair. Préfère LDAPS (636) avec vérification du certificat." });
      if ((k === "radius" && ["CHAP", "PAP"].includes(v.radProto)) || (k === "tacplus" && v.tacProto === "PAP")) notes.push({ type: "warn", text: `${k === "radius" ? v.radProto : "PAP"} est faible : préfère PEAP-MSCHAPv2 / EAP-TTLS (RADIUS) ou CHAP (TACACS+).` });
      if (v.allow.includes("all") && v.allow.length > 1) notes.push({ type: "warn", text: "« all » dans l'Allow List rend les autres entrées inutiles." });
      return { steps, cli: cli.filter(Boolean), notes,
        verify: [`test authentication authentication-profile ${ap} username ${q(v.apply === "admins" ? v.admins[0] : "utilisateur")} password`, "show admins all"] };
    },
  });
})();
