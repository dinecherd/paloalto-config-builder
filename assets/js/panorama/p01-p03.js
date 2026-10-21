/* PANW Config Builder — Panorama 11.1
   Catégories P01 (Mise en service Panorama), P02 (Ajout de pare-feux), P03 (Templates).
   Source : cours officiel EDU-220 11.1 (MOD-01 à MOD-03, Labs 1 à 3, annexe A).
   Champs partagés (contrat) : client, panoName, panoIp, panoGw, panoIp2, dns1, dns2, ntp1, ntp2,
   fwSerial, fwName, fwMgmtIp, authKey, template, stack, dg, cg, collector, adminUser.
   Retours spécifiques Panorama : push[] (mode opérationnel après commit sur Panorama),
   fwCli[] (commandes à saisir côté pare-feu). */
(function () {
  const C = PAN.cfg;
  const { register, q, members, yn } = C;
  const V = C.V;

  /* ---------- catégories ---------- */
  const CATS = [["P01", "Mise en service Panorama"], ["P02", "Ajout de pare-feux"], ["P03", "Templates"]];
  CATS.forEach(([code, name]) => {
    if (typeof C.category === "function") C.category(code, name);
    else if (C.MODNAMES) C.MODNAMES[code] = name;
  });

  /* =====================================================================
     Helpers communs P01-P03
     ===================================================================== */
  const ipOk = s => PAN.ip.valid(String(s).trim());
  const bare = s => String(s || "").trim().split("/")[0];
  const prefixOf = s => { const p = String(s).split("/")[1]; return p === undefined ? 32 : +p; };
  const toInt = s => PAN.ip.toInt(String(s).trim());
  const maskStr = n => { const m = n === 0 ? 0 : (~0 << (32 - n)) >>> 0; return [m >>> 24, (m >>> 16) & 255, (m >>> 8) & 255, m & 255].join("."); };
  const sameNet = (a, b, len) => len === 0 || ((toInt(a) ^ toInt(b)) >>> (32 - len)) === 0;
  const inCidr = (ip, cidr) => { const [n, l] = String(cidr).split("/"); return sameNet(ip, n, l === undefined ? 32 : +l); };
  const cidrOk = c => V.cidr(c) === null;
  // texte libre côté CLI : sans accents pour éviter les soucis d'encodage en SSH
  const ascii = t => String(t || "").normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/\n/g, " ");
  const esc = s => (PAN.esc ? PAN.esc(String(s)) : String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));

  const SERIAL_RX = /^\d{12,15}$/;
  const serial = s => SERIAL_RX.test(String(s).trim()) ? null : "Numéro de série : 12 à 15 chiffres (Dashboard > General Information > Serial #)";
  const serialList = (arr, v, self) => {
    for (const s of arr) { const e = serial(s); if (e) return `« ${s} » : ${e}`; }
    const all = [self, ...arr].filter(Boolean);
    const dup = all.find((s, i) => all.indexOf(s) !== i);
    return dup ? `Numéro de série en double : ${dup}` : null;
  };
  const objName = n => /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(String(n)) ? null : "Nom : 63 caractères max, lettres/chiffres/. _ - (sans espace), commence par une lettre ou un chiffre";
  const varName = n => /^\$[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(String(n)) ? null : "Variable : commence par $ puis lettres/chiffres/_ - . (ex. $Internet-Interface)";
  const hhmm = v => /^([01]\d|2[0-3]):[0-5]\d$/.test(v) ? null : "Heure au format HH:MM (24 h), ex. 02:30";
  const swVer = v => /^\d{1,2}\.\d\.\d{1,2}(-h\d{1,2})?$/.test(String(v)) ? null : "Version PAN-OS, ex. 11.1.6 ou 11.1.4-h7";
  const rows = s => String(s || "").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#")).map(l => l.split(/\s*[,;]\s*/));
  const TPL = t => `set template ${q(t)} config devices localhost.localdomain`;
  const MASKED = "•••••••• (valeur saisie)";
  const VALIDATE = "à valider avec « ? » sur ta version";
  const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };

  const TZ = [["Europe/Paris"], ["Europe/Brussels"], ["Europe/Zurich"], ["Europe/Luxembourg"], ["Europe/London"], ["America/Montreal"], ["America/Chicago"],
    ["Indian/Reunion"], ["America/Martinique"], ["America/Guadeloupe"], ["Africa/Casablanca"], ["UTC"]];
  const DAYS = [["sunday", "Sunday"], ["monday", "Monday"], ["tuesday", "Tuesday"], ["wednesday", "Wednesday"], ["thursday", "Thursday"], ["friday", "Friday"], ["saturday", "Saturday"]];
  const dayGui = d => (DAYS.find(x => x[0] === d) || [d, d])[1];
  const RECGUI = { none: "None", "every-15-mins": "Every 15 Minutes", "every-30-mins": "Every 30 Minutes", hourly: "Hourly", daily: "Daily", weekly: "Weekly" };
  const MINMAX = { "every-15-mins": 14, "every-30-mins": 29, hourly: 59 };

  /* Champs de planification génériques (Panorama > Dynamic Updates et Device Deployment > Dynamic Updates) */
  const schedFields = (p, label, recs, def, extra = {}) => [
    ...(extra.toggle ? [{ id: p + "On", label: extra.toggle, type: "checkbox", default: def.on !== false, group: label, wide: true }] : []),
    ...(extra.name ? [{ id: p + "Name", label: "Nom de la planification", type: "text", required: true, default: extra.name, validate: objName, show: v => v[p + "On"] }] : []),
    { id: p + "Rec", label: "Récurrence", type: "select", default: def.rec, options: recs, group: extra.toggle ? undefined : label, show: v => !extra.toggle || v[p + "On"] },
    { id: p + "Min", label: "Minutes après le début de période", type: "number", min: 0, required: true, default: def.min ?? 5,
      show: v => (!extra.toggle || v[p + "On"]) && v[p + "Rec"] in MINMAX,
      validate: (m, v) => +m > MINMAX[v[p + "Rec"]] ? `Maximum ${MINMAX[v[p + "Rec"]]} pour cette récurrence` : null },
    { id: p + "Day", label: "Jour", type: "select", default: def.day || "sunday", options: DAYS, show: v => (!extra.toggle || v[p + "On"]) && v[p + "Rec"] === "weekly" },
    { id: p + "Time", label: "Heure (HH:MM)", type: "text", required: true, default: def.time || "02:00", validate: hhmm,
      show: v => (!extra.toggle || v[p + "On"]) && ["daily", "weekly"].includes(v[p + "Rec"]) },
    { id: p + "Act", label: "Action", type: "select", default: "download-and-install",
      options: [["download-and-install", "Download and Install"], ["download-only", "Download Only"]],
      show: v => (!extra.toggle || v[p + "On"]) && v[p + "Rec"] !== "none" },
  ];
  const schedGui = (v, p) => {
    const r = v[p + "Rec"];
    return [["Recurrence", RECGUI[r]],
      ["Minutes Past " + (r === "hourly" ? "Hour" : "Period"), r in MINMAX ? String(v[p + "Min"]) : ""],
      ["Day", r === "weekly" ? dayGui(v[p + "Day"]) : ""],
      ["Time", ["daily", "weekly"].includes(r) ? v[p + "Time"] : ""],
      ["Action", r === "none" ? "" : (v[p + "Act"] === "download-only" ? "download-only" : "download-and-install")]];
  };
  const schedTail = (v, p) => {
    const r = v[p + "Rec"], act = `action ${v[p + "Act"]}`;
    if (r === "none") return "none";
    if (r === "daily") return `daily at ${v[p + "Time"]} ${act}`;
    if (r === "weekly") return `weekly day-of-week ${v[p + "Day"]} at ${v[p + "Time"]} ${act}`;
    return `${r} at ${v[p + "Min"]} ${act}`;
  };
  // clé de comparaison pour détecter deux planifications au même instant
  const schedSlot = (v, p) => {
    const r = v[p + "Rec"];
    if (r === "none") return null;
    if (r === "weekly") return `w-${v[p + "Day"]}-${v[p + "Time"]}`;
    if (r === "daily") return `d-${v[p + "Time"]}`;
    return `m-${v[p + "Min"]}`;
  };

  /* Panorama Settings côté pare-feu (réutilisé par p02-add-fw, p02-bulk) */
  const fwPanoCli = (v, opts = {}) => [
    opts.hostname && v.fwName && `set deviceconfig system hostname ${q(v.fwName)}`,
    `set deviceconfig system panorama local-panorama panorama-server ${bare(v.panoIp)}`,
    v.panoIp2 && `set deviceconfig system panorama local-panorama panorama-server-2 ${bare(v.panoIp2)}`,
    "# Clé d'enregistrement (commande opérationnelle, exécutée via run) : coller la valeur copiée dans Panorama",
    "run request authkey set <CLE-GENEREE-PAR-PANORAMA>",
  ].filter(Boolean);
  const fwPanoStep = (v, extra = {}) => ({
    title: "Côté pare-feu : déclarer Panorama", path: ["Pare-feu", "Device", "Setup", "Management"], window: "Panorama Settings",
    action: "Sur le pare-feu (WebUI locale) : cadre « Panorama Settings » → icône ⚙.",
    fields: [["Managed By", "Local Panorama"], ["Panorama Servers (1re ligne)", bare(v.panoIp)], ["Panorama Servers (2e ligne — pair HA)", v.panoIp2 ? bare(v.panoIp2) : ""],
      ["Auth Key", "(coller la clé copiée depuis Panorama)"],
      ["Enable pushing device monitoring data to Panorama", extra.mon === undefined ? true : extra.mon],
      ["Receive Timeout / Send Timeout for Connection to Panorama (sec)", extra.timeouts || "240 / 240 (défaut)"],
      ["Enable automated commit recovery", extra.recovery === undefined ? true : extra.recovery],
      ["Number of attempts to check for Panorama connectivity", extra.recovery ? extra.attempts : ""],
      ["Interval between retries (sec)", extra.recovery ? extra.interval : ""]],
    note: "Les boutons « Disable Panorama Policy and Objects » et « Disable Device and Network Template » ne servent qu'à désactiver la gestion par Panorama : ne pas cliquer.",
  });

  const PUSH_NOTE = { type: "or", title: "Push vers les pare-feux",
    text: "Un « Commit to Panorama » ne modifie que Panorama. Les pare-feux ne reçoivent la configuration qu'au « Push to Devices » (ou « Commit and Push ») : surveille le résultat dans Tasks (Task Manager) en bas à droite." };

  /* =====================================================================
     P01 · Management de Panorama (hostname, IP MGT, DNS, NTP, fuseau)
     ===================================================================== */
  register({
    id: "p01-mgmt",
    module: "P01",
    title: "Management Panorama : IP, DNS, NTP & identité",
    icon: "🖧",
    desc: "Première connexion, interface de management (IP, passerelle, services, Permitted IP), hostname, domaine, bannière, fuseau, géolocalisation, DNS, NTP et serveur de mise à jour.",
    tags: "panorama setup management interface mgt hostname dns ntp timezone banner permitted ip update server latitude longitude",
    fields: [
      { id: "client", label: "Nom du client (optionnel)", type: "text", default: "", placeholder: "ACME", group: "Identité de Panorama", hint: "Repris dans les descriptions et le rapport du projet." },
      { id: "panoName", label: "Hostname Panorama", type: "text", required: true, validate: "hostname", default: "Panorama-01", placeholder: "pano-paris-01" },
      { id: "domain", label: "Domaine", type: "text", validate: "fqdn", default: "", placeholder: "corp.local" },
      { id: "timezone", label: "Fuseau horaire", type: "select", default: "Europe/Paris", options: TZ,
        hint: "Panorama horodate les logs reçus des pare-feux : garde le même fuseau (ou UTC partout) pour faciliter les corrélations." },
      { id: "banner", label: "Bannière de connexion (Login Banner)", type: "textarea", default: "*** Panorama - acces reserve aux administrateurs ***",
        hint: "Astuce du cours : une bannière explicite évite de confondre la WebUI de Panorama avec celle d'un pare-feu." },
      { id: "lat", label: "Latitude (optionnel)", type: "text", default: "", placeholder: "48.85",
        validate: x => /^-?\d{1,2}(\.\d+)?$/.test(x) && Math.abs(+x) <= 90 ? null : "Latitude entre -90 et 90 (ex. 48.85)" },
      { id: "lon", label: "Longitude (optionnel)", type: "text", default: "", placeholder: "2.35",
        validate: x => /^-?\d{1,3}(\.\d+)?$/.test(x) && Math.abs(+x) <= 180 ? null : "Longitude entre -180 et 180 (ex. 2.35)",
        hint: "Place Panorama sur les cartes de l'ACC et des rapports." },

      { id: "panoIp", label: "IP de management Panorama (IP/masque)", type: "cidr", required: true, default: "192.168.1.252/24", group: "Interface de management",
        hint: "IP par défaut d'usine : 192.168.1.1/24. Panorama n'a pas de client DHCP : l'adresse est toujours statique." },
      { id: "panoGw", label: "Passerelle par défaut", type: "ip", required: true, default: "192.168.1.1",
        validate: (g, v) => { if (!cidrOk(v.panoIp)) return null; if (g === bare(v.panoIp)) return "La passerelle doit être différente de l'IP de Panorama";
          return inCidr(g, v.panoIp) ? null : "La passerelle n'est pas dans le sous-réseau de management"; } },
      { id: "pubIp", label: "Public IP Address (optionnel)", type: "ip", default: "",
        hint: "Adresse NAT publiée sur un pare-feu périmétrique, pour les pare-feux distants qui ne joignent pas l'IP privée de Panorama." },
      { id: "https", label: "HTTPS", type: "checkbox", default: true, group: "Services autorisés sur l'interface MGT" },
      { id: "ssh", label: "SSH", type: "checkbox", default: true },
      { id: "ping", label: "Ping", type: "checkbox", default: true },
      { id: "snmp", label: "SNMP (supervision)", type: "checkbox", default: false },
      { id: "http", label: "HTTP (non chiffré — déconseillé)", type: "checkbox", default: false },
      { id: "telnet", label: "Telnet (non chiffré — déconseillé)", type: "checkbox", default: false },
      { id: "permitted", label: "Permitted IP Addresses (séparées par des virgules)", type: "list", validate: "ipcidr", default: ["192.168.0.0/16"], wide: true,
        group: "Restriction d'accès", hint: "Optionnel mais fortement recommandé. Vide = Panorama joignable depuis n'importe quelle adresse." },
      { id: "permDesc", label: "Description", type: "text", default: "Reseau de management", show: v => v.permitted.length > 0 },
      { id: "adminIp", label: "IP de ton poste d'administration (contrôle)", type: "ip", default: "192.168.1.50",
        hint: "Uniquement pour vérifier que tu ne te bloques pas toi-même.",
        validate: (a, v) => v.permitted.length && v.permitted.every(c => PAN.ip.validCidr(c)) && !v.permitted.some(c => inCidr(a, c))
          ? "Ce poste n'est couvert par aucune Permitted IP : tu perdras l'accès à Panorama après le commit" : null },

      { id: "dns1", label: "DNS primaire", type: "ip", required: true, default: "1.1.1.1", group: "Services (DNS, NTP, mises à jour)" },
      { id: "dns2", label: "DNS secondaire", type: "ip", default: "8.8.8.8" },
      { id: "ntp1", label: "NTP primaire", type: "text", validate: "host", default: "0.pool.ntp.org" },
      { id: "ntp2", label: "NTP secondaire", type: "text", validate: "host", default: "1.pool.ntp.org" },
      { id: "updServer", label: "Update Server", type: "text", required: true, validate: "fqdn", default: "updates.paloaltonetworks.com" },
      { id: "verifyId", label: "Verify Update Server Identity", type: "checkbox", default: true },
    ],
    example: { client: "Lab EDU-220", panoName: "Panorama", domain: "panw.lab", timezone: "UTC", banner: "*** This is Panorama ***", lat: "41.00", lon: "87.00",
      panoIp: "192.168.1.252/24", panoGw: "192.168.1.10", snmp: true, permitted: ["192.168.0.0/16"], permDesc: "Management network",
      dns1: "192.168.50.53", dns2: "8.8.8.8", ntp1: "pool.ntp.org", ntp2: "time-a-g.nist.gov" },
    build(v) {
      const ip = bare(v.panoIp), mask = maskStr(prefixOf(v.panoIp));
      const on = a => a.filter(x => x[1]).map(x => x[0]);
      const steps = [
        { title: "Première connexion à Panorama", path: ["Navigateur"],
          action: "Se connecter en HTTPS sur l'IP de management (usine : https://192.168.1.1 — pas de redirection HTTP → HTTPS), compte admin / admin. Panorama impose le changement du mot de passe admin.",
          fields: [], note: "Sans accès réseau : port console (9600 8N1) puis configure → set deviceconfig system ip-address … → commit. Au premier login, seuls les onglets Dashboard, ACC, Monitor et Panorama sont visibles : Policies/Objects apparaissent avec le premier device group, Network/Device avec le premier template." },
        { title: "Configurer l'interface de management", path: ["Panorama", "Setup", "Interfaces"], window: "Management Interface Settings",
          action: "Cliquer sur « Management » dans la colonne Interface Name.",
          fields: [["IP Address", ip], ["Netmask", mask], ["Default Gateway", v.panoGw], ["Public IP Address", v.pubIp],
            ["Administrative Management Services", on([["HTTP", v.http], ["HTTPS", v.https], ["Telnet", v.telnet], ["SSH", v.ssh]]).join(", ") || "(aucun)"],
            ["Network Services", on([["Ping", v.ping], ["SNMP", v.snmp]]).join(", ") || "(aucun)"]],
          note: "Avec une seule interface, laisser cochés tous les « Device Management Services » (gestion des pare-feux, collecte des logs, communication collector group, déploiement). Sur un M-Series, ces rôles peuvent être répartis sur eth1/eth2…",
          warn: (v.http || v.telnet) ? "HTTP et Telnet transmettent les identifiants en clair : à proscrire sur Panorama." : null },
      ];
      if (v.permitted.length) steps.push({ title: "Restreindre l'accès à Panorama", path: ["Panorama", "Setup", "Interfaces"], window: "Management Interface Settings",
        action: "Dans la même fenêtre, cadre « Permitted IP Addresses » : Add pour chaque réseau, puis OK.",
        fields: v.permitted.map(c => ["Permitted IP Address", c]).concat([["Description", v.permDesc]]),
        warn: "Vérifie que ton poste d'administration est couvert, sinon accès perdu dès le commit." });
      steps.push(
        { title: "Paramètres généraux", path: ["Panorama", "Setup", "Management"], window: "General Settings",
          action: "Cadre « General Settings » → icône ⚙ en haut à droite.",
          fields: [["Hostname", v.panoName], ["Domain", v.domain], ["Login Banner", v.banner], ["Time Zone", v.timezone], ["Latitude", v.lat], ["Longitude", v.lon]] },
        { title: "Serveur de mise à jour et DNS", path: ["Panorama", "Setup", "Services"], window: "Services",
          action: "Icône ⚙ du cadre « Services », onglet Services.",
          fields: [["Update Server", v.updServer], ["Verify Update Server Identity", v.verifyId], ["Primary DNS Server", v.dns1], ["Secondary DNS Server", v.dns2]],
          note: "Si Panorama sort par un proxy, renseigner ici Proxy Server / Port / User. En environnement isolé (air-gapped), les contenus peuvent être importés manuellement." },
      );
      if (v.ntp1 || v.ntp2) steps.push({ title: "Serveurs NTP", path: ["Panorama", "Setup", "Services"], tab: "NTP", window: "Services",
        action: "Toujours dans la fenêtre Services, onglet NTP, puis OK.",
        fields: [["Primary NTP Server Address", v.ntp1], ["Secondary NTP Server Address", v.ntp2], ["Authentication Type", "None"]] });

      const dis = b => yn(!b);
      const cli = [
        `set deviceconfig system hostname ${q(v.panoName)}`,
        v.domain && `set deviceconfig system domain ${q(v.domain)}`,
        `set deviceconfig system timezone ${v.timezone}`,
        v.banner && `set deviceconfig system login-banner ${q(ascii(v.banner))}`,
        (v.lat || v.lon) && `set deviceconfig system geo-location latitude ${v.lat || 0} longitude ${v.lon || 0}`,
        `set deviceconfig system ip-address ${ip} netmask ${mask} default-gateway ${v.panoGw}`,
        v.pubIp && `set deviceconfig system public-ip-address ${v.pubIp}`,
        `set deviceconfig system service disable-https ${dis(v.https)} disable-ssh ${dis(v.ssh)} disable-icmp ${dis(v.ping)} disable-http ${dis(v.http)} disable-telnet ${dis(v.telnet)} disable-snmp ${dis(v.snmp)}`,
        ...v.permitted.map(c => `set deviceconfig system permitted-ip ${c}${v.permDesc ? " description " + q(ascii(v.permDesc)) : ""}`),
        `set deviceconfig system dns-setting servers primary ${v.dns1}`,
        v.dns2 && `set deviceconfig system dns-setting servers secondary ${v.dns2}`,
        v.ntp1 && `set deviceconfig system ntp-servers primary-ntp-server ntp-server-address ${v.ntp1}`,
        v.ntp2 && `set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address ${v.ntp2}`,
        `set deviceconfig system update-server ${v.updServer}`,
        `set deviceconfig system server-verification ${yn(v.verifyId)}`,
      ].filter(Boolean);

      const notes = [
        { type: "warn", title: "Changement d'IP de management", text: `Si l'adresse change, le commit coupe ta session : reconnecte-toi sur https://${ip}. Les pare-feux déjà rattachés doivent aussi pointer vers la nouvelle IP (Panorama Settings).` },
        { type: "or", title: "Description de commit", text: "Saisis une Description à chaque « Commit to Panorama » : elle apparaît dans Tasks et dans le Config log, précieux quand plusieurs administrateurs travaillent en parallèle." },
      ];
      if (!v.https && !v.ssh) notes.push({ type: "bad", title: "Aucun accès d'administration", text: "HTTPS et SSH désactivés : seul le port console permettra d'administrer Panorama." });
      if (!v.permitted.length) notes.push({ type: "warn", text: "Aucune Permitted IP : la WebUI et le SSH de Panorama sont joignables depuis n'importe quelle source." });
      if (!v.ntp1 && !v.ntp2) notes.push({ type: "warn", text: "Sans NTP, les horodatages des logs, rapports et planifications (mises à jour, exports) dérivent : NTP est fortement recommandé." });
      if (v.lat || v.lon) notes.push({ type: "or", text: `Syntaxe géolocalisation (geo-location latitude/longitude) : ${VALIDATE}.` });
      if (v.pubIp) notes.push({ type: "or", text: `Syntaxe « public-ip-address » : ${VALIDATE}.` });
      return { steps, cli, notes,
        verify: ["show system info | match \"hostname|ip-address|netmask|default-gateway|sw-version|system-mode\"", "show ntp", "ping host " + v.updServer] };
    },
  });

  /* =====================================================================
     P01 · Licences, support, logiciel & mises à jour dynamiques de Panorama
     ===================================================================== */
  register({
    id: "p01-licence",
    module: "P01",
    title: "Licences, logiciel & mises à jour de Panorama",
    icon: "🔑",
    desc: "Numéro de série (VM), activation des licences (capacité, support), mise à niveau logicielle de Panorama et planification de ses mises à jour dynamiques.",
    tags: "panorama licence license support serial capacity software upgrade dynamic updates antivirus applications threats wildfire schedule",
    fields: [
      { id: "platform", label: "Plate-forme", type: "select", default: "vm", group: "Enregistrement & licences",
        options: [["vm", "Panorama virtuel (ESXi, KVM, Hyper-V, cloud public)"], ["m", "Appliance M-Series (M-300, M-600, M-700…)"]] },
      { id: "panoSerial", label: "Numéro de série Panorama", type: "text", required: true, default: "000710012345678", validate: serial, show: v => v.platform === "vm",
        hint: "Un Panorama virtuel n'a pas de série à l'installation : la saisir dans General Settings (fournie par le CSP après enregistrement de l'auth code)." },
      { id: "licMethod", label: "Activation des licences", type: "select", default: "fetch",
        options: [["fetch", "Retrieve license keys from license server (accès Internet)"], ["authcode", "Activate feature using authorization code"], ["manual", "Manually upload license key (hors ligne)"]] },
      { id: "authCode", label: "Code d'autorisation", type: "text", required: true, default: "", placeholder: "I1234567", show: v => v.licMethod === "authcode",
        validate: x => /^[A-Za-z0-9]{6,16}$/.test(x) ? null : "Code d'autorisation alphanumérique (6 à 16 caractères)" },
      { id: "supportCode", label: "Code d'autorisation du support (optionnel)", type: "text", default: "", placeholder: "I7654321",
        validate: x => /^[A-Za-z0-9]{6,16}$/.test(x) ? null : "Code alphanumérique (6 à 16 caractères)",
        hint: "Le support conditionne l'accès aux mises à jour logicielles et aux contenus (Apps, Threats, Antivirus)." },

      { id: "swUpgrade", label: "Mettre à niveau le logiciel de Panorama", type: "checkbox", default: false, group: "Logiciel Panorama", wide: true },
      { id: "swVersion", label: "Version cible", type: "text", required: true, default: "11.1.6", validate: swVer, show: v => v.swUpgrade,
        hint: "Lis les release notes. Panorama doit toujours être mis à niveau AVANT les pare-feux qu'il gère (même version ou plus récente)." },
      { id: "swReboot", label: "Redémarrer immédiatement après installation", type: "checkbox", default: false, show: v => v.swUpgrade,
        hint: "Décoché = installation maintenant, redémarrage dans la fenêtre de maintenance (la mise à niveau n'est effective qu'après le reboot)." },

      ...schedFields("thr", "Mises à jour dynamiques de Panorama — Applications and Threats",
        [["daily", "Daily"], ["weekly", "Weekly"], ["hourly", "Hourly"], ["every-30-mins", "Every 30 Minutes"], ["none", "None"]], { rec: "daily", time: "01:15" }),
      { id: "thrThr", label: "Threshold (heures, optionnel)", type: "number", min: 1, max: 336, default: "", show: v => v.thrRec !== "none",
        hint: "Délai d'attente avant installation d'un contenu publié." },
      ...schedFields("av", "Mises à jour dynamiques de Panorama — Antivirus",
        [["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["every-30-mins", "Every 30 Minutes"], ["none", "None"]], { rec: "hourly", min: 22 }),
      ...schedFields("wf", "Mises à jour dynamiques de Panorama — WildFire",
        [["every-15-mins", "Every 15 Minutes"], ["every-30-mins", "Every 30 Minutes"], ["hourly", "Hourly"], ["none", "None"]], { rec: "every-15-mins", min: 3 }),
    ],
    example: { platform: "vm", licMethod: "fetch", thrRec: "weekly", thrDay: "sunday", thrTime: "02:00", avRec: "weekly", avDay: "sunday", avTime: "01:00", wfRec: "none" },
    build(v) {
      const vm = v.platform === "vm";
      const steps = [];
      if (vm) steps.push({ title: "Saisir le numéro de série du Panorama virtuel", path: ["Panorama", "Setup", "Management"], window: "General Settings",
        action: "Cadre « General Settings » → icône ⚙ → champ Serial Number, puis OK et Commit to Panorama.",
        fields: [["Serial Number", v.panoSerial]], note: "Sans série valide, Panorama ne peut ni récupérer ses licences ni gérer de pare-feu." });
      const licGui = {
        fetch: ["Retrieve license keys from license server", "Panorama contacte le serveur de licences Palo Alto Networks (accès Internet + DNS requis)."],
        authcode: ["Activate feature using authorization code", "Pour une fonctionnalité nouvellement achetée : le code figure dans l'e-mail de commande."],
        manual: ["Manually upload license key", "Hors ligne : activer la licence sur le Customer Support Portal, télécharger le fichier de clé puis l'importer ici."],
      }[v.licMethod];
      steps.push({ title: "Activer les licences", path: ["Panorama", "Licenses"], window: "License Management",
        action: `Cadre « License Management » → « ${licGui[0]} ».`, fields: [["Authorization Code", v.licMethod === "authcode" && v.authCode]], note: licGui[1] });
      if (v.supportCode) steps.push({ title: "Activer le support", path: ["Panorama", "Support"],
        action: "« Activate support using authorization code ».", fields: [["Authorization Code", v.supportCode]] });
      steps.push({ title: "Contrôler licences et support", path: ["Panorama", "Licenses"],
        action: "Vérifier la licence de capacité (nombre de pare-feux gérables : 25, 100, 1 000…) et la date d'expiration ; puis Panorama > Support pour l'échéance du support.", fields: [] });
      if (v.swUpgrade) steps.push({ title: `Mettre à niveau Panorama en ${v.swVersion}`, path: ["Panorama", "Software"],
        action: `Check Now → lire les Release Notes → Download sur ${v.swVersion} → Install → ${v.swReboot ? "Yes au redémarrage" : "No (redémarrage différé)"}.`,
        fields: [["Version", v.swVersion]],
        warn: "Sauvegarde la configuration (named snapshot exporté) avant toute mise à niveau. Respecte le chemin de mise à niveau (versions intermédiaires éventuelles)." });
      steps.push(
        { title: "Interroger le serveur de mises à jour", path: ["Panorama", "Dynamic Updates"], action: "Cliquer « Check Now » en bas à gauche.", fields: [],
          note: "Panorama a besoin des dernières Applications/Threats pour proposer les nouvelles App-ID et signatures dans les règles et profils qu'il pousse." },
        { title: "Planifier Applications and Threats", path: ["Panorama", "Dynamic Updates"], window: "Applications and Threats Update Schedule",
          action: "Section « Applications and Threats » → lien à droite de Schedule (« None » par défaut).",
          fields: [...schedGui(v, "thr"), ["Threshold (hours)", v.thrRec !== "none" && v.thrThr]] },
        { title: "Planifier Antivirus", path: ["Panorama", "Dynamic Updates"], window: "Antivirus Update Schedule",
          action: "Section « Antivirus » → lien Schedule.", fields: schedGui(v, "av") },
        { title: "Planifier WildFire", path: ["Panorama", "Dynamic Updates"], window: "WildFire Update Schedule",
          action: "Section « WildFire » → lien Schedule.", fields: schedGui(v, "wf") },
      );

      const base = node => `set deviceconfig system update-schedule ${node} recurring`;
      const cli = [
        `${base("threats")} ${schedTail(v, "thr")}`,
        v.thrThr && v.thrRec !== "none" && `${base("threats")} threshold ${v.thrThr}`,
        `${base("anti-virus")} ${schedTail(v, "av")}`,
        `${base("wildfire")} ${schedTail(v, "wf")}`,
      ].filter(Boolean);

      const verify = [
        "# --- Licences & support ---",
        v.licMethod === "fetch" && "request license fetch",
        v.licMethod === "authcode" && `request license fetch auth-code ${v.authCode}`,
        v.licMethod === "manual" && "# Import manuel du fichier de licence : WebUI (Manually upload license key)",
        v.supportCode && `request support check`,
        "request license info",
        "# --- Contenus de Panorama ---",
        "request content upgrade check", "request content upgrade download latest", "request content upgrade install version latest",
        "request anti-virus upgrade check", "request anti-virus upgrade download latest", "request anti-virus upgrade install version latest",
        ...(v.swUpgrade ? ["# --- Logiciel Panorama ---", "request system software check", `request system software download version ${v.swVersion}`,
          `request system software install version ${v.swVersion}`, v.swReboot ? "request restart system" : "# request restart system   (à lancer dans la fenêtre de maintenance)"] : []),
        "show system info | match \"serial|sw-version|app-version|av-version|wildfire-version\"",
      ].filter(Boolean);
      const cliRaw = [
        ...(vm ? ["# --- Série du Panorama virtuel (mode opérationnel) ---", `set serial-number ${v.panoSerial}`, ""] : []),
        "# --- Planification des mises à jour de Panorama ---", "configure", ...cli, "commit", "exit", "", ...verify.map(l => l.startsWith("# ---") ? "\n" + l : l),
      ].join("\n").split("\n");

      const notes = [
        { type: "or", title: "Ordre de mise à niveau", text: "Panorama d'abord, pare-feux ensuite : Panorama doit être à une version égale ou supérieure à celle des pare-feux et Log Collectors qu'il gère." },
        { type: "or", text: "Installe Applications and Threats avant Antivirus lors de la première mise en service. Les planifications de Panorama ne concernent que Panorama : celles des pare-feux se font dans Panorama > Device Deployment > Dynamic Updates (module « Déploiement vers les pare-feux »)." },
        { type: "or", text: "Fonctions additionnelles : Panorama > Plugins (SD-WAN, Cloud Services, ZTP, VM-Series cloud, Kubernetes…) — chaque plugin doit être compatible avec ta version de Panorama." },
      ];
      if (vm) notes.push({ type: "warn", text: `« set serial-number » est une commande opérationnelle propre au Panorama virtuel : ${VALIDATE}.` });
      if (v.thrRec === "weekly" || v.avRec === "weekly") notes.push({ type: "warn", text: "Récurrence hebdomadaire = usage lab. En production, suivre les « Best Practices for Applications and Threats Content Updates » (antivirus horaire, Apps & Threats quotidien avec threshold)." });
      const slots = ["thr", "av", "wf"].map(p => schedSlot(v, p)).filter(Boolean);
      if (slots.length !== new Set(slots).size) notes.push({ type: "warn", text: "Deux planifications tombent au même moment : décale-les, Panorama ne télécharge qu'une mise à jour à la fois." });
      return { steps, cli, cliRaw, notes };
    },
  });

  /* =====================================================================
     P01 · Mode de fonctionnement & disques de logs
     ===================================================================== */
  register({
    id: "p01-mode",
    module: "P01",
    title: "Mode Panorama & disques de logs",
    icon: "🧭",
    desc: "Choisir le mode (Panorama, Management Only, Log Collector), vérifier les ressources et ajouter les disques de logs du Panorama virtuel ou les paires RAID d'un M-Series.",
    tags: "panorama mode system-mode management-only log collector logger legacy disque disk raid vm ressources",
    noCommit: true,
    fields: [
      { id: "platform", label: "Plate-forme", type: "select", default: "vm", group: "Mode",
        options: [["vm", "Panorama virtuel"], ["m", "Appliance M-Series"]] },
      { id: "mode", label: "Mode cible", type: "select", default: "panorama",
        options: [["panorama", "Panorama — gestion des pare-feux + collecte de logs (défaut)"], ["management-only", "Management Only — gestion seule, logs sur des Log Collectors"],
          ["logger", "Log Collector — collecteur dédié (Dedicated Log Collector)"]] },
      { id: "change", label: "Le mode actuel est différent : générer la commande de changement de mode", type: "checkbox", default: false, wide: true,
        hint: "Le mode par défaut des M-Series et des VM est Panorama : ne coche que si tu dois en changer." },
      { id: "backup", label: "Sauvegarder et exporter la configuration avant (recommandé)", type: "checkbox", default: true, wide: true, show: v => v.change },
      { id: "vmDisks", label: "Nombre de disques virtuels de logs à ajouter", type: "number", min: 0, max: 12, default: "1",
        show: v => v.platform === "vm" && v.mode !== "management-only", group: "Stockage des logs",
        hint: "Disques virtuels de 2 To ajoutés dans l'hyperviseur (jusqu'à 24 To au total). Le disque système n'est pas utilisé pour les logs des pare-feux." },
      { id: "raidPair", label: "Paire RAID à ajouter", type: "select", default: "none", show: v => v.platform === "m" && v.mode !== "management-only", group: "Stockage des logs",
        options: [["none", "Aucune (déjà en place)"], ["B", "Paire B (B1 + B2)"], ["C", "Paire C (C1 + C2)"], ["D", "Paire D (D1 + D2)"]] },
      { id: "panoIp", label: "IP du Panorama de gestion (IP/masque)", type: "cidr", required: true, default: "192.168.1.252/24", show: v => v.mode === "logger",
        group: "Rattachement du Log Collector", hint: "Un Log Collector dédié n'a plus de WebUI : il est géré depuis Panorama." },
      { id: "panoIp2", label: "IP du Panorama pair HA (optionnel)", type: "ipcidr", default: "", show: v => v.mode === "logger" },
    ],
    build(v) {
      const vm = v.platform === "vm";
      const MODE = { panorama: "Panorama", "management-only": "Management Only", logger: "Log Collector" }[v.mode];
      const disks = vm && v.mode !== "management-only" ? Math.max(0, Math.min(12, +v.vmDisks || 0)) : 0;
      const letters = "bcdefghijklm".split("").slice(0, disks).map(l => "sd" + l);
      const steps = [
        { title: "Vérifier le mode et les ressources", path: ["Dashboard"], window: "General Information",
          action: "Relever Mode, Model, Serial #, Software Version. Le mode se change uniquement en CLI (console ou SSH).",
          fields: [["Mode attendu", MODE]],
          note: "Ressources indiquées dans le cours pour chaque mode sur VM : 16 vCPU et 32 Go de RAM minimum (jusqu'à 24 To de logs en mode Panorama / Log Collector). Vérifie le guide de dimensionnement pour ton nombre de pare-feux et ton débit de logs." },
      ];
      if (v.change && v.backup) steps.push({ title: "Sauvegarder la configuration", path: ["Panorama", "Setup", "Operations"],
        action: "« Save named Panorama configuration snapshot » puis « Export named Panorama configuration snapshot » vers ton poste.", fields: [["Name", `avant-changement-mode-${today()}.xml`]] });
      if (v.change) steps.push({ title: `Passer en mode ${MODE}`, path: ["CLI"],
        action: `Commande « request system system-mode ${v.mode} » puis confirmer (y). Panorama redémarre automatiquement.`, fields: [],
        warn: v.mode === "logger" ? "En mode Log Collector, la WebUI disparaît et la configuration Panorama locale n'est pas conservée (seuls les paramètres de management restent) : l'appareil sera ensuite ajouté comme Managed Collector depuis Panorama." : null });
      if (disks) steps.push({ title: `Ajouter ${disks} disque(s) virtuel(s) de logs`, path: ["Hyperviseur", "puis CLI Panorama"],
        action: `Éteindre ou non selon l'hyperviseur, ajouter ${disks} disque(s) de 2 To (thick provisioning recommandé), redémarrer si nécessaire, puis initialiser chaque disque en CLI.`,
        fields: [["Disques", letters.join(", ")]], note: "Le traitement peut durer plusieurs minutes par disque : suivre avec « show system disk details »." });
      if (!vm && v.raidPair !== "none") steps.push({ title: `Ajouter la paire RAID ${v.raidPair}`, path: ["CLI"],
        action: `Insérer les disques ${v.raidPair}1 et ${v.raidPair}2, puis les ajouter au RAID en CLI et attendre la fin de la synchronisation.`, fields: [] });
      if (v.mode === "logger") steps.push({ title: "Rattacher le Log Collector à Panorama", path: ["CLI du Log Collector"],
        action: "Déclarer l'IP de Panorama dans la configuration du collecteur, puis l'ajouter dans Panorama > Managed Collectors (module P05).",
        fields: [["Panorama Server", bare(v.panoIp)], ["Panorama Server 2", v.panoIp2 ? bare(v.panoIp2) : ""]] });
      if (v.mode !== "logger") steps.push({ title: "Contrôler l'espace de logs", path: ["Panorama", "Setup", "Management"], window: "Logging and Reporting Settings",
        action: "Onglet Log Storage : vérifier la capacité détectée et ajuster les quotas par type de log si besoin.", fields: [] });

      const cliRaw = [
        "# --- 1. État actuel (mode opérationnel) ---",
        "show system info | match \"system-mode|model|serial|sw-version\"",
        "show system disk-space",
      ];
      if (v.change) {
        if (v.backup) cliRaw.push("", "# --- 2. Sauvegarde avant changement ---", "configure", `save config to avant-changement-mode-${today()}.xml`, "exit");
        cliRaw.push("", `# --- ${v.backup ? 3 : 2}. Changement de mode (confirmation y, puis redémarrage automatique) ---`, `request system system-mode ${v.mode}`);
      }
      if (disks) cliRaw.push("", "# --- Disques virtuels de logs (après ajout dans l'hyperviseur) ---", ...letters.map(d => `request system disk add ${d}`), "show system disk details");
      if (!vm && v.raidPair !== "none") cliRaw.push("", "# --- Paire RAID ---", "show system raid detail", `request system raid add ${v.raidPair}1`, `request system raid add ${v.raidPair}2`, "show system raid detail");
      if (v.mode === "logger") cliRaw.push("", "# --- Sur le Log Collector : pointer vers Panorama ---", "configure",
        `set deviceconfig system panorama-server ${bare(v.panoIp)}`, ...(v.panoIp2 ? [`set deviceconfig system panorama-server-2 ${bare(v.panoIp2)}`] : []), "commit", "exit");
      cliRaw.push("", "# --- Vérification ---", "show system info | match system-mode", v.mode !== "management-only" ? "show system logdb-quota" : "show system disk-space");

      const notes = [
        { type: "or", title: "Les trois modes", html: "<ul><li><b>Panorama</b> : gestion des pare-feux + collecte locale des logs (déploiement « basique »).</li><li><b>Management Only</b> : gestion seule ; les logs des pare-feux vont vers des Dedicated Log Collectors (déploiement « distribué »).</li><li><b>Log Collector</b> : collecteur dédié, sans WebUI, géré par un Panorama.</li></ul>Le mode Legacy n'est plus supporté." },
        { type: "warn", text: `Syntaxes « request system disk add », « request system raid add » et « set deviceconfig system panorama-server » (Log Collector) : ${VALIDATE}.` },
      ];
      if (v.mode === "management-only") notes.push({ type: "warn", text: "En Management Only, Panorama ne stocke pas les logs des pare-feux : prévois au moins un Log Collector dédié et un Collector Group, sinon les logs ne sont pas centralisés." });
      if (v.change && v.mode === "panorama") notes.push({ type: "or", text: "Retour en mode Panorama : les disques de logs existants sont conservés mais vérifie les quotas après le redémarrage." });
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P01 · Snapshots de configuration Panorama (manuel)
     ===================================================================== */
  register({
    id: "p01-snapshot",
    module: "P01",
    title: "Snapshots de configuration Panorama",
    icon: "💾",
    desc: "Enregistrer, exporter ou recharger un snapshot nommé de la configuration Panorama ; exporter le bundle Panorama + pare-feux ; restaurer un pare-feu depuis ses sauvegardes.",
    tags: "panorama snapshot save export load revert configuration bundle backup sauvegarde restauration operations",
    noCommit: true,
    fields: [
      { id: "action", label: "Opération", type: "select", default: "save", group: "Opération",
        options: [["save", "Enregistrer + exporter un snapshot nommé"], ["load", "Recharger un snapshot nommé (restauration)"], ["bundle", "Exporter le bundle Panorama + pare-feux"], ["fw", "Restaurer la config d'un pare-feu depuis Panorama"]] },
      { id: "snap", label: "Nom du snapshot", type: "text", required: true, default: `Panorama-${today()}.xml`, show: v => v.action === "save" || v.action === "load",
        validate: n => /^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.xml$/.test(n) ? (["running-config.xml", "candidate-config.xml"].includes(n) ? "Nom réservé" : null) : "Nom de fichier .xml (lettres, chiffres, . _ -)" },
      { id: "exp", label: "Export", type: "select", default: "browser", show: v => v.action === "save",
        options: [["browser", "Téléchargement navigateur (WebUI)"], ["scp", "SCP (CLI)"], ["none", "Pas d'export"]] },
      { id: "scpUser", label: "Utilisateur SCP", type: "text", required: true, default: "backup", validate: objName, show: v => v.action === "save" && v.exp === "scp" },
      { id: "scpHost", label: "Serveur SCP", type: "text", required: true, default: "192.168.1.20", validate: "host", show: v => v.action === "save" && v.exp === "scp" },
      { id: "scpPath", label: "Répertoire distant", type: "text", required: true, default: "/backup/panorama/", show: v => v.action === "save" && v.exp === "scp",
        validate: p => /^[~\/][^\s]*$/.test(p) ? null : "Chemin absolu sans espace" },
      { id: "fwName", label: "Pare-feu concerné", type: "text", required: true, default: "FW-Paris-01", show: v => v.action === "fw" },
    ],
    build(v) {
      const steps = [], cliRaw = [];
      if (v.action === "save") {
        steps.push({ title: "Enregistrer un snapshot nommé", path: ["Panorama", "Setup", "Operations"], window: "Save Named Panorama Configuration",
          action: "Cadre « Configuration Management » → « Save named Panorama configuration snapshot ».", fields: [["Name", v.snap]],
          note: "Le fichier est stocké sur Panorama lui-même : il faut l'exporter pour disposer d'une vraie sauvegarde." });
        if (v.exp === "browser") steps.push({ title: "Exporter vers le poste", path: ["Panorama", "Setup", "Operations"],
          action: "« Export named Panorama configuration snapshot » → choisir le fichier → OK : le navigateur télécharge le XML.", fields: [["Name", v.snap]] });
        cliRaw.push("configure", `save config to ${v.snap}`, "exit");
        if (v.exp === "scp") cliRaw.push(`scp export configuration from ${v.snap} to ${v.scpUser}@${v.scpHost}:${v.scpPath}`);
        if (v.exp === "browser") cliRaw.push("# Export navigateur : uniquement via la WebUI");
        cliRaw.push("", "# --- Vérification ---", `show config saved ${v.snap}`);
      } else if (v.action === "load") {
        steps.push({ title: "Recharger le snapshot", path: ["Panorama", "Setup", "Operations"], window: "Load Named Configuration",
          action: "« Load named Panorama configuration snapshot » → choisir le fichier → OK. (Fichier externe : d'abord « Import named Panorama configuration snapshot ».)",
          fields: [["Name", v.snap]] },
        { title: "Appliquer", path: ["Commit", "Commit to Panorama"], action: "Le snapshot devient la configuration candidate : Commit to Panorama, puis Push to Devices si les pare-feux doivent revenir à cet état.", fields: [],
          warn: "Le chargement remplace TOUTE la configuration candidate de Panorama (templates, device groups, managed devices…)." });
        cliRaw.push("configure", `load config from ${v.snap}`, "commit", "exit", "", "# Puis pousser vers les pare-feux si nécessaire (Commit > Push to Devices)");
      } else if (v.action === "bundle") {
        steps.push({ title: "Exporter le bundle Panorama + pare-feux", path: ["Panorama", "Setup", "Operations"],
          action: "« Export Panorama and devices config bundle » : archive de la running-config de Panorama et de la dernière configuration de chaque pare-feu géré.", fields: [],
          note: "Pour une sauvegarde automatique quotidienne de ce bundle vers SCP/FTP, utiliser Panorama > Scheduled Config Export (module P10 Sauvegarde planifiée)." });
        cliRaw.push("# Export du bundle : WebUI (Panorama > Setup > Operations) ou export planifié (Panorama > Scheduled Config Export)", "show config saved");
      } else {
        steps.push({ title: "Ouvrir les sauvegardes du pare-feu", path: ["Panorama", "Managed Devices", "Summary"],
          action: `Ligne « ${v.fwName} » → colonne Backups → lien « Manage ».`, fields: [],
          note: "À gauche : configurations enregistrées manuellement sur le pare-feu. À droite : versions stockées automatiquement par Panorama à chaque commit (pare-feu ou push)." },
        { title: "Charger la version souhaitée", path: ["Panorama", "Managed Devices", "Summary"], window: "Device Configuration Backups",
          action: "Cliquer « Load » sur la version : elle devient la configuration candidate DU PARE-FEU.", fields: [],
          warn: "Il faut ensuite faire un Commit sur le pare-feu lui-même pour l'appliquer." });
        cliRaw.push("# Restauration d'une sauvegarde pare-feu : WebUI Panorama (Backups > Manage > Load) puis commit sur le pare-feu");
      }
      return { steps, cli: cliRaw, cliRaw, notes: [
        { type: "or", title: "Types de configuration Panorama", html: "<ul><li><b>Running</b> : configuration active après commit.</li><li><b>Candidate</b> : modifications en cours, non commitées.</li><li><b>Versions</b> : copies horodatées créées automatiquement à chaque commit (Load Panorama configuration version).</li><li><b>Snapshots nommés</b> : copies manuelles, à prendre avant tout changement important.</li></ul>" },
        { type: "warn", text: "Les secrets du XML sont chiffrés avec la master key : conserve-la pour restaurer sur un autre Panorama." },
      ] };
    },
  });

  /* =====================================================================
     P01 · Commit & Push (Commit to Panorama / Push to Devices)
     ===================================================================== */
  register({
    id: "p01-commit",
    module: "P01",
    title: "Commit & push vers les pare-feux",
    icon: "🚚",
    desc: "Comprendre et préparer Commit to Panorama, Push to Devices et Commit and Push : portée (device groups, template stacks), Edit Selections, Force Template Values, planification.",
    tags: "commit push devices commit and push edit selections push scope force template values merge candidate schedule task manager",
    noCommit: true,
    fields: [
      { id: "descr", label: "Description du commit", type: "text", default: "Mise en service Panorama", group: "Commit to Panorama",
        hint: "Optionnelle mais fortement recommandée : visible dans Tasks et dans le Config log." },
      { id: "byAdmin", label: "Ne committer que mes modifications (Commit Changes Made By)", type: "checkbox", default: false, wide: true,
        hint: "Utile quand plusieurs administrateurs travaillent en même temps sur Panorama." },
      { id: "adminUser", label: "Administrateur", type: "text", required: true, default: "admin", validate: objName, show: v => v.byAdmin },
      { id: "doPush", label: "Pousser ensuite vers les pare-feux", type: "checkbox", default: true, group: "Push to Devices", wide: true },
      { id: "dg", label: "Device group à pousser (optionnel)", type: "text", default: "DG-Paris", validate: objName, show: v => v.doPush },
      { id: "stack", label: "Template stack à pousser (optionnel)", type: "text", default: "TS-Paris", validate: objName, show: v => v.doPush },
      { id: "inclTpl", label: "Include Device and Network Templates (avec le device group)", type: "checkbox", default: true, show: v => v.doPush && v.dg },
      { id: "merge", label: "Merge with Device Candidate Config", type: "checkbox", default: true, show: v => v.doPush },
      { id: "force", label: "Force Template Values (écrase les surcharges locales)", type: "checkbox", default: false, show: v => v.doPush && (v.stack || v.inclTpl) },
      { id: "sched", label: "Planifier le push (Schedule)", type: "checkbox", default: false, show: v => v.doPush, wide: true },
      { id: "schedName", label: "Nom de la planification", type: "text", required: true, default: "Push-nuit", validate: objName, show: v => v.doPush && v.sched },
      { id: "schedType", label: "Type", type: "select", default: "one-time", options: [["one-time", "One-time"], ["recurring", "Recurring"]], show: v => v.doPush && v.sched },
      { id: "schedTime", label: "Heure (HH:MM)", type: "text", required: true, default: "22:00", validate: hhmm, show: v => v.doPush && v.sched },
    ],
    build(v) {
      const steps = [
        { title: "Contrôler les changements", path: ["Commit", "Commit to Panorama"], window: "Commit to Panorama",
          action: "Avant de valider : Preview Changes (comparaison running/candidate : rouge = supprimé, jaune = modifié, vert = ajouté), Change Summary, Validate Commit.",
          fields: [["Commit All Changes", !v.byAdmin], ["Commit Changes Made By", v.byAdmin && v.adminUser], ["Description", v.descr]] },
        { title: "Commit to Panorama", path: ["Commit", "Commit to Panorama"], action: "Cliquer Commit et attendre Status = Completed. Dans Tasks, le lien « Commit Description » n'apparaît que si une description a été saisie.", fields: [] },
      ];
      if (v.doPush && (v.dg || v.stack)) {
        steps.push({ title: "Push to Devices — portée", path: ["Commit", "Push to Devices"], window: "Push Scope Selection",
          action: "Cliquer « Edit Selections » : onglets Device Groups / Templates / Collector Groups ; cocher uniquement les éléments et pare-feux à mettre à jour (Last Commit State « Out of Sync » = changements en attente).",
          fields: [["Device Groups", v.dg], ["Templates", v.stack], ["Include Device and Network Templates", v.dg && v.inclTpl], ["Merge with Device Candidate Config", v.merge],
            ["Force Template Values", v.force]],
          note: "« Validate Device Group Push » / « Validate Template Push » testent le push sans l'appliquer. « Preview Changes » à droite de chaque pare-feu montre le diff exact.",
          warn: v.force ? "Force Template Values remplace toute valeur de template surchargée localement sur les pare-feux : vérifie les surcharges (icônes engrenage vert + orange) avant." : null });
        if (v.sched) steps.push({ title: "Planifier le push", path: ["Commit", "Push to Devices", "Schedule"], window: "Config Push Scheduler",
          action: "Bouton « Schedule » de la fenêtre Push to Devices.", fields: [["Name", v.schedName], ["Type", v.schedType === "one-time" ? "One-time" : "Recurring"], ["Time", v.schedTime],
            ["Device Groups / Templates", [v.dg, v.stack].filter(Boolean)]] });
        steps.push({ title: "Suivre l'exécution", path: ["Tasks"], action: "Task Manager – All Tasks : chaque job « Commit All » passe à Completed ou Failed ; cliquer le job puis le lien du pare-feu pour le détail d'erreur.", fields: [] });
      }
      const push = [];
      if (v.doPush && !v.sched) {
        const opts = `${v.merge ? "" : " merge-with-candidate-cfg no"}${v.force ? " force-template-values yes" : ""}`;
        if (v.dg) push.push(`commit-all shared-policy device-group ${q(v.dg)}${v.inclTpl ? " include-template yes" : ""}${v.merge ? "" : " merge-with-candidate-cfg no"}${v.inclTpl && v.force ? " force-template-values yes" : ""}`);
        if (v.stack && !(v.dg && v.inclTpl)) push.push(`commit-all template-stack name ${q(v.stack)}${opts}`);
        if (push.length) push.push("show jobs all");
      }
      const notes = [
        { type: "or", title: "Trois commandes", html: "<ul><li><b>Commit to Panorama</b> : candidate → running de Panorama uniquement.</li><li><b>Push to Devices</b> : envoie templates, device groups et configuration des collector groups aux équipements gérés.</li><li><b>Commit and Push</b> : les deux en une seule étape.</li></ul>" },
        { type: "warn", text: `Options « merge-with-candidate-cfg » / « force-template-values » de commit-all : ${VALIDATE}. La planification de push se fait uniquement dans la WebUI.` },
      ];
      if (v.byAdmin) notes.push({ type: "warn", text: `Syntaxe du commit partiel « commit partial admin [ … ] » : ${VALIDATE}.` });
      const d = v.descr ? ` description ${q(ascii(v.descr))}` : "";
      const cliRaw = ["configure", v.byAdmin ? `commit partial admin [ ${q(v.adminUser)} ]${d}` : `commit${d}`, "exit",
        ...(push.length ? ["", "# --- Push vers les pare-feux (mode opérationnel Panorama) ---", ...push] : []),
        ...(v.doPush && v.sched ? ["", "# Push planifié : WebUI uniquement (Push to Devices > Schedule)"] : []),
        "", "# --- Vérification ---", "show devices all"];
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P02 · Ajouter un pare-feu géré (auth key + config côté pare-feu)
     ===================================================================== */
  register({
    id: "p02-add-fw",
    module: "P02",
    title: "Ajouter un pare-feu à Panorama",
    icon: "➕",
    desc: "Numéro de série dans Managed Devices, clé d'enregistrement (device registration auth key), association device group / template stack, puis configuration Panorama Settings côté pare-feu.",
    tags: "managed devices add firewall serial auth key authkey device registration panorama settings associate auto push onboarding",
    fields: [
      { id: "fwSerial", label: "Numéro de série du pare-feu", type: "text", required: true, default: "007951000123456", validate: serial, group: "Pare-feu à ajouter",
        hint: "Pare-feu : Dashboard > General Information > Serial #. Un VM-Series doit être licencié pour avoir une série." },
      { id: "extraSerials", label: "Autres pare-feux (séries, séparées par des virgules)", type: "list", default: [], wide: true,
        validate: (a, v) => serialList(a, v, v.fwSerial), hint: "Même clé utilisable pour tous les pare-feux ajoutés dans cette opération." },
      { id: "fwName", label: "Hostname à donner au pare-feu (optionnel)", type: "text", validate: "hostname", default: "FW-Paris-01",
        hint: "Après connexion, Panorama affiche le hostname à la place de la série." },
      { id: "fwMgmtIp", label: "IP de management du pare-feu (info)", type: "ipcidr", default: "192.168.1.254/24" },

      { id: "panoIp", label: "IP de management Panorama", type: "ipcidr", required: true, default: "192.168.1.252/24", group: "Panorama" },
      { id: "panoIp2", label: "IP du Panorama pair HA (optionnel)", type: "ipcidr", default: "" },
      { id: "authKey", label: "Nom de la clé d'enregistrement", type: "text", required: true, default: "AK-Onboarding", validate: objName,
        hint: "Depuis PAN-OS 10.1, un pare-feu ne se connecte à Panorama qu'avec une auth key valide générée par Panorama." },
      { id: "akLife", label: "Durée de validité (minutes)", type: "number", min: 1, max: 525600, required: true, default: "1440", hint: "1440 = 24 h (durée de la clé générée par le bouton Generate Auth Key)." },
      { id: "akCount", label: "Nombre d'utilisations", type: "number", min: 1, max: 5000, required: true, default: "1",
        validate: (c, v) => +c < 1 + v.extraSerials.length ? `Au moins ${1 + v.extraSerials.length} (un par pare-feu ajouté)` : null },

      { id: "assoc", label: "Associer dès l'ajout (Associate Devices)", type: "checkbox", default: true, group: "Association", wide: true },
      { id: "stack", label: "Template stack", type: "text", default: "TS-Paris", validate: objName, show: v => v.assoc },
      { id: "dg", label: "Device group", type: "text", default: "DG-Paris", validate: objName, show: v => v.assoc },
      { id: "cg", label: "Collector group (optionnel)", type: "text", default: "", validate: objName, show: v => v.assoc },
      { id: "autoPush", label: "Auto Push on 1st Connect", type: "checkbox", default: true, show: v => v.assoc && (v.stack || v.dg),
        hint: "Panorama pousse automatiquement device group et template stack à la première connexion du pare-feu." },

      { id: "monData", label: "Enable pushing device monitoring data to Panorama", type: "checkbox", default: true, group: "Options côté pare-feu" },
      { id: "recovery", label: "Enable automated commit recovery", type: "checkbox", default: true,
        hint: "Après un push, le pare-feu vérifie qu'il joint toujours Panorama ; sinon il revient à la configuration précédente." },
      { id: "recAttempts", label: "Nombre de tentatives", type: "number", min: 1, max: 30, default: "1", show: v => v.recovery },
      { id: "recInterval", label: "Intervalle entre tentatives (s)", type: "number", min: 5, max: 3600, default: "10", show: v => v.recovery },
    ],
    example: { fwSerial: "007951000342260", extraSerials: ["007951000342261"], fwName: "chicago-fw", fwMgmtIp: "192.168.1.254/24", panoIp: "192.168.1.252/24", akCount: "2", assoc: false },
    build(v) {
      const serials = [v.fwSerial, ...v.extraSerials];
      const steps = [
        { title: "Relever le numéro de série", path: ["Pare-feu", "Dashboard"], window: "General Information",
          action: "Sur chaque pare-feu, copier le champ « Serial # » dans un fichier texte.", fields: [["Serial #", serials]] },
        { title: "Ajouter le(s) pare-feu(x) et générer la clé", path: ["Panorama", "Managed Devices", "Summary"], window: "Add Device(s)",
          action: "Bouton « Add » en bas à gauche. Une série par ligne. Cliquer « Generate Auth Key » puis « Copy Auth Key » et coller la valeur dans un fichier texte.",
          fields: [["Serial", serials.join("\n")], ["Associate Devices", v.assoc], ["Auto Push on 1st Connect", v.assoc && v.autoPush]],
          note: "La clé générée par le bouton est valable 24 h et sert pour tous les pare-feux listés. Passé ce délai : supprimer les pare-feux et recommencer (ou générer une nouvelle clé en CLI)." },
      ];
      if (v.assoc) steps.push({ title: "Association", path: ["Panorama", "Managed Devices", "Summary"], window: "Device Association",
        action: "La fenêtre liste les séries : choisir dans chaque colonne, puis OK.",
        fields: [["Device Group", v.dg], ["Template Stack", v.stack], ["Collector Group", v.cg]],
        note: "Le device group et le template stack doivent déjà exister (modules P03 Template stack et P04 Device group)." });
      steps.push(fwPanoStep(v, { mon: v.monData, recovery: v.recovery, attempts: v.recAttempts, interval: v.recInterval }));
      if (v.fwName) steps.push({ title: "Côté pare-feu : hostname", path: ["Pare-feu", "Device", "Setup", "Management"], window: "General Settings",
        action: "Cadre « General Settings » → ⚙ (en profiter pour Domain, Time Zone, Latitude/Longitude).", fields: [["Hostname", v.fwName]] });
      steps.push({ title: "Côté pare-feu : Commit", path: ["Pare-feu", "Commit"], action: "Commit local sur le pare-feu : il commence à contacter Panorama (TCP 3978). Panorama n'accepte la connexion qu'une fois l'ajout de la série commité (étape suivante).", fields: [] });

      const cli = [
        "# Clé d'enregistrement (commande opérationnelle exécutée via run)",
        `run request authkey add name ${q(v.authKey)} lifetime ${v.akLife} count ${v.akCount}`,
        ...serials.map(s => `set mgt-config devices ${s}`),
        ...(v.assoc && v.stack ? serials.map(s => `set template-stack ${q(v.stack)} devices ${s}`) : []),
        ...(v.assoc && v.dg ? serials.map(s => `set device-group ${q(v.dg)} devices ${s}`) : []),
        v.assoc && v.autoPush && "# Auto Push on 1st Connect : option de la fenêtre Add Device(s) (WebUI)",
      ].filter(Boolean);
      const push = [];
      if (v.assoc && !v.autoPush) {
        push.push("# Une fois le pare-feu « Connected » :");
        if (v.dg) push.push(`commit-all shared-policy device-group ${q(v.dg)}${v.stack ? " include-template yes" : ""}`);
        else if (v.stack) push.push(`commit-all template-stack name ${q(v.stack)}`);
      }
      const fwCli = fwPanoCli(v, { hostname: true });

      const notes = [
        { type: "ok", title: "Après le Commit to Panorama", text: "Panorama > Managed Devices > Summary : rafraîchir (⟳) jusqu'à Device State = « Connected » (quelques minutes) ; le hostname remplace alors la série. Les colonnes se personnalisent via le petit triangle d'un en-tête (Columns) et par glisser-déposer." },
        { type: "or", title: "Flux réseau", text: `Le pare-feu initie la connexion vers Panorama (${bare(v.panoIp)}) en TCP 3978 (management et logs) ; les mises à jour logicielles/contenus distribuées par Panorama utilisent TCP 28443. Autorise ces flux sur tout équipement intermédiaire.` },
        { type: "or", text: "La clé (auth key) n'est utilisée qu'une fois : après une première connexion réussie, le pare-feu n'en a plus besoin. Elle doit être appliquée AVANT le commit côté pare-feu." },
        { type: "warn", text: `Syntaxes « request authkey add » (Panorama) et « request authkey set » (pare-feu) : ${VALIDATE}. La valeur de la clé est générée par Panorama (affichée par la commande ou par Copy Auth Key).` },
      ];
      if (v.assoc && v.cg) notes.push({ type: "or", text: `Rattachement au collector group « ${v.cg} » : se fait dans Panorama > Collector Groups > Device Log Forwarding (module P05 Collector group).` });
      if (v.assoc && (v.stack || v.dg)) notes.push(PUSH_NOTE);
      return { steps, cli, push, fwCli, notes,
        verify: ["show devices all", "show devices connected", "# Côté pare-feu : show panorama-status (doit indiquer Connected : yes)"] };
    },
  });

  /* =====================================================================
     P02 · Import en masse (CSV)
     ===================================================================== */
  register({
    id: "p02-bulk",
    module: "P02",
    title: "Import en masse de pare-feux (CSV)",
    icon: "📥",
    desc: "Générer le fichier CSV d'import de Managed Devices (série, device group, template stack, collector group, log collector, auto-push) et l'équivalent CLI.",
    tags: "bulk import csv many firewalls device association zero touch masse onboarding",
    fields: [
      { id: "lines", label: "Pare-feux (une ligne par pare-feu : série[, device group[, template stack]])", type: "textarea", required: true, wide: true, group: "Liste des pare-feux",
        default: "007951000123456, DG-Paris, TS-Paris\n007951000123457, DG-Lyon, TS-Lyon\n007951000123458",
        hint: "Colonnes vides = valeurs par défaut ci-dessous. Lignes commençant par # ignorées.",
        validate: t => {
          const r = rows(t); if (!r.length) return "Au moins un pare-feu";
          const seen = new Set();
          for (const [s, d, st] of r) {
            if (serial(s)) return `« ${s} » : ${serial(s)}`;
            if (seen.has(s)) return `Série en double : ${s}`; seen.add(s);
            if (d && objName(d)) return `Device group « ${d} » : ${objName(d)}`;
            if (st && objName(st)) return `Template stack « ${st} » : ${objName(st)}`;
          }
          return null;
        } },
      { id: "dg", label: "Device group par défaut", type: "text", default: "DG-Paris", validate: objName, group: "Valeurs par défaut" },
      { id: "stack", label: "Template stack par défaut", type: "text", default: "TS-Paris", validate: objName },
      { id: "cg", label: "Collector group (optionnel)", type: "text", default: "", validate: objName },
      { id: "collector", label: "Log collector — série (optionnel)", type: "text", default: "", validate: serial },
      { id: "autoPush", label: "Auto push on first connect", type: "checkbox", default: true },
      { id: "panoIp", label: "IP de management Panorama", type: "ipcidr", required: true, default: "192.168.1.252/24", group: "Enregistrement" },
      { id: "panoIp2", label: "IP du Panorama pair HA (optionnel)", type: "ipcidr", default: "" },
      { id: "authKey", label: "Nom de la clé d'enregistrement", type: "text", required: true, default: "AK-Bulk", validate: objName },
      { id: "akLife", label: "Validité (minutes)", type: "number", min: 1, max: 525600, required: true, default: "1440" },
    ],
    build(v) {
      const list = rows(v.lines).map(([s, d, st]) => ({ s, d: d || v.dg || "", st: st || v.stack || "" }));
      const qq = x => `"${String(x).replace(/"/g, '""')}"`;
      const csv = [["serial", "device-group", "template-stack", "collector-group", "log-collector", "auto-push-on-first-connect"].map(qq).join(","),
        ...list.map(x => [x.s, x.d, x.st, v.cg, v.collector, v.autoPush && (x.d || x.st) ? "yes" : "no"].map(qq).join(","))].join("\n");
      const steps = [
        { title: "Côté pare-feux : déclarer Panorama", path: ["Pare-feu", "Device", "Setup", "Management"], window: "Panorama Settings",
          action: "Sur chaque pare-feu (ou via bootstrap / ZTP) : Panorama Servers + Auth Key, puis Commit (bloc « Côté pare-feu »).", fields: [["Panorama Servers", [bare(v.panoIp), v.panoIp2 && bare(v.panoIp2)].filter(Boolean)]] },
        { title: "Préparer le fichier CSV", path: ["Poste d'administration"],
          action: "Enregistrer le contenu affiché dans la note « Fichier CSV » sous le nom pare-feux.csv (UTF-8, sans ligne vide à la fin).", fields: [["Pare-feux", String(list.length)]],
          note: "Le bouton « Download Sample CSV » de la fenêtre Add Device(s) fournit le gabarit officiel : compare son en-tête avec celui-ci avant l'import." },
        { title: "Importer", path: ["Panorama", "Managed Devices", "Summary"], window: "Add Device(s)",
          action: "Add → Generate Auth Key (copier la clé) → Import → Browse : choisir pare-feux.csv → contrôler les colonnes de la fenêtre Device Association → OK.",
          fields: [["Associate Devices", true]] },
      ];
      const sets = [];
      list.forEach(x => {
        sets.push(`set mgt-config devices ${x.s}`);
        if (x.st) sets.push(`set template-stack ${q(x.st)} devices ${x.s}`);
        if (x.d) sets.push(`set device-group ${q(x.d)} devices ${x.s}`);
      });
      const cli = ["# Équivalent CLI de l'import (sans auto-push : pousser ensuite)",
        `run request authkey add name ${q(v.authKey)} lifetime ${v.akLife} count ${list.length}`, ...sets];
      const dgs = [...new Set(list.map(x => x.d).filter(Boolean))], sts = [...new Set(list.map(x => x.st).filter(Boolean))];
      const push = v.autoPush ? [] : ["# Une fois les pare-feux « Connected » :", ...dgs.map(d => `commit-all shared-policy device-group ${q(d)} include-template yes`),
        ...sts.filter(() => !dgs.length).map(s => `commit-all template-stack name ${q(s)}`)];
      const notes = [
        { type: "ok", title: "Fichier CSV", html: `<pre style="white-space:pre;overflow:auto;margin:6px 0 0">${esc(csv)}</pre>` },
        { type: "or", text: `Device groups référencés : ${dgs.join(", ") || "aucun"} — template stacks : ${sts.join(", ") || "aucun"}. Ils doivent exister avant l'import (sinon l'association échoue).` },
        { type: "warn", text: "L'auto-push à la première connexion n'est supporté que sur les pare-feux mono-vsys." },
        { type: "warn", text: `En-tête CSV reconstitué d'après le cours (série, device-group, template, collector-group, log-collector, auto-push-on-first-connect) : compare avec « Download Sample CSV » de ta version. Syntaxe « request authkey » : ${VALIDATE}.` },
      ];
      if (v.cg) notes.push({ type: "or", text: `Collector group « ${v.cg} » : vérifier ensuite l'affectation dans Panorama > Collector Groups > Device Log Forwarding.` });
      return { steps, cli, push, fwCli: fwPanoCli(v), notes, verify: ["show devices all", "show devices connected"] };
    },
  });

  /* =====================================================================
     P02 · Migrer un pare-feu existant (import de sa configuration)
     ===================================================================== */
  register({
    id: "p02-migrate",
    module: "P02",
    title: "Migrer un pare-feu existant sous Panorama",
    icon: "📦",
    desc: "Importer la configuration locale d'un pare-feu en production dans un template et un device group, l'intégrer à la structure cible puis pousser le config bundle.",
    tags: "migration import device configuration existing firewall transition brownfield config bundle push rule import location",
    noCommit: true,
    fields: [
      { id: "fwSerial", label: "Numéro de série du pare-feu", type: "text", required: true, default: "007951000123456", validate: serial, group: "Pare-feu à migrer",
        hint: "Le pare-feu doit d'abord être ajouté et « Connected » (module Ajouter un pare-feu)." },
      { id: "fwName", label: "Hostname du pare-feu", type: "text", required: true, validate: "hostname", default: "FW-Paris-01" },
      { id: "impTpl", label: "Template créé par l'import", type: "text", required: true, default: "TPL-import-FW01", validate: objName, group: "Import (Import device configuration to Panorama)" },
      { id: "impStack", label: "Template stack créé par l'import", type: "text", required: true, default: "TPL-import-FW01_stack", validate: objName,
        hint: "Panorama crée automatiquement un stack pour le template importé : relève son nom exact dans Panorama > Templates après l'import." },
      { id: "impDg", label: "Device group créé par l'import", type: "text", required: true, default: "DG-import-FW01", validate: objName },
      { id: "ruleLoc", label: "Rule Import Location", type: "select", default: "pre-rulebase", options: [["pre-rulebase", "Pre Rulebase"], ["post-rulebase", "Post Rulebase"]],
        hint: "S'applique à toutes les rulebases importées (Security, NAT, Decryption…)." },
      { id: "sharedObj", label: "Import devices' shared objects into Panorama's shared context", type: "checkbox", default: false,
        hint: "Décoché = les objets partagés du pare-feu restent dans le device group importé (moins de risque de conflit dans Shared)." },
      { id: "strategy", label: "Intégration dans la structure cible", type: "select", default: "child", group: "Structure cible",
        options: [["child", "Garder le DG importé comme enfant d'un DG parent (plus sûr)"], ["move", "Déplacer le pare-feu dans un DG et un stack existants"], ["keep", "Conserver tel quel (DG + stack importés)"]] },
      { id: "parentDg", label: "Device group parent", type: "text", required: true, default: "DG-Paris", validate: objName, show: v => v.strategy === "child" },
      { id: "dg", label: "Device group cible", type: "text", required: true, default: "DG-Paris", validate: objName, show: v => v.strategy === "move" },
      { id: "stack", label: "Template stack cible", type: "text", required: true, default: "TS-Paris", validate: objName, show: v => v.strategy !== "keep",
        hint: "Le stack cible doit contenir le template importé (ou ses réglages repris) pour ne rien perdre des interfaces/zones/routage." },
      { id: "keepTpl", label: "Ajouter le template importé en tête du stack cible", type: "checkbox", default: true, show: v => v.strategy !== "keep" },
    ],
    build(v) {
      const S = v.fwSerial, finalDg = v.strategy === "move" ? v.dg : v.impDg, finalStack = v.strategy === "keep" ? v.impStack : v.stack;
      const steps = [
        { title: "Préparer la migration", path: ["Planification"],
          action: "Même version PAN-OS sur Panorama et le pare-feu (Panorama ≥ pare-feu), noms de zones harmonisés entre sites, liste des réglages qui resteront gérés localement, snapshot nommé exporté du pare-feu.",
          fields: [], warn: "La dernière étape remplace la configuration locale du pare-feu par celle gérée par Panorama : planifie une fenêtre de maintenance." },
        { title: "Importer la configuration du pare-feu", path: ["Panorama", "Setup", "Operations"], window: "Import Device Configuration",
          action: "Cadre « Configuration Management » → « Import device configuration to Panorama ».",
          fields: [["Device", `${v.fwName} (${S})`], ["Template Name", v.impTpl], ["Device Group Name", v.impDg],
            ["Import devices' shared objects into Panorama's shared context", v.sharedObj], ["Rule Import Location", v.ruleLoc === "pre-rulebase" ? "Pre Rulebase" : "Post Rulebase"]],
          note: "Panorama crée un template, un template stack et un device group temporaires contenant ce seul pare-feu, avec une copie de toute sa configuration." },
        { title: "Contrôler l'import", path: ["Policies / Objects / Network / Device"], action: `Sélecteurs Device Group = ${v.impDg} et Template = ${v.impTpl} : vérifier règles, objets, interfaces, zones, routage. Corriger les conflits de noms éventuels.`, fields: [] },
      ];
      if (v.strategy === "child") steps.push({ title: "Rattacher le DG importé à son parent", path: ["Panorama", "Device Groups"], window: "Device Group",
        action: `Cliquer « ${v.impDg} » → Parent Device Group.`, fields: [["Parent Device Group", v.parentDg]],
        note: "Le pare-feu hérite alors des règles et objets du parent tout en gardant ses règles importées ; tu pourras les remonter progressivement vers le parent." });
      if (v.strategy === "move") steps.push({ title: "Déplacer règles et objets puis le pare-feu", path: ["Policies", "Security"],
        action: `Sélectionner les règles importées → « Move » vers le device group ${v.dg} (idem objets). Puis Panorama > Device Groups : décocher ${v.fwName} dans ${v.impDg}, le cocher dans ${v.dg}.`,
        fields: [], warn: "Si tu déplaces le pare-feu sans déplacer ses règles et objets, il perdra sa politique au prochain push." });
      if (v.strategy !== "keep") steps.push({ title: "Rattacher le pare-feu au template stack cible", path: ["Panorama", "Templates"], window: "Template Stack",
        action: `Éditer ${v.impStack} : décocher ${v.fwName}. Éditer ${v.stack} : ${v.keepTpl ? `ajouter le template ${v.impTpl} (Move Up : en tête), ` : ""}cocher ${v.fwName}.`,
        fields: [["Templates", v.keepTpl ? [v.impTpl, "(templates existants)"] : "(inchangé)"], ["Devices", v.fwName]],
        note: "Un pare-feu n'appartient qu'à un seul template stack : il doit être retiré de l'ancien avant d'apparaître dans le nouveau." });
      steps.push(
        { title: "Commit to Panorama", path: ["Commit", "Commit to Panorama"], action: "Valider la nouvelle structure sur Panorama.", fields: [] },
        { title: "Pousser le config bundle", path: ["Panorama", "Setup", "Operations"], window: "Export or Push Device Config Bundle",
          action: `« Export or push device config bundle » → Device = ${v.fwName} → OK → « Push & Commit ».`, fields: [],
          note: "Le pare-feu supprime sa configuration locale de politiques/objets/réseau et adopte celle de Panorama (le management local reste)." },
        { title: "Synchroniser", path: ["Commit", "Push to Devices"], window: "Push Scope Selection",
          action: "Edit Selections → cocher le DG et le stack du pare-feu → Push. Vérifier ensuite Managed Devices > Summary : Shared Policy et Template « In Sync ».",
          fields: [["Device Group", finalDg], ["Template Stack", finalStack], ["Include Device and Network Templates", true]] },
      );
      const cli = ["# 1. Import : WebUI (Panorama > Setup > Operations > Import device configuration to Panorama)"];
      if (v.strategy === "move") cli.push("# 2. Déplacer d'abord les règles et objets importés vers le DG cible (WebUI : Move)", `delete device-group ${q(v.impDg)} devices ${S}`, `set device-group ${q(v.dg)} devices ${S}`);
      if (v.strategy === "child") cli.push(`# 2. DG parent : WebUI (Panorama > Device Groups > ${v.impDg} > Parent Device Group = ${v.parentDg})`);
      if (v.strategy !== "keep") {
        cli.push(`delete template-stack ${q(v.impStack)} devices ${S}`);
        if (v.keepTpl) cli.push(`# Le premier template de la liste est le plus prioritaire : réordonner au besoin dans la WebUI`, `set template-stack ${q(v.stack)} templates ${q(v.impTpl)}`);
        cli.push(`set template-stack ${q(v.stack)} devices ${S}`);
      }
      const push = ["# Après le push du config bundle (WebUI : Export or push device config bundle > Push & Commit)",
        `commit-all shared-policy device-group ${q(finalDg)} include-template yes`];
      const notes = [
        { type: "or", title: "Étapes (annexe A du cours)", text: "1. Ajouter le pare-feu à Panorama  2. Importer sa configuration  3. L'adapter dans Panorama  4. Commit to Panorama  5. Pousser le config bundle puis la configuration." },
        { type: "warn", text: "Zones : les règles poussées par Panorama référencent des noms de zones. Harmonise les noms (ex. Trust/Untrust/DMZ partout) avant d'intégrer plusieurs pare-feux importés dans le même device group." },
        v.sharedObj && { type: "warn", text: "Objets partagés importés dans Shared : en cas de nom identique avec un objet existant de valeur différente, l'import échoue ou crée des conflits. Contrôle Objects (Device Group = Shared) avant." },
        v.keepTpl && v.strategy !== "keep" && { type: "warn", text: "« set template-stack … templates X » ajoute le template à la liste existante ; si le stack contient déjà d'autres templates, vérifie l'ordre final dans la WebUI (le plus haut l'emporte en cas de conflit)." },
        { type: "or", text: `L'import et le push du config bundle se font dans la WebUI ; équivalents CLI éventuels : ${VALIDATE}.` },
      ].filter(Boolean);
      const cliRaw = [cli[0], "configure", ...cli.slice(1), "commit", "exit", "", "# --- Push vers les pare-feux (mode opérationnel Panorama) ---", ...push,
        "", "# --- Vérification ---", "show devices all"];
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P02 · Déploiement licences / logiciel / contenus vers les pare-feux
     ===================================================================== */
  register({
    id: "p02-deploy",
    module: "P02",
    title: "Déploiement vers les pare-feux (licences, contenus, PAN-OS)",
    icon: "🚀",
    desc: "Rafraîchir les licences des pare-feux, planifier la distribution des mises à jour dynamiques et déployer une version PAN-OS depuis Panorama > Device Deployment.",
    tags: "device deployment licenses software upgrade dynamic updates schedules content antivirus wildfire app threat revert content panos firewall",
    fields: [
      { id: "fwSerial", label: "Pare-feu ciblé (série)", type: "text", required: true, default: "007951000123456", validate: serial, group: "Cible" },
      { id: "extraSerials", label: "Autres pare-feux (séries, séparées par des virgules)", type: "list", default: [], wide: true, validate: (a, v) => serialList(a, v, v.fwSerial) },
      { id: "licRefresh", label: "Rafraîchir les licences des pare-feux", type: "checkbox", default: true, group: "Licences", wide: true },

      ...schedFields("dt", "Planification Apps & Threats", [["daily", "Daily"], ["weekly", "Weekly"], ["hourly", "Hourly"], ["every-30-mins", "Every 30 Minutes"]],
        { rec: "daily", time: "02:30" }, { toggle: "Planifier App and Threat", name: "Daily-App-and-Threat-Updates" }),
      ...schedFields("da", "Planification Antivirus", [["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["every-30-mins", "Every 30 Minutes"]],
        { rec: "hourly", min: 45 }, { toggle: "Planifier Anti Virus", name: "Hourly-AV-Updates" }),
      ...schedFields("dw", "Planification WildFire", [["every-15-mins", "Every 15 Minutes"], ["every-30-mins", "Every 30 Minutes"], ["hourly", "Hourly"]],
        { rec: "every-15-mins", min: 7, on: false }, { toggle: "Planifier WildFire", name: "WildFire-Updates" }),

      { id: "sw", label: "Déployer une version PAN-OS", type: "checkbox", default: false, group: "Logiciel PAN-OS", wide: true },
      { id: "swVersion", label: "Version cible", type: "text", required: true, default: "11.1.6", validate: swVer, show: v => v.sw },
      { id: "swPlatform", label: "Plate-forme (nom du fichier PanOS_<plate-forme>-<version>)", type: "select", default: "vm", show: v => v.sw,
        options: [["vm", "VM-Series (vm)"], ["400", "PA-400 (400)"], ["1400", "PA-1400 (1400)"], ["3400", "PA-3400 (3400)"], ["5400", "PA-5400 (5400)"], ["3200", "PA-3200 (3200)"], ["5200", "PA-5200 (5200)"], ["220", "PA-220 (220)"], ["800", "PA-800 (800)"]] },
      { id: "swMode", label: "Mode d'installation", type: "select", default: "upload", show: v => v.sw,
        options: [["upload", "Upload only to device (do not install) — préparation sans coupure"], ["reboot", "Reboot device after install"]] },
    ],
    example: { dtRec: "weekly", dtDay: "sunday", dtTime: "02:30", dtName: "Weekly-App-and-Threat-Updates", daRec: "weekly", daDay: "sunday", daTime: "02:45", daName: "Weekly-AV-Updates", dwOn: false },
    build(v) {
      const serials = [v.fwSerial, ...v.extraSerials];
      const types = [["dt", "App and Threat", "content"], ["da", "Anti Virus", "anti-virus"], ["dw", "WildFire", "wildfire"]].filter(([p]) => v[p + "On"]);
      const steps = [];
      if (v.licRefresh) steps.push({ title: "Rafraîchir les licences", path: ["Panorama", "Device Deployment", "Licenses"],
        action: "Bouton « Refresh » en bas → cocher les pare-feux → Refresh. Une fois Completed, rafraîchir la liste (⟳) pour afficher les licences et dates d'expiration.",
        fields: [["Devices", serials]], note: "Cette vue centralise toutes les licences (exportable PDF/CSV) ; Activate / Deactivate sont aussi disponibles ici." });
      if (types.length) {
        steps.push({ title: "Récupérer la liste des contenus", path: ["Panorama", "Device Deployment", "Dynamic Updates"], action: "Cliquer « Check Now » en bas à gauche.", fields: [] });
        types.forEach(([p, label]) => steps.push({ title: `Planifier ${label}`, path: ["Panorama", "Device Deployment", "Dynamic Updates", "Schedules"], window: "Update Schedule",
          action: "Bouton « Schedules » en bas → Add.",
          fields: [["Name", v[p + "Name"]], ["Type", label], ...schedGui(v, p), ["Devices", serials]] }));
      }
      if (v.sw) {
        const file = `PanOS_${v.swPlatform}-${v.swVersion}`;
        steps.push(
          { title: `Télécharger PAN-OS ${v.swVersion}`, path: ["Panorama", "Device Deployment", "Software"],
            action: `Check Now → repérer la ligne Platform « ${v.swPlatform} » / Version ${v.swVersion} → Download.`, fields: [["Fichier", file]],
            note: "Un fichier par plate-forme : télécharge chaque modèle présent dans le parc." },
          { title: "Déployer", path: ["Panorama", "Device Deployment", "Software"], window: "Deploy Software File",
            action: "Lien « Install » de la ligne → filtrer et cocher les pare-feux → OK.",
            fields: [["Devices", serials], ["Upload only to device (do not install)", v.swMode === "upload"], ["Reboot device after install", v.swMode === "reboot"]],
            warn: v.swMode === "reboot" ? "Le pare-feu redémarre à la fin de l'installation : coupure de service (en HA, mettre à niveau un membre à la fois)." : "Les fichiers sont seulement transférés : installation et redémarrage restent à faire dans la fenêtre de maintenance." });
      }
      const cli = types.map(([p, , t]) => `set deviceconfig system deployment-update-schedule ${q(v[p + "Name"])} type ${t} recurring ${schedTail(v, p)}`)
        .concat(types.map(([p]) => `set deviceconfig system deployment-update-schedule ${q(v[p + "Name"])} devices ${members(serials)}`));
      if (!cli.length) cli.push("# Aucune planification : seules les actions opérationnelles (licences, logiciel) sont générées");
      const devs = members(serials);
      const push = [
        v.licRefresh && `request batch license refresh devices ${members(serials)}`,
        ...(v.sw ? ["request batch software check", "request batch software info",
          `request batch software download file PanOS_${v.swPlatform}-${v.swVersion}`,
          v.swMode === "upload" ? `request batch software upload file PanOS_${v.swPlatform}-${v.swVersion} devices ${devs}`
            : `request batch software install file PanOS_${v.swPlatform}-${v.swVersion} devices ${devs} restart yes`] : []),
        "show jobs all",
      ].filter(Boolean);
      const cliRaw = ["configure", ...cli, "commit", "exit", "", "# --- Actions opérationnelles sur Panorama (licences, logiciel) ---", ...push,
        "", "# --- Vérification ---", "show devices all"];
      const notes = [
        { type: "or", title: "Panorama, point de distribution", text: "Panorama télécharge contenus et logiciels une seule fois puis les distribue aux pare-feux : utile pour des pare-feux sans accès Internet direct. « Revert Content » (en bas de Device Deployment > Dynamic Updates) permet de revenir à un contenu précédent sur les pare-feux sélectionnés." },
        { type: "warn", text: "Choisis UNE source de planification : soit les Schedules de Panorama (ici), soit des planifications poussées par template sur les pare-feux — jamais les deux." },
        { type: "warn", text: `Syntaxes « deployment-update-schedule » et « request batch … » : ${VALIDATE}. La WebUI reste la référence.` },
        { type: "or", text: "Toujours mettre Panorama à niveau avant les pare-feux ; un pare-feu ne peut pas être géré par un Panorama de version inférieure." },
      ];
      const slots = types.map(([p]) => schedSlot(v, p)).filter(Boolean);
      if (slots.length !== new Set(slots).size) notes.unshift({ type: "bad", title: "Planifications simultanées", text: "Deux planifications démarrent au même moment : Panorama ne traite qu'un téléchargement à la fois, décale-les (ex. 02:30 et 02:45)." });
      if (v.dtOn && v.dtRec === "weekly") notes.push({ type: "warn", text: "Apps & Threats hebdomadaire = usage lab ; en production suivre les « Best Practices for Applications and Threats Content Updates »." });
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P03 · Template (réseau : profils, interfaces, zones, routage)
     ===================================================================== */
  const PROFILES = {
    "Allow-ping": "ping yes",
    "Allow-management": "https yes ssh yes ping yes snmp yes response-pages yes",
  };
  const parseIfaces = t => rows(t).map(([iface, zone, ip, prof, ...c]) => ({ iface, zone, ip: ip || "", prof: prof || "", comment: c.join(", ") }));

  register({
    id: "p03-template",
    module: "P03",
    title: "Template : interfaces, zones & routage",
    icon: "🧱",
    desc: "Créer un template et y définir la partie réseau commune : profils de gestion d'interface, interfaces (IP fixes ou variables $), zones, virtual router ou logical router et route par défaut.",
    tags: "template network interfaces zones virtual router logical router advanced routing interface management profile variables layer3",
    fields: [
      { id: "template", label: "Nom du template", type: "text", required: true, default: "TPL-Global", validate: objName, group: "Template" },
      { id: "tplDesc", label: "Description", type: "text", default: "Reseau commun - interfaces, zones, routage",
        hint: "Optionnelle mais fortement recommandée : elle indique aux autres admins ce que contient le template." },
      { id: "vsys", label: "Vsys par défaut", type: "text", default: "vsys1", validate: v => /^vsys\d{1,3}$/.test(v) ? null : "Format vsysN (ex. vsys1)" },
      { id: "profs", label: "Créer les profils de gestion d'interface Allow-ping et Allow-management", type: "checkbox", default: true, wide: true, group: "Interface Management Profiles",
        hint: "Allow-ping : Ping. Allow-management : HTTPS, SSH, Ping, SNMP, Response Pages." },
      { id: "ifaces", label: "Interfaces (une par ligne : interface, zone, IP/masque | $variable | dhcp, profil, commentaire)", type: "textarea", required: true, wide: true, group: "Interfaces & zones",
        default: "ethernet1/1, Internet, $Internet-Interface, Allow-ping, Internet interface\nethernet1/2, Users_Net, $User_Net-Interface, Allow-management, User network\nethernet1/3, Extranet, $Extranet-Interface, Allow-management, Extranet interface",
        hint: "Une variable ($…) permet d'utiliser le même template pour tous les pare-feux : la valeur propre à chaque pare-feu est définie dans le template stack (module Variables).",
        validate: t => {
          const r = parseIfaces(t); if (!r.length) return "Au moins une interface";
          const seen = new Set();
          for (const x of r) {
            if (V.iface(x.iface)) return `« ${x.iface} » : ${V.iface(x.iface)}`;
            if (seen.has(x.iface)) return `Interface en double : ${x.iface}`; seen.add(x.iface);
            if (!x.zone || V.name(x.zone)) return `Zone de ${x.iface} : ${x.zone ? V.name(x.zone) : "obligatoire"}`;
            if (!x.ip) return `${x.iface} : adresse obligatoire (IP/masque, $variable ou dhcp)`;
            if (x.ip !== "dhcp" && !x.ip.startsWith("$") && V.cidr(x.ip)) return `${x.iface} : ${V.cidr(x.ip)}`;
            if (x.ip.startsWith("$") && varName(x.ip)) return `${x.iface} : ${varName(x.ip)}`;
            if (x.prof && objName(x.prof)) return `${x.iface} : profil ${objName(x.prof)}`;
          }
          return null;
        } },
      { id: "uidZones", label: "Zones avec User-ID activé (Enable User Identification)", type: "list", default: ["Users_Net", "Extranet"], wide: true },
      { id: "autoVars", label: "Déclarer dans le template les variables $ utilisées (valeur par défaut factice 192.0.2.x/24)", type: "checkbox", default: true, wide: true,
        hint: "Une variable doit avoir une valeur par défaut ; la vraie valeur par pare-feu est saisie dans le stack (module Variables)." },
      { id: "routing", label: "Routage", type: "select", default: "lr", group: "Routage",
        options: [["lr", "Logical router (Advanced Routing Engine)"], ["vr", "Virtual router (moteur historique)"], ["none", "Pas de routage dans ce template"]] },
      { id: "rName", label: "Nom du routeur", type: "text", required: true, default: "LR-1", validate: objName, show: v => v.routing !== "none" },
      { id: "advRouting", label: "Activer Advanced Routing dans le template", type: "checkbox", default: true, show: v => v.routing === "lr",
        hint: "Device > Setup > Management > General Settings > Advanced Routing (redémarrage du pare-feu requis la première fois)." },
      { id: "defRoute", label: "Créer une route par défaut", type: "checkbox", default: true, show: v => v.routing !== "none" },
      { id: "routeName", label: "Nom de la route", type: "text", required: true, default: "Default-Route", validate: objName, show: v => v.routing !== "none" && v.defRoute },
      { id: "defIf", label: "Interface de sortie", type: "text", required: true, default: "ethernet1/1", validate: "iface", show: v => v.routing !== "none" && v.defRoute },
      { id: "defGw", label: "Next hop (IP ou $variable)", type: "text", required: true, default: "203.0.113.1", show: v => v.routing !== "none" && v.defRoute,
        validate: x => x.startsWith("$") ? varName(x) : V.ip(x),
        hint: "Si chaque site a son propre routeur amont, utilise une variable (ex. $FW-Default-GW)." },
    ],
    example: { template: "Global-Settings", tplDesc: "Network - Interfaces, Zones, Logical Router", routeName: "Firewall-Default-Gateway", rName: "LR-1" },
    build(v) {
      const T = TPL(v.template), list = parseIfaces(v.ifaces);
      const zones = {}; list.forEach(x => (zones[x.zone] = zones[x.zone] || []).push(x.iface));
      const vars = [...new Set([...list.map(x => x.ip), v.routing !== "none" && v.defRoute ? v.defGw : ""].filter(x => String(x).startsWith("$")))];
      const usedProfs = [...new Set(list.map(x => x.prof).filter(Boolean))];
      const missingProf = usedProfs.filter(p => !(v.profs && PROFILES[p]));
      const ifaceNames = list.map(x => x.iface);
      const steps = [
        { title: "Créer le template", path: ["Panorama", "Templates"], window: "Template", action: "Bouton « Add » en bas à gauche.",
          fields: [["Name", v.template], ["Description", v.tplDesc], ["Default VSYS", v.vsys]],
          note: "Dès le premier template, les onglets Network et Device apparaissent dans Panorama." },
      ];
      if (v.profs) steps.push({ title: "Profils de gestion d'interface", path: ["Network", "Network Profiles", "Interface Mgmt"],
        action: `Sélecteur Template (en haut) = ${v.template}. Add pour chaque profil.`,
        fields: [["Allow-ping — Network Services", "Ping"], ["Allow-management — Administrative Management Services", "HTTPS, SSH"], ["Allow-management — Network Services", "Ping, SNMP, Response Pages"]] });
      if (vars.length && v.autoVars) steps.push({ title: "Déclarer les variables", path: ["Panorama", "Templates"], window: "Template Variables",
        action: `Ligne ${v.template} → colonne Variables → « Manage… » → Add pour chaque variable (Type IP Netmask).`,
        fields: vars.map((n, i) => [n, n === v.defGw ? `192.0.2.${254}` : `192.0.2.${i + 1}/24`]),
        note: "Valeur par défaut obligatoire (le champ ne peut pas rester vide) ; elle est remplacée par la valeur du stack ou du pare-feu." });
      list.forEach(x => steps.push({ title: `Interface ${x.iface}`, path: ["Network", "Interfaces", "Ethernet"], window: "Ethernet Interface",
        action: `Sélecteur Template = ${v.template}. « Add Interface » (Slot ${x.iface.match(/ethernet(\d+)/) ? x.iface.match(/ethernet(\d+)/)[1] : "1"}) ; onglet IPv4 pour l'adresse, onglet Advanced pour le profil.`,
        fields: [["Interface Name", x.iface], ["Comment", x.comment], ["Interface Type", "Layer3"], ["Security Zone", x.zone],
          ["IPv4", x.ip === "dhcp" ? "DHCP Client" : x.ip], ["Management Profile", x.prof]],
        note: x.ip.startsWith("$") ? "Dans la liste d'adresses IP, choisir la variable (ou « New Variable »)." : null }));
      if (v.routing !== "none") steps.push({ title: v.routing === "lr" ? `Logical router ${v.rName}` : `Virtual router ${v.rName}`,
        path: v.routing === "lr" ? ["Network", "Routing", "Logical Routers"] : ["Network", "Virtual Routers"],
        window: v.routing === "lr" ? "Logical Router" : "Virtual Router",
        action: `Sélecteur Template = ${v.template}. Add → Name, section General : ajouter les interfaces${v.defRoute ? " ; section Static (IPv4) : Add" : ""}.`,
        fields: [["Name", v.rName], ["Interfaces", ifaceNames], ...(v.defRoute ? [["Static Route — Name", v.routeName], ["Destination", "0.0.0.0/0"], ["Interface", v.defIf], ["Next Hop", "IP Address"], ["Next Hop IP", v.defGw]] : [])],
        note: v.routing === "lr" ? "Les logical routers n'apparaissent que si Advanced Routing est activé dans le template (Device > Setup > Management)." : null });
      Object.entries(zones).forEach(([z, ifs]) => steps.push({ title: `Zone ${z}`, path: ["Network", "Zones"], window: "Zone",
        action: `Sélecteur Template = ${v.template}. Add.`, fields: [["Name", z], ["Type", "Layer3"], ["Interfaces", ifs], ["Enable User Identification", v.uidZones.includes(z)]] }));

      const cli = [
        `set template ${q(v.template)} description ${q(ascii(v.tplDesc))}`,
        `set template ${q(v.template)} settings default-vsys ${v.vsys}`,
        ...(v.profs ? Object.entries(PROFILES).map(([n, s]) => `${T} network profiles interface-management-profile ${n} ${s}`) : []),
        ...(v.autoVars ? vars.map((n, i) => `set template ${q(v.template)} variable ${n} type ip-netmask ${n === v.defGw ? "192.0.2.254" : `192.0.2.${i + 1}/24`}`) : []),
      ];
      list.forEach(x => {
        const sub = x.iface.includes(".");
        const parent = x.iface.split(".")[0];
        const node = sub ? `${T} network interface ethernet ${parent} layer3 units ${x.iface}` : `${T} network interface ethernet ${x.iface} layer3`;
        if (sub) cli.push(`${node} tag ${x.iface.split(".")[1]}`);
        cli.push(x.ip === "dhcp" ? `${node} dhcp-client enable yes` : `${node} ip ${x.ip}`);
        if (x.prof) cli.push(`${node} interface-management-profile ${q(x.prof)}`);
        if (x.comment) cli.push(`${node.replace(/ layer3$/, "")} comment ${q(ascii(x.comment))}`);
      });
      cli.push(`${T} vsys ${v.vsys} import network interface ${members(ifaceNames)}`);
      Object.entries(zones).forEach(([z, ifs]) => {
        cli.push(`${T} vsys ${v.vsys} zone ${q(z)} network layer3 ${members(ifs)}`);
        if (v.uidZones.includes(z)) cli.push(`${T} vsys ${v.vsys} zone ${q(z)} enable-user-identification yes`);
      });
      if (v.routing === "lr") {
        if (v.advRouting) cli.push(`${T} deviceconfig system advance-routing yes`);
        cli.push(`${T} network logical-router ${q(v.rName)} vrf default interface ${members(ifaceNames)}`);
        if (v.defRoute) cli.push(`${T} network logical-router ${q(v.rName)} vrf default routing-table ip static-route ${q(v.routeName)} destination 0.0.0.0/0 interface ${v.defIf} nexthop ip-address ${v.defGw}`);
      } else if (v.routing === "vr") {
        cli.push(`${T} network virtual-router ${q(v.rName)} interface ${members(ifaceNames)}`);
        if (v.defRoute) cli.push(`${T} network virtual-router ${q(v.rName)} routing-table ip static-route ${q(v.routeName)} destination 0.0.0.0/0 interface ${v.defIf} nexthop ip-address ${v.defGw}`);
      }

      const notes = [
        { type: "or", title: "Un template seul ne s'applique pas", text: "Un pare-feu est rattaché à un template stack (depuis Panorama 9.0), jamais directement à un template : ajoute ce template à un stack (module Template stack) puis Push to Devices." },
        { type: "warn", title: "Sélecteur Template", text: "Dans les onglets Network et Device, vérifie TOUJOURS le menu déroulant Template en haut avant d'ajouter un élément : c'est l'erreur la plus fréquente (objet créé dans le mauvais template)." },
        { type: "or", text: "Ne définis dans un template que ce qui doit être commun : tout réglage non défini garde la valeur locale du pare-feu. Les noms de zones doivent être identiques sur tous les pare-feux qui partagent des règles." },
      ];
      if (missingProf.length) notes.push({ type: "warn", text: `Profil(s) référencé(s) mais non créé(s) ici : ${missingProf.join(", ")} — ils doivent exister dans le template (ou un template du même stack).` });
      if (vars.length && !v.autoVars) notes.push({ type: "warn", text: `Variables utilisées : ${vars.join(", ")} — elles doivent être déclarées (module Variables) avant le commit, sinon erreur de validation.` });
      if (v.defRoute && v.routing !== "none" && !ifaceNames.includes(v.defIf)) notes.push({ type: "bad", text: `L'interface de sortie ${v.defIf} n'est pas dans la liste des interfaces du template.` });
      if (v.routing === "lr" && v.advRouting) notes.push({ type: "warn", text: `Activation d'Advanced Routing (« deviceconfig system advance-routing yes ») : ${VALIDATE} ; elle impose un redémarrage du pare-feu au premier push.` });
      return { steps, cli, notes };
    },
  });

  /* =====================================================================
     P03 · Template stack
     ===================================================================== */
  register({
    id: "p03-stack",
    module: "P03",
    title: "Template stack",
    icon: "🗂️",
    desc: "Combiner plusieurs templates dans un ordre de priorité, y rattacher les pare-feux et pousser la configuration réseau/device.",
    tags: "template stack pile ordre priorité héritage devices push force template values",
    fields: [
      { id: "stack", label: "Nom du template stack", type: "text", required: true, default: "TS-Paris", validate: objName, group: "Template stack" },
      { id: "stackDesc", label: "Description", type: "text", default: "Pare-feux du site de Paris" },
      { id: "template", label: "Template n°1 (priorité la plus haute)", type: "text", required: true, default: "TPL-Global", validate: objName, group: "Templates (ordre = priorité)",
        hint: "En cas de valeur définie dans plusieurs templates, c'est le template le plus HAUT dans la pile qui l'emporte." },
      { id: "extraTpl", label: "Templates suivants, par priorité décroissante (séparés par des virgules)", type: "list", default: ["TPL-Paris"], wide: true,
        validate: (a, v) => { for (const t of a) if (objName(t)) return `« ${t} » : ${objName(t)}`;
          const all = [v.template, ...a]; if (all.length > 8) return "8 templates maximum par stack";
          const d = all.find((t, i) => all.indexOf(t) !== i); return d ? `Template en double : ${d}` : null; } },
      { id: "vsys", label: "Vsys par défaut", type: "text", default: "vsys1", validate: x => /^vsys\d{1,3}$/.test(x) ? null : "Format vsysN" },
      { id: "fwSerial", label: "Pare-feu à rattacher (série)", type: "text", required: true, default: "007951000123456", validate: serial, group: "Pare-feux" },
      { id: "extraSerials", label: "Autres pare-feux (séries)", type: "list", default: [], wide: true, validate: (a, v) => serialList(a, v, v.fwSerial) },
      { id: "oldStack", label: "Stack actuel à quitter (optionnel)", type: "text", default: "", validate: objName,
        hint: "Un pare-feu n'appartient qu'à un seul stack : s'il est déjà rattaché ailleurs, il doit d'abord en être retiré." },
      { id: "doPush", label: "Pousser le stack après le commit", type: "checkbox", default: true, group: "Push", wide: true },
      { id: "force", label: "Force Template Values", type: "checkbox", default: false, show: v => v.doPush,
        hint: "Écrase les valeurs surchargées localement sur les pare-feux. Utilisé dans les labs ; en production, contrôle d'abord les surcharges." },
    ],
    example: { stack: "US-Stack", stackDesc: "Contains settings for firewalls in US", template: "Global-Settings", extraTpl: ["Region-Americas"], force: true },
    build(v) {
      const tpls = [v.template, ...v.extraTpl], serials = [v.fwSerial, ...v.extraSerials];
      const steps = [
        { title: "Créer le template stack", path: ["Panorama", "Templates"], window: "Template Stack",
          action: "Bouton « Add Stack » en bas. Section Templates : Add pour chaque template, puis Move Up / Move Down pour obtenir l'ordre ci-dessous. À droite : cocher les pare-feux.",
          fields: [["Name", v.stack], ["Description", v.stackDesc], ["Default VSYS", v.vsys], ["Templates (haut → bas)", tpls.map((t, i) => `${i + 1}. ${t}`).join("  ")], ["Devices", serials]],
          note: "Seuls les pare-feux non rattachés à un autre stack apparaissent dans la liste." },
        { title: "Contrôler", path: ["Panorama", "Templates"],
          action: "La colonne Type indique Template-Stack, la colonne Stack la liste des templates, la colonne Devices les pare-feux rattachés.", fields: [] },
      ];

      const cli = [
        `set template-stack ${q(v.stack)} description ${q(ascii(v.stackDesc))}`,
        `set template-stack ${q(v.stack)} templates ${members(tpls)}`,
        `set template-stack ${q(v.stack)} settings default-vsys ${v.vsys}`,
        ...(v.oldStack ? serials.map(s => `delete template-stack ${q(v.oldStack)} devices ${s}`) : []),
        ...serials.map(s => `set template-stack ${q(v.stack)} devices ${s}`),
      ];
      const push = v.doPush ? [`commit-all template-stack name ${q(v.stack)}${v.force ? " force-template-values yes" : ""}`, "show jobs all"] : [];
      const notes = [
        { type: "or", title: "Ordre = priorité", text: `Ici, une valeur définie dans ${tpls[0]} l'emporte sur la même valeur dans ${tpls[tpls.length - 1]}. Bonne pratique du cours : un template global commun à tous les stacks + des templates régionaux/sites (8 templates max par stack, un même template réutilisable dans plusieurs stacks).` },
        { type: "or", text: "Surcharges locales : un administrateur peut modifier sur le pare-feu une valeur poussée par template (engrenage vert → vert + orange). Force Template Values les annule au prochain push." },
        PUSH_NOTE,
        v.doPush && { type: "ok", title: "Après le push", text: "Se déconnecter puis se reconnecter à la WebUI du pare-feu : les éléments reçus portent une petite icône d'engrenage vert (survol = template stack d'origine)." },
      ].filter(Boolean);
      if (v.force) notes.push({ type: "warn", title: "Force Template Values", text: `Dans Push to Devices > Edit Selections > onglet Templates, cocher « Force Template Values » (confirmer Yes) : écrase toute valeur surchargée localement sur les pare-feux. Option CLI « force-template-values » de commit-all : ${VALIDATE}.` });
      if (tpls.length === 1) notes.push({ type: "or", text: "Un seul template : pense à séparer réglages communs et réglages propres au site pour réutiliser le template commun dans d'autres stacks." });
      return { steps, cli, push, notes, verify: ["show template-stack", "show devices all | match \"hostname|template\""] };
    },
  });

  /* =====================================================================
     P03 · Variables de template ($)
     ===================================================================== */
  const VARTYPES = [["ip-netmask", "IP Netmask"], ["ip-range", "IP Range"], ["fqdn", "FQDN"], ["group-id", "Group ID"], ["device-priority", "Device Priority"],
    ["device-id", "Device ID"], ["interface", "Interface"], ["as-number", "AS Number"], ["qos-profile", "QoS Profile"], ["egress-max", "Egress Max"], ["link-tag", "Link Tag"]];
  const VTYPE = Object.fromEntries(VARTYPES);
  const varVal = (type, val) => {
    switch (type) {
      case "ip-netmask": return PAN.ip.validCidr(val) ? null : "IP ou IP/masque attendu";
      case "ip-range": { const [a, b] = String(val).split("-"); return ipOk(a || "") && ipOk(b || "") && toInt(a) <= toInt(b) ? null : "Plage IP attendue (ex. 10.0.0.10-10.0.0.20)"; }
      case "fqdn": return V.fqdn(val);
      case "interface": return V.iface(val);
      case "group-id": case "device-priority": case "device-id": case "as-number": case "egress-max": return /^\d+$/.test(val) ? null : "Valeur numérique attendue";
      default: return String(val).length ? null : "Valeur obligatoire";
    }
  };

  register({
    id: "p03-variables",
    module: "P03",
    title: "Variables de template ($)",
    icon: "💲",
    desc: "Déclarer des variables (IP, plages, FQDN, interfaces…) dans un template ou un stack, puis leur valeur propre à chaque pare-feu (CLI ou import CSV).",
    tags: "variables template stack $ csv import export device key-value table override ip netmask fqdn",
    fields: [
      { id: "scope", label: "Déclarer les variables dans", type: "select", default: "template", group: "Portée",
        options: [["template", "Un template"], ["stack", "Le template stack"]],
        hint: "Une variable de stack peut redéfinir la valeur d'une variable de template. Les valeurs par pare-feu se règlent toujours au niveau du stack." },
      { id: "template", label: "Template", type: "text", required: true, default: "TPL-Global", validate: objName, show: v => v.scope === "template" },
      { id: "stack", label: "Template stack (valeurs par pare-feu)", type: "text", required: true, default: "TS-Paris", validate: objName },
      { id: "vars", label: "Variables (une par ligne : $nom, type, valeur par défaut, description)", type: "textarea", required: true, wide: true, group: "Variables",
        default: "$Internet-Interface, ip-netmask, 1.1.1.1/24, Internet interface\n$User_Net-Interface, ip-netmask, 2.2.2.2/24, User network interface\n$Extranet-Interface, ip-netmask, 3.3.3.3/24, Extranet interface",
        hint: `Types : ${VARTYPES.map(t => t[0]).join(", ")}. Les noms sont sensibles à la casse.`,
        validate: t => {
          const r = rows(t); if (!r.length) return "Au moins une variable";
          const seen = new Set();
          for (const [n, type, val] of r) {
            if (varName(n)) return `« ${n} » : ${varName(n)}`;
            if (seen.has(n)) return `Variable en double : ${n}`; seen.add(n);
            if (!VTYPE[type]) return `${n} : type inconnu « ${type || ""} »`;
            if (!val) return `${n} : valeur par défaut obligatoire (Panorama refuse une variable vide)`;
            const e = varVal(type, val); if (e) return `${n} : ${e}`;
          }
          return null;
        } },
      { id: "devVals", label: "Valeurs par pare-feu (une par ligne : série, $nom, valeur)", type: "textarea", wide: true, group: "Valeurs par pare-feu",
        default: "007951000123456, $Internet-Interface, 203.0.113.20/24\n007951000123456, $User_Net-Interface, 192.168.1.1/24\n007951000123456, $Extranet-Interface, 192.168.50.1/24",
        hint: "Laisse vide pour garder la valeur par défaut partout. Équivaut à l'import du fichier CSV de variables dans le stack.",
        validate: (t, v) => {
          const types = Object.fromEntries(rows(v.vars).map(([n, type]) => [n, type]));
          for (const [s, n, val] of rows(t)) {
            if (serial(s)) return `« ${s} » : ${serial(s)}`;
            if (varName(n || "")) return `« ${n || ""} » : ${varName(n || "")}`;
            if (!val) return `${s} / ${n} : valeur manquante`;
            if (types[n]) { const e = varVal(types[n], val); if (e) return `${s} / ${n} : ${e}`; }
          }
          return null;
        } },
    ],
    build(v) {
      const vars = rows(v.vars).map(([n, type, val, ...d]) => ({ n, type, val, desc: d.join(", ") }));
      const types = Object.fromEntries(vars.map(x => [x.n, x.type]));
      const dv = rows(v.devVals).map(([s, n, val]) => ({ s, n, val }));
      const owner = v.scope === "template" ? `template ${q(v.template)}` : `template-stack ${q(v.stack)}`;
      const steps = [
        { title: "Déclarer les variables", path: ["Panorama", "Templates"], window: "Template Variables",
          action: `Ligne ${v.scope === "template" ? v.template : v.stack} → colonne Variables → « Manage… » → Add pour chaque variable.${v.scope === "template" ? " (Effacer d'éventuels filtres avec Clear Filters.)" : ""}`,
          fields: vars.map(x => [x.n, `${VTYPE[x.type]} = ${x.val}${x.desc ? " — " + x.desc : ""}`]) },
        { title: "Utiliser les variables", path: ["Network / Device"],
          action: "Dans les champs compatibles (adresse IP d'interface, next hop, adresse de serveur…), sélectionner la variable au lieu d'une valeur fixe (ou « New Variable » directement depuis le champ).", fields: [] },
      ];
      if (dv.length) {
        const bySerial = {}; dv.forEach(x => (bySerial[x.s] = bySerial[x.s] || []).push(x));
        steps.push(
          { title: "Valeurs par pare-feu — méthode CSV", path: ["Panorama", "Templates"], window: "Import Variables",
            action: `Cocher ${v.stack} → bas de page « Variable CSV » → Export (gabarit pré-rempli avec les pare-feux du stack) → compléter → Variable CSV → Import → Browse → OK.`,
            fields: Object.entries(bySerial).map(([s, l]) => [s, l.map(x => `${x.n}=${x.val}`).join("  ")]),
            note: "Pas de ligne vide à la fin du fichier. Alternative sans fichier : bloc CLI (valeurs par pare-feu dans le stack)." },
          { title: "Contrôler les valeurs", path: ["Panorama", "Templates"], window: "Device Key-Value Table",
            action: `Ligne ${v.stack} → colonne « Device Key-Value Table » → View : une colonne par pare-feu, une ligne par variable.`, fields: [] },
        );
      }
      const cli = [];
      vars.forEach(x => {
        cli.push(`set ${owner} variable ${x.n} type ${x.type} ${x.val}`);
        if (x.desc) cli.push(`set ${owner} variable ${x.n} description ${q(ascii(x.desc))}`);
      });
      dv.forEach(x => cli.push(`set template-stack ${q(v.stack)} devices ${x.s} variable ${x.n} type ${types[x.n] || "ip-netmask"} ${x.val}`));
      const table = dv.length ? (() => {
        const ss = [...new Set(dv.map(x => x.s))], ns = [...new Set(dv.map(x => x.n))];
        const cell = (s, n) => { const f = dv.find(x => x.s === s && x.n === n); return f ? f.val : "(défaut)"; };
        return `<table style="border-collapse:collapse;margin-top:6px"><tr><th style="text-align:left;padding:2px 8px">Variable</th>${ss.map(s => `<th style="padding:2px 8px">${esc(s)}</th>`).join("")}</tr>${ns.map(n => `<tr><td style="padding:2px 8px"><code>${esc(n)}</code></td>${ss.map(s => `<td style="padding:2px 8px"><code>${esc(cell(s, n))}</code></td>`).join("")}</tr>`).join("")}</table>`;
      })() : "";
      const unknown = [...new Set(dv.filter(x => !types[x.n]).map(x => x.n))];
      const notes = [
        { type: "or", title: "Pourquoi des variables ?", text: "Sans variable, 200 pare-feux avec une IP interne différente = 200 templates. Avec une variable $Inside_IP, un seul template et une valeur par pare-feu. Limites : 4 096 variables par template, 8 192 par stack." },
        dv.length && { type: "ok", title: "Valeurs par pare-feu", html: table },
        unknown.length && { type: "warn", text: `Variable(s) non déclarée(s) dans ce module : ${unknown.join(", ")} — elles doivent exister dans un template du stack (type supposé ip-netmask dans la CLI).` },
        { type: "or", text: "Une valeur peut encore être surchargée localement sur le pare-feu. Le pare-feu reçoit toujours une valeur résolue : la variable n'existe que dans Panorama." },
        { type: "warn", text: `Syntaxe « set template-stack … devices <série> variable … » (valeur par pare-feu) : ${VALIDATE}. Le format exact du CSV dépend de la version : pars toujours de l'Export.` },
        PUSH_NOTE,
      ].filter(Boolean);
      return { steps, cli, notes, push: [`commit-all template-stack name ${q(v.stack)}`, "show jobs all"] };
    },
  });

  /* =====================================================================
     P03 · Paramètres Device via template (DNS, NTP, Panorama, admins, logs)
     ===================================================================== */
  const COLORS = [["red", "Red"], ["orange", "Orange"], ["yellow", "Yellow"], ["green", "Green"], ["blue", "Blue"], ["purple", "Purple"], ["gray", "Gray"]];

  register({
    id: "p03-device",
    module: "P03",
    title: "Paramètres Device via template",
    icon: "⚙️",
    desc: "Pousser les réglages Device communs : domaine, bannières, fuseau, DNS, NTP, serveurs Panorama, passerelle et Permitted IP du MGT, administrateur de secours, envoi des logs System/Config, profils syslog et e-mail.",
    tags: "template device setup management dns ntp banner header panorama servers permitted ip administrator log settings system configuration syslog email server profile",
    fields: [
      { id: "template", label: "Template", type: "text", required: true, default: "TPL-Global", validate: objName, group: "Template" },
      { id: "stack", label: "Template stack à pousser ensuite (optionnel)", type: "text", default: "TS-Paris", validate: objName },

      { id: "sGen", label: "Paramètres généraux (domaine, bannière, fuseau)", type: "checkbox", default: true, group: "General Settings", wide: true },
      { id: "domain", label: "Domaine", type: "text", validate: "fqdn", default: "corp.local", show: v => v.sGen },
      { id: "banner", label: "Login Banner", type: "textarea", default: "Acces reserve au personnel autorise.", show: v => v.sGen },
      { id: "timezone", label: "Fuseau horaire", type: "select", default: "Europe/Paris", options: TZ, show: v => v.sGen },

      { id: "sSvc", label: "DNS & NTP", type: "checkbox", default: true, group: "Services", wide: true },
      { id: "dns1", label: "DNS primaire", type: "ip", required: true, default: "1.1.1.1", show: v => v.sSvc },
      { id: "dns2", label: "DNS secondaire", type: "ip", default: "8.8.8.8", show: v => v.sSvc },
      { id: "ntp1", label: "NTP primaire", type: "text", validate: "host", default: "0.pool.ntp.org", show: v => v.sSvc },
      { id: "ntp2", label: "NTP secondaire", type: "text", validate: "host", default: "1.pool.ntp.org", show: v => v.sSvc },

      { id: "sPano", label: "Serveurs Panorama (Panorama Settings)", type: "checkbox", default: true, group: "Panorama Settings", wide: true,
        hint: "Garantit que tous les pare-feux gardent la bonne IP de Panorama (et du pair HA)." },
      { id: "panoIp", label: "IP de management Panorama", type: "ipcidr", required: true, default: "192.168.1.252/24", show: v => v.sPano },
      { id: "panoIp2", label: "IP du Panorama pair HA (optionnel)", type: "ipcidr", default: "", show: v => v.sPano },

      { id: "sMgmt", label: "Interface de management des pare-feux (passerelle, Permitted IP)", type: "checkbox", default: false, group: "Management Interface", wide: true,
        hint: "L'adresse IP MGT reste propre à chaque pare-feu : seuls les éléments communs sont mis dans le template." },
      { id: "fwGw", label: "Passerelle par défaut du MGT", type: "text", default: "192.168.1.1", show: v => v.sMgmt,
        validate: x => x.startsWith("$") ? varName(x) : V.ip(x), hint: "IP ou variable $ si la passerelle diffère selon les sites." },
      { id: "permitted", label: "Permitted IP Addresses", type: "list", validate: "ipcidr", default: ["192.168.0.0/16"], show: v => v.sMgmt, wide: true },
      { id: "permDesc", label: "Description", type: "text", default: "Management network hosts", show: v => v.sMgmt && v.permitted.length > 0 },

      { id: "sBanner", label: "Bandeau d'en-tête de la WebUI (Banners and Messages)", type: "checkbox", default: false, group: "Banners and Messages", wide: true,
        hint: "Un bandeau coloré par région évite de confondre les WebUI (ex. rouge = Amériques, orange = Europe)." },
      { id: "hdrBanner", label: "Header Banner", type: "text", required: true, default: "Pare-feu site de Paris", show: v => v.sBanner },
      { id: "hdrColor", label: "Header Color", type: "select", default: "red", options: COLORS, show: v => v.sBanner },

      { id: "sAdmin", label: "Administrateur local de secours", type: "checkbox", default: true, group: "Administrateur", wide: true,
        hint: "Compte poussé sur tous les pare-feux : accès de dernier recours si les autres comptes/l'authentification externe sont indisponibles." },
      { id: "adminUser", label: "Nom", type: "text", required: true, default: "globaladmin", validate: objName, show: v => v.sAdmin },
      { id: "admRole", label: "Rôle dynamique", type: "select", default: "superuser", show: v => v.sAdmin,
        options: [["superuser", "Superuser"], ["superreader", "Superuser (read-only)"], ["deviceadmin", "Device administrator"], ["devicereader", "Device administrator (read-only)"]] },

      { id: "sLogs", label: "Envoyer les logs System et Configuration à Panorama", type: "checkbox", default: true, group: "Log Settings", wide: true,
        hint: "Les logs Traffic/Threat/URL se transfèrent via un Log Forwarding Profile dans les règles (module P05)." },

      { id: "sSyslog", label: "Profil serveur Syslog", type: "checkbox", default: false, group: "Server Profiles", wide: true },
      { id: "syslogProf", label: "Nom du profil", type: "text", required: true, default: "Syslog_Servers", validate: objName, show: v => v.sSyslog },
      { id: "syslogName", label: "Nom du serveur", type: "text", required: true, default: "Syslog-1", validate: objName, show: v => v.sSyslog },
      { id: "syslogIp", label: "Adresse du serveur syslog", type: "text", required: true, default: "192.168.50.55", show: v => v.sSyslog,
        validate: x => x.startsWith("$") ? varName(x) : V.host(x) },
      { id: "syslogTr", label: "Transport", type: "select", default: "UDP", options: [["UDP"], ["TCP"], ["SSL"]], show: v => v.sSyslog },
      { id: "syslogPort", label: "Port", type: "port", required: true, default: "514", show: v => v.sSyslog },
      { id: "sEmail", label: "Profil serveur e-mail", type: "checkbox", default: false, wide: true },
      { id: "mailProf", label: "Nom du profil", type: "text", required: true, default: "Email_Servers", validate: objName, show: v => v.sEmail },
      { id: "mailName", label: "Nom du serveur", type: "text", required: true, default: "Mail-1", validate: objName, show: v => v.sEmail },
      { id: "mailDisplay", label: "Email Display Name", type: "text", default: "Pare-feu Paris", show: v => v.sEmail },
      { id: "mailFrom", label: "From", type: "text", required: true, validate: "email", default: "fw-paris@corp.local", show: v => v.sEmail },
      { id: "mailTo", label: "To", type: "text", required: true, validate: "email", default: "secops@corp.local", show: v => v.sEmail },
      { id: "mailGw", label: "Email Gateway", type: "text", required: true, validate: "host", default: "192.168.50.150", show: v => v.sEmail },
    ],
    example: { template: "Global-Settings", stack: "US-Stack", domain: "panw.lab", banner: "Authorized access only", timezone: "UTC", sSvc: false, panoIp: "192.168.1.252/24",
      sMgmt: true, fwGw: "192.168.1.1", permitted: ["192.168.0.0/16"], sAdmin: true, adminUser: "globaladmin", sLogs: true },
    build(v) {
      const T = TPL(v.template), sh = `set template ${q(v.template)} config shared`;
      const sel = `Sélecteur Template (en haut) = ${v.template}.`;
      const steps = [], cli = [];
      if (v.sGen) {
        steps.push({ title: "General Settings", path: ["Device", "Setup", "Management"], window: "General Settings", action: `${sel} Cadre General Settings → ⚙.`,
          fields: [["Domain", v.domain], ["Login Banner", v.banner], ["Time Zone", v.timezone]], note: "Ne pas renseigner le Hostname ici : il est propre à chaque pare-feu." });
        cli.push(v.domain && `${T} deviceconfig system domain ${q(v.domain)}`, v.banner && `${T} deviceconfig system login-banner ${q(ascii(v.banner))}`, `${T} deviceconfig system timezone ${v.timezone}`);
      }
      if (v.sPano) {
        steps.push({ title: "Panorama Settings", path: ["Device", "Setup", "Management"], window: "Panorama Settings", action: `${sel} Cadre Panorama Settings → ⚙.`,
          fields: [["Managed By", "Local Panorama"], ["Panorama Servers", [bare(v.panoIp), v.panoIp2 && bare(v.panoIp2)].filter(Boolean)]] });
        cli.push(`${T} deviceconfig system panorama local-panorama panorama-server ${bare(v.panoIp)}`, v.panoIp2 && `${T} deviceconfig system panorama local-panorama panorama-server-2 ${bare(v.panoIp2)}`);
      }
      if (v.sBanner) {
        steps.push({ title: "Banners and Messages", path: ["Device", "Setup", "Management"], window: "Banners and Messages", action: `${sel} Cadre Banners and Messages (colonne de droite, en bas) → ⚙.`,
          fields: [["Message of the Day", "☐ décoché"], ["Header Banner", v.hdrBanner], ["Header Color", COLORS.find(c => c[0] === v.hdrColor)[1]]] });
        cli.push(`${T} deviceconfig system motd-and-banner banner-header ${q(ascii(v.hdrBanner))}`, `# Header Color « ${COLORS.find(c => c[0] === v.hdrColor)[1]} » : à choisir dans la WebUI (codes couleur CLI : ${VALIDATE})`);
      }
      if (v.sSvc) {
        steps.push({ title: "DNS", path: ["Device", "Setup", "Services"], window: "Services", action: `${sel} Cadre Services → ⚙.`, fields: [["Primary DNS Server", v.dns1], ["Secondary DNS Server", v.dns2]] });
        if (v.ntp1 || v.ntp2) steps.push({ title: "NTP", path: ["Device", "Setup", "Services"], tab: "NTP", window: "Services", action: "Onglet NTP.", fields: [["Primary NTP Server Address", v.ntp1], ["Secondary NTP Server Address", v.ntp2]] });
        cli.push(`${T} deviceconfig system dns-setting servers primary ${v.dns1}`, v.dns2 && `${T} deviceconfig system dns-setting servers secondary ${v.dns2}`,
          v.ntp1 && `${T} deviceconfig system ntp-servers primary-ntp-server ntp-server-address ${v.ntp1}`, v.ntp2 && `${T} deviceconfig system ntp-servers secondary-ntp-server ntp-server-address ${v.ntp2}`);
      }
      if (v.sMgmt) {
        steps.push({ title: "Interface de management", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings", action: `${sel} Cliquer « Management ».`,
          fields: [["Default Gateway", v.fwGw], ...v.permitted.map(c => ["Permitted IP Address", c]), ["Description", v.permitted.length && v.permDesc]],
          warn: "La nouvelle passerelle doit router le trafic de management des pare-feux (dans le lab : via une interface du pare-feu de Chicago) — sinon perte de connexion avec Panorama, rattrapée par l'automated commit recovery." });
        cli.push(v.fwGw && `${T} deviceconfig system default-gateway ${v.fwGw}`, ...v.permitted.map(c => `${T} deviceconfig system permitted-ip ${c}${v.permDesc ? " description " + q(ascii(v.permDesc)) : ""}`));
      }
      if (v.sLogs) {
        steps.push({ title: "Logs System et Configuration vers Panorama", path: ["Device", "Log Settings"], window: "Log Settings - System / Configuration",
          action: `${sel} Section System → Add, puis section Configuration → Add.`,
          fields: [["System — Name", "Firewall_System_Logs_to_Panorama"], ["Configuration — Name", "Firewall_Configuration_Logs_to_Panorama"], ["Filter", "All Logs"], ["Forward Method", "Panorama/Cloud Logging ✓"]] });
        cli.push(`${sh} log-settings system match-list Firewall_System_Logs_to_Panorama filter "All Logs" send-to-panorama yes`,
          `${sh} log-settings system match-list Firewall_System_Logs_to_Panorama description "Sends all firewall system log entries to Panorama"`,
          `${sh} log-settings config match-list Firewall_Configuration_Logs_to_Panorama filter "All Logs" send-to-panorama yes`,
          `${sh} log-settings config match-list Firewall_Configuration_Logs_to_Panorama description "Sends all firewall configuration log entries to Panorama"`);
      }
      if (v.sAdmin) {
        steps.push({ title: `Administrateur ${v.adminUser}`, path: ["Device", "Administrators"], window: "Administrator", action: `${sel} Add.`,
          fields: [["Name", v.adminUser], ["Administrator Type", "Dynamic"], ["Role", { superuser: "Superuser", superreader: "Superuser (read-only)", deviceadmin: "Device administrator", devicereader: "Device administrator (read-only)" }[v.admRole]], ["Password / Confirm Password", MASKED]] });
        cli.push(`set template ${q(v.template)} config mgt-config users ${q(v.adminUser)} permissions role-based ${v.admRole === "deviceadmin" || v.admRole === "devicereader" ? `${v.admRole} localhost.localdomain` : `${v.admRole} yes`}`,
          "# Ligne interactive : la coller SEULE puis saisir le mot de passe deux fois",
          `set template ${q(v.template)} config mgt-config users ${q(v.adminUser)} password`);
      }
      if (v.sSyslog) {
        steps.push({ title: "Profil serveur Syslog", path: ["Device", "Server Profiles", "Syslog"], window: "Syslog Server Profile", action: `${sel} Add (Location : Shared), onglet Servers → Add.`,
          fields: [["Name", v.syslogProf], ["Server — Name", v.syslogName], ["Syslog Server", v.syslogIp], ["Transport", v.syslogTr], ["Port", v.syslogPort], ["Format", "BSD"], ["Facility", "LOG_USER"]] });
        cli.push(`${sh} log-settings syslog ${q(v.syslogProf)} server ${q(v.syslogName)} server ${v.syslogIp} transport ${v.syslogTr} port ${v.syslogPort} format BSD facility LOG_USER`);
      }
      if (v.sEmail) {
        steps.push({ title: "Profil serveur e-mail", path: ["Device", "Server Profiles", "Email"], window: "Email Server Profile", action: `${sel} Add, onglet Servers → Add. (Ne pas tester tant que le routage n'est pas en place.)`,
          fields: [["Name", v.mailProf], ["Server — Name", v.mailName], ["Email Display Name", v.mailDisplay], ["From", v.mailFrom], ["To", v.mailTo], ["Email Gateway", v.mailGw]] });
        cli.push(`${sh} log-settings email ${q(v.mailProf)} server ${q(v.mailName)} display-name ${q(ascii(v.mailDisplay))} from ${v.mailFrom} to ${v.mailTo} gateway ${v.mailGw}`);
      }
      const cleaned = cli.filter(Boolean);
      if (!cleaned.length) cleaned.push("# Aucune section cochée");
      const notes = [
        { type: "or", title: "Sélecteur Template", text: "Dans l'onglet Device de Panorama, contrôle le menu Template en haut de page avant chaque modification." },
        { type: "or", text: "Sur le pare-feu, chaque valeur reçue porte une icône d'engrenage vert ; un admin local peut la surcharger (engrenage vert + orange), annulée au push suivant si Force Template Values est coché." },
        v.sAdmin && { type: "warn", title: "Commande interactive", text: "« … mgt-config users … password » demande le mot de passe au clavier : colle-la seule. Mot de passe fort et coffre-fort obligatoires pour ce compte de secours." },
        (v.sSyslog || v.sEmail) && { type: "or", text: "Pour des profils différents par région (ex. US-Syslog-1 / EU-Syslog-1), crée un template régional (Panorama > Templates > Clone) plutôt que de dupliquer tout le template global, ou utilise une variable $ pour l'adresse du serveur." },
        v.sBanner && { type: "warn", text: `Chemin CLI « motd-and-banner banner-header » : ${VALIDATE}.` },
        v.sLogs && { type: "warn", text: `Syntaxe « log-settings system/config match-list … send-to-panorama » : ${VALIDATE}.` },
        v.stack && PUSH_NOTE,
      ].filter(Boolean);
      return { steps, cli: cleaned, notes, push: v.stack ? [`commit-all template-stack name ${q(v.stack)}`, "show jobs all"] : [] };
    },
  });
})();
