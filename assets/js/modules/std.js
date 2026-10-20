/* Déploiement standard client : configuration de base complète d'un pare-feu en un seul formulaire */
(function () {
  const { register, q, members } = PAN.cfg;
  const ip = PAN.ip;

  /* ---------- helpers réseau ---------- */
  const toIp = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const maskInt = m => (m === 0 ? 0 : (~0 << (32 - m)) >>> 0);
  const split = c => { const [a, m] = String(c).split("/"); return { a, m: +m }; };
  const netOf = c => { const { a, m } = split(c); return toIp((ip.toInt(a) & maskInt(m)) >>> 0) + "/" + m; };
  const maskStr = m => toIp(maskInt(m));
  const inNet = (addr, c) => { const { a, m } = split(c); return ((ip.toInt(addr) & maskInt(m)) >>> 0) === ((ip.toInt(a) & maskInt(m)) >>> 0); };
  const overlap = (c1, c2) => { const x = split(c1), y = split(c2), m = Math.min(x.m, y.m);
    return ((ip.toInt(x.a) & maskInt(m)) >>> 0) === ((ip.toInt(y.a) & maskInt(m)) >>> 0); };
  const cidrOk = c => PAN.cfg.V.cidr(c) === null;
  // texte libre côté CLI : sans accents pour éviter tout souci d'encodage en SSH
  const ascii = t => String(t).normalize("NFD").replace(/[\u0300-\u036f]/g, "");

  register({
    id: "std-baseline",
    module: "STD",
    title: "Configuration de base d'un client",
    icon: "🚀",
    desc: "Un seul formulaire pour toute la config initiale : système, management, interfaces, zones, routage, NAT sortant, publication de serveur, règles de sécurité, profils et mises à jour.",
    tags: "standard client baseline déploiement initial complet installation",
    fields: [
      /* --- Client & système --- */
      { id: "client", label: "Nom du client", type: "text", default: "ACME", placeholder: "ACME", group: "Client & système", hint: "Utilisé dans les descriptions et la bannière." },
      { id: "hostname", label: "Hostname", type: "text", required: true, validate: "hostname", default: "PA-FW-01" },
      { id: "domain", label: "Domaine", type: "text", validate: "fqdn", default: "acme.local" },
      { id: "timezone", label: "Fuseau horaire", type: "select", default: "Europe/Paris",
        options: [["Europe/Paris"], ["Europe/Brussels"], ["Europe/Zurich"], ["Europe/Luxembourg"], ["America/Montreal"], ["Indian/Reunion"], ["America/Martinique"], ["America/Guadeloupe"], ["Africa/Casablanca"], ["UTC"]] },
      { id: "banner", label: "Ajouter une bannière de connexion « accès réservé »", type: "checkbox", default: true, wide: true },
      { id: "dns1", label: "DNS primaire", type: "ip", required: true, default: "1.1.1.1" },
      { id: "dns2", label: "DNS secondaire", type: "ip", default: "8.8.8.8" },
      { id: "ntp1", label: "NTP primaire", type: "text", validate: "host", default: "0.pool.ntp.org" },
      { id: "ntp2", label: "NTP secondaire", type: "text", validate: "host", default: "1.pool.ntp.org" },

      /* --- Management --- */
      { id: "mgmtIp", label: "IP de management (IP/masque)", type: "cidr", required: true, default: "192.168.1.254/24", group: "Interface de management" },
      { id: "mgmtGw", label: "Passerelle management", type: "ip", required: true, default: "192.168.1.1",
        validate: (v, a) => cidrOk(a.mgmtIp) && !inNet(v, a.mgmtIp) ? "La passerelle doit être dans le sous-réseau de management" : null },
      { id: "permitted", label: "Réseaux autorisés à administrer (optionnel)", type: "list", validate: "ipcidr", default: ["192.168.1.0/24"], wide: true,
        hint: "Permitted IP Addresses. Vide = toutes les IP peuvent joindre le management." },

      /* --- WAN --- */
      { id: "wanIf", label: "Interface WAN", type: "text", required: true, validate: "iface", default: "ethernet1/1", group: "WAN (Internet)" },
      { id: "wanZone", label: "Zone WAN", type: "text", required: true, validate: "name", default: "Untrust" },
      { id: "wanMode", label: "Adressage WAN", type: "select", default: "static", options: [["static", "IP statique"], ["dhcp", "Client DHCP"]] },
      { id: "wanIp", label: "IP WAN (IP/masque)", type: "cidr", required: true, default: "203.0.113.10/24", show: v => v.wanMode === "static" },
      { id: "wanGw", label: "Passerelle Internet (next hop)", type: "ip", required: true, default: "203.0.113.1", show: v => v.wanMode === "static",
        validate: (v, a) => cidrOk(a.wanIp) && !inNet(v, a.wanIp) ? "La passerelle doit être dans le sous-réseau WAN" : (cidrOk(a.wanIp) && v === split(a.wanIp).a ? "La passerelle ne peut pas être l'IP du pare-feu" : null) },

      /* --- LAN --- */
      { id: "lanIf", label: "Interface LAN", type: "text", required: true, validate: (v, a) => PAN.cfg.V.iface(v) || (v === a.wanIf ? "Interface déjà utilisée pour le WAN" : null), default: "ethernet1/2", group: "LAN" },
      { id: "lanZone", label: "Zone LAN", type: "text", required: true, validate: (v, a) => PAN.cfg.V.name(v) || (v === a.wanZone ? "Nom de zone déjà utilisé" : null), default: "Trust" },
      { id: "lanIp", label: "IP LAN du pare-feu (IP/masque)", type: "cidr", required: true, default: "192.168.1.1/24",
        validate: (v, a) => a.wanMode === "static" && cidrOk(a.wanIp) && cidrOk(v) && overlap(v, a.wanIp) ? "Chevauche le sous-réseau WAN" : null },
      { id: "lanApps", label: "Applications autorisées LAN → Internet", type: "list", required: true, wide: true,
        default: ["web-browsing", "ssl", "dns", "ntp", "ping", "ms-update", "apple-update"],
        hint: "App-ID séparées par des virgules. Le service reste <code>application-default</code>." },

      /* --- DMZ --- */
      { id: "dmz", label: "Ajouter une DMZ", type: "checkbox", default: true, group: "DMZ & publication de serveur", wide: true },
      { id: "dmzIf", label: "Interface DMZ", type: "text", required: true, default: "ethernet1/3", show: v => v.dmz,
        validate: (v, a) => PAN.cfg.V.iface(v) || ([a.wanIf, a.lanIf].includes(v) ? "Interface déjà utilisée" : null) },
      { id: "dmzZone", label: "Zone DMZ", type: "text", required: true, validate: (v, a) => PAN.cfg.V.name(v) || ([a.wanZone, a.lanZone].includes(v) ? "Nom de zone déjà utilisé" : null), default: "DMZ", show: v => v.dmz },
      { id: "dmzIp", label: "IP DMZ du pare-feu (IP/masque)", type: "cidr", required: true, default: "172.16.1.1/24", show: v => v.dmz,
        validate: (v, a) => cidrOk(v) && cidrOk(a.lanIp) && overlap(v, a.lanIp) ? "Chevauche le LAN" : null },
      { id: "publish", label: "Publier un serveur de la DMZ sur Internet (Destination NAT)", type: "checkbox", default: true, show: v => v.dmz, wide: true },
      { id: "srvName", label: "Nom du serveur", type: "text", validate: "name", required: true, default: "Web", show: v => v.dmz && v.publish },
      { id: "srvIp", label: "IP privée du serveur", type: "ip", required: true, default: "172.16.1.10", show: v => v.dmz && v.publish,
        validate: (v, a) => cidrOk(a.dmzIp) && !inNet(v, a.dmzIp) ? "Doit être dans le sous-réseau DMZ" : (cidrOk(a.dmzIp) && v === split(a.dmzIp).a ? "C'est l'IP du pare-feu" : null) },
      { id: "srvPub", label: "IP publique du serveur", type: "ip", required: true, default: "203.0.113.20", show: v => v.dmz && v.publish,
        hint: "Peut être l'IP WAN elle-même ou une autre IP du bloc public." },
      { id: "srvPort", label: "Port publié (TCP)", type: "port", required: true, default: "443", show: v => v.dmz && v.publish },
      { id: "srvApps", label: "Applications du serveur", type: "list", default: ["ssl", "web-browsing"], show: v => v.dmz && v.publish },

      /* --- Sécurité --- */
      { id: "profiles", label: "Groupe de profils de sécurité standard (AV, Anti-Spyware, Vulnérabilités, URL, File Blocking, WildFire)", type: "checkbox", default: true, group: "Sécurité & exploitation", wide: true },
      { id: "url", label: "Licence URL Filtering (PAN-DB) active", type: "checkbox", default: true, show: v => v.profiles, wide: true },
      { id: "edl", label: "Bloquer les IP malveillantes connues (listes Palo Alto prédéfinies)", type: "checkbox", default: true, wide: true },
      { id: "denyAll", label: "Règle « Deny-All » journalisée en fin de rulebase", type: "checkbox", default: true, wide: true },
      { id: "updates", label: "Planifier les mises à jour dynamiques (Apps & Threats, Antivirus, WildFire)", type: "checkbox", default: true, wide: true },
    ],

    build(v) {
      const steps = [], cli = [], notes = [];
      const c = v.client ? `${v.client} - ` : "";
      const mg = split(v.mgmtIp);
      const lan = split(v.lanIp), lanNet = netOf(v.lanIp);
      const dmzOn = v.dmz, pubOn = dmzOn && v.publish;
      const dmzNet = dmzOn ? netOf(v.dmzIp) : null;
      const wanStatic = v.wanMode === "static";
      const ifs = [v.wanIf, v.lanIf].concat(dmzOn ? [v.dmzIf] : []);
      const srvObj = pubOn ? `Srv-${v.srvName}-${v.dmzZone}` : "", pubObj = pubOn ? `Srv-${v.srvName}-Public` : "", svc = pubOn ? `tcp-${v.srvPort}` : "";
      const bannerTxt = `Accès réservé au personnel autorisé de ${v.client || "l'entreprise"}. Toute connexion est journalisée.`;

      /* 1. Système */
      steps.push({ title: "Paramètres généraux", path: ["Device", "Setup", "Management"], window: "General Settings",
        action: "Cadre « General Settings » → icône ⚙.",
        fields: [["Hostname", v.hostname], ["Domain", v.domain], ["Login Banner", v.banner ? bannerTxt : ""], ["Time Zone", v.timezone]] });
      cli.push("# --- Système ---", `set deviceconfig system hostname ${q(v.hostname)}`);
      if (v.domain) cli.push(`set deviceconfig system domain ${q(v.domain)}`);
      cli.push(`set deviceconfig system timezone ${v.timezone}`);
      if (v.banner) cli.push(`set deviceconfig system login-banner ${q(ascii(bannerTxt))}`);

      steps.push({ title: "Serveurs DNS et NTP", path: ["Device", "Setup", "Services"], tab: "Services puis NTP", window: "Services",
        action: "Cadre « Services » → icône ⚙. Renseigner les DNS (onglet Services) puis les NTP (onglet NTP).",
        fields: [["Primary DNS Server", v.dns1], ["Secondary DNS Server", v.dns2], ["Primary NTP Server Address", v.ntp1], ["Secondary NTP Server Address", v.ntp2]] });
      cli.push(`set deviceconfig system dns-setting servers primary ${v.dns1}`);
      if (v.dns2) cli.push(`set deviceconfig system dns-setting servers secondary ${v.dns2}`);
      if (v.ntp1) cli.push(`set deviceconfig system ntp-servers primary-ntp-server ntp-server-address ${v.ntp1}`);
      if (v.ntp2) cli.push(`set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address ${v.ntp2}`);

      /* 2. Management */
      steps.push({ title: "Interface de management", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
        action: "Cliquer sur « Management ».",
        fields: [["IP Type", "Static"], ["IP Address", mg.a], ["Netmask", maskStr(mg.m)], ["Default Gateway", v.mgmtGw],
          ["Administrative Management Services", "HTTPS, SSH"], ["Network Services", "Ping"], ["Permitted IP Addresses", v.permitted]],
        warn: "Au commit, la session sera coupée si tu modifies l'IP sur laquelle tu es connecté : reconnecte-toi sur https://" + mg.a });
      cli.push("# --- Management ---",
        `set deviceconfig system ip-address ${mg.a} netmask ${maskStr(mg.m)} default-gateway ${v.mgmtGw}`,
        "set deviceconfig system service disable-http yes disable-telnet yes disable-https no disable-ssh no disable-icmp no");
      (v.permitted || []).forEach(p => cli.push(`set deviceconfig system permitted-ip ${p}`));

      /* 3. Profil de gestion d'interface (ping sur LAN/DMZ) */
      steps.push({ title: "Profil de gestion d'interface « Allow-Ping »", path: ["Network", "Network Profiles", "Interface Mgmt"], window: "Interface Management Profile",
        action: "Add.", fields: [["Name", "Allow-Ping"], ["Network Services", "Ping"]],
        note: "Permet de pinguer les passerelles LAN/DMZ du pare-feu. Ne jamais l'appliquer sur le WAN avec HTTPS/SSH." });
      cli.push("# --- Profil de gestion d'interface ---", "set network profiles interface-management-profile Allow-Ping ping yes");

      /* 4. Zones */
      const zones = [[v.wanZone, v.wanIf], [v.lanZone, v.lanIf]].concat(dmzOn ? [[v.dmzZone, v.dmzIf]] : []);
      zones.forEach(([z]) => steps.push({ title: `Zone ${z}`, path: ["Network", "Zones"], window: "Zone", action: "Add.",
        fields: [["Name", z], ["Type", "Layer3"], ["Interfaces", "(affectée à l'étape interface)"], ["Enable User Identification", z === v.lanZone ? "à activer si User-ID est utilisé" : ""]] }));
      cli.push("# --- Zones et interfaces ---");

      /* 5. Interfaces */
      const ifStep = (ifn, zone, addr, mgmtProf, extra) => steps.push({ title: `Interface ${ifn} (${zone})`, path: ["Network", "Interfaces", "Ethernet"], window: `Ethernet Interface — ${ifn}`,
        action: `Cliquer sur ${ifn}. Onglet Config, puis IPv4${mgmtProf ? ", puis Advanced > Other Info" : ""}.`,
        fields: [["Comment", `${c}${zone}`], ["Interface Type", "Layer3"], ["Virtual Router", "default"], ["Security Zone", zone]].concat(extra, mgmtProf ? [["Management Profile", mgmtProf]] : []) });
      ifStep(v.wanIf, v.wanZone, v.wanIp, null, wanStatic ? [["IPv4 Type", "Static"], ["IP", v.wanIp]] : [["IPv4 Type", "DHCP Client"], ["Automatically create default route pointing to default gateway provided by server", true]]);
      ifStep(v.lanIf, v.lanZone, v.lanIp, "Allow-Ping", [["IPv4 Type", "Static"], ["IP", v.lanIp]]);
      if (dmzOn) ifStep(v.dmzIf, v.dmzZone, v.dmzIp, "Allow-Ping", [["IPv4 Type", "Static"], ["IP", v.dmzIp]]);

      const ifCli = (ifn, zone, cmt) => { cli.push(`set network interface ethernet ${ifn} comment ${q(ascii(cmt))}`); return ifn; };
      ifCli(v.wanIf, v.wanZone, `${c}${v.wanZone}`);
      cli.push(wanStatic ? `set network interface ethernet ${v.wanIf} layer3 ip ${v.wanIp}` : `set network interface ethernet ${v.wanIf} layer3 dhcp-client create-default-route yes`);
      ifCli(v.lanIf, v.lanZone, `${c}${v.lanZone}`);
      cli.push(`set network interface ethernet ${v.lanIf} layer3 ip ${v.lanIp}`, `set network interface ethernet ${v.lanIf} layer3 interface-management-profile Allow-Ping`);
      if (dmzOn) { ifCli(v.dmzIf, v.dmzZone, `${c}${v.dmzZone}`); cli.push(`set network interface ethernet ${v.dmzIf} layer3 ip ${v.dmzIp}`, `set network interface ethernet ${v.dmzIf} layer3 interface-management-profile Allow-Ping`); }
      zones.forEach(([z, i]) => cli.push(`set zone ${q(z)} network layer3 ${i}`));

      /* 6. Routage */
      cli.push("# --- Routage ---", `set network virtual-router default interface ${members(ifs)}`);
      if (wanStatic) {
        steps.push({ title: "Route par défaut", path: ["Network", "Virtual Routers", "default"], tab: "Static Routes > IPv4", window: "Virtual Router — Static Route",
          action: "Ouvrir le virtual router « default », onglet Static Routes, Add.",
          fields: [["Name", "Default-Route"], ["Destination", "0.0.0.0/0"], ["Interface", v.wanIf], ["Next Hop", "IP Address"], ["IP Address", v.wanGw]],
          note: "Vérifie dans l'onglet Router Settings que les interfaces " + ifs.join(", ") + " sont bien membres du virtual router." });
        cli.push(`set network virtual-router default routing-table ip static-route Default-Route destination 0.0.0.0/0 interface ${v.wanIf} nexthop ip-address ${v.wanGw}`);
      }

      /* 7. Objets */
      const objs = [["Net-" + v.lanZone, lanNet, "Réseau " + v.lanZone]];
      if (dmzOn) objs.push(["Net-" + v.dmzZone, dmzNet, "Réseau " + v.dmzZone]);
      if (pubOn) objs.push([srvObj, v.srvIp, `Serveur ${v.srvName} (IP privée)`], [pubObj, v.srvPub, `Serveur ${v.srvName} (IP publique)`]);
      objs.forEach(([n, a, d]) => steps.push({ title: `Objet adresse ${n}`, path: ["Objects", "Addresses"], window: "Address", action: "Add.",
        fields: [["Name", n], ["Description", d], ["Type", "IP Netmask"], ["Value", a]] }));
      cli.push("# --- Objets ---");
      objs.forEach(([n, a, d]) => cli.push(`set address ${q(n)} ip-netmask ${a} description ${q(ascii(d))}`));
      if (pubOn) {
        steps.push({ title: `Objet service ${svc}`, path: ["Objects", "Services"], window: "Service", action: "Add.",
          fields: [["Name", svc], ["Protocol", "TCP"], ["Destination Port", v.srvPort]] });
        cli.push(`set service ${svc} protocol tcp port ${v.srvPort}`);
      }

      /* 8. Profils */
      if (v.profiles) {
        steps.push({ title: "Groupe de profils « Std-Profiles »", path: ["Objects", "Security Profile Groups"], window: "Security Profile Group", action: "Add.",
          fields: [["Name", "Std-Profiles"], ["Antivirus Profile", "default"], ["Anti-Spyware Profile", "strict"], ["Vulnerability Protection Profile", "strict"],
            ["URL Filtering Profile", v.url ? "default" : "None"], ["File Blocking Profile", "basic file blocking"], ["WildFire Analysis Profile", "default"]],
          note: "Profils prédéfinis Palo Alto : base solide. Tu peux les cloner et les durcir ensuite (module « Profils de sécurité »)." });
        cli.push("# --- Profils de sécurité ---",
          `set profile-group Std-Profiles virus default spyware strict vulnerability strict file-blocking "basic file blocking" wildfire-analysis default${v.url ? " url-filtering default" : ""}`);
      }
      const prof = v.profiles ? " profile-setting group Std-Profiles" : "";

      /* 9. NAT */
      const natSrc = ["Net-" + v.lanZone].concat(dmzOn ? ["Net-" + v.dmzZone] : []);
      const natFrom = [v.lanZone].concat(dmzOn ? [v.dmzZone] : []);
      steps.push({ title: "NAT sortant SNAT-LAN-Internet", path: ["Policies", "NAT"], tab: "General / Original Packet / Translated Packet", window: "NAT Policy Rule",
        action: "Add. Remplir les 3 onglets.",
        fields: [["Name", "SNAT-LAN-Internet"], ["Description", `${c}Sortie Internet en DIPP`], ["Source Zone", natFrom], ["Destination Zone", v.wanZone], ["Destination Interface", v.wanIf],
          ["Service", "any"], ["Source Address", natSrc], ["Destination Address", "any"],
          ["Translation Type", "Dynamic IP And Port"], ["Address Type", "Interface Address"], ["Interface", v.wanIf], ["IP Address", wanStatic ? v.wanIp : "(DHCP)"]] });
      cli.push("# --- NAT ---",
        `set rulebase nat rules SNAT-LAN-Internet from ${members(natFrom)} to ${q(v.wanZone)} to-interface ${v.wanIf} source ${members(natSrc)} destination any service any source-translation dynamic-ip-and-port interface-address interface ${v.wanIf}${wanStatic ? " ip " + v.wanIp : ""}`);
      if (pubOn) {
        steps.push({ title: `NAT entrant DNAT-${v.srvName}-${v.dmzZone}`, path: ["Policies", "NAT"], tab: "General / Original Packet / Translated Packet", window: "NAT Policy Rule",
          action: "Add. Attention : en Destination NAT, la zone de destination est celle de l'IP PUBLIQUE (WAN).",
          fields: [["Name", `DNAT-${v.srvName}-${v.dmzZone}`], ["Source Zone", v.wanZone], ["Destination Zone", v.wanZone], ["Destination Interface", "any"], ["Service", svc],
            ["Source Address", "any"], ["Destination Address", pubObj], ["Source Translation", "None"], ["Destination Translation — Translation Type", "Static IP"], ["Translated Address", srvObj]] });
        cli.push(`set rulebase nat rules DNAT-${v.srvName}-${v.dmzZone} from ${q(v.wanZone)} to ${q(v.wanZone)} source any destination ${q(pubObj)} service ${svc} destination-translation translated-address ${q(srvObj)}`,
          `move rulebase nat rules DNAT-${v.srvName}-${v.dmzZone} top`);
        if (wanStatic && v.srvPub !== split(v.wanIp).a && !inNet(v.srvPub, v.wanIp))
          notes.push({ type: "warn", title: "IP publique hors du sous-réseau WAN", text: `${v.srvPub} n'est pas dans ${netOf(v.wanIp)} : le FAI doit router cette IP vers ${split(v.wanIp).a}.` });
      }

      /* 10. Règles de sécurité (dans l'ordre final) */
      const rules = [];
      if (v.edl) {
        rules.push({ n: "Block-Malicious-Out", d: "Bloque les flux vers les IP malveillantes connues", from: "any", to: v.wanZone, src: "any", dst: ["panw-highrisk-ip-list", "panw-known-ip-list", "panw-bulletproof-ip-list"], app: "any", svc: "any", act: "drop", prof: "" });
        rules.push({ n: "Block-Malicious-In", d: "Bloque les flux depuis les IP malveillantes connues", from: v.wanZone, to: "any", src: ["panw-highrisk-ip-list", "panw-known-ip-list", "panw-bulletproof-ip-list"], dst: "any", app: "any", svc: "any", act: "drop", prof: "" });
      }
      rules.push({ n: `${v.lanZone}-to-Internet`, d: `${c}Accès Internet des utilisateurs`, from: v.lanZone, to: v.wanZone, src: "Net-" + v.lanZone, dst: "any", app: v.lanApps, svc: "application-default", act: "allow", prof });
      if (dmzOn) rules.push({ n: `${v.dmzZone}-to-Internet`, d: `${c}Mises à jour des serveurs DMZ`, from: v.dmzZone, to: v.wanZone, src: "Net-" + v.dmzZone, dst: "any", app: ["dns", "ntp", "ssl", "web-browsing", "ms-update"], svc: "application-default", act: "allow", prof });
      if (pubOn) rules.push({ n: `Allow-${v.srvName}-${v.dmzZone}`, d: `${c}Publication ${v.srvName} (IP pré-NAT, zone post-NAT)`, from: v.wanZone, to: v.dmzZone, src: "any", dst: pubObj, app: v.srvApps && v.srvApps.length ? v.srvApps : "any", svc, act: "allow", prof });
      if (v.denyAll) rules.push({ n: "Deny-All-Log", d: "Refus explicite journalisé", from: "any", to: "any", src: "any", dst: "any", app: "any", svc: "any", act: "deny", prof: "" });

      rules.forEach(r => steps.push({ title: `Règle de sécurité ${r.n}`, path: ["Policies", "Security"], tab: "General / Source / Destination / Application / Service / Actions", window: "Security Policy Rule",
        action: "Add. Les règles doivent apparaître dans cet ordre (glisser-déposer ou Move si besoin).",
        fields: [["Name", r.n], ["Description", r.d], ["Rule Type", "universal (default)"], ["Source Zone", r.from], ["Source Address", r.src], ["Destination Zone", r.to], ["Destination Address", r.dst],
          ["Application", r.app], ["Service", r.svc], ["Action", r.act], ["Profile Setting", r.prof ? "Group : Std-Profiles" : ""], ["Log at Session End", true]],
        note: r.n.startsWith("Allow-") ? "Règle de publication : adresse de destination = IP PUBLIQUE (pré-NAT), zone de destination = " + v.dmzZone + " (post-NAT)." : undefined }));
      cli.push("# --- Règles de sécurité (ordre final) ---");
      rules.forEach(r => cli.push(`set rulebase security rules ${q(r.n)} from ${members(r.from)} to ${members(r.to)} source ${members(r.src)} destination ${members(r.dst)} source-user any category any application ${members(r.app)} service ${members(r.svc)} action ${r.act} log-end yes description ${q(ascii(r.d))}${r.prof}`));
      rules.forEach(r => cli.push(`move rulebase security rules ${q(r.n)} bottom`));
      if (v.denyAll) {
        steps.push({ title: "Journaliser la règle interzone-default", path: ["Policies", "Security"], window: "Security Policy Rule — interzone-default",
          action: "Sélectionner interzone-default (en bas) → Override → onglet Actions.", fields: [["Action", "deny"], ["Log at Session End", true]] });
        cli.push("set rulebase default-security-rules rules interzone-default action deny log-end yes");
      }

      /* 11. Mises à jour */
      if (v.updates) {
        steps.push({ title: "Mises à jour dynamiques", path: ["Device", "Dynamic Updates"], window: "Schedule",
          action: "Cliquer « Check Now », puis le lien « Schedule » de chaque type.",
          fields: [["Applications and Threats", "Daily 01:00 — Download and Install"], ["Antivirus", "Hourly à :15 — Download and Install"], ["WildFire", "Every Minute — Download and Install"]],
          note: "Une licence Threat Prevention est nécessaire pour Antivirus/Threats, et WildFire pour les mises à jour WildFire." });
        cli.push("# --- Mises à jour dynamiques ---",
          "set deviceconfig system update-schedule threats recurring daily at 01:00 action download-and-install",
          "set deviceconfig system update-schedule anti-virus recurring hourly at 15 action download-and-install",
          "set deviceconfig system update-schedule wildfire recurring every-min action download-and-install");
      }

      notes.push({ type: "or", title: "Avant de commencer", text: "Change le mot de passe admin par défaut, vérifie licences et version PAN-OS (Device > Licenses, Device > Software), et fais une sauvegarde (Device > Setup > Operations > Save named configuration snapshot)." });

      const client = lan.a.split(".").slice(0, 3).concat("50").join(".");
      return {
        steps, cli, notes,
        verify: [
          "show interface all",
          "show routing route",
          `ping source ${lan.a} host 8.8.8.8`,
          `test security-policy-match from ${q(v.lanZone)} to ${q(v.wanZone)} source ${client} destination 8.8.8.8 protocol 6 destination-port 443 application ssl`,
          `test nat-policy-match from ${q(v.lanZone)} to ${q(v.wanZone)} source ${client} destination 8.8.8.8 protocol 6 destination-port 443`,
        ].concat(pubOn ? [`test nat-policy-match from ${q(v.wanZone)} to ${q(v.wanZone)} source 198.51.100.50 destination ${v.srvPub} protocol 6 destination-port ${v.srvPort}`,
          `test security-policy-match from ${q(v.wanZone)} to ${q(v.dmzZone)} source 198.51.100.50 destination ${v.srvPub} protocol 6 destination-port ${v.srvPort}`] : []),
      };
    },
  });
})();
