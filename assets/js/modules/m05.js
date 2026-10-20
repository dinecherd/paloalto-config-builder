/* Modules M05 — interfaces, zones & routage (PAN-OS 11.0, firewall mono-vsys) */
(function () {
  const { register, q, members, yn } = PAN.cfg;

  /* ---------- helpers locaux ---------- */
  const toInt = s => PAN.ip.toInt(String(s).trim());
  const toIp = n => [24, 16, 8, 0].map(s => (n >>> s) & 255).join(".");
  const maskInt = p => (p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0);
  function net(cidr) {
    const [a, m] = String(cidr).split("/"); const p = +m;
    const ip = toInt(a), mk = maskInt(p), n = (ip & mk) >>> 0, b = (n | (~mk >>> 0)) >>> 0;
    return { ip, p, mask: toIp(mk), net: n, bcast: b, netStr: toIp(n) + "/" + p };
  }
  const inNet = (ipStr, nw) => { const x = toInt(ipStr); return x >= nw.net && x <= nw.bcast; };
  const isCidr = s => PAN.cfg.V.cidr(s) === null;
  /* IP/masque d'hôte : ni adresse réseau ni broadcast (masques ≤ /30) */
  const hostCidr = val => {
    if (!isCidr(val)) return "Format IP/masque attendu (ex. 192.168.1.1/24)";
    const n = net(val);
    if (n.p < 1) return "Masque /0 interdit sur une interface";
    if (n.p <= 30 && (n.ip === n.net || n.ip === n.bcast)) return `${val.split("/")[0]} est l'adresse ${n.ip === n.net ? "réseau" : "de broadcast"} de ${n.netStr}`;
    return null;
  };
  const physIf = v => /^ethernet\d+\/\d+$/.test(v) ? null : "Interface physique attendue (ex. ethernet1/2)";
  const ifList = arr => { for (const x of arr) if (PAN.cfg.V.iface(x)) return `« ${x} » : interface PAN-OS invalide`; return new Set(arr).size === arr.length ? null : "Interface en double"; };
  /* hiérarchie CLI de config L3 d'une interface (pour IP / profil de gestion) */
  function l3Base(i) {
    let m;
    if ((m = /^(ethernet\d+\/\d+)(\.\d+)?$/.exec(i))) return `network interface ethernet ${m[1]} layer3${m[2] ? " units " + i : ""}`;
    if ((m = /^(ae\d+)(\.\d+)?$/.exec(i))) return `network interface aggregate-ethernet ${m[1]} layer3${m[2] ? " units " + i : ""}`;
    if ((m = /^(vlan|loopback|tunnel)(\.\d+)?$/.exec(i))) return `network interface ${m[1]}${m[2] ? " units " + i : ""}`;
    return `network interface ethernet ${i} layer3`;
  }
  const ifTab = i => /^vlan/.test(i) ? "VLAN" : /^loopback/.test(i) ? "Loopback" : /^tunnel/.test(i) ? "Tunnel" : "Ethernet";
  const importLine = ifs => `set import network interface ${members(ifs)}`;
  const importNote = "# mono-vsys : rattache l'interface à vsys1 (la WebUI le fait automatiquement)";
  const zoneOpt = (dflt) => ({ id: "zone", label: "Zone de sécurité", type: "text", required: true, validate: "name", default: dflt, hint: "Sensible à la casse." });

  /* ======================================================================
     m05-zone · Zone de sécurité
     ====================================================================== */
  const ZTYPES = [["layer3", "Layer3"], ["layer2", "Layer2"], ["virtual-wire", "Virtual Wire"], ["tap", "Tap"], ["tunnel", "Tunnel"]];
  register({
    id: "m05-zone",
    module: "M05",
    title: "Zone de sécurité",
    icon: "🧱",
    desc: "Créer une zone (Layer3, Layer2, Virtual Wire, Tap, Tunnel), y rattacher les interfaces, Zone Protection et User-ID.",
    tags: "zone security zone trust untrust dmz user-id zone protection",
    fields: [
      { id: "name", label: "Nom de la zone", type: "text", required: true, validate: "name", default: "Trust", hint: "Sensible à la casse — réutilisé tel quel dans les règles." },
      { id: "type", label: "Type", type: "select", default: "layer3", options: ZTYPES },
      { id: "ifs", label: "Interfaces membres", type: "list", default: ["ethernet1/2"], validate: ifList, placeholder: "ethernet1/2, ethernet1/2.10",
        show: v => v.type !== "tunnel", hint: "Séparées par des virgules. Chaque interface doit déjà être du même type que la zone." },
      { id: "zpp", label: "Zone Protection Profile (optionnel)", type: "text", validate: "name", placeholder: "Std-ZP", group: "Options" },
      { id: "logSetting", label: "Log Setting (optionnel)", type: "text", validate: "name", placeholder: "Log-Forwarding" },
      { id: "uid", label: "Enable User Identification", type: "checkbox", default: true, show: v => v.type !== "tap" && v.type !== "tunnel" },
      { id: "incl", label: "User-ID — Include List (réseaux)", type: "list", validate: "cidr", default: ["192.168.1.0/24"], show: v => v.uid && v.type !== "tap" && v.type !== "tunnel", placeholder: "192.168.1.0/24", hint: "Vide = tous les réseaux de la zone." },
      { id: "excl", label: "User-ID — Exclude List (réseaux)", type: "list", validate: "cidr", show: v => v.uid && v.type !== "tap" && v.type !== "tunnel", placeholder: "192.168.1.0/28" },
    ],
    build(v) {
      const t = ZTYPES.find(x => x[0] === v.type)[1];
      const hasIfs = v.type !== "tunnel" && v.ifs.length;
      const uid = v.uid && v.type !== "tap" && v.type !== "tunnel";
      const steps = [{
        title: `Créer la zone ${v.name}`, path: ["Network", "Zones"], window: "Zone", action: "Cliquer sur Add en bas de la liste.",
        fields: [["Name", v.name], ["Type", t], ["Interfaces (Add)", hasIfs ? v.ifs : ""], ["Zone Protection Profile", v.zpp], ["Log Setting", v.logSetting],
          ["Enable User Identification", uid], ["User Identification ACL — Include List", uid ? v.incl : ""], ["User Identification ACL — Exclude List", uid ? v.excl : ""]],
        note: v.type === "tunnel" ? "Zone Tunnel : utilisée par la Tunnel Content Inspection (Policies > Tunnel Inspection), aucune interface n'y est rattachée." : "Seules les interfaces du même type et non encore affectées à une zone apparaissent dans la liste.",
      }];
      const z = `set zone ${q(v.name)}`;
      const cli = [
        hasIfs ? `${z} network ${v.type} ${members(v.ifs)}` : `${z} network ${v.type}`,
        v.zpp && `${z} network zone-protection-profile ${q(v.zpp)}`,
        v.logSetting && `${z} network log-setting ${q(v.logSetting)}`,
        uid && `${z} enable-user-identification yes`,
        uid && v.incl.length && `${z} user-acl include-list ${members(v.incl)}`,
        uid && v.excl.length && `${z} user-acl exclude-list ${members(v.excl)}`,
      ].filter(Boolean);
      const notes = [];
      if (v.zpp) notes.push({ type: "or", text: `Le Zone Protection Profile « ${v.zpp} » doit exister (Network > Network Profiles > Zone Protection).` });
      if (hasIfs && v.type !== "tap") notes.push({ type: "or", text: "Une interface ne peut appartenir qu'à une seule zone. Le trafic intrazone est autorisé par défaut, l'interzone est refusé." });
      if (v.uid && v.type === "layer3" && v.name.toLowerCase().includes("untrust")) notes.push({ type: "warn", text: "N'active pas User-ID sur une zone externe (Untrust) : risque de fuite d'identifiants via le probing." });
      return { steps, cli, notes, verify: [`show zone-protection zone ${q(v.name)}`, hasIfs ? `show interface ${v.ifs[0]}` : "show interface all"] };
    },
  });

  /* ======================================================================
     m05-l3-interface · Interface Ethernet Layer 3
     ====================================================================== */
  register({
    id: "m05-l3-interface",
    module: "M05",
    title: "Interface Ethernet Layer 3",
    icon: "🔌",
    desc: "Interface Layer3 complète : commentaire, virtual router, zone, IPv4 statique ou client DHCP, profil de gestion, vitesse/duplex.",
    tags: "interface ethernet layer3 l3 ip dhcp client zone virtual router management profile",
    fields: [
      { id: "iface", label: "Interface", type: "text", required: true, validate: physIf, default: "ethernet1/2" },
      { id: "comment", label: "Commentaire", type: "text", default: "LAN", placeholder: "Lien vers le cœur de réseau" },
      { id: "vr", label: "Virtual Router", type: "text", required: true, validate: "name", default: "default", group: "Routage & zone", hint: "« default » = VR présent en configuration usine." },
      zoneOpt("Trust"),
      { id: "zoneNew", label: "Créer la zone depuis l'interface (New Zone)", type: "checkbox", default: true },
      { id: "mode", label: "Adressage IPv4", type: "select", default: "static", group: "IPv4", options: [["static", "Static"], ["dhcp", "DHCP Client"]] },
      { id: "ips", label: "Adresse(s) IP/masque", type: "list", required: true, default: ["192.168.1.1/24"], show: v => v.mode === "static",
        validate: arr => { for (const x of arr) { const e = hostCidr(x); if (e) return `« ${x} » : ${e}`; } return new Set(arr).size === arr.length ? null : "Adresse en double"; },
        hint: "Toujours avec le masque (/24). Plusieurs adresses séparées par des virgules." },
      { id: "dhcpRoute", label: "Automatically create default route pointing to default gateway provided by server", type: "checkbox", default: true, show: v => v.mode === "dhcp" },
      { id: "dhcpMetric", label: "Default Route Metric", type: "number", default: "10", min: 1, max: 65535, show: v => v.mode === "dhcp" && v.dhcpRoute },
      { id: "mgmt", label: "Interface Management Profile (optionnel)", type: "text", validate: "name", placeholder: "Allow-Ping", group: "Advanced" },
      { id: "speed", label: "Link Speed", type: "select", default: "auto", options: [["auto"], ["10"], ["100"], ["1000"], ["10000"]] },
      { id: "duplex", label: "Link Duplex", type: "select", default: "auto", options: [["auto"], ["full"], ["half"]] },
      { id: "testIp", label: "Hôte à pinguer pour le test (optionnel)", type: "ip", default: "192.168.1.50", group: "Vérification" },
    ],
    build(v) {
      const i = v.iface, b = `set network interface ethernet ${i}`;
      const steps = [
        { title: `Ouvrir ${i} et définir le type Layer3`, path: ["Network", "Interfaces", "Ethernet"], tab: "Config", window: "Ethernet Interface",
          action: `Cliquer sur le lien ${i}.`,
          fields: [["Interface Name", i], ["Comment", v.comment], ["Interface Type", "Layer3"], ["Virtual Router", v.vr], ["Security Zone", v.zoneNew ? `New Zone → ${v.zone}` : v.zone]],
          note: v.zoneNew ? `New Zone ouvre la fenêtre Zone : Name = ${v.zone}, Type = Layer3, ${i} déjà listée → OK.` : `La zone ${v.zone} doit exister (type Layer3) — module « Zone de sécurité » (#m05-zone).` },
        v.mode === "static"
          ? { title: "Adresse IPv4 statique", path: ["Network", "Interfaces", "Ethernet", i], tab: "IPv4", window: "Ethernet Interface",
              action: "Onglet IPv4 → Type Static → sous IP, cliquer Add pour chaque adresse.", fields: [["Type", "Static"], ["IP", v.ips]],
              warn: "Inclure le masque (/24) : sans masque, l'adresse est créée en /32." }
          : { title: "Client DHCP", path: ["Network", "Interfaces", "Ethernet", i], tab: "IPv4", window: "Ethernet Interface",
              fields: [["Type", "DHCP Client"], ["Enable", true], ["Automatically create default route pointing to default gateway provided by server", v.dhcpRoute], ["Default Route Metric", v.dhcpRoute ? v.dhcpMetric : ""]] },
        { title: "Paramètres avancés", path: ["Network", "Interfaces", "Ethernet", i], tab: "Advanced", window: "Ethernet Interface",
          action: "Onglet Advanced → Link Settings et, dans Other Info, Management Profile. Puis OK.",
          fields: [["Link Speed", v.speed], ["Link Duplex", v.duplex], ["Link State", "auto"], ["Management Profile", v.mgmt]],
          note: v.mgmt ? `Le profil « ${v.mgmt} » doit exister — module « Interface Management Profile » (#m05-mgmt-profile). Confirmer l'avertissement par Yes si HTTPS/SSH est activé.` : "" },
      ];
      const cli = [
        b + (v.mode === "static" ? ` layer3 ip ${members(v.ips)}` : ` layer3 dhcp-client enable yes create-default-route ${yn(v.dhcpRoute)}${v.dhcpRoute ? " default-route-metric " + v.dhcpMetric : ""}`),
        v.comment && `${b} comment ${q(v.comment)}`,
        (v.speed !== "auto" || v.duplex !== "auto") && `${b} link-speed ${v.speed} link-duplex ${v.duplex}`,
        v.mgmt && `${b} layer3 interface-management-profile ${q(v.mgmt)}`,
        importNote, importLine([i]),
        `set network virtual-router ${q(v.vr)} interface ${i}`,
        `set zone ${q(v.zone)} network layer3 ${i}`,
      ].filter(Boolean);
      const src = v.mode === "static" ? v.ips[0].split("/")[0] : "";
      const verify = [`show interface ${i}`, `show routing interface`, `show routing route virtual-router ${q(v.vr)}`];
      if (v.mode === "dhcp") verify.push(`show dhcp client state ${i}`);
      if (v.testIp) verify.push(`ping source ${src || "<IP-de-" + i + ">"} host ${v.testIp}`);
      const notes = [{ type: "or", text: "Le voyant Link State reste gris jusqu'au commit. Sans profil de gestion, l'interface ne répond ni au ping ni à SSH/HTTPS." }];
      if (v.mode === "static" && v.testIp && !v.ips.some(x => inNet(v.testIp, net(x)))) notes.push({ type: "warn", text: `${v.testIp} n'est dans aucun sous-réseau de ${i} : le ping passera par la table de routage.` });
      if (v.speed !== "auto" && v.duplex === "auto" || v.speed === "auto" && v.duplex !== "auto") notes.push({ type: "warn", text: "Forcer vitesse ET duplex des deux côtés (firewall et switch), sinon risque de mismatch." });
      return { steps, cli, verify, notes };
    },
  });

  /* ======================================================================
     m05-subinterface · Sous-interface Layer 3 (VLAN 802.1Q)
     ====================================================================== */
  register({
    id: "m05-subinterface",
    module: "M05",
    title: "Sous-interface VLAN (Layer 3)",
    icon: "🔀",
    desc: "Sous-interface 802.1Q sur un parent Layer3 : tag VLAN, IP, virtual router, zone, profil de gestion.",
    tags: "subinterface sous-interface vlan tag 802.1q trunk dot1q layer3",
    fields: [
      { id: "parent", label: "Interface parente", type: "text", required: true, validate: physIf, default: "ethernet1/2", hint: "Doit être en Layer3 (avec ou sans IP)." },
      { id: "parentSet", label: "Passer le parent en Layer3 (sans IP) dans ce flux", type: "checkbox", default: false },
      { id: "tag", label: "Tag VLAN", type: "text", required: true, validate: "vlan", default: "10" },
      { id: "suffix", label: "Suffixe de sous-interface", type: "number", min: 1, max: 9999, placeholder: "= tag (recommandé)", hint: "Vide = identique au tag." },
      { id: "comment", label: "Commentaire", type: "text", default: "VLAN 10 - Users" },
      { id: "ip", label: "Adresse IP/masque", type: "text", required: true, validate: hostCidr, default: "192.168.10.1/24", group: "IPv4 & routage" },
      { id: "vr", label: "Virtual Router", type: "text", required: true, validate: "name", default: "default" },
      zoneOpt("Users-VLAN10"),
      { id: "zoneNew", label: "Créer la zone depuis l'interface (New Zone)", type: "checkbox", default: true },
      { id: "mgmt", label: "Interface Management Profile (optionnel)", type: "text", validate: "name", placeholder: "Allow-Ping" },
    ],
    build(v) {
      const sfx = v.suffix || v.tag, sub = `${v.parent}.${sfx}`;
      const b = `set network interface ethernet ${v.parent} layer3 units ${sub}`;
      const steps = [];
      if (v.parentSet) steps.push({ title: `Passer ${v.parent} en Layer3`, path: ["Network", "Interfaces", "Ethernet"], tab: "Config", window: "Ethernet Interface",
        action: `Cliquer sur ${v.parent}, Interface Type = Layer3, sans IP ni zone, puis OK.`, fields: [["Interface Type", "Layer3"], ["Virtual Router", "None"], ["Security Zone", "None"]] });
      steps.push(
        { title: `Créer la sous-interface ${sub}`, path: ["Network", "Interfaces", "Ethernet"], tab: "Config", window: "Layer3 Subinterface",
          action: `Sélectionner la ligne ${v.parent} (sans ouvrir le lien) → Add Subinterface en bas.`,
          fields: [["Interface Name", `${v.parent} . ${sfx}`], ["Comment", v.comment], ["Tag", v.tag], ["Virtual Router", v.vr], ["Security Zone", v.zoneNew ? `New Zone → ${v.zone}` : v.zone]],
          note: v.zoneNew ? `New Zone : Name = ${v.zone}, Type = Layer3 (${sub} pré-sélectionnée) → OK.` : `La zone ${v.zone} doit exister (type Layer3).` },
        { title: "Adresse IPv4", path: ["Network", "Interfaces", "Ethernet", sub], tab: "IPv4", window: "Layer3 Subinterface",
          fields: [["Type", "Static"], ["IP (Add)", v.ip]] },
      );
      if (v.mgmt) steps.push({ title: "Profil de gestion", path: ["Network", "Interfaces", "Ethernet", sub], tab: "Advanced", window: "Layer3 Subinterface",
        fields: [["Other Info › Management Profile", v.mgmt]], note: `Le profil doit exister — module « Interface Management Profile » (#m05-mgmt-profile).` });
      steps[steps.length - 1].action = (steps[steps.length - 1].action ? steps[steps.length - 1].action + " " : "") + "Cliquer OK.";
      const cli = [
        v.parentSet && `set network interface ethernet ${v.parent} layer3`,
        `${b} tag ${v.tag}`,
        `${b} ip ${v.ip}`,
        v.comment && `${b} comment ${q(v.comment)}`,
        v.mgmt && `${b} interface-management-profile ${q(v.mgmt)}`,
        importNote, importLine([sub]),
        `set network virtual-router ${q(v.vr)} interface ${sub}`,
        `set zone ${q(v.zone)} network layer3 ${sub}`,
      ].filter(Boolean);
      const notes = [{ type: "or", text: `Le port du switch en face doit être en trunk 802.1Q avec le VLAN ${v.tag} autorisé.` }];
      if (String(sfx) !== String(v.tag)) notes.push({ type: "warn", text: `Suffixe (.${sfx}) ≠ tag (${v.tag}) : valide, mais source d'erreurs d'exploitation. Préférer suffixe = tag.` });
      return { steps, cli, notes, verify: [`show interface ${sub}`, `show routing interface`, `ping source ${v.ip.split("/")[0]} host <hôte-VLAN-${v.tag}>`] };
    },
  });

  /* ======================================================================
     m05-mgmt-profile · Interface Management Profile
     ====================================================================== */
  const SVC = [
    ["https", "HTTPS", "Administrative Management Services"], ["ssh", "SSH", "Administrative Management Services"],
    ["http", "HTTP", "Administrative Management Services"], ["telnet", "Telnet", "Administrative Management Services"],
    ["httpOcsp", "HTTP OCSP", "Network Services"], ["ping", "Ping", "Network Services"], ["snmp", "SNMP", "Network Services"],
    ["responsePages", "Response Pages", "Network Services"], ["userid", "User-ID", "Network Services"],
    ["sysSsl", "User-ID Syslog Listener-SSL", "Network Services"], ["sysUdp", "User-ID Syslog Listener-UDP", "Network Services"],
  ];
  const SVCCLI = { https: "https", ssh: "ssh", http: "http", telnet: "telnet", httpOcsp: "http-ocsp", ping: "ping", snmp: "snmp",
    responsePages: "response-pages", userid: "userid-service", sysSsl: "userid-syslog-listener-ssl", sysUdp: "userid-syslog-listener-udp" };
  register({
    id: "m05-mgmt-profile",
    module: "M05",
    title: "Interface Management Profile",
    icon: "🛂",
    desc: "Services autorisés à destination d'une interface de données (ping, HTTPS, SSH, SNMP, Response Pages, User-ID) + rattachement aux interfaces.",
    tags: "interface management profile ping https ssh snmp response pages user-id permitted ip",
    fields: [
      { id: "name", label: "Nom du profil", type: "text", required: true, validate: (x, v) => PAN.cfg.V.name(x) || (SVC.some(([k]) => v[k]) ? null : "Coche au moins un service"), default: "Allow-Mgmt",
        hint: "Ex. Allow-Ping (ping seul, côté Internet) ou Allow-Mgmt (HTTPS/SSH/ping, côté LAN)." },
      ...SVC.map(([k, l, g], i) => ({ id: k, label: l, type: "checkbox", default: ["https", "ssh", "ping"].includes(k), group: i === 0 ? "Administrative Management Services" : i === 4 ? "Network Services" : undefined })),
      { id: "permitted", label: "Permitted IP Addresses", type: "list", validate: "ipcidr", default: ["192.168.1.0/24"], group: "Restriction & rattachement", placeholder: "192.168.1.0/24", hint: "Vide = toute source autorisée." },
      { id: "ifs", label: "Interfaces auxquelles l'attacher", type: "list", validate: ifList, default: ["ethernet1/2"], placeholder: "ethernet1/2, ethernet1/2.10, vlan.10" },
      { id: "testIp", label: "IP de l'interface pour le test (optionnel)", type: "ip", default: "192.168.1.1" },
    ],
    build(v) {
      const on = SVC.filter(([k]) => v[k]);
      const admin = on.filter(([, , g]) => g.startsWith("Admin")).map(([, l]) => l);
      const netw = on.filter(([, , g]) => g.startsWith("Network")).map(([, l]) => l);
      const steps = [{
        title: `Créer le profil ${v.name}`, path: ["Network", "Network Profiles", "Interface Mgmt"], window: "Interface Management Profile",
        action: "Cliquer sur Add, cocher les services, ajouter les IP autorisées puis OK.",
        fields: [["Name", v.name], ["Administrative Management Services", admin], ["Network Services", netw], ["Permitted IP Addresses (Add)", v.permitted]],
      }];
      v.ifs.forEach(i => steps.push({
        title: `Attacher ${v.name} à ${i}`, path: ["Network", "Interfaces", ifTab(i)], tab: "Advanced", window: ifTab(i) === "Ethernet" ? "Ethernet Interface" : `${ifTab(i)} Interface`,
        action: `Ouvrir ${i} → onglet Advanced → Other Info → Management Profile. OK${admin.length ? " puis Yes sur l'avertissement" : ""}.`,
        fields: [["Management Profile", v.name]],
      }));
      const p = `set network profiles interface-management-profile ${q(v.name)}`;
      const cli = [
        `${p} ${on.map(([k]) => `${SVCCLI[k]} yes`).join(" ")}`,
        v.permitted.length && `${p} permitted-ip ${members(v.permitted)}`,
        ...v.ifs.map(i => `set ${l3Base(i)} interface-management-profile ${q(v.name)}`),
      ].filter(Boolean);
      const notes = [];
      if (v.http || v.telnet) notes.push({ type: "bad", title: "Protocoles en clair", text: "HTTP/Telnet transmettent les identifiants en clair : préférer HTTPS/SSH." });
      if (admin.length && !v.permitted.length) notes.push({ type: "warn", text: "Services d'administration ouverts sans Permitted IP : restreindre aux réseaux d'admin." });
      if (admin.length && v.ifs.some(i => i === "ethernet1/1")) notes.push({ type: "warn", text: "Ne jamais exposer HTTPS/SSH sur l'interface côté Internet : utiliser un profil ping seul (Allow-Ping)." });
      if (v.ifs.some(i => /^ethernet\d+\/\d+$/.test(i) === false && /^ethernet/.test(i))) notes.push({ type: "or", text: "Sous-interface : le profil se règle dans l'onglet Advanced de la sous-interface elle-même." });
      notes.push({ type: "or", text: "Profil appliqué uniquement au trafic destiné à l'IP de l'interface où arrive le paquet. Response Pages : requis pour Authentication Portal / pages URL Continue sur l'interface." });
      const verify = v.ifs.map(i => `show interface ${i}`);
      if (v.testIp) notes.push({ type: "ok", title: "Test depuis un poste autorisé", text: [v.ping && `ping ${v.testIp}`, v.ssh && `ssh admin@${v.testIp}`, v.https && `https://${v.testIp}`].filter(Boolean).join("  ·  ") || "—" });
      return { steps, cli, notes, verify };
    },
  });

  /* ======================================================================
     m05-virtual-router · Virtual Router + routes statiques
     ====================================================================== */
  const parseRoute = s => s.split(";").map(x => x.trim());
  register({
    id: "m05-virtual-router",
    module: "M05",
    title: "Virtual Router & routes statiques",
    icon: "🧭",
    desc: "Virtual router (moteur legacy), interfaces membres, route par défaut et routes statiques IPv4.",
    tags: "virtual router vr routage static route default route next hop metric admin distance",
    fields: [
      { id: "name", label: "Nom du virtual router", type: "text", required: true, validate: "name", default: "default", hint: "« default » existe déjà en config usine : on le modifie au lieu d'en ajouter un." },
      { id: "ifs", label: "Interfaces", type: "list", required: true, validate: ifList, default: ["ethernet1/1", "ethernet1/2", "ethernet1/3"] },
      { id: "dflt", label: "Ajouter une route par défaut", type: "checkbox", default: true, group: "Route par défaut" },
      { id: "dName", label: "Nom de la route", type: "text", validate: "name", default: "Default-Route", required: true, show: v => v.dflt },
      { id: "dIf", label: "Interface de sortie", type: "text", required: true, validate: (x, v) => PAN.cfg.V.iface(x) || (v.ifs.includes(x) ? null : "Doit faire partie des interfaces du VR"), default: "ethernet1/1", show: v => v.dflt },
      { id: "dGw", label: "Next Hop IP Address", type: "ip", required: true, default: "203.0.113.1", show: v => v.dflt },
      { id: "routes", label: "Autres routes : destination;next-hop;interface", type: "list", group: "Routes supplémentaires", wide: true,
        placeholder: "10.10.0.0/16;192.168.1.254;ethernet1/2", default: ["10.10.0.0/16;192.168.1.254;ethernet1/2"],
        validate: (arr, v) => {
          for (const r of arr) {
            const [d, g, i] = parseRoute(r);
            if (!d || !g || !i) return `« ${r} » : format destination;next-hop;interface`;
            if (!isCidr(d)) return `« ${r} » : destination IP/masque invalide`;
            const n = net(d); if (n.ip !== n.net) return `« ${r} » : destination non alignée (réseau = ${n.netStr})`;
            if (!PAN.ip.valid(g)) return `« ${r} » : next-hop invalide`;
            if (!v.ifs.includes(i)) return `« ${r} » : ${i} n'est pas dans le VR`;
          }
          return null;
        }, hint: "Une route par entrée, entrées séparées par des virgules. Nom auto : Route-<réseau>." },
      { id: "metric", label: "Metric", type: "number", default: "10", min: 1, max: 65535, group: "Paramètres communs" },
      { id: "ad", label: "Admin Distance (vide = 10)", type: "number", min: 10, max: 240 },
      { id: "testIp", label: "Destination de test (fib-lookup)", type: "ip", default: "8.8.8.8" },
    ],
    build(v) {
      const R = [];
      if (v.dflt) R.push({ name: v.dName, dest: "0.0.0.0/0", gw: v.dGw, ifc: v.dIf });
      v.routes.forEach(r => { const [d, g, i] = parseRoute(r); R.push({ name: "Route-" + d.replace("/", "_"), dest: d, gw: g, ifc: i }); });
      const steps = [{
        title: v.name === "default" ? "Éditer le virtual router default" : `Créer le virtual router ${v.name}`, path: ["Network", "Virtual Routers"], tab: "Router Settings › General", window: "Virtual Router",
        action: v.name === "default" ? "Cliquer sur le lien default." : "Cliquer sur Add.",
        fields: [["Name", v.name], ["Interfaces (Add)", v.ifs]],
        note: "Ajouter une interface ici équivaut à choisir le Virtual Router dans l'onglet Config de l'interface.",
      }];
      R.forEach(r => steps.push({
        title: `Route statique ${r.name}`, path: ["Network", "Virtual Routers", v.name], tab: "Static Routes › IPv4", window: "Virtual Router - Static Route - IPv4",
        action: "Cliquer sur Add en bas de l'onglet IPv4.",
        fields: [["Name", r.name], ["Destination", r.dest], ["Interface", r.ifc], ["Next Hop", "IP Address"], ["(IP)", r.gw], ["Admin Distance", v.ad], ["Metric", v.metric]],
      }));
      if (R.length) steps[steps.length - 1].action += " OK, puis OK sur la fenêtre Virtual Router.";
      const vr = `set network virtual-router ${q(v.name)}`;
      const cli = [`${vr} interface ${members(v.ifs)}`,
        ...R.map(r => `${vr} routing-table ip static-route ${q(r.name)} destination ${r.dest} interface ${r.ifc} nexthop ip-address ${r.gw} metric ${v.metric}${v.ad ? " admin-dist " + v.ad : ""}`)];
      const notes = [{ type: "or", title: "Moteur de routage", text: "PAN-OS 11.0 utilise par défaut le moteur legacy (Virtual Routers). Si l'Advanced Routing Engine est activé (Device > Setup > Management > General Settings), la config se fait dans Network > Routing > Logical Routers." }];
      const names = R.map(r => r.name); if (new Set(names).size !== names.length) notes.push({ type: "bad", text: "Deux routes portent le même nom : la seconde écrasera la première." });
      if (v.name !== "default") notes.push({ type: "warn", text: "Une interface ne peut appartenir qu'à un seul VR : la retirer d'abord du VR default si nécessaire." });
      return { steps, cli, notes, verify: [`show routing route virtual-router ${q(v.name)}`, `show routing fib virtual-router ${q(v.name)}`, `test routing fib-lookup virtual-router ${q(v.name)} ip ${v.testIp || "8.8.8.8"}`] };
    },
  });

  /* ======================================================================
     m05-dhcp-server · Serveur DHCP
     ====================================================================== */
  const poolErr = (p, nw) => {
    let a, b;
    if (p.includes("-")) { [a, b] = p.split("-").map(s => s.trim()); if (!PAN.ip.valid(a) || !PAN.ip.valid(b)) return "plage invalide (ex. 192.168.1.100-192.168.1.200)"; if (toInt(a) > toInt(b)) return "début > fin"; }
    else if (isCidr(p)) { const n = net(p); a = toIp(n.net); b = toIp(n.bcast); }
    else if (PAN.ip.valid(p)) a = b = p;
    else return "plage, IP ou IP/masque attendu";
    if (!nw) return null;
    if (!inNet(a, nw) || !inNet(b, nw)) return `hors du sous-réseau ${nw.netStr}`;
    if (nw.ip >= toInt(a) && nw.ip <= toInt(b)) return "contient l'IP de l'interface";
    return null;
  };
  register({
    id: "m05-dhcp-server",
    module: "M05",
    title: "Serveur DHCP",
    icon: "📡",
    desc: "Serveur DHCP sur une interface Layer3 : pool, réservations, passerelle, masque, DNS, bail.",
    tags: "dhcp server serveur pool lease bail reservation dns gateway",
    fields: [
      { id: "iface", label: "Interface", type: "text", required: true, validate: "iface", default: "ethernet1/2" },
      { id: "ifIp", label: "IP/masque de l'interface", type: "text", required: true, validate: hostCidr, default: "192.168.1.1/24", hint: "Sert à valider le pool (l'interface doit déjà être configurée)." },
      { id: "mode", label: "Mode", type: "select", default: "enabled", options: [["enabled", "enabled"], ["auto", "auto"], ["disabled", "disabled"]] },
      { id: "probe", label: "Ping IP when allocating new IP", type: "checkbox", default: true },
      { id: "lease", label: "Lease", type: "select", default: "timeout", options: [["timeout", "Timeout"], ["unlimited", "Unlimited"]] },
      { id: "leaseMin", label: "Durée du bail (minutes)", type: "number", default: "1440", min: 1, max: 1000000, show: v => v.lease === "timeout", hint: "1440 = 1 jour." },
      { id: "pools", label: "IP Pools", type: "list", required: true, default: ["192.168.1.100-192.168.1.200"], group: "Adressage",
        validate: (arr, v) => { const nw = hostCidr(v.ifIp) ? null : net(v.ifIp); for (const p of arr) { const e = poolErr(p, nw); if (e) return `« ${p} » : ${e}`; } return null; } },
      { id: "reserved", label: "Réservations : IP;MAC (optionnel)", type: "list", wide: true, placeholder: "192.168.1.20;00:50:56:aa:bb:cc",
        validate: (arr, v) => { const nw = hostCidr(v.ifIp) ? null : net(v.ifIp); for (const r of arr) { const [ip, mac] = r.split(";").map(s => (s || "").trim());
          if (!PAN.ip.valid(ip)) return `« ${r} » : IP invalide`; if (nw && !inNet(ip, nw)) return `« ${r} » : hors du sous-réseau`;
          if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac || "")) return `« ${r} » : MAC attendue au format aa:bb:cc:dd:ee:ff`; } return null; } },
      { id: "gw", label: "Gateway", type: "ip", required: true, default: "192.168.1.1", group: "Options",
        validate: (x, v) => !hostCidr(v.ifIp) && !inNet(x, net(v.ifIp)) ? "Passerelle hors du sous-réseau de l'interface" : null },
      { id: "mask", label: "Subnet Mask (vide = déduit)", type: "ip", placeholder: "255.255.255.0" },
      { id: "dns1", label: "Primary DNS", type: "ip", default: "8.8.8.8" },
      { id: "dns2", label: "Secondary DNS", type: "ip", default: "8.8.4.4" },
      { id: "suffix", label: "DNS Suffix", type: "text", validate: "fqdn", placeholder: "corp.local" },
    ],
    build(v) {
      const nw = net(v.ifIp), mask = v.mask || nw.mask;
      const lease = v.lease === "unlimited" ? "Unlimited" : `Timeout ${Math.floor(v.leaseMin / 1440)} j ${Math.floor((v.leaseMin % 1440) / 60)} h ${v.leaseMin % 60} min`;
      const res = v.reserved.map(r => r.split(";").map(s => s.trim()));
      const steps = [
        { title: `Serveur DHCP sur ${v.iface}`, path: ["Network", "DHCP", "DHCP Server"], tab: "Lease", window: "DHCP Server",
          action: "Cliquer sur Add.",
          fields: [["Interface", v.iface], ["Mode", v.mode], ["Ping IP when allocating new IP", v.probe], ["Lease", lease], ["IP Pools (Add)", v.pools], ["Reserved Address (Add)", res.map(([ip, mac]) => `${ip} → ${mac}`)]] },
        { title: "Options DHCP", path: ["Network", "DHCP", "DHCP Server", v.iface], tab: "Options", window: "DHCP Server",
          action: "Onglet Options, puis OK.",
          fields: [["Inheritance Source", "None"], ["Gateway", v.gw], ["Subnet Mask", mask], ["Primary DNS", v.dns1], ["Secondary DNS", v.dns2], ["DNS Suffix", v.suffix]] },
      ];
      const s = `set network dhcp interface ${v.iface} server`;
      const cli = [
        `${s} mode ${v.mode}`,
        `${s} probe-ip ${yn(v.probe)}`,
        `${s} ip-pool ${members(v.pools)}`,
        ...res.map(([ip, mac]) => `${s} reserved ${ip} mac ${mac.toLowerCase()}`),
        v.lease === "unlimited" ? `${s} option lease unlimited` : `${s} option lease timeout ${v.leaseMin}`,
        `${s} option gateway ${v.gw}`,
        `${s} option subnet-mask ${mask}`,
        v.dns1 && `${s} option dns primary ${v.dns1}`,
        v.dns2 && `${s} option dns secondary ${v.dns2}`,
        v.suffix && `${s} option dns-suffix ${q(v.suffix)}`,
      ].filter(Boolean);
      const notes = [];
      if (v.mask && v.mask !== nw.mask) notes.push({ type: "warn", text: `Subnet Mask ${v.mask} ≠ masque de l'interface (${nw.mask}).` });
      if (res.some(([ip]) => v.pools.some(p => poolErr(p, null) === null && (() => { const [a, b] = p.includes("-") ? p.split("-") : [p.split("/")[0], p.split("/")[0]]; return toInt(ip) >= toInt(a) && toInt(ip) <= toInt(b); })())))
        notes.push({ type: "or", text: "Une réservation est dans le pool : autorisé, l'IP est alors retirée de l'allocation dynamique." });
      if (toIp(nw.ip) !== v.gw) notes.push({ type: "or", text: `Passerelle ${v.gw} ≠ IP du firewall (${toIp(nw.ip)}) : vérifier que c'est voulu.` });
      notes.push({ type: "warn", text: "Désactiver tout autre serveur DHCP du segment (ou utiliser le mode auto, qui se met en veille s'il en détecte un)." });
      return { steps, cli, notes, verify: [`show dhcp server settings ${v.iface}`, `show dhcp server lease interface ${v.iface}`] };
    },
  });

  /* ======================================================================
     m05-vwire · Virtual Wire
     ====================================================================== */
  const tagsOk = s => /^\d+(-\d+)?(,\d+(-\d+)?)*$/.test(s) && s.split(/[,-]/).every(x => +x >= 0 && +x <= 4094) ? null : "Tags 0-4094, plage ou liste (ex. 0-4094 ou 10,20,100-200)";
  register({
    id: "m05-vwire",
    module: "M05",
    title: "Virtual Wire",
    icon: "🪢",
    desc: "Insertion transparente (bump-in-the-wire) : 2 interfaces Virtual Wire, l'objet Virtual Wire et 2 zones.",
    tags: "virtual wire vwire transparent bump in the wire tag allowed link state pass through",
    fields: [
      { id: "name", label: "Nom du Virtual Wire", type: "text", required: true, validate: "name", default: "VW-1" },
      { id: "if1", label: "Interface 1", type: "text", required: true, validate: physIf, default: "ethernet1/4" },
      { id: "if2", label: "Interface 2", type: "text", required: true, validate: (x, v) => physIf(x) || (x === v.if1 ? "Doit différer de l'interface 1" : null), default: "ethernet1/5" },
      { id: "z1", label: "Zone de l'interface 1", type: "text", required: true, validate: "name", default: "VW-Trust", group: "Zones" },
      { id: "z2", label: "Zone de l'interface 2", type: "text", required: true, validate: (x, v) => PAN.cfg.V.name(x) || (x === v.z1 ? "Utiliser deux zones distinctes" : null), default: "VW-Untrust" },
      { id: "tags", label: "Tag Allowed", type: "text", validate: tagsOk, default: "0-4094", group: "Options", hint: "Vide = trafic non tagué uniquement. 0 = non tagué." },
      { id: "mcast", label: "Multicast Firewalling", type: "checkbox", default: false },
      { id: "lsp", label: "Link State Pass Through", type: "checkbox", default: true },
    ],
    build(v) {
      const steps = [v.if1, v.if2].map(i => ({
        title: `Passer ${i} en Virtual Wire`, path: ["Network", "Interfaces", "Ethernet"], tab: "Config", window: "Ethernet Interface",
        action: `Cliquer sur ${i}, Interface Type = Virtual Wire, laisser Virtual Wire et Security Zone sur None, OK.`,
        fields: [["Interface Type", "Virtual Wire"]],
      }));
      steps.push({ title: `Créer le Virtual Wire ${v.name}`, path: ["Network", "Virtual Wires"], window: "Virtual Wire", action: "Cliquer sur Add.",
        fields: [["Name", v.name], ["Interface1", v.if1], ["Interface2", v.if2], ["Tag Allowed", v.tags], ["Multicast Firewalling", v.mcast], ["Link State Pass Through", v.lsp]] });
      [[v.z1, v.if1], [v.z2, v.if2]].forEach(([z, i]) => steps.push({ title: `Créer la zone ${z}`, path: ["Network", "Zones"], window: "Zone", action: "Cliquer sur Add.",
        fields: [["Name", z], ["Type", "Virtual Wire"], ["Interfaces (Add)", i]] }));
      const w = `set network virtual-wire ${q(v.name)}`;
      const cli = [
        `set network interface ethernet ${v.if1} virtual-wire`, `set network interface ethernet ${v.if2} virtual-wire`,
        importNote, importLine([v.if1, v.if2]),
        `${w} interface1 ${v.if1} interface2 ${v.if2}`,
        v.tags && `${w} tag-allowed ${v.tags}`,
        `${w} multicast-firewalling enable ${yn(v.mcast)}`,
        `${w} link-state-pass-through enable ${yn(v.lsp)}`,
        `set zone ${q(v.z1)} network virtual-wire ${v.if1}`,
        `set zone ${q(v.z2)} network virtual-wire ${v.if2}`,
      ].filter(Boolean);
      const notes = [
        { type: "warn", text: `Sans règle de sécurité ${v.z1} ↔ ${v.z2}, le trafic est bloqué par la règle interzone-default : créer les règles dans les deux sens (M06).` },
        { type: "or", text: "Config usine : le « default-vwire » utilise ethernet1/1 et ethernet1/2 (zones trust/untrust). Le supprimer s'il entre en conflit." },
      ];
      if (!v.tags) notes.push({ type: "warn", text: "Tag Allowed vide : le trafic 802.1Q tagué sera rejeté." });
      return { steps, cli, notes, verify: [`show interface ${v.if1}`, `show interface ${v.if2}`, "show session all filter from " + q(v.z1)] };
    },
  });

  /* ======================================================================
     m05-layer2-vlan · Interfaces Layer 2 + VLAN + interface VLAN
     ====================================================================== */
  register({
    id: "m05-layer2-vlan",
    module: "M05",
    title: "Layer 2, VLAN & interface VLAN",
    icon: "🔗",
    desc: "Interfaces Layer2 regroupées dans un objet VLAN, zone Layer2 et interface VLAN (SVI) routée optionnelle.",
    tags: "layer2 l2 vlan switch svi interface vlan bridge",
    fields: [
      { id: "ifs", label: "Interfaces Layer2", type: "list", required: true, default: ["ethernet1/6", "ethernet1/7"],
        validate: arr => { for (const x of arr) { const e = physIf(x); if (e) return `« ${x} » : ${e}`; } return new Set(arr).size === arr.length ? null : "Interface en double"; } },
      { id: "vlan", label: "Nom de l'objet VLAN", type: "text", required: true, validate: "name", default: "VLAN-20" },
      { id: "zone", label: "Zone Layer2", type: "text", required: true, validate: "name", default: "L2-Users" },
      { id: "svi", label: "Créer une interface VLAN (routage L3)", type: "checkbox", default: true, group: "Interface VLAN (SVI)" },
      { id: "sviName", label: "Interface VLAN", type: "text", required: true, default: "vlan.20", show: v => v.svi, validate: x => /^vlan\.\d{1,4}$/.test(x) && +x.split(".")[1] >= 1 && +x.split(".")[1] <= 9999 ? null : "Format vlan.N (ex. vlan.20)" },
      { id: "sviIp", label: "IP/masque", type: "text", required: true, validate: hostCidr, default: "192.168.20.1/24", show: v => v.svi },
      { id: "sviVr", label: "Virtual Router", type: "text", required: true, validate: "name", default: "default", show: v => v.svi },
      { id: "sviZone", label: "Zone Layer3 de l'interface VLAN", type: "text", required: true, default: "L3-Users-VLAN20", show: v => v.svi,
        validate: (x, v) => PAN.cfg.V.name(x) || (x === v.zone ? "Doit différer de la zone Layer2 (types différents)" : null) },
      { id: "mgmt", label: "Interface Management Profile (optionnel)", type: "text", validate: "name", placeholder: "Allow-Ping", show: v => v.svi },
    ],
    build(v) {
      const steps = v.ifs.map(i => ({ title: `Passer ${i} en Layer2`, path: ["Network", "Interfaces", "Ethernet"], tab: "Config", window: "Ethernet Interface",
        action: `Cliquer sur ${i}, Interface Type = Layer2, OK.`, fields: [["Interface Type", "Layer2"], ["VLAN", "None"], ["Security Zone", "None"]] }));
      steps.push({ title: `Créer la zone ${v.zone}`, path: ["Network", "Zones"], window: "Zone", action: "Cliquer sur Add.",
        fields: [["Name", v.zone], ["Type", "Layer2"], ["Interfaces (Add)", v.ifs]] });
      steps.push({ title: `Créer l'objet VLAN ${v.vlan}`, path: ["Network", "VLANs"], window: "VLAN", action: "Cliquer sur Add.",
        fields: [["Name", v.vlan], ["VLAN Interface", "None"], ["Interfaces (Add)", v.ifs]],
        note: v.svi ? "L'interface VLAN sera liée à cet objet à l'étape suivante." : "" });
      if (v.svi) steps.push(
        { title: `Créer l'interface ${v.sviName}`, path: ["Network", "Interfaces", "VLAN"], tab: "Config", window: "VLAN Interface", action: "Cliquer sur Add.",
          fields: [["Interface Name", `vlan . ${v.sviName.split(".")[1]}`], ["VLAN", v.vlan], ["Virtual Router", v.sviVr], ["Security Zone", `New Zone → ${v.sviZone} (Layer3)`]] },
        { title: "Adresse IPv4 et profil de gestion", path: ["Network", "Interfaces", "VLAN", v.sviName], tab: "IPv4", window: "VLAN Interface",
          action: "Onglet IPv4 → Static → Add. Onglet Advanced → Management Profile. OK.",
          fields: [["Type", "Static"], ["IP", v.sviIp], ["Advanced › Management Profile", v.mgmt]] },
      );
      const cli = [...v.ifs.map(i => `set network interface ethernet ${i} layer2`), importNote,
        importLine(v.svi ? [...v.ifs, v.sviName] : v.ifs),
        `set zone ${q(v.zone)} network layer2 ${members(v.ifs)}`,
        `set network vlan ${q(v.vlan)} interface ${members(v.ifs)}`];
      if (v.svi) cli.push(
        `set network interface vlan units ${v.sviName} ip ${v.sviIp}`,
        v.mgmt && `set network interface vlan units ${v.sviName} interface-management-profile ${q(v.mgmt)}`,
        `set network vlan ${q(v.vlan)} virtual-interface interface ${v.sviName}`,
        `set network virtual-router ${q(v.sviVr)} interface ${v.sviName}`,
        `set zone ${q(v.sviZone)} network layer3 ${v.sviName}`);
      const notes = [
        { type: "or", text: "Interfaces Layer2 non taguées = ports d'accès. Pour un trunk : sous-interfaces Layer2 (Add Subinterface, Tag) ajoutées à l'objet VLAN." },
        { type: "warn", text: `Le trafic entre interfaces de ${v.zone} est intrazone (autorisé par défaut). Vers ${v.svi ? v.sviZone + " / autres zones" : "les autres zones"}, une règle de sécurité est requise.` },
      ];
      return { steps, cli: cli.filter(Boolean), notes, verify: [`show vlan all`, `show mac all`, ...(v.svi ? [`show interface ${v.sviName}`, `show arp ${v.sviName}`] : [])] };
    },
  });

  /* ======================================================================
     m05-tap · Interface Tap
     ====================================================================== */
  register({
    id: "m05-tap",
    module: "M05",
    title: "Interface Tap (SPAN)",
    icon: "👁️",
    desc: "Visibilité passive sur un port miroir (SPAN) : interface Tap, zone Tap et règle d'autorisation avec logs.",
    tags: "tap span mirror port miroir visibilité passive",
    fields: [
      { id: "iface", label: "Interface", type: "text", required: true, validate: physIf, default: "ethernet1/8" },
      { id: "zone", label: "Zone Tap", type: "text", required: true, validate: "name", default: "Tap-Zone" },
      { id: "rule", label: "Créer la règle Tap (allow + log)", type: "checkbox", default: true, group: "Règle de sécurité" },
      { id: "ruleName", label: "Nom de la règle", type: "text", required: true, validate: "name", default: "Tap-Visibility", show: v => v.rule },
      { id: "profGroup", label: "Groupe de profils (optionnel)", type: "text", validate: "name", placeholder: "Std-Profiles", show: v => v.rule, hint: "Pour obtenir aussi les logs Threat." },
    ],
    build(v) {
      const steps = [
        { title: `Passer ${v.iface} en Tap`, path: ["Network", "Interfaces", "Ethernet"], tab: "Config", window: "Ethernet Interface",
          action: `Cliquer sur ${v.iface}.`, fields: [["Interface Type", "Tap"], ["Security Zone", `New Zone → ${v.zone} (Tap)`]] },
      ];
      if (v.rule) steps.push(
        { title: `Règle ${v.ruleName}`, path: ["Policies", "Security"], tab: "General / Source / Destination", window: "Security Policy Rule", action: "Cliquer sur Add.",
          fields: [["Name", v.ruleName], ["Source Zone", v.zone], ["Destination Zone", v.zone], ["Application", "Any"], ["Service", "any"]] },
        { title: "Action et logs", path: ["Policies", "Security", v.ruleName], tab: "Actions", window: "Security Policy Rule", action: "Onglet Actions, puis OK.",
          fields: [["Action", "Allow"], ["Profile Type", v.profGroup ? "Group" : ""], ["Group Profile", v.profGroup], ["Log at Session End", true]] });
      const r = `set rulebase security rules ${q(v.ruleName)}`;
      const cli = [`set network interface ethernet ${v.iface} tap`, importNote, importLine([v.iface]), `set zone ${q(v.zone)} network tap ${v.iface}`];
      if (v.rule) cli.push(`${r} from ${q(v.zone)} to ${q(v.zone)} source any destination any source-user any application any service any category any action allow log-end yes`,
        v.profGroup && `${r} profile-setting group ${q(v.profGroup)}`);
      const notes = [
        { type: "or", text: "Configurer le port miroir (SPAN/RSPAN) sur le switch vers cette interface. Le firewall ne peut pas bloquer : visibilité uniquement." },
        { type: "warn", text: "Pas de décryptage SSL Forward Proxy possible en Tap ; le trafic asymétrique (un seul sens vu) limite l'identification App-ID." },
      ];
      return { steps, cli: cli.filter(Boolean), notes, verify: [`show interface ${v.iface}`, `show session all filter from ${q(v.zone)}`] };
    },
  });
})();
