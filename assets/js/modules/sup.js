/* Modules SUP : VPN IPsec site-à-site, GlobalProtect, HA actif/passif, Zone Protection, DoS Protection, Service Routes */
(function () {
  const { register, q, members, yn, V } = PAN.cfg;
  const both = (k, fn) => (val, v) => (Array.isArray(val) ? V.listOf(k)(val) : typeof k === "function" ? k(val) : V[k](val)) || fn(val, v);

  /* ---------- helpers IP locaux ---------- */
  const ipInt = s => PAN.ip.toInt(String(s).trim());
  const cidrRange = c => {
    const [a, m] = String(c).split("/"); const p = m === undefined ? 32 : +m;
    const mask = p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0;
    const net = (ipInt(a) & mask) >>> 0;
    return [net, (net | (~mask >>> 0)) >>> 0];
  };
  const overlap = (a, b) => { const [s1, e1] = cidrRange(a), [s2, e2] = cidrRange(b); return s1 <= e2 && s2 <= e1; };
  const inCidr = (ip, c) => { const [s, e] = cidrRange(c), n = ipInt(ip); return n >= s && n <= e; };
  const ipOf = c => String(c).split("/")[0];
  const maskOk = m => { if (!PAN.ip.valid(m)) return false; const n = ipInt(m); return ((~n >>> 0) & ((~n >>> 0) + 1)) === 0; };
  const prefixToMask = p => { const n = p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0; return [24, 16, 8, 0].map(s => (n >>> s) & 255).join("."); };
  const sameSubnet = (a, b, mask) => maskOk(mask) && ((ipInt(a) & ipInt(mask)) >>> 0) === ((ipInt(b) & ipInt(mask)) >>> 0);
  const tunnelIf = v => /^tunnel\.\d{1,4}$/.test(v) && +v.split(".")[1] >= 1 && +v.split(".")[1] <= 9999 ? null : "Format tunnel.N (N entre 1 et 9999)";
  const ethIf = v => /^ethernet\d+\/\d+$/.test(v) ? null : "Interface physique attendue (ex. ethernet1/4)";
  const rangeOrCidr = v => {
    if (PAN.ip.validCidr(v) && v.includes("/")) return null;
    const m = String(v).split("-");
    if (m.length === 2 && PAN.ip.valid(m[0]) && PAN.ip.valid(m[1])) return ipInt(m[0]) <= ipInt(m[1]) ? null : "Début de plage > fin de plage";
    return "Plage (10.10.10.1-10.10.10.50) ou réseau (10.10.10.0/24) attendu";
  };
  const poolNets = v => {
    if (v.includes("/")) return [v];
    const [a, b] = v.split("-"); return [a + "/32", b + "/32"];
  };
  const link = (id, label) => `<a href="#${id}">Module « ${PAN.esc(label)} » (#${id})</a>`;
  const rate = (min, max) => (val) => /^\d+$/.test(val) && +val >= min && +val <= max ? null : `Entier entre ${min} et ${max}`;
  const ratesOk = (pfx) => (val, v) => {
    const a = +v[pfx + "Alarm"], b = +v[pfx + "Act"], c = +v[pfx + "Max"];
    if ([a, b, c].some(isNaN)) return null;
    return a <= b && b <= c ? null : "Attendu : Alarm ≤ Activate ≤ Maximum";
  };

  /* =====================================================================
     SUP · VPN IPsec site-à-site (route-based)
     ===================================================================== */
  register({
    id: "sup-ipsec-s2s",
    module: "SUP",
    title: "VPN IPsec site-à-site",
    icon: "🔐",
    desc: "Tunnel IPsec route-based complet : zone VPN, interface tunnel, profils IKE/IPsec, IKE Gateway, IPsec Tunnel, routes statiques et règles de sécurité.",
    tags: "vpn ipsec ike site-to-site tunnel proxy-id psk",
    fields: [
      { id: "outIf", label: "Interface externe (locale)", type: "text", required: true, validate: "iface", default: "ethernet1/1", group: "Extrémités du tunnel" },
      { id: "outIp", label: "IP publique locale (IP/masque de l'interface)", type: "cidr", required: true, default: "203.0.113.10/24" },
      { id: "outZone", label: "Zone de l'interface externe", type: "text", required: true, validate: "name", default: "Untrust" },
      { id: "peerIp", label: "IP publique du peer", type: "ip", required: true, default: "198.51.100.10",
        validate: (val, v) => PAN.ip.valid(ipOf(v.outIp)) && val === ipOf(v.outIp) ? "Le peer doit être différent de l'IP locale" : null },
      { id: "psk", label: "Clé pré-partagée (PSK)", type: "password", required: true, default: "Ch@ngeMe-Psk-2024!",
        validate: val => val.length < 12 ? "12 caractères minimum recommandés" : val.length > 255 ? "255 caractères maximum" : null,
        hint: "Identique des deux côtés. Mélange majuscules, chiffres et symboles." },
      { id: "ikeVer", label: "Version IKE", type: "select", default: "ikev2",
        options: [["ikev2", "IKEv2 only mode"], ["ikev1", "IKEv1 only mode"], ["ikev2-preferred", "IKEv2 preferred mode"]] },
      { id: "passive", label: "Mode passif (le pare-feu n'initie jamais le tunnel)", type: "checkbox", default: false },
      { id: "natt", label: "NAT Traversal (peer ou firewall derrière un NAT)", type: "checkbox", default: false },

      { id: "localNets", label: "Réseaux locaux (CIDR, séparés par des virgules)", type: "list", required: true, validate: "cidr", default: ["192.168.1.0/24"], group: "Réseaux protégés", wide: true },
      { id: "remoteNets", label: "Réseaux distants (CIDR)", type: "list", required: true, default: ["10.20.0.0/24"], wide: true,
        validate: (arr, v) => {
          for (const r of arr) { if (!PAN.ip.validCidr(r) || !r.includes("/")) return `« ${r} » : format IP/masque attendu`; }
          for (const r of arr) for (const l of (v.localNets || [])) if (PAN.ip.validCidr(l) && overlap(r, l)) return `« ${r} » chevauche le réseau local « ${l} »`;
          return null;
        } },
      { id: "usersZone", label: "Zone des réseaux locaux", type: "text", required: true, validate: "name", default: "Trust" },

      { id: "ikeProf", label: "Nom du profil IKE Crypto", type: "text", required: true, validate: "name", default: "IKE-AES256-SHA256-DH14", group: "Phase 1 — IKE Crypto" },
      { id: "ikeDh", label: "DH Group", type: "select", default: "group14",
        options: [["group14", "group14 (2048 bits)"], ["group19", "group19 (ECP 256)"], ["group20", "group20 (ECP 384)"], ["group21", "group21 (ECP 521)"], ["group5", "group5 (déconseillé)"], ["group2", "group2 (déconseillé)"]] },
      { id: "ikeHash", label: "Authentication", type: "select", default: "sha256", options: [["sha256"], ["sha384"], ["sha512"], ["sha1", "sha1 (déconseillé)"]] },
      { id: "ikeEnc", label: "Encryption", type: "select", default: "aes-256-cbc",
        options: [["aes-256-cbc"], ["aes-192-cbc"], ["aes-128-cbc"], ["aes-256-gcm", "aes-256-gcm (IKEv2 uniquement)"], ["aes-128-gcm", "aes-128-gcm (IKEv2 uniquement)"], ["3des", "3des (déconseillé)"]],
        validate: (val, v) => /gcm/.test(val) && v.ikeVer !== "ikev2" ? "GCM en phase 1 n'est supporté qu'en mode « IKEv2 only »" : null },
      { id: "ikeLife", label: "Key Lifetime (heures)", type: "number", default: "8", min: 1, max: 65535, required: true },

      { id: "ipsecProf", label: "Nom du profil IPsec Crypto", type: "text", required: true, validate: "name", default: "IPSEC-AES256-DH14", group: "Phase 2 — IPsec Crypto" },
      { id: "espEnc", label: "ESP Encryption", type: "select", default: "aes-256-gcm",
        options: [["aes-256-gcm"], ["aes-128-gcm"], ["aes-256-cbc"], ["aes-192-cbc"], ["aes-128-cbc"], ["3des", "3des (déconseillé)"]] },
      { id: "espAuth", label: "ESP Authentication", type: "select", default: "sha256",
        options: [["sha256"], ["sha384"], ["sha512"], ["sha1", "sha1 (déconseillé)"]], show: v => !/gcm/.test(v.espEnc),
        hint: "Avec AES-GCM, l'authentification est intégrée (Authentication = none)." },
      { id: "pfs", label: "DH Group (PFS)", type: "select", default: "group14",
        options: [["group14"], ["group19"], ["group20"], ["group21"], ["group5"], ["group2"], ["no-pfs", "no-pfs (pas de PFS)"]] },
      { id: "ipsecLife", label: "Lifetime (heures)", type: "number", default: "1", min: 1, max: 65535, required: true },

      { id: "gwName", label: "Nom de l'IKE Gateway", type: "text", required: true, validate: "name", default: "IKE-GW-Site-B", group: "Tunnel & routage" },
      { id: "tunName", label: "Nom de l'IPsec Tunnel", type: "text", required: true, validate: "name", default: "IPSec-Site-B" },
      { id: "tunIf", label: "Interface tunnel", type: "text", required: true, validate: tunnelIf, default: "tunnel.1" },
      { id: "tunIp", label: "IP de l'interface tunnel (optionnelle)", type: "cidr", default: "",
        hint: "Requise seulement pour le tunnel monitor ou un routage dynamique (ex. 169.254.10.1/30)." },
      { id: "vpnZone", label: "Zone VPN", type: "text", required: true, validate: "name", default: "VPN" },
      { id: "vr", label: "Virtual Router", type: "text", required: true, validate: "name", default: "default" },
      { id: "proxy", label: "Configurer des Proxy IDs (peer policy-based : ASA, Check Point, strongSwan…)", type: "checkbox", default: false, wide: true },
      { id: "monitor", label: "Tunnel monitor", type: "checkbox", default: false },
      { id: "monDst", label: "IP surveillée (côté distant)", type: "ip", required: true, default: "169.254.10.2", show: v => v.monitor,
        validate: (val, v) => !v.tunIp ? "Renseigne d'abord l'IP de l'interface tunnel" : null },
      { id: "rules", label: "Créer les règles de sécurité Trust ↔ VPN", type: "checkbox", default: true, group: "Politique" },
    ],
    build(v) {
      const gcm = /gcm/.test(v.espEnc);
      const espAuth = gcm ? "none" : v.espAuth;
      const verLabel = { ikev2: "IKEv2 only mode", ikev1: "IKEv1 only mode", "ikev2-preferred": "IKEv2 preferred mode" }[v.ikeVer];
      const pids = [];
      if (v.proxy) v.localNets.forEach(l => v.remoteNets.forEach(r => pids.push({ name: `PID-${pids.length + 1}`, l, r })));
      const useV1 = v.ikeVer !== "ikev2", useV2 = v.ikeVer !== "ikev1";

      const steps = [
        { title: "Créer la zone VPN", path: ["Network", "Zones"], action: "Add. Les interfaces seront rattachées à l'étape suivante.", window: "Zone",
          fields: [["Name", v.vpnZone], ["Type", "Layer3"]],
          note: "Une zone dédiée au tunnel permet d'écrire des règles explicites Trust ↔ VPN." },
        { title: `Créer l'interface ${v.tunIf}`, path: ["Network", "Interfaces", "Tunnel"], action: "Add.", window: "Tunnel Interface",
          fields: [["Interface Name", "tunnel . " + v.tunIf.split(".")[1]], ["Config › Virtual Router", v.vr], ["Config › Security Zone", v.vpnZone], ["IPv4 › IP", v.tunIp]] },
        { title: "Créer le profil IKE Crypto (phase 1)", path: ["Network", "Network Profiles", "IKE Crypto"], action: "Add.", window: "IKE Crypto Profile",
          fields: [["Name", v.ikeProf], ["DH Group", v.ikeDh], ["Authentication", v.ikeHash], ["Encryption", v.ikeEnc], ["Key Lifetime", `Hours : ${v.ikeLife}`]],
          note: "Les valeurs doivent correspondre exactement à celles du peer." },
        { title: "Créer le profil IPsec Crypto (phase 2)", path: ["Network", "Network Profiles", "IPSec Crypto"], action: "Add.", window: "IPSec Crypto Profile",
          fields: [["Name", v.ipsecProf], ["IPSec Protocol", "ESP"], ["Encryption", v.espEnc], ["Authentication", espAuth], ["DH Group", v.pfs], ["Lifetime", `Hours : ${v.ipsecLife}`]] },
        { title: "Créer l'IKE Gateway — onglet General", path: ["Network", "Network Profiles", "IKE Gateways"], tab: "General", action: "Add.", window: "IKE Gateway",
          fields: [["Name", v.gwName], ["Version", verLabel], ["Address Type", "IPv4"], ["Interface", v.outIf], ["Local IP Address", v.outIp],
            ["Peer IP Address Type", "IP"], ["Peer Address", v.peerIp], ["Authentication", "Pre-Shared Key"], ["Pre-shared Key", "•••••• (PSK saisie)"], ["Confirm Pre-shared Key", "•••••• (PSK saisie)"],
            ["Local Identification", "None"], ["Peer Identification", "None"]] },
        { title: "IKE Gateway — onglet Advanced Options", path: ["Network", "Network Profiles", "IKE Gateways", v.gwName], tab: "Advanced Options", window: "IKE Gateway",
          fields: [["Enable Passive Mode", v.passive], ["Enable NAT Traversal", v.natt],
            ...(useV1 ? [["IKEv1 › Exchange Mode", "main"], ["IKEv1 › IKE Crypto Profile", v.ikeProf], ["IKEv1 › Dead Peer Detection", true]] : []),
            ...(useV2 ? [["IKEv2 › IKE Crypto Profile", v.ikeProf], ["IKEv2 › Liveness Check", true]] : [])] },
        { title: "Créer l'IPsec Tunnel — onglet General", path: ["Network", "IPSec Tunnels"], tab: "General", action: "Add.", window: "IPSec Tunnel",
          fields: [["Name", v.tunName], ["Tunnel Interface", v.tunIf], ["Type", "Auto Key"], ["Address Type", "IPv4"], ["IKE Gateway", v.gwName], ["IPSec Crypto Profile", v.ipsecProf],
            ["Show Advanced Options", true], ["Enable Replay Protection", true],
            ...(v.monitor ? [["Tunnel Monitor", true], ["Destination IP", v.monDst], ["Profile", "default"]] : [])] },
      ];
      if (pids.length) steps.push({ title: "IPsec Tunnel — onglet Proxy IDs", path: ["Network", "IPSec Tunnels", v.tunName], tab: "Proxy IDs", window: "Proxy ID",
        action: `Sous-onglet IPv4 › Add, une entrée par couple local/distant (${pids.length}).`,
        fields: pids.map(p => [`${p.name} (Local › Remote, Protocol Any)`, `${p.l} › ${p.r}`]),
        note: "Chaque Proxy ID négocie sa propre SA ; ils doivent être le miroir exact de ceux du peer." });
      steps.push({ title: "Router les réseaux distants dans le tunnel", path: ["Network", "Virtual Routers", v.vr, "Static Routes"], tab: "IPv4", window: "Virtual Router - Static Route - IPv4",
        action: `Add une route par réseau distant (${v.remoteNets.length}).`,
        fields: v.remoteNets.map((r, i) => [`Route-VPN-${i + 1} › Destination / Interface / Next Hop`, `${r} / ${v.tunIf} / None`]) });
      if (v.rules) steps.push(
        { title: "Règle sortante vers le site distant", path: ["Policies", "Security"], action: "Add (placer avant toute règle de blocage).", window: "Security Policy Rule",
          fields: [["General › Name", "Trust-to-VPN"], ["Source › Source Zone", v.usersZone], ["Source › Source Address", v.localNets], ["Destination › Destination Zone", v.vpnZone],
            ["Destination › Destination Address", v.remoteNets], ["Application", "any"], ["Service/URL Category › Service", "any"], ["Actions › Action", "Allow"], ["Actions › Log at Session End", true]] },
        { title: "Règle entrante depuis le site distant", path: ["Policies", "Security"], action: "Add.", window: "Security Policy Rule",
          fields: [["General › Name", "VPN-to-Trust"], ["Source › Source Zone", v.vpnZone], ["Source › Source Address", v.remoteNets], ["Destination › Destination Zone", v.usersZone],
            ["Destination › Destination Address", v.localNets], ["Application", "any"], ["Service/URL Category › Service", "any"], ["Actions › Action", "Allow"], ["Actions › Log at Session End", true]],
          note: "Affine ensuite les applications (App-ID) selon les flux réellement nécessaires." });

      const P = `set network ike crypto-profiles`;
      const G = `set network ike gateway ${q(v.gwName)}`;
      const T = `set network tunnel ipsec ${q(v.tunName)}`;
      const cli = [
        `# Zone + interface tunnel`,
        `set network interface tunnel units ${v.tunIf} comment ${q("VPN " + v.gwName)}`,
        v.tunIp && `set network interface tunnel units ${v.tunIf} ip ${v.tunIp}`,
        `set zone ${q(v.vpnZone)} network layer3 ${v.tunIf}`,
        `set network virtual-router ${q(v.vr)} interface ${v.tunIf}`,
        `# Phase 1`,
        `${P} ike-crypto-profiles ${q(v.ikeProf)} dh-group ${v.ikeDh}`,
        `${P} ike-crypto-profiles ${q(v.ikeProf)} hash ${v.ikeHash}`,
        `${P} ike-crypto-profiles ${q(v.ikeProf)} encryption ${v.ikeEnc}`,
        `${P} ike-crypto-profiles ${q(v.ikeProf)} lifetime hours ${v.ikeLife}`,
        `# Phase 2`,
        `${P} ipsec-crypto-profiles ${q(v.ipsecProf)} esp encryption ${v.espEnc}`,
        `${P} ipsec-crypto-profiles ${q(v.ipsecProf)} esp authentication ${espAuth}`,
        `${P} ipsec-crypto-profiles ${q(v.ipsecProf)} dh-group ${v.pfs}`,
        `${P} ipsec-crypto-profiles ${q(v.ipsecProf)} lifetime hours ${v.ipsecLife}`,
        `# IKE Gateway`,
        `${G} protocol version ${v.ikeVer}`,
        useV1 && `${G} protocol ikev1 ike-crypto-profile ${q(v.ikeProf)} exchange-mode main`,
        useV1 && `${G} protocol ikev1 dpd enable yes`,
        useV2 && `${G} protocol ikev2 ike-crypto-profile ${q(v.ikeProf)}`,
        useV2 && `${G} protocol ikev2 dpd enable yes`,
        `${G} local-address interface ${v.outIf} ip ${v.outIp}`,
        `${G} peer-address ip ${v.peerIp}`,
        `${G} authentication pre-shared-key key ${q(v.psk)}`,
        `${G} protocol-common passive-mode ${yn(v.passive)}`,
        `${G} protocol-common nat-traversal enable ${yn(v.natt)}`,
        `# IPsec Tunnel`,
        `${T} tunnel-interface ${v.tunIf}`,
        `${T} auto-key ike-gateway ${q(v.gwName)}`,
        `${T} auto-key ipsec-crypto-profile ${q(v.ipsecProf)}`,
        `${T} anti-replay yes`,
        ...pids.map(p => `${T} auto-key proxy-id ${p.name} local ${p.l} remote ${p.r} protocol any`),
        v.monitor && `${T} tunnel-monitor enable yes destination-ip ${v.monDst} tunnel-monitor-profile default`,
        `# Routes vers les réseaux distants`,
        ...v.remoteNets.map((r, i) => `set network virtual-router ${q(v.vr)} routing-table ip static-route Route-VPN-${i + 1} destination ${r} interface ${v.tunIf}`),
        ...(v.rules ? [
          `# Règles de sécurité`,
          `set rulebase security rules Trust-to-VPN from ${q(v.usersZone)} to ${q(v.vpnZone)} source ${members(v.localNets)} destination ${members(v.remoteNets)} application any service any action allow log-end yes`,
          `set rulebase security rules VPN-to-Trust from ${q(v.vpnZone)} to ${q(v.usersZone)} source ${members(v.remoteNets)} destination ${members(v.localNets)} application any service any action allow log-end yes`,
        ] : []),
      ].filter(Boolean);

      const notes = [
        { type: "or", title: "Trafic IKE/ESP vers le pare-feu", text: `IKE (UDP 500/4500) et ESP arrivent sur ${ipOf(v.outIp)} depuis la zone ${v.outZone} : c'est du trafic intrazone (${v.outZone} → ${v.outZone}), autorisé par la règle par défaut « intrazone-default ». Si une règle « deny any any » ou une intrazone-default modifiée précède, ajoute une règle ${v.outZone} → ${v.outZone}, destination ${ipOf(v.outIp)}, applications ike, ipsec-esp, ipsec-esp-udp.` },
        { type: "warn", text: "Le peer doit avoir la configuration miroir : mêmes propositions phase 1/2, même PSK, réseaux local/distant inversés." },
      ];
      if (!v.proxy) notes.push({ type: "or", text: "Sans Proxy ID, PAN-OS négocie 0.0.0.0/0 ↔ 0.0.0.0/0. Si le peer est policy-based (ASA, Check Point…), coche « Proxy IDs » sinon la phase 2 échoue (TS_UNACCEPTABLE / no proposal chosen)." });
      if (v.natt === false && PAN.ip.isPrivate(ipOf(v.outIp))) notes.push({ type: "warn", text: "L'IP locale est privée : le pare-feu est probablement derrière un NAT, active NAT Traversal." });
      if (v.passive) notes.push({ type: "warn", text: "Mode passif : le tunnel ne montera que si le peer initie. test vpn ike-sa ne fonctionnera pas depuis ce pare-feu." });

      return {
        steps, cli, notes,
        verify: [
          `test vpn ike-sa gateway ${q(v.gwName)}`,
          `test vpn ipsec-sa tunnel ${q(v.tunName)}`,
          `show vpn ike-sa gateway ${q(v.gwName)}`,
          `show vpn ipsec-sa tunnel ${q(v.tunName)}`,
          `show vpn flow`,
          `show routing route destination ${v.remoteNets[0]}`,
          `less mp-log ikemgr.log`,
        ],
      };
    },
  });

  /* =====================================================================
     SUP · GlobalProtect Portal + Gateway
     ===================================================================== */
  register({
    id: "sup-globalprotect",
    module: "SUP",
    title: "GlobalProtect Portal & Gateway",
    icon: "🌐",
    desc: "Accès distant GlobalProtect sur un seul pare-feu : certificats, profil SSL/TLS, interface tunnel, Gateway, Portal, activation du client et règles.",
    tags: "globalprotect gp vpn remote access portal gateway ssl certificat",
    fields: [
      { id: "fqdn", label: "FQDN public du portail/gateway", type: "text", required: true, validate: "fqdn", default: "vpn.example.com", group: "Accès externe",
        hint: "Doit résoudre (DNS public) vers l'IP de l'interface externe." },
      { id: "outIf", label: "Interface externe", type: "text", required: true, validate: "iface", default: "ethernet1/1" },
      { id: "outIp", label: "IP de l'interface externe (IP/masque)", type: "cidr", required: true, default: "203.0.113.10/24" },
      { id: "outZone", label: "Zone externe", type: "text", required: true, validate: "name", default: "Untrust" },

      { id: "caName", label: "Nom du certificat CA (auto-signé)", type: "text", required: true, validate: "name", default: "GP-Root-CA", group: "Certificats" },
      { id: "certName", label: "Nom du certificat serveur", type: "text", required: true, default: "GP-Server-Cert",
        validate: both("name", (val, v) => val === v.caName ? "Doit différer du nom de la CA" : null) },
      { id: "sslProf", label: "Nom du SSL/TLS Service Profile", type: "text", required: true, validate: "name", default: "GP-SSL-TLS" },
      { id: "authProf", label: "Authentication Profile (existant)", type: "text", required: true, validate: "name", default: "Corp-LDAP-Auth",
        hint: "À créer au préalable : module « Profil d'authentification »." },

      { id: "tunIf", label: "Interface tunnel", type: "text", required: true, validate: tunnelIf, default: "tunnel.10", group: "Tunnel & réseau client" },
      { id: "gpZone", label: "Zone des clients VPN", type: "text", required: true, validate: "name", default: "GP-VPN" },
      { id: "vr", label: "Virtual Router", type: "text", required: true, validate: "name", default: "default" },
      { id: "pool", label: "IP Pool des clients", type: "text", required: true, validate: rangeOrCidr, default: "10.100.0.0/24" },
      { id: "routes", label: "Split tunnel — Access Routes (vide = full tunnel)", type: "list", default: ["192.168.1.0/24", "172.16.1.0/24"], wide: true,
        validate: (arr, v) => {
          for (const r of arr) if (!PAN.ip.validCidr(r) || !r.includes("/")) return `« ${r} » : format IP/masque attendu`;
          if (rangeOrCidr(v.pool) === null) for (const r of arr) for (const p of poolNets(v.pool)) if (overlap(r, p)) return `« ${r} » chevauche l'IP Pool`;
          return null;
        } },
      { id: "dns", label: "Serveurs DNS poussés aux clients", type: "list", validate: "ip", default: ["192.168.1.10"] },
      { id: "dnsSuffix", label: "Suffixe DNS", type: "text", validate: "fqdn", default: "corp.example.com" },

      { id: "gwName", label: "Nom de la Gateway", type: "text", required: true, validate: "name", default: "GP-Gateway", group: "Gateway & Portal" },
      { id: "portalName", label: "Nom du Portal", type: "text", required: true, default: "GP-Portal",
        validate: both("name", (val, v) => val === v.gwName ? "Doit différer du nom de la Gateway" : null) },
      { id: "agentCfg", label: "Nom de la configuration Agent", type: "text", required: true, validate: "name", default: "GP-Agent-Default" },
      { id: "connect", label: "Connect Method", type: "select", default: "user-logon",
        options: [["user-logon", "User-logon (Always On)"], ["on-demand", "On-demand (Manual user initiated connection)"], ["pre-logon", "Pre-logon (Always On)"]] },
      { id: "dstZones", label: "Zones accessibles aux clients VPN", type: "list", required: true, validate: "name", default: ["Trust", "DMZ"], group: "Politique" },
    ],
    build(v) {
      const ip = ipOf(v.outIp);
      const full = !v.routes.length;
      const connectLabel = { "user-logon": "User-logon (Always On)", "on-demand": "On-demand (Manual user initiated connection)", "pre-logon": "Pre-logon (Always On)" }[v.connect];
      const steps = [
        { title: "Générer la CA racine", path: ["Device", "Certificate Management", "Certificates"], tab: "Device Certificates", action: "Generate (en bas de page).", window: "Generate Certificate",
          fields: [["Certificate Type", "Local"], ["Certificate Name", v.caName], ["Common Name", v.caName], ["Signed By", "(vide)"], ["Certificate Authority", true], ["Algorithm", "RSA"], ["Number of Bits", "2048"], ["Digest", "sha256"]],
          note: "En production, préfère un certificat serveur émis par une CA publique ou l'IGC de l'entreprise : étapes 1-2 remplacées par Import." },
        { title: "Générer le certificat serveur du portail/gateway", path: ["Device", "Certificate Management", "Certificates"], tab: "Device Certificates", action: "Generate.", window: "Generate Certificate",
          fields: [["Certificate Type", "Local"], ["Certificate Name", v.certName], ["Common Name", v.fqdn], ["Signed By", v.caName], ["Certificate Authority", false], ["Algorithm", "RSA"], ["Number of Bits", "2048"], ["Digest", "sha256"],
            ["Certificate Attributes › Hostname", v.fqdn], ["Certificate Attributes › IP", ip]],
          warn: "Le CN/SAN doit correspondre exactement à l'adresse saisie par les utilisateurs, sinon erreur de certificat côté client." },
        { title: "Créer le SSL/TLS Service Profile", path: ["Device", "Certificate Management", "SSL/TLS Service Profile"], action: "Add.", window: "SSL/TLS Service Profile",
          fields: [["Name", v.sslProf], ["Certificate", v.certName], ["Min Version", "TLSv1.2"], ["Max Version", "Max"]] },
        { title: "Créer la zone des clients VPN", path: ["Network", "Zones"], action: "Add.", window: "Zone",
          fields: [["Name", v.gpZone], ["Type", "Layer3"], ["Enable User Identification", true]],
          note: "User-ID sur la zone : les logs et règles voient le nom d'utilisateur GlobalProtect." },
        { title: `Créer l'interface ${v.tunIf}`, path: ["Network", "Interfaces", "Tunnel"], action: "Add.", window: "Tunnel Interface",
          fields: [["Interface Name", "tunnel . " + v.tunIf.split(".")[1]], ["Config › Virtual Router", v.vr], ["Config › Security Zone", v.gpZone]] },
        { title: "Gateway — onglet General", path: ["Network", "GlobalProtect", "Gateways"], tab: "General", action: "Add.", window: "GlobalProtect Gateway Configuration",
          fields: [["Name", v.gwName], ["Interface", v.outIf], ["IP Address Type", "IPv4 Only"], ["IPv4 Address", v.outIp]] },
        { title: "Gateway — onglet Authentication", path: ["Network", "GlobalProtect", "Gateways", v.gwName], tab: "Authentication", window: "GlobalProtect Gateway Configuration",
          action: "Choisir le SSL/TLS Service Profile puis Client Authentication › Add.",
          fields: [["SSL/TLS Service Profile", v.sslProf], ["Client Authentication › Name", "Default-Auth"], ["OS", "Any"], ["Authentication Profile", v.authProf]] },
        { title: "Gateway — Agent › Tunnel Settings", path: ["Network", "GlobalProtect", "Gateways", v.gwName, "Agent"], tab: "Tunnel Settings", window: "GlobalProtect Gateway Configuration",
          fields: [["Tunnel Mode", true], ["Tunnel Interface", v.tunIf], ["Enable IPSec", true]] },
        { title: "Gateway — Agent › Client Settings", path: ["Network", "GlobalProtect", "Gateways", v.gwName, "Agent", "Client Settings"], action: "Add, puis renseigner les sous-onglets.", window: "Configs",
          fields: [["Config Selection Criteria › Name", "Default-Client"], ["Source User", "any"], ["OS", "Any"], ["IP Pools › IP Pool", v.pool],
            ["Split Tunnel › Access Route › Include", full ? "(vide : tout le trafic passe dans le tunnel)" : v.routes]] },
        { title: "Gateway — Agent › Network Services", path: ["Network", "GlobalProtect", "Gateways", v.gwName, "Agent"], tab: "Network Services", window: "GlobalProtect Gateway Configuration",
          fields: [["Inheritance Source", "None"], ["Primary DNS", v.dns[0]], ["Secondary DNS", v.dns[1]], ["DNS Suffix", v.dnsSuffix]] },
        { title: "Portal — onglet General", path: ["Network", "GlobalProtect", "Portals"], tab: "General", action: "Add.", window: "GlobalProtect Portal Configuration",
          fields: [["Name", v.portalName], ["Interface", v.outIf], ["IP Address Type", "IPv4 Only"], ["IPv4 Address", v.outIp]] },
        { title: "Portal — onglet Authentication", path: ["Network", "GlobalProtect", "Portals", v.portalName], tab: "Authentication", window: "GlobalProtect Portal Configuration",
          fields: [["SSL/TLS Service Profile", v.sslProf], ["Client Authentication › Name", "Default-Auth"], ["OS", "Any"], ["Authentication Profile", v.authProf]] },
        { title: "Portal — onglet Agent : CA de confiance", path: ["Network", "GlobalProtect", "Portals", v.portalName], tab: "Agent", window: "GlobalProtect Portal Configuration",
          action: "Trusted Root CA › Add.",
          fields: [["Trusted Root CA", v.caName], ["Install in Local Root Certificate Store", true]] },
        { title: "Portal — configuration Agent", path: ["Network", "GlobalProtect", "Portals", v.portalName, "Agent"], action: "Agent › Add, puis renseigner chaque onglet.", window: "Configs",
          fields: [["Authentication › Name", v.agentCfg], ["Client Certificate", "None"], ["Save User Credentials", "Yes"],
            ["Config Selection Criteria › User/User Group", "any"], ["OS", "Any"],
            ["External › External Gateways › Add › Name", v.gwName], ["Address", `FQDN : ${v.fqdn}`], ["Source Region / Priority", "Any / Highest"],
            ["App › Connect Method", connectLabel]] },
        { title: "Activer le client GlobalProtect", path: ["Device", "GlobalProtect Client"], action: "Check Now → Download la version souhaitée → Activate.", fields: [],
          note: "Sans version activée, le portail ne peut pas distribuer ni mettre à jour l'agent." },
        { title: "Règle de sécurité clients VPN → ressources internes", path: ["Policies", "Security"], action: "Add.", window: "Security Policy Rule",
          fields: [["General › Name", "GP-VPN-to-Internal"], ["Source › Source Zone", v.gpZone], ["Source › Source Address", v.pool], ["User › Source User", "any (ou groupes)"],
            ["Destination › Destination Zone", v.dstZones], ["Application", "any"], ["Service", "application-default"], ["Actions › Action", "Allow"], ["Actions › Profile Setting", "Group (profils standards)"]] },
      ];
      if (full) steps.push({ title: "Règle d'accès Internet des clients (full tunnel)", path: ["Policies", "Security"], action: "Add, puis vérifier qu'une règle NAT source couvre la zone VPN.", window: "Security Policy Rule",
        fields: [["General › Name", "GP-VPN-to-Internet"], ["Source › Source Zone", v.gpZone], ["Destination › Destination Zone", v.outZone], ["Application", "any"], ["Service", "application-default"], ["Actions › Action", "Allow"]] });

      const GW = `set global-protect global-protect-gateway ${q(v.gwName)}`;
      const PT = `set global-protect global-protect-portal ${q(v.portalName)}`;
      const AC = `${PT} client-config configs ${q(v.agentCfg)}`;
      const ops = [
        `# --- Certificats (mode opérationnel) ---`,
        `request certificate generate certificate-name ${q(v.caName)} name ${q(v.caName)} algorithm RSA rsa-nbits 2048 digest sha256 ca yes`,
        `request certificate generate certificate-name ${q(v.certName)} name ${v.fqdn} signed-by ${q(v.caName)} algorithm RSA rsa-nbits 2048 digest sha256 hostname ${v.fqdn} ip ${ip}`,
        ``, `configure`,
      ];
      const cfg = [
        `set shared ssl-tls-service-profile ${q(v.sslProf)} certificate ${q(v.certName)} protocol-settings min-version tls1-2 max-version max`,
        `set zone ${q(v.gpZone)} network layer3 ${v.tunIf}`,
        `set zone ${q(v.gpZone)} enable-user-identification yes`,
        `set network interface tunnel units ${v.tunIf} comment GlobalProtect`,
        `set network virtual-router ${q(v.vr)} interface ${v.tunIf}`,
        `# Gateway`,
        `${GW} local-address interface ${v.outIf} ip ipv4 ${v.outIp}`,
        `${GW} ssl-tls-service-profile ${q(v.sslProf)}`,
        `${GW} client-auth Default-Auth os Any authentication-profile ${q(v.authProf)}`,
        `${GW} tunnel-mode yes`,
        `${GW} remote-user-tunnel ${q(v.gwName + "-N")}`,
        `set network tunnel global-protect-gateway ${q(v.gwName + "-N")} tunnel-interface ${v.tunIf}`,
        `set network tunnel global-protect-gateway ${q(v.gwName + "-N")} ipsec enable yes`,
        `${GW} remote-user-tunnel-configs Default-Client source-user any os any`,
        `${GW} remote-user-tunnel-configs Default-Client ip-pool ${v.pool}`,
        !full && `${GW} remote-user-tunnel-configs Default-Client split-tunneling access-route ${members(v.routes)}`,
        v.dns.length && `${GW} remote-user-tunnel-configs Default-Client dns-server ${members(v.dns)}`,
        v.dnsSuffix && `${GW} remote-user-tunnel-configs Default-Client dns-suffix ${v.dnsSuffix}`,
        `# Portal`,
        `${PT} portal-config local-address interface ${v.outIf} ip ipv4 ${v.outIp}`,
        `${PT} portal-config ssl-tls-service-profile ${q(v.sslProf)}`,
        `${PT} portal-config client-auth Default-Auth os Any authentication-profile ${q(v.authProf)}`,
        `${PT} client-config root-ca ${q(v.caName)} install-in-cert-store yes`,
        `${AC} source-user any os any save-user-credentials 1`,
        `${AC} gateways external list ${q(v.gwName)} fqdn ${v.fqdn}`,
        `${AC} gateways external list ${q(v.gwName)} priority-rule Any priority 1`,
        `# Règles`,
        `set rulebase security rules GP-VPN-to-Internal from ${q(v.gpZone)} to ${members(v.dstZones)} source ${v.pool} destination any application any service application-default action allow log-end yes`,
        full && `set rulebase security rules GP-VPN-to-Internet from ${q(v.gpZone)} to ${q(v.outZone)} source any destination any application any service application-default action allow log-end yes`,
        `commit`, `exit`, ``,
        `# --- Client GlobalProtect (mode opérationnel) ---`,
        `request global-protect-client software check`,
        `# request global-protect-client software download version <version>`,
        `# request global-protect-client software activate version <version>`,
        ``, `# --- Vérification ---`,
        `show global-protect-gateway current-user`,
        `show global-protect-gateway statistics`,
        `show global-protect-portal current-user`,
      ].filter(x => x !== false && x !== 0 && x != null);

      const notes = [
        { type: "or", html: `L'Authentication Profile <b>${PAN.esc(v.authProf)}</b> doit exister : ${link("m04-auth-profile", "Profil d'authentification")}.` },
        { type: "warn", title: "Conflit HTTPS 443", text: `Si un Interface Management Profile autorise HTTPS sur ${v.outIf}, il entre en conflit avec le portail : retire HTTPS de ce profil (bonne pratique de toute façon sur une interface externe).` },
        { type: "or", text: `Connexion au portail/gateway (${v.outZone} → ${ip}) : trafic intrazone ${v.outZone} → ${v.outZone}, autorisé par la règle intrazone-default sauf si une règle de blocage la précède.` },
        { type: "warn", text: "La CLI GlobalProtect est longue et sensible à la version : le pas-à-pas WebUI est la méthode recommandée. Vérifie le résultat dans la WebUI avant commit." },
      ];
      if (full) notes.push({ type: "warn", text: `Full tunnel : prévois une règle NAT source ${v.gpZone} → ${v.outZone} (sinon pas d'accès Internet pour les clients).` });
      return { steps, cli: [], cliRaw: ops.concat(cfg), notes };
    },
  });

  /* =====================================================================
     SUP · HA actif/passif (2 firewalls)
     ===================================================================== */
  const haPortV = v => /^(management|ha1-a|ha1-b|ha2-a|ha2-b|ethernet\d+\/\d+)$/.test(v) ? null : "management, ha1-a, ha1-b, ha2-a, ha2-b ou ethernetX/Y";
  register({
    id: "sup-ha-active-passive",
    module: "SUP",
    title: "Haute disponibilité actif/passif",
    icon: "🔁",
    desc: "Paire HA actif/passif : liens HA1/HA2 (et backup), élection, synchronisation, link/path monitoring. Génère la configuration des deux pare-feux.",
    tags: "ha high availability active passive ha1 ha2 failover cluster",
    fields: [
      { id: "groupId", label: "Group ID (identique sur les 2)", type: "number", required: true, default: "1", min: 1, max: 63, group: "Général" },
      { id: "desc", label: "Description", type: "text", default: "HA pair site principal" },
      { id: "nameA", label: "Nom du Firewall A", type: "text", required: true, validate: "hostname", default: "fw-01" },
      { id: "nameB", label: "Nom du Firewall B", type: "text", required: true, default: "fw-02",
        validate: both("hostname", (val, v) => val === v.nameA ? "Doit différer du Firewall A" : null) },
      { id: "configSync", label: "Enable Config Sync", type: "checkbox", default: true },

      { id: "prioA", label: "Device Priority A (plus bas = actif)", type: "number", required: true, default: "100", min: 0, max: 255, group: "Élection" },
      { id: "prioB", label: "Device Priority B", type: "number", required: true, default: "110", min: 0, max: 255,
        validate: (val, v) => +val === +v.prioA ? "Priorités identiques : l'élection se fera sur l'adresse MAC, choisis des valeurs distinctes" : null },
      { id: "preempt", label: "Preemptive (retour automatique sur A après réparation)", type: "checkbox", default: true },
      { id: "hbBackup", label: "Heartbeat Backup (via le port MGT)", type: "checkbox", default: true },
      { id: "timers", label: "HA Timer Settings", type: "select", default: "recommended", options: [["recommended", "Recommended"], ["aggressive", "Aggressive"]] },
      { id: "pls", label: "Passive Link State", type: "select", default: "auto", options: [["auto", "auto"], ["shutdown", "shutdown"]] },

      { id: "ha1Port", label: "Port HA1 (Control Link)", type: "text", required: true, validate: haPortV, default: "ethernet1/4", group: "Control Link (HA1)",
        hint: "management, ha1-a (port dédié) ou une interface data (passée en type HA)." },
      { id: "ha1IpA", label: "IP HA1 Firewall A", type: "ip", required: true, default: "10.255.255.1", show: v => v.ha1Port !== "management" },
      { id: "ha1IpB", label: "IP HA1 Firewall B", type: "ip", required: true, default: "10.255.255.2", show: v => v.ha1Port !== "management",
        validate: (val, v) => val === v.ha1IpA ? "Doit différer de l'IP A" : maskOk(v.ha1Mask) && !sameSubnet(val, v.ha1IpA, v.ha1Mask) ? "A et B doivent être dans le même sous-réseau" : null },
      { id: "ha1Mask", label: "Netmask HA1", type: "text", required: true, default: "255.255.255.252", show: v => v.ha1Port !== "management",
        validate: val => maskOk(val) ? null : "Masque décimal attendu (ex. 255.255.255.252)" },
      { id: "mgmtA", label: "IP de management Firewall A", type: "ip", required: true, default: "192.168.1.254", show: v => v.ha1Port === "management" },
      { id: "mgmtB", label: "IP de management Firewall B", type: "ip", required: true, default: "192.168.1.253", show: v => v.ha1Port === "management",
        validate: (val, v) => val === v.mgmtA ? "Doit différer de A" : null },

      { id: "ha1b", label: "Control Link HA1 Backup", type: "checkbox", default: true, group: "Control Link (HA1 Backup)" },
      { id: "ha1bPort", label: "Port HA1 Backup", type: "text", required: true, default: "ethernet1/6", show: v => v.ha1b,
        validate: both(haPortV, (val, v) => val === v.ha1Port ? "Doit différer du port HA1" : null) },
      { id: "ha1bIpA", label: "IP HA1 Backup A", type: "ip", required: true, default: "10.255.254.1", show: v => v.ha1b },
      { id: "ha1bIpB", label: "IP HA1 Backup B", type: "ip", required: true, default: "10.255.254.2", show: v => v.ha1b,
        validate: (val, v) => val === v.ha1bIpA ? "Doit différer de l'IP A" : maskOk(v.ha1bMask) && !sameSubnet(val, v.ha1bIpA, v.ha1bMask) ? "A et B doivent être dans le même sous-réseau" : null },
      { id: "ha1bMask", label: "Netmask HA1 Backup", type: "text", required: true, default: "255.255.255.252", show: v => v.ha1b,
        validate: val => maskOk(val) ? null : "Masque décimal attendu" },

      { id: "ha2Port", label: "Port HA2 (Data Link)", type: "text", required: true, default: "ethernet1/5", group: "Data Link (HA2)",
        validate: both(haPortV, (val, v) => val === "management" ? "HA2 ne peut pas utiliser le port MGT" : val === v.ha1Port || (v.ha1b && val === v.ha1bPort) ? "Port déjà utilisé par HA1" : null) },
      { id: "ha2Transport", label: "Transport", type: "select", default: "ethernet", options: [["ethernet"], ["ip"], ["udp"]] },
      { id: "ha2IpA", label: "IP HA2 Firewall A", type: "ip", required: true, default: "10.255.253.1", show: v => v.ha2Transport !== "ethernet" },
      { id: "ha2IpB", label: "IP HA2 Firewall B", type: "ip", required: true, default: "10.255.253.2", show: v => v.ha2Transport !== "ethernet",
        validate: (val, v) => val === v.ha2IpA ? "Doit différer de l'IP A" : null },
      { id: "ha2Mask", label: "Netmask HA2", type: "text", required: true, default: "255.255.255.252", show: v => v.ha2Transport !== "ethernet",
        validate: val => maskOk(val) ? null : "Masque décimal attendu" },

      { id: "linkMon", label: "Link Monitoring", type: "checkbox", default: true, group: "Link & Path Monitoring" },
      { id: "linkIfs", label: "Interfaces surveillées (bascule si l'une tombe)", type: "list", required: true, default: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], show: v => v.linkMon, wide: true,
        validate: both("iface", (arr, v) => arr.some(i => [v.ha1Port, v.ha2Port, v.ha1b && v.ha1bPort].includes(i)) ? "Ne surveille pas les ports HA eux-mêmes" : null) },
      { id: "pathMon", label: "Path Monitoring", type: "checkbox", default: false },
      { id: "pathVr", label: "Virtual Router", type: "text", required: true, validate: "name", default: "default", show: v => v.pathMon },
      { id: "pathDst", label: "IP à pinger", type: "list", required: true, validate: "ip", default: ["203.0.113.1"], show: v => v.pathMon },
    ],
    build(v) {
      const mg = v.ha1Port === "management";
      const fw = {
        A: { name: v.nameA, prio: v.prioA, ha1: mg ? v.mgmtA : v.ha1IpA, peer: mg ? v.mgmtB : v.ha1IpB, ha1b: v.ha1bIpA, peerB: v.ha1bIpB, ha2: v.ha2IpA },
        B: { name: v.nameB, prio: v.prioB, ha1: mg ? v.mgmtB : v.ha1IpB, peer: mg ? v.mgmtA : v.ha1IpA, ha1b: v.ha1bIpB, peerB: v.ha1bIpA, ha2: v.ha2IpB },
      };
      const haIfs = [v.ha1Port, v.ha1b && v.ha1bPort, v.ha2Port].filter(p => p && /^ethernet/.test(p));
      const tLbl = { recommended: "Recommended", aggressive: "Aggressive" }[v.timers];
      const steps = [], cliRaw = [];

      ["A", "B"].forEach(k => {
        const f = fw[k], tag = `[Firewall ${k} · ${f.name}] `;
        haIfs.forEach(i => steps.push({ title: tag + `Passer ${i} en type HA`, path: ["Network", "Interfaces", "Ethernet", i], window: "Ethernet Interface",
          fields: [["Interface Type", "HA"]], note: "L'interface ne doit appartenir à aucune zone ni virtual router." }));
        steps.push(
          { title: tag + "Activer la HA (Setup)", path: ["Device", "High Availability", "General"], tab: "General", window: "Setup", action: "Cadre « Setup » › ⚙.",
            fields: [["Enable HA", true], ["Group ID", v.groupId], ["Description", v.desc], ["Mode", "Active Passive"], ["Enable Config Sync", v.configSync],
              ["Peer HA1 IP Address", f.peer], ["Backup Peer HA1 IP Address", v.ha1b ? f.peerB : ""]] },
          { title: tag + "Election Settings", path: ["Device", "High Availability", "General"], tab: "General", window: "Election Settings", action: "Cadre « Election Settings » › ⚙.",
            fields: [["Device Priority", f.prio], ["Preemptive", v.preempt], ["Heartbeat Backup", v.hbBackup], ["HA Timer Settings", tLbl]],
            note: k === "A" ? "Preemptive doit être identique sur les deux pare-feux." : "" },
          { title: tag + "Active/Passive Settings", path: ["Device", "High Availability", "General"], tab: "General", window: "Active/Passive Settings", action: "Cadre « Active/Passive Settings » › ⚙.",
            fields: [["Passive Link State", v.pls], ["Monitor Fail Hold Down Time (min)", "1"]] },
          { title: tag + "Control Link (HA1)", path: ["Device", "High Availability", "HA Communications"], tab: "HA Communications", window: "Control Link (HA1)", action: "Cadre « Control Link (HA1) » › ⚙.",
            fields: [["Port", v.ha1Port], ["IPv4/IPv6 Address", mg ? "(IP de management utilisée)" : f.ha1], ["Netmask", mg ? "" : v.ha1Mask]] },
        );
        if (v.ha1b) steps.push({ title: tag + "Control Link (HA1 Backup)", path: ["Device", "High Availability", "HA Communications"], tab: "HA Communications", window: "Control Link (HA1 Backup)",
          action: "Cadre « Control Link (HA1 Backup) » › ⚙.", fields: [["Port", v.ha1bPort], ["IPv4/IPv6 Address", f.ha1b], ["Netmask", v.ha1bMask]] });
        steps.push({ title: tag + "Data Link (HA2)", path: ["Device", "High Availability", "HA Communications"], tab: "HA Communications", window: "Data Link (HA2)", action: "Cadre « Data Link (HA2) » › ⚙.",
          fields: [["Enable Session Synchronization", true], ["Port", v.ha2Port], ["Transport", v.ha2Transport],
            ...(v.ha2Transport !== "ethernet" ? [["IPv4/IPv6 Address", f.ha2], ["Netmask", v.ha2Mask]] : []),
            ["HA2 Keep-alive", true], ["Action", "Log Only"]] });
        if (v.linkMon) steps.push({ title: tag + "Link Monitoring", path: ["Device", "High Availability", "Link and Path Monitoring"], tab: "Link and Path Monitoring", window: "Link Group",
          action: "Cadre « Link Monitoring » › ⚙ : Enabled, Failure Condition Any. Puis Link Groups › Add.",
          fields: [["Link Monitoring › Enabled", true], ["Failure Condition", "Any"], ["Link Group › Name", "LG-Data"], ["Enabled", true], ["Failure Condition", "Any"], ["Interfaces", v.linkIfs]] });
        if (v.pathMon) steps.push({ title: tag + "Path Monitoring", path: ["Device", "High Availability", "Link and Path Monitoring"], tab: "Link and Path Monitoring", window: "Path Group",
          action: "Cadre « Path Monitoring » › ⚙ : Enabled, Failure Condition Any. Puis Path Group › Add Virtual Router.",
          fields: [["Path Monitoring › Enabled", true], ["Name (Virtual Router)", v.pathVr], ["Enabled", true], ["Failure Condition", "Any"], ["Destination IP Groups › Name", "PG-Gateway"], ["Destination IP", v.pathDst]] });
        if (k === "A") steps.push({ title: tag + "Commit sur le Firewall A", path: ["Commit"], action: "Commit sur le Firewall A, puis se connecter au Firewall B.", fields: [] });

        const H = `set deviceconfig high-availability`;
        cliRaw.push(`# --- Firewall ${k} (${f.name}) ---`, "configure",
          ...haIfs.map(i => `set network interface ethernet ${i} ha`),
          `${H} enabled yes`,
          `${H} group group-id ${v.groupId}`,
          v.desc && `${H} group description ${q(v.desc)}`,
          `${H} group peer-ip ${f.peer}`,
          v.ha1b && `${H} group peer-ip-backup ${f.peerB}`,
          `${H} group mode active-passive passive-link-state ${v.pls}`,
          `${H} group election-option device-priority ${f.prio}`,
          `${H} group election-option preemptive ${yn(v.preempt)}`,
          `${H} group election-option heartbeat-backup ${yn(v.hbBackup)}`,
          `${H} group election-option timers ${v.timers}`,
          `${H} group configuration-synchronization enabled ${yn(v.configSync)}`,
          `${H} group state-synchronization enabled yes`,
          `${H} group state-synchronization transport ${v.ha2Transport}`,
          `${H} group state-synchronization ha2-keep-alive enabled yes action log-only`,
          `${H} interface ha1 port ${v.ha1Port}`,
          !mg && `${H} interface ha1 ip-address ${f.ha1} netmask ${v.ha1Mask}`,
          v.ha1b && `${H} interface ha1-backup port ${v.ha1bPort} ip-address ${f.ha1b} netmask ${v.ha1bMask}`,
          `${H} interface ha2 port ${v.ha2Port}`,
          v.ha2Transport !== "ethernet" && `${H} interface ha2 ip-address ${f.ha2} netmask ${v.ha2Mask}`,
          ...(v.linkMon ? [
            `${H} group monitoring link-monitoring enabled yes failure-condition any`,
            `${H} group monitoring link-monitoring link-groups LG-Data enabled yes failure-condition any interface ${members(v.linkIfs)}`] : []),
          ...(v.pathMon ? [
            `${H} group monitoring path-monitoring enabled yes failure-condition any`,
            `${H} group monitoring path-monitoring path-group virtual-router ${q(v.pathVr)} enabled yes failure-condition any destination-ip-group PG-Gateway destination-ip ${members(v.pathDst)}`] : []),
          "commit", "exit", "");
      });
      cliRaw.push("# --- Vérification (sur chaque firewall) ---", "show high-availability state", "show high-availability all", "show high-availability link-monitoring",
        "# Sur l'actif, si la configuration n'est pas synchronisée :", "request high-availability sync-to-remote running-config");

      const notes = [
        { type: "warn", title: "Prérequis", text: "Même modèle, même version PAN-OS, mêmes versions de contenu (Apps/Threats, AV, WildFire) et mêmes licences sur les deux pare-feux, sinon la HA reste en état non-functional ou suspended." },
        { type: "or", text: `Les paramètres HA et le management ne sont pas synchronisés : configure les deux pare-feux. Une fois la paire formée, configure le reste (interfaces, politiques…) uniquement sur l'actif (${+v.prioA < +v.prioB ? v.nameA : v.nameB}).` },
      ];
      if (!v.ha1b && !v.hbBackup) notes.push({ type: "warn", text: "Ni HA1 Backup ni Heartbeat Backup : la perte du seul lien HA1 provoque un split-brain (deux actifs)." });
      if (mg && v.hbBackup) notes.push({ type: "warn", text: "HA1 utilise déjà le port MGT : Heartbeat Backup n'apporte rien, privilégie un HA1 Backup sur un port data." });
      return { steps, cliRaw: cliRaw.filter(x => x !== false && x != null), notes };
    },
  });

  /* =====================================================================
     SUP · Zone Protection Profile
     ===================================================================== */
  const floods = [["syn", "SYN", "tcp-syn"], ["udp", "UDP", "udp"], ["icmp", "ICMP", "icmp"], ["oip", "Other IP", "other-ip"]];
  const zpFields = [];
  floods.forEach(([k, l], i) => {
    const g = i === 0 ? "Flood Protection" : undefined;
    zpFields.push({ id: k, label: `${l} Flood`, type: "checkbox", default: true, group: g });
    if (k === "syn") zpFields.push({ id: "synAction", label: "Action SYN", type: "select", default: "syn-cookies", options: [["syn-cookies", "SYN Cookies"], ["red", "Random Early Drop"]], show: v => v.syn });
    zpFields.push(
      { id: k + "Alarm", label: `${l} — Alarm Rate (pps)`, type: "number", required: true, default: "10000", min: 0, max: 2000000, show: v => v[k] },
      { id: k + "Act", label: `${l} — Activate (pps)`, type: "number", required: true, default: "10000", min: 1, max: 2000000, show: v => v[k], validate: ratesOk(k) },
      { id: k + "Max", label: `${l} — Maximum (pps)`, type: "number", required: true, default: "40000", min: 1, max: 2000000, show: v => v[k], validate: ratesOk(k) });
  });
  const scans = [["tcpScan", "TCP Port Scan", 8001, 2], ["hostSweep", "Host Sweep", 8002, 10], ["udpScan", "UDP Port Scan", 8003, 2]];
  scans.forEach(([k, l, , iv], i) => zpFields.push(
    { id: k, label: l, type: "checkbox", default: true, group: i === 0 ? "Reconnaissance Protection" : undefined },
    { id: k + "Act", label: `${l} — Action`, type: "select", default: "alert", options: [["allow", "Allow"], ["alert", "Alert"], ["block", "Block"], ["block-ip", "Block IP"]], show: v => v[k] },
    { id: k + "Int", label: `${l} — Interval (s)`, type: "number", required: true, default: String(iv), min: 2, max: 65535, show: v => v[k] },
    { id: k + "Thr", label: `${l} — Threshold (events)`, type: "number", required: true, default: "100", min: 2, max: 65535, show: v => v[k] }));
  zpFields.push(
    { id: "blockDur", label: "Block IP — Duration (s)", type: "number", required: true, default: "3600", min: 1, max: 3600, show: v => scans.some(([k]) => v[k] && v[k + "Act"] === "block-ip") },
    { id: "trackBy", label: "Block IP — Track By", type: "select", default: "source", options: [["source", "source"], ["source-and-destination", "source-and-destination"]], show: v => scans.some(([k]) => v[k] && v[k + "Act"] === "block-ip") });
  const pba = [
    ["ipSpoof", "IP Drop", "Spoofed IP address", "discard-ip-spoof", true],
    ["ipStrict", "IP Drop", "Strict IP Address Check", "strict-ip-check", true],
    ["ipFrag", "IP Drop", "Fragmented traffic", "discard-ip-frag", false],
    ["ipSsr", "IP Drop", "Strict Source Routing", "discard-strict-source-routing", true],
    ["ipLsr", "IP Drop", "Loose Source Routing", "discard-loose-source-routing", true],
    ["ipUnknown", "IP Drop", "Unknown", "discard-unknown-option", true],
    ["ipMalformed", "IP Drop", "Malformed", "discard-malformed-option", true],
    ["tcpSynData", "TCP Drop", "TCP SYN with Data", "discard-tcp-syn-with-data", true],
    ["tcpSynAckData", "TCP Drop", "TCP SYNACK with Data", "discard-tcp-synack-with-data", true],
    ["tcpOverlap", "TCP Drop", "Mismatched overlapping TCP segment", "discard-overlapping-tcp-segment-mismatch", true],
    ["icmpId0", "ICMP Drop", "ICMP Ping ID 0", "discard-icmp-ping-zero-id", true],
    ["icmpFrag", "ICMP Drop", "ICMP Fragment", "discard-icmp-frag", true],
    ["icmpLarge", "ICMP Drop", "ICMP Large Packet (>1024)", "discard-icmp-large-packet", true],
    ["icmpErr", "ICMP Drop", "Discard ICMP embedded with error message", "discard-icmp-embedded-error", true],
  ];
  pba.forEach(([id, tab, l, , d], i) => zpFields.push({ id, label: `${tab} › ${l}`, type: "checkbox", default: d, group: i === 0 ? "Packet Based Attack Protection" : undefined }));

  register({
    id: "sup-zone-protection",
    module: "SUP",
    title: "Zone Protection Profile",
    icon: "🛡️",
    desc: "Protection de la zone exposée : flood (SYN/UDP/ICMP/Other IP), reconnaissance (scans, host sweep), attaques par paquets, puis application à la zone.",
    tags: "zone protection flood syn cookies reconnaissance scan spoofing dos",
    fields: [
      { id: "name", label: "Nom du profil", type: "text", required: true, validate: "name", default: "ZP-Untrust", group: "Profil" },
      { id: "zone", label: "Zone à protéger", type: "text", required: true, validate: "name", default: "Untrust" },
      ...zpFields,
    ],
    build(v) {
      const Z = `set network profiles zone-protection-profile ${q(v.name)}`;
      const fl = floods.filter(([k]) => v[k]);
      const sc = scans.filter(([k]) => v[k]);
      const actLbl = { allow: "Allow", alert: "Alert", block: "Block", "block-ip": "Block IP" };
      const blockIp = sc.some(([k]) => v[k + "Act"] === "block-ip");
      const steps = [
        { title: "Créer le profil — Flood Protection", path: ["Network", "Network Profiles", "Zone Protection"], tab: "Flood Protection", action: "Add, puis renseigner chaque sous-onglet (SYN, UDP, ICMP, Other IP).", window: "Zone Protection Profile",
          fields: [["Name", v.name], ...floods.flatMap(([k, l]) => v[k]
            ? [[`${l} › Enable`, true], ...(k === "syn" ? [["SYN › Action", v.synAction === "red" ? "Random Early Drop" : "SYN Cookies"]] : []), [`${l} › Alarm / Activate / Maximum (pps)`, `${v[k + "Alarm"]} / ${v[k + "Act"]} / ${v[k + "Max"]}`]]
            : [[`${l} › Enable`, "☐ décoché"]])],
          note: "Seuils exprimés en paquets/s pour toute la zone : base-les sur le trafic réel (pic normal + marge), pas sur les valeurs par défaut." },
        { title: "Reconnaissance Protection", path: ["Network", "Network Profiles", "Zone Protection", v.name], tab: "Reconnaissance Protection", window: "Zone Protection Profile",
          fields: [...scans.flatMap(([k, l]) => v[k] ? [[`${l} › Enable / Action`, `✓ / ${actLbl[v[k + "Act"]]}`], [`${l} › Interval / Threshold`, `${v[k + "Int"]} s / ${v[k + "Thr"]}`]] : [[`${l} › Enable`, "☐ décoché"]]),
            ...(blockIp ? [["Block IP › Track By", v.trackBy], ["Block IP › Duration (sec)", v.blockDur]] : [])] },
        ...["IP Drop", "TCP Drop", "ICMP Drop"].map(tab => ({
          title: `Packet Based Attack Protection — ${tab}`, path: ["Network", "Network Profiles", "Zone Protection", v.name, "Packet Based Attack Protection"], tab, window: "Zone Protection Profile",
          fields: pba.filter(p => p[1] === tab).map(([id, , l]) => [l, v[id] ? true : "☐ décoché"]),
          note: tab === "IP Drop" && v.ipStrict ? "Strict IP Address Check rejette aussi les IP source réseau/broadcast : sans risque sur une zone Internet." : "" })),
        { title: `Appliquer le profil à la zone ${v.zone}`, path: ["Network", "Zones", v.zone], window: "Zone",
          fields: [["Zone Protection Profile", v.name], ["Enable Packet Buffer Protection", true]] },
      ];
      const cli = [
        ...fl.flatMap(([k, , c]) => {
          const mode = k === "syn" ? v.synAction : "red";
          return [`${Z} flood ${c} enable yes`, `${Z} flood ${c} ${mode} alarm-rate ${v[k + "Alarm"]} activate-rate ${v[k + "Act"]} maximal-rate ${v[k + "Max"]}`];
        }),
        ...floods.filter(([k]) => !v[k]).map(([, , c]) => `${Z} flood ${c} enable no`),
        ...sc.flatMap(([k, , id]) => {
          const a = v[k + "Act"];
          return [`${Z} scan ${id} interval ${v[k + "Int"]} threshold ${v[k + "Thr"]}`,
            a === "block-ip" ? `${Z} scan ${id} action block-ip track-by ${v.trackBy} duration ${v.blockDur}` : `${Z} scan ${id} action ${a}`];
        }),
        ...pba.map(([id, , , c]) => `${Z} ${c} ${yn(v[id])}`),
        `set zone ${q(v.zone)} network zone-protection-profile ${q(v.name)}`,
        `set zone ${q(v.zone)} network enable-packet-buffer-protection yes`,
      ];
      const notes = [
        { type: "or", text: "Le profil protège le trafic entrant (ingress) de la zone, avant toute politique. Commence avec des actions Alert, observe Monitor > Logs > Threat, puis durcis." },
      ];
      if (v.ipFrag) notes.push({ type: "warn", text: "Fragmented traffic : bloque aussi les fragments légitimes (VPN, DNS EDNS, UDP volumineux). À valider avant production." });
      if (v.synAction === "syn-cookies" && v.syn) notes.push({ type: "ok", text: "SYN Cookies : protège sans dropper le trafic légitime ; recommandé sur une zone Internet." });
      return {
        steps, cli, notes,
        verify: [`show zone-protection zone ${q(v.zone)}`, "show counter global filter delta yes severity drop", "show counter global filter delta yes | match flow_dos"],
      };
    },
  });

  /* =====================================================================
     SUP · DoS Protection (profil + politique)
     ===================================================================== */
  const dosFl = [["syn", "SYN Flood", "tcp-syn"], ["udp", "UDP Flood", "udp"], ["icmp", "ICMP Flood", "icmp"], ["oip", "Other IP Flood", "other-ip"]];
  register({
    id: "sup-dos-protection",
    module: "SUP",
    title: "DoS Protection (profil + politique)",
    icon: "🧱",
    desc: "Profil DoS Protection (classified ou aggregate) et règle Policies > DoS Protection pour protéger un serveur publié.",
    tags: "dos protection flood classified aggregate serveur sessions",
    fields: [
      { id: "prof", label: "Nom du profil DoS", type: "text", required: true, validate: "name", default: "DoS-Srv-Web", group: "Profil DoS Protection" },
      { id: "ptype", label: "Type", type: "select", default: "classified",
        options: [["classified", "Classified (seuils par IP)"], ["aggregate", "Aggregate (seuils pour tout le trafic de la règle)"]] },
      ...dosFl.map(([k, l]) => ({ id: k, label: l, type: "checkbox", default: true })),
      { id: "synAction", label: "Action SYN", type: "select", default: "syn-cookies", options: [["syn-cookies", "SYN Cookies"], ["red", "Random Early Drop"]], show: v => v.syn },
      { id: "fAlarm", label: "Alarm Rate (connexions/s)", type: "number", required: true, default: "10000", min: 0, max: 2000000 },
      { id: "fAct", label: "Activate Rate (connexions/s)", type: "number", required: true, default: "10000", min: 1, max: 2000000, validate: ratesOk("f") },
      { id: "fMax", label: "Max Rate (connexions/s)", type: "number", required: true, default: "40000", min: 2, max: 2000000, validate: ratesOk("f") },
      { id: "blockDur", label: "Block Duration (s)", type: "number", required: true, default: "300", min: 1, max: 21600 },
      { id: "sess", label: "Resources Protection — limiter les sessions", type: "checkbox", default: true },
      { id: "maxSess", label: "Max Concurrent Sessions", type: "number", required: true, default: "32768", min: 1, max: 4194304, show: v => v.sess },

      { id: "rule", label: "Nom de la règle DoS", type: "text", required: true, default: "DoS-Protect-Srv-Web", group: "Politique DoS Protection",
        validate: both("name", val => val.length > 31 ? "31 caractères maximum pour une règle DoS" : null) },
      { id: "fromZone", label: "Zone source", type: "text", required: true, validate: "name", default: "Untrust" },
      { id: "toZone", label: "Zone de destination", type: "text", required: true, validate: "name", default: "DMZ" },
      { id: "dst", label: "Adresse(s) du serveur protégé", type: "list", required: true, validate: "ipcidr", default: ["172.16.1.10"] },
      { id: "svc", label: "Service(s)", type: "list", required: true, validate: "name", default: ["service-http", "service-https"] },
      { id: "action", label: "Action", type: "select", default: "protect", options: [["protect", "Protect"], ["allow", "Allow"], ["deny", "Deny"]] },
      { id: "crit", label: "Address (classification)", type: "select", default: "destination-ip-only", show: v => v.ptype === "classified",
        options: [["destination-ip-only", "destination-ip-only"], ["source-ip-only", "source-ip-only"], ["src-dest-ip-both", "src-dest-ip-both"]] },
    ],
    build(v) {
      const D = `set profiles dos-protection ${q(v.prof)}`, R = `set rulebase dos rules ${q(v.rule)}`;
      const on = dosFl.filter(([k]) => v[k]);
      const rates = `${v.fAlarm} / ${v.fAct} / ${v.fMax}`;
      const steps = [
        { title: "Créer le profil DoS Protection", path: ["Objects", "Security Profiles", "DoS Protection"], tab: "Flood Protection", action: "Add, puis un sous-onglet par type de flood.", window: "DoS Protection Profile",
          fields: [["Name", v.prof], ["Type", v.ptype === "classified" ? "Classified" : "Aggregate"],
            ...dosFl.map(([k, l]) => [l, v[k] ? true : "☐ décoché"]),
            ["SYN Flood › Action", v.syn ? (v.synAction === "red" ? "Random Early Drop" : "SYN Cookies") : ""],
            ["Alarm / Activate / Max Rate (cps)", rates], ["Block Duration (sec)", v.blockDur]] },
        { title: "Profil — Resources Protection", path: ["Objects", "Security Profiles", "DoS Protection", v.prof], tab: "Resources Protection", window: "DoS Protection Profile",
          fields: [["Sessions", v.sess ? true : "☐ décoché"], ["Max Concurrent Sessions", v.sess ? v.maxSess : ""]] },
        { title: "Règle DoS — General / Source", path: ["Policies", "DoS Protection"], tab: "Source", action: "Add.", window: "DoS Rule",
          fields: [["General › Name", v.rule], ["Source › Type", "Zone"], ["Zone", v.fromZone], ["Source Address", "Any"], ["Source User", "any"]] },
        { title: "Règle DoS — Destination", path: ["Policies", "DoS Protection", v.rule], tab: "Destination", window: "DoS Rule",
          fields: [["Type", "Zone"], ["Zone", v.toZone], ["Destination Address", v.dst]] },
        { title: "Règle DoS — Option/Protection", path: ["Policies", "DoS Protection", v.rule], tab: "Option/Protection", window: "DoS Rule",
          fields: [["Service", v.svc], ["Action", v.action === "protect" ? "Protect" : v.action === "allow" ? "Allow" : "Deny"],
            ...(v.action === "protect" ? (v.ptype === "classified" ? [["Classified", true], ["Profile", v.prof], ["Address", v.crit]] : [["Aggregate › Profile", v.prof]]) : [])] },
      ];
      const cli = [
        `${D} type ${v.ptype}`,
        ...on.flatMap(([k, , c]) => {
          const mode = k === "syn" ? v.synAction : "red";
          return [`${D} flood ${c} enable yes`, `${D} flood ${c} ${mode} alarm-rate ${v.fAlarm} activate-rate ${v.fAct} maximal-rate ${v.fMax}`, `${D} flood ${c} ${mode} block duration ${v.blockDur}`];
        }),
        v.sess && `${D} resource sessions enabled yes max-concurrent-limit ${v.maxSess}`,
        `${R} from zone ${q(v.fromZone)}`,
        `${R} to zone ${q(v.toZone)}`,
        `${R} source any destination ${members(v.dst)} source-user any service ${members(v.svc)}`,
        `${R} action ${v.action}`,
        v.action === "protect" && (v.ptype === "classified"
          ? `${R} protection classified profile ${q(v.prof)} classification-criteria address ${v.crit}`
          : `${R} protection aggregate profile ${q(v.prof)}`),
      ].filter(Boolean);
      const notes = [
        { type: "or", text: "Seuils en connexions/s vers le(s) serveur(s) : mesure le pic normal (ACC, Monitor) et fixe Alarm ~ pic +15 %, Activate au-dessus, Max ≈ capacité du serveur." },
        { type: "warn", text: "Si le serveur est publié par NAT de destination, vérifie avec test dos-policy-match que la règle matche bien l'adresse utilisée (publique ou privée) avant de te fier à la protection." },
      ];
      if (v.ptype === "classified" && v.crit !== "destination-ip-only" && /^untrust$/i.test(v.fromZone))
        notes.push({ type: "warn", text: "Classification par IP source depuis Internet : un compteur par IP source, risque d'épuiser les ressources. Préfère destination-ip-only." });
      return {
        steps, cli, notes,
        verify: [
          `test dos-policy-match from ${q(v.fromZone)} to ${q(v.toZone)} source 198.51.100.50 destination ${ipOf(v.dst[0])} protocol 6 destination-port 443`,
          `show dos-protection rule ${q(v.rule)} statistics`,
          "show counter global filter delta yes | match dos",
        ],
      };
    },
  });

  /* =====================================================================
     SUP · Service Route Configuration
     ===================================================================== */
  const services = [["dns", "DNS"], ["ntp", "NTP"], ["paloalto-networks-services", "Palo Alto Networks Services"], ["url-updates", "URL Updates"], ["syslog", "Syslog"], ["email", "Email"], ["ldap", "LDAP"], ["radius", "RADIUS"]];
  register({
    id: "sup-service-route",
    module: "SUP",
    title: "Service Routes (sortie via interface data)",
    icon: "🛣️",
    desc: "Fait sortir DNS, NTP, mises à jour, Syslog… par une interface data au lieu du port de management.",
    tags: "service route dns ntp updates management interface source",
    fields: [
      { id: "srcIf", label: "Source Interface", type: "text", required: true, validate: "iface", default: "ethernet1/1", group: "Interface source" },
      { id: "srcIp", label: "Source Address (IP/masque de l'interface)", type: "cidr", required: true, default: "203.0.113.10/24" },
      ...services.map(([k, l], i) => ({ id: "s_" + k, label: l, type: "checkbox", default: ["dns", "ntp", "paloalto-networks-services", "url-updates"].includes(k), group: i === 0 ? "Services concernés" : undefined })),
    ],
    build(v) {
      const sel = services.filter(([k]) => v["s_" + k]);
      if (!sel.length) return { steps: [], cli: [], notes: [{ type: "warn", text: "Sélectionne au moins un service." }] };
      const steps = [
        { title: "Ouvrir la configuration des Service Routes", path: ["Device", "Setup", "Services"], tab: "Services", window: "Service Route Configuration",
          action: "Cadre « Service Features » › Service Route Configuration › Customize.", fields: [] },
        { title: "Définir la source par service", path: ["Device", "Setup", "Services", "Service Route Configuration"], tab: "IPv4", window: "Service Route Source",
          action: "Cocher les services ci-dessous, puis Set Selected Routes (ou cliquer chaque service).",
          fields: [["Services", sel.map(s => s[1])], ["Source Interface", v.srcIf], ["Source Address", v.srcIp]] },
      ];
      const cli = sel.map(([k]) => `set deviceconfig system route service ${k} source interface ${v.srcIf} address ${v.srcIp}`);
      const notes = [
        { type: "or", text: "Les services non listés restent sur le port de management. Le flux sort avec l'IP source choisie : le routage du VR et, si besoin, le NAT en aval doivent le permettre." },
        { type: "warn", text: "Si la source est une interface interne (Trust), le trafic traverse le pare-feu : il faut alors une règle de sécurité et un NAT source vers Internet." },
      ];
      if (v.s_dns) notes.push({ type: "ok", text: "Teste la résolution après commit : ping host updates.paloaltonetworks.com." });
      return {
        steps, cli, notes,
        verify: [`ping source ${ipOf(v.srcIp)} host 8.8.8.8`, "ping host updates.paloaltonetworks.com", "show ntp", "request content upgrade check"],
      };
    },
  });
})();
