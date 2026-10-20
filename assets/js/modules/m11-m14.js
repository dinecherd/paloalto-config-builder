/* Modules M11 (WildFire), M12 (User-ID), M13 (Décryptage), M14 (Logs & rapports) */
(function () {
  const { register, q, members, yn } = PAN.cfg;

  /* ---------- helpers locaux ---------- */
  const NAME = "name";
  const zoneList = v => { for (const z of v) { if (z !== "any" && PAN.cfg.V.name(z)) return `« ${z} » : nom de zone invalide`; } return null; };
  const addrList = v => { for (const a of v) { if (a !== "any" && !PAN.ip.validCidr(a) && PAN.cfg.V.name(a)) return `« ${a} » : IP, IP/masque, any ou nom d'objet attendu`; } return null; };
  const catList = v => { for (const c of v) { if (!/^[a-z0-9][a-z0-9-]*$/.test(c)) return `« ${c} » : nom de catégorie PAN-DB (minuscules et tirets, ex. financial-services)`; } return null; };
  const dn = v => /^[A-Za-z]+=[^,]+(,[A-Za-z]+=[^,]+)*$/.test(v) ? null : "DN LDAP attendu (ex. dc=corp,dc=local)";
  const yes = b => (b ? "yes" : "no");
  const qb = x => (String(x).includes("\\") ? `"${x}"` : q(x)); // domaine\utilisateur toujours entre guillemets
  /* CLI complète quand des commandes opérationnelles précèdent la config (cliRaw) */
  function rawCli(op, cfg, verify, commit = true) {
    const out = [];
    if (op.length) out.push("# --- Mode opérationnel (admin@pa>) ---", ...op, "");
    out.push("configure", ...cfg);
    if (commit) out.push("commit");
    out.push("exit");
    if (verify && verify.length) out.push("", "# --- Vérification (mode opérationnel) ---", ...verify);
    return out;
  }

  /* =====================================================================
     M11 · WildFire
     ===================================================================== */
  const WF_TYPES = ["any", "pe", "pdf", "ms-office", "archive", "jar", "flash", "apk", "MacOSX", "linux", "script", "email-link"];

  register({
    id: "m11-wildfire-profile",
    module: "M11",
    title: "Profil WildFire Analysis",
    icon: "🔥",
    desc: "Profil WildFire Analysis (applications, types de fichiers, direction, cloud public/privé) puis rattachement à un groupe de profils et/ou à une règle de sécurité.",
    tags: "wildfire analysis profile sandbox profile group",
    fields: [
      { id: "name", label: "Nom du profil", type: "text", required: true, validate: NAME, default: "Std-WF" },
      { id: "desc", label: "Description", type: "text", default: "Envoi des fichiers inconnus à WildFire" },
      { id: "ruleName", label: "Nom de la règle du profil", type: "text", required: true, validate: NAME, default: "All_Files", group: "Règle du profil" },
      { id: "apps", label: "Applications", type: "list", required: true, default: ["any"], hint: "any ou liste (ex. web-browsing, smtp)" },
      { id: "fileTypes", label: "Types de fichiers", type: "list", required: true, default: ["any"],
        hint: "any ou parmi : " + WF_TYPES.slice(1).join(", "),
        validate: v => { const bad = v.find(x => !WF_TYPES.includes(x)); return bad ? `« ${bad} » : type inconnu` : (v.includes("any") && v.length > 1 ? "« any » doit être seul" : null); } },
      { id: "direction", label: "Direction", type: "select", default: "both", options: [["both", "both"], ["upload", "upload"], ["download", "download"]] },
      { id: "analysis", label: "Analyse", type: "select", default: "public-cloud", options: [["public-cloud", "public-cloud"], ["private-cloud", "private-cloud (WF-500)"]] },
      { id: "group", label: "Groupe de profils (Security Profile Group)", type: "text", validate: NAME, default: "Std-Profiles", group: "Application du profil",
        hint: "Laisser vide pour rattacher le profil directement à la règle." },
      { id: "groupNew", label: "Créer le groupe (sinon : groupe existant modifié)", type: "checkbox", default: false, show: v => !!v.group },
      { id: "secRule", label: "Règle de sécurité à protéger", type: "text", validate: NAME, default: "LAN-to-Internet", hint: "Optionnel si le groupe est déjà appliqué aux règles." },
    ],
    build(v) {
      const steps = [
        { title: "Créer le profil WildFire Analysis", path: ["Objects", "Security Profiles", "WildFire Analysis"], window: "WildFire Analysis Profile",
          action: "Cliquer sur Add.", fields: [["Name", v.name], ["Description", v.desc]] },
        { title: "Ajouter la règle du profil", path: ["Objects", "Security Profiles", "WildFire Analysis"], window: "WildFire Analysis Profile",
          action: "Dans la fenêtre du profil, cliquer sur Add (en bas à gauche) puis renseigner la ligne. OK pour fermer.",
          fields: [["Name", v.ruleName], ["Applications", v.apps], ["File Types", v.fileTypes], ["Direction", v.direction], ["Analysis", v.analysis]] },
      ];
      const cli = [
        v.desc && `set profiles wildfire-analysis ${q(v.name)} description ${q(v.desc)}`,
        `set profiles wildfire-analysis ${q(v.name)} rules ${q(v.ruleName)} application ${members(v.apps)} file-type ${members(v.fileTypes)} direction ${v.direction} analysis ${v.analysis}`,
      ];
      if (v.group) {
        steps.push({ title: v.groupNew ? "Créer le groupe de profils" : "Ajouter le profil au groupe de profils", path: ["Objects", "Security Profile Groups"], window: "Security Profile Group",
          action: v.groupNew ? "Cliquer sur Add." : `Cliquer sur le groupe ${v.group} pour l'éditer.`,
          fields: [["Name", v.group], ["WildFire Analysis Profile", v.name]],
          note: "Les autres profils du groupe (Antivirus, Anti-Spyware, Vulnerability, URL Filtering…) restent inchangés." });
        cli.push(`set profile-group ${q(v.group)} wildfire-analysis ${q(v.name)}`);
      }
      if (v.secRule) {
        steps.push({ title: "Appliquer à la règle de sécurité", path: ["Policies", "Security"], tab: "Actions", window: "Security Policy Rule",
          action: `Ouvrir la règle ${v.secRule} → onglet Actions → section Profile Setting.`,
          fields: v.group ? [["Profile Type", "Group"], ["Group Profile", v.group]] : [["Profile Type", "Profiles"], ["WildFire Analysis", v.name]] });
        cli.push(v.group ? `set rulebase security rules ${q(v.secRule)} profile-setting group ${q(v.group)}`
          : `set rulebase security rules ${q(v.secRule)} profile-setting profiles wildfire-analysis ${q(v.name)}`);
      }
      const notes = [
        { type: "or", text: "Prérequis : licence WildFire active (Device > Licenses) pour les mises à jour temps réel et tous les types de fichiers ; sans licence seuls les PE sont envoyés." },
        { type: "or", title: "Paramètres globaux", text: "Région du cloud, limites de taille et rapports benign/grayware : module « Paramètres WildFire & mises à jour » (#m11-wildfire-settings)." },
      ];
      if (v.analysis === "private-cloud") notes.push({ type: "warn", text: "private-cloud : le serveur WF-500 doit être déclaré dans Device > Setup > WildFire (WildFire Private Cloud)." });
      if (!v.group && !v.secRule) notes.push({ type: "warn", text: "Le profil n'est appliqué à aucune règle : il ne sera pas utilisé." });
      notes.push({ type: "ok", text: "Test : télécharger http://wildfire.paloaltonetworks.com/publicapi/test/pe (fichier de test) puis Monitor > Logs > WildFire Submissions (verdict après 5 à 15 min)." });
      return { steps, cli: cli.filter(Boolean), notes,
        verify: ["show wildfire status", "test wildfire registration", "debug wildfire upload-log show", `show running security-policy | match "${v.secRule || ""}"`].filter(l => !/match ""$/.test(l)) };
    },
  });

  const WF_REGIONS = [
    ["wildfire.paloaltonetworks.com", "Global (US)"], ["eu.wildfire.paloaltonetworks.com", "Europe (Pays-Bas)"],
    ["de.wildfire.paloaltonetworks.com", "Allemagne"], ["uk.wildfire.paloaltonetworks.com", "Royaume-Uni"],
    ["ca.wildfire.paloaltonetworks.com", "Canada"],
    ["jp.wildfire.paloaltonetworks.com", "Japon"], ["sg.wildfire.paloaltonetworks.com", "Singapour"],
    ["au.wildfire.paloaltonetworks.com", "Australie"], ["in.wildfire.paloaltonetworks.com", "Inde"],
  ];
  const WF_SESSION = [
    ["src-ip", "Source IP"], ["src-port", "Source Port"], ["dest-ip", "Destination IP"], ["dest-port", "Destination Port"],
    ["vsys-id", "Virtual System"], ["app-name", "Application"], ["username", "User"], ["url", "URL"],
    ["filename", "Filename"], ["email-sender", "Email sender"], ["email-recipient", "Email recipient"], ["email-subject", "Email subject"],
  ];
  const WF_SCHED = [["real-time", "Real-time"], ["every-min", "Every Minute"], ["every-15-mins", "Every 15 Minutes"], ["every-30-mins", "Every 30 Minutes"], ["every-hour", "Every Hour"], ["none", "None"]];

  register({
    id: "m11-wildfire-settings",
    module: "M11",
    title: "Paramètres WildFire & mises à jour",
    icon: "☁️",
    desc: "Device > Setup > WildFire : cloud régional, limites de taille par type, rapports benign/grayware, informations de session transmises ; planification des mises à jour WildFire.",
    tags: "wildfire cloud region file size benign grayware session dynamic updates",
    fields: [
      { id: "cloud", label: "WildFire Public Cloud", type: "select", default: "wildfire.paloaltonetworks.com", options: WF_REGIONS },
      { id: "privCloud", label: "WildFire Private Cloud (IP/FQDN WF-500, optionnel)", type: "text", validate: "host" },
      { id: "pe", label: "Limite pe (MB, 1-50)", type: "number", min: 1, max: 50, default: "16", group: "File Size Limits" },
      { id: "pdf", label: "Limite pdf (KB, 100-51200)", type: "number", min: 100, max: 51200, default: "3072" },
      { id: "office", label: "Limite ms-office (KB, 200-51200)", type: "number", min: 200, max: 51200, default: "16384" },
      { id: "archive", label: "Limite archive (MB, 1-50)", type: "number", min: 1, max: 50, default: "50" },
      { id: "benign", label: "Report Benign Files", type: "checkbox", default: true, group: "Rapports" },
      { id: "grayware", label: "Report Grayware Files", type: "checkbox", default: true },
      ...WF_SESSION.map(([k, l], i) => ({ id: "s_" + k, label: l, type: "checkbox", default: true, group: i ? undefined : "Session Information Settings (cochés = envoyés à WildFire)" })),
      { id: "sched", label: "Mise à jour WildFire (Dynamic Updates)", type: "select", default: "real-time", options: WF_SCHED, group: "Dynamic Updates" },
    ],
    build(v) {
      const excl = WF_SESSION.filter(([k]) => !v["s_" + k]);
      const steps = [
        { title: "Paramètres généraux WildFire", path: ["Device", "Setup", "WildFire"], window: "General Settings",
          action: "Cliquer sur l'icône ⚙ du cadre « General Settings ».",
          fields: [["WildFire Public Cloud", v.cloud], ["WildFire Private Cloud", v.privCloud], ["Report Benign Files", v.benign], ["Report Grayware Files", v.grayware],
            ["File Size Limits › pe", v.pe + " MB"], ["File Size Limits › pdf", v.pdf + " KB"], ["File Size Limits › ms-office", v.office + " KB"], ["File Size Limits › archive", v.archive + " MB"]],
          note: "Les autres types (apk, jar, flash, MacOSX, linux, script) gardent leur valeur par défaut." },
        { title: "Informations de session transmises", path: ["Device", "Setup", "WildFire"], window: "Session Information Settings",
          action: "Cliquer sur l'icône ⚙ du cadre « Session Information Settings » et décocher les informations à ne pas envoyer.",
          fields: excl.length ? excl.map(([, l]) => [l, "☐ décoché"]) : [["Toutes les options", "✓ cochées (défaut)"]] },
        { title: "Planifier les mises à jour WildFire", path: ["Device", "Dynamic Updates"], window: "WildFire Update Schedule",
          action: "Cliquer sur Check Now, puis sur le lien de planification (Schedule) de la section WildFire.",
          fields: [["Recurrence", WF_SCHED.find(s => s[0] === v.sched)[1]], ["Action", v.sched === "real-time" || v.sched === "none" ? "" : "download-and-install"]] },
      ];
      const b = "set deviceconfig setting wildfire";
      const cli = [
        `${b} public-cloud-server ${v.cloud}`,
        v.privCloud && `${b} private-cloud-server ${v.privCloud}`,
        `${b} file-size-limit pe size-limit ${v.pe}`,
        `${b} file-size-limit pdf size-limit ${v.pdf}`,
        `${b} file-size-limit ms-office size-limit ${v.office}`,
        `${b} file-size-limit archive size-limit ${v.archive}`,
        `${b} report-benign-file ${yes(v.benign)}`,
        `${b} report-grayware-file ${yes(v.grayware)}`,
        ...WF_SESSION.map(([k]) => `${b} session-info-select exclude-${k} ${yes(!v["s_" + k])}`),
        v.sched === "none" ? "delete deviceconfig system update-schedule wildfire"
          : v.sched === "real-time" ? "set deviceconfig system update-schedule wildfire recurring real-time"
          : `set deviceconfig system update-schedule wildfire recurring ${v.sched} action download-and-install`,
      ].filter(Boolean);
      const notes = [];
      if (v.sched === "none") notes.push({ type: "bad", text: "Sans mise à jour WildFire, les signatures des nouveaux malwares ne sont pas reçues entre deux mises à jour Antivirus." });
      if (!v.s_username || !v.s_url) notes.push({ type: "or", text: "Exclure User/URL limite le contenu des rapports WildFire (utile pour la conformité RGPD)." });
      notes.push({ type: "or", text: "Région : choisir le cloud le plus proche / imposé par la politique de résidence des données. Le pare-feu doit résoudre et joindre le FQDN en HTTPS (443) depuis l'interface de management (ou la service route WildFire)." });
      return { steps, cli, notes, verify: ["show wildfire status", "test wildfire registration", "show system info | match wildfire"] };
    },
  });

  /* =====================================================================
     M12 · User-ID
     ===================================================================== */
  register({
    id: "m12-enable-zone",
    module: "M12",
    title: "Activer User-ID sur une zone",
    icon: "🪪",
    desc: "Network > Zones : Enable User Identification sur les zones internes, avec listes d'inclusion / d'exclusion de réseaux.",
    tags: "user-id zone enable user identification include exclude",
    fields: [
      { id: "zones", label: "Zone(s) interne(s)", type: "list", required: true, validate: zoneList, default: ["Trust"], hint: "Uniquement les zones internes (jamais Untrust)." },
      { id: "include", label: "Include List (réseaux)", type: "list", validate: "ipcidr", default: ["192.168.1.0/24"], hint: "Vide = tous les réseaux de la zone." },
      { id: "exclude", label: "Exclude List (réseaux)", type: "list", validate: "ipcidr", default: [] },
    ],
    build(v) {
      const steps = v.zones.map(z => ({
        title: `Activer User-ID sur la zone ${z}`, path: ["Network", "Zones"], window: "Zone",
        action: `Cliquer sur la zone ${z} pour l'éditer → section User Identification ACL.`,
        fields: [["Name", z], ["Enable User Identification", true], ["Include List", v.include], ["Exclude List", v.exclude]],
      }));
      const cli = v.zones.flatMap(z => [
        `set zone ${q(z)} enable-user-identification yes`,
        v.include.length && `set zone ${q(z)} user-acl include-list ${members(v.include)}`,
        v.exclude.length && `set zone ${q(z)} user-acl exclude-list ${members(v.exclude)}`,
      ]).filter(Boolean);
      const notes = [];
      if (v.zones.some(z => /untrust|internet|outside|wan/i.test(z))) notes.push({ type: "bad", text: "N'activez pas User-ID sur une zone externe : le pare-feu tenterait de sonder / exposerait l'agent User-ID vers Internet." });
      notes.push({ type: "or", text: "Sources de mapping : module « Agent User-ID intégré » (#m12-server-monitoring) ou « Authentication Portal » (#m12-auth-portal)." });
      return { steps, cli, notes, verify: ["show user ip-user-mapping all", "show user ip-user-mapping all | match " + (v.include[0] || "").split("/")[0].split(".").slice(0, 3).join(".")].filter(l => !/match $/.test(l)) };
    },
  });

  register({
    id: "m12-ldap-group-mapping",
    module: "M12",
    title: "Profil LDAP & Group Mapping",
    icon: "📒",
    desc: "LDAP Server Profile (serveurs, Base DN, Bind DN, SSL) puis Group Mapping pour utiliser les groupes AD/LDAP dans les règles.",
    tags: "ldap server profile group mapping active directory groupes",
    example: { pw: "Bind-Passw0rd!" },
    fields: [
      { id: "prof", label: "Nom du profil LDAP", type: "text", required: true, validate: NAME, default: "LDAP-AD" },
      { id: "srvName", label: "Nom du serveur", type: "text", required: true, validate: NAME, default: "DC1", group: "Serveur LDAP" },
      { id: "srvAddr", label: "Adresse du serveur (IP/FQDN)", type: "text", required: true, validate: "host", default: "192.168.1.10" },
      { id: "srv2Name", label: "Serveur secondaire — nom (optionnel)", type: "text", default: "",
        validate: (x, v) => PAN.cfg.V.name(x) || (!v.srv2Addr ? "Renseigner aussi l'adresse du serveur secondaire" : x === v.srvName ? "Nom déjà utilisé par le serveur principal" : null) },
      { id: "srv2Addr", label: "Serveur secondaire — adresse", type: "text", validate: (x, v) => PAN.cfg.V.host(x) || (!v.srv2Name ? "Renseigner aussi le nom du serveur secondaire" : null) },
      { id: "ldapType", label: "Type", type: "select", default: "active-directory",
        options: [["active-directory", "active-directory"], ["e-directory", "e-directory"], ["sun", "sun"], ["other", "other"]] },
      { id: "ssl", label: "Require SSL/TLS secured connection (LDAPS)", type: "checkbox", default: true },
      { id: "verify", label: "Verify Server Certificate for SSL sessions", type: "checkbox", default: false, show: v => v.ssl },
      { id: "port", label: "Port", type: "port", required: true, default: "636", hint: "389 (LDAP / StartTLS) ou 636 (LDAPS)." },
      { id: "base", label: "Base DN", type: "text", required: true, validate: dn, default: "dc=corp,dc=local", group: "Authentification" },
      { id: "bind", label: "Bind DN", type: "text", required: true, default: "svc-paloalto@corp.local", hint: "UPN (user@domaine) ou DN complet." },
      { id: "pw", label: "Bind Password", type: "password", required: true, default: "" },
      { id: "gm", label: "Nom du Group Mapping", type: "text", required: true, validate: NAME, default: "GM-Corp", group: "Group Mapping" },
      { id: "domain", label: "User Domain (NetBIOS)", type: "text", validate: "hostname", default: "corp", hint: "Préfixe des utilisateurs : corp\\jdupont." },
      { id: "interval", label: "Update Interval (s, 60-86400)", type: "number", min: 60, max: 86400, default: "3600" },
      { id: "groups", label: "Group Include List (DN des groupes)", type: "list", default: ["cn=GG-Marketing,ou=Groups,dc=corp,dc=local", "cn=GG-IT,ou=Groups,dc=corp,dc=local"],
        hint: "DN complets ; chaque nouveau DN commence par cn= (séparateur « ; » accepté). Vide = tous les groupes.", wide: true },
    ],
    build(v) {
      const groups = splitDN(v.groups);
      const steps = [
        { title: "Créer le profil de serveur LDAP", path: ["Device", "Server Profiles", "LDAP"], window: "LDAP Server Profile",
          action: "Cliquer sur Add. Dans Server List, Add pour chaque serveur.",
          fields: [["Profile Name", v.prof], ["Server List › Name", v.srvName], ["Server List › LDAP Server", v.srvAddr], ["Server List › Port", v.port],
            ["Server List › Name (2)", v.srv2Name], ["Server List › LDAP Server (2)", v.srv2Addr],
            ["Type", v.ldapType], ["Base DN", v.base], ["Bind DN", v.bind], ["Password / Confirm Password", "••••••••"],
            ["Require SSL/TLS secured connection", v.ssl], ["Verify Server Certificate for SSL sessions", v.ssl && v.verify]],
          note: "Avec Base DN vide, la liste déroulante permet de le récupérer depuis le serveur (après saisie du serveur et du Bind)." },
        { title: "Group Mapping — onglet Server Profile", path: ["Device", "User Identification", "Group Mapping Settings"], tab: "Server Profile", window: "Group Mapping",
          action: "Cliquer sur Add.",
          fields: [["Name", v.gm], ["Server Profile", v.prof], ["User Domain", v.domain], ["Update Interval", v.interval], ["Enabled", true]] },
        { title: "Group Mapping — attributs", path: ["Device", "User Identification", "Group Mapping Settings"], tab: "User and Group Attributes", window: "Group Mapping",
          fields: v.ldapType === "active-directory"
            ? [["Primary Username", "sAMAccountName"], ["Group Name", "name"], ["Group Member", "member"]]
            : [["Primary Username", "uid"], ["Group Name", "cn"], ["Group Member", "member"]],
          note: "Valeurs pré-remplies selon le Type du profil LDAP ; vérifier qu'elles correspondent à l'annuaire." },
      ];
      if (groups.length) steps.push({ title: "Group Mapping — groupes à importer", path: ["Device", "User Identification", "Group Mapping Settings"], tab: "Group Include List", window: "Group Mapping",
        action: "Déplier l'arborescence de gauche (Available Groups), sélectionner les groupes et cliquer sur ➕ pour les passer dans Included Groups.",
        fields: groups.map((g, i) => ["Included Groups #" + (i + 1), g]) });
      const P = `set shared server-profile ldap ${q(v.prof)}`;
      const cli = [
        `${P} server ${q(v.srvName)} address ${v.srvAddr} port ${v.port}`,
        v.srv2Name && v.srv2Addr && `${P} server ${q(v.srv2Name)} address ${v.srv2Addr} port ${v.port}`,
        `${P} ldap-type ${v.ldapType}`,
        `${P} base ${q(v.base)}`,
        `${P} bind-dn ${q(v.bind)}`,
        `${P} bind-password ${q(v.pw)}`,
        `${P} ssl ${yes(v.ssl)}`,
        v.ssl && `${P} verify-server-certificate ${yes(v.verify)}`,
        `set group-mapping ${q(v.gm)} server-profile ${q(v.prof)}`,
        v.domain && `set group-mapping ${q(v.gm)} domain ${q(v.domain)}`,
        `set group-mapping ${q(v.gm)} update-interval ${v.interval}`,
        `set group-mapping ${q(v.gm)} enabled yes`,
        groups.length && `set group-mapping ${q(v.gm)} group-include-list ${members(groups)}`,
      ].filter(Boolean);
      const notes = [];
      if (v.ssl && v.port === "389") notes.push({ type: "warn", text: "SSL coché avec le port 389 : utilise StartTLS. Pour LDAPS, utiliser 636." });
      if (!v.ssl) notes.push({ type: "warn", text: "LDAP en clair : le mot de passe du compte de bind circule sans chiffrement. Préférer LDAPS (636)." });
      if (v.verify) notes.push({ type: "or", text: "Verify Server Certificate : la CA de l'annuaire doit être importée (Device > Certificate Management > Certificates) et le nom du serveur doit correspondre au CN/SAN." });
      if (!groups.length) notes.push({ type: "or", text: "Group Include List vide : tous les groupes de l'annuaire sont importés (charge inutile sur les grands AD)." });
      notes.push({ type: "or", text: "Le compte de bind n'a besoin que de droits de lecture sur l'annuaire." });
      return { steps, cli, notes, verify: ["show user group-mapping state all", "show user group list", groups.length ? `show user group name ${q(groups[0])}` : "show user group-mapping statistics"] };
    },
  });
  /* DN : la saisie « list » coupe sur les virgules → on recolle les RDN et on accepte « ; » comme séparateur */
  function splitDN(arr) {
    const out = [];
    arr.join(",").split(";").forEach(chunk => {
      let cur = [];
      chunk.split(",").map(s => s.trim()).filter(Boolean).forEach(rdn => {
        if (/^cn=/i.test(rdn) && cur.length) { out.push(cur.join(",")); cur = []; }
        cur.push(rdn);
      });
      if (cur.length) out.push(cur.join(","));
    });
    return out;
  }

  register({
    id: "m12-server-monitoring",
    module: "M12",
    title: "Agent User-ID intégré (Server Monitoring)",
    icon: "🛰️",
    desc: "Agent User-ID intégré à PAN-OS : compte de service, surveillance des contrôleurs de domaine / Exchange (WinRM ou WMI), réseaux inclus/exclus, utilisateurs ignorés.",
    tags: "user-id agent server monitoring active directory winrm wmi exchange service account include exclude",
    example: { pw: "Svc-Passw0rd!" },
    fields: [
      { id: "acct", label: "Compte de service (domaine\\utilisateur)", type: "text", required: true, default: "corp\\svc-userid",
        validate: x => /^[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+$/.test(x) ? null : "Format domaine\\utilisateur (NetBIOS), ex. corp\\svc-userid" },
      { id: "dnsDomain", label: "Domain's DNS Name", type: "text", validate: "fqdn", default: "corp.local" },
      { id: "pw", label: "Mot de passe du compte", type: "password", required: true, default: "" },
      { id: "transport", label: "Transport Protocol", type: "select", default: "winrm-http", group: "Serveurs surveillés",
        options: [["winrm-http", "WinRM-HTTP (Kerberos)"], ["winrm-https", "WinRM-HTTPS"], ["wmi", "WMI"]] },
      { id: "krb", label: "Kerberos Server Profile (créé si absent)", type: "text", validate: NAME, default: "KRB-Corp", show: v => v.transport === "winrm-http", required: true },
      { id: "servers", label: "Contrôleurs de domaine (FQDN ou IP)", type: "list", required: true, default: ["dc1.corp.local", "dc2.corp.local"],
        validate: (arr, v) => { for (const s of arr) { const e = PAN.cfg.V.host(s); if (e) return `« ${s} » : ${e}`; if (v.transport === "winrm-http" && PAN.ip.valid(s)) return `« ${s} » : WinRM-HTTP (Kerberos) exige un FQDN`; } return null; } },
      { id: "exchange", label: "Serveurs Microsoft Exchange (optionnel)", type: "list", validate: "host", default: [] },
      { id: "secLog", label: "Enable Security Log", type: "checkbox", default: true, group: "Server Monitor" },
      { id: "secFreq", label: "Server Log Monitor Frequency (s)", type: "number", min: 1, max: 3600, default: "2", show: v => v.secLog },
      { id: "session", label: "Enable Session (lecture des sessions SMB)", type: "checkbox", default: false },
      { id: "timeout", label: "User Identification Timeout (min)", type: "number", min: 1, max: 1440, default: "45", hint: "Onglet Cache. Doit dépasser la durée typique de bail DHCP / session." },
      { id: "incl", label: "Réseaux inclus", type: "list", validate: "ipcidr", default: ["192.168.1.0/24"], group: "Include/Exclude Networks & Ignore User List" },
      { id: "excl", label: "Réseaux exclus", type: "list", validate: "ipcidr", default: [] },
      { id: "ignore", label: "Ignore User List", type: "list", default: ["svc-backup", "svc-sccm"], hint: "Comptes de service à ne jamais mapper (sans domaine)." },
    ],
    build(v) {
      const T = { "winrm-http": "WinRM-HTTP", "winrm-https": "WinRM-HTTPS", wmi: "WMI" }[v.transport];
      const host = s => s.split(".")[0].replace(/[^A-Za-z0-9_-]/g, "-").toUpperCase();
      const srvs = [...v.servers.map(s => ({ n: "DC-" + host(s), a: s, t: "Microsoft Active Directory", k: "active-directory" })),
        ...v.exchange.map(s => ({ n: "EXCH-" + host(s), a: s, t: "Microsoft Exchange", k: "exchange" }))];
      const steps = [];
      const cli = [];
      if (v.transport === "winrm-http") {
        steps.push({ title: "Créer le profil de serveur Kerberos", path: ["Device", "Server Profiles", "Kerberos"], window: "Kerberos Server Profile",
          action: "Cliquer sur Add, puis Add dans la liste des serveurs (un par contrôleur de domaine).",
          fields: [["Profile Name", v.krb], ...v.servers.flatMap((s, i) => [[`Name (${i + 1})`, "KDC-" + host(s)], [`Kerberos Server (${i + 1})`, s], [`Port (${i + 1})`, "88"]])] });
        v.servers.forEach(s => cli.push(`set shared server-profile kerberos ${q(v.krb)} server ${q("KDC-" + host(s))} host ${s} port 88`));
      }
      steps.push(
        { title: "Compte de surveillance des serveurs", path: ["Device", "User Identification", "User Mapping"], tab: "Server Monitor Account", window: "Palo Alto Networks User-ID Agent Setup",
          action: "Cliquer sur l'icône ⚙ du cadre « Palo Alto Networks User-ID Agent Setup ».",
          fields: [["User Name", v.acct], ["Domain's DNS Name", v.dnsDomain], ["Password / Confirm Password", "••••••••"], ["Kerberos Server Profile", v.transport === "winrm-http" ? v.krb : ""]] },
        { title: "Fréquences de surveillance", path: ["Device", "User Identification", "User Mapping"], tab: "Server Monitor", window: "Palo Alto Networks User-ID Agent Setup",
          fields: [["Enable Security Log", v.secLog], ["Server Log Monitor Frequency (sec)", v.secLog ? v.secFreq : ""], ["Enable Session", v.session]] },
        { title: "Délai d'expiration des mappings", path: ["Device", "User Identification", "User Mapping"], tab: "Cache", window: "Palo Alto Networks User-ID Agent Setup",
          fields: [["Enable User Identification Timeout", true], ["User Identification Timeout (min)", v.timeout]] },
      );
      if (v.ignore.length) steps.push({ title: "Comptes ignorés", path: ["Device", "User Identification", "User Mapping"], tab: "Ignore User List", window: "Palo Alto Networks User-ID Agent Setup",
        action: "Add pour chaque compte, puis OK pour fermer la fenêtre.", fields: v.ignore.map((u, i) => ["Ignore User #" + (i + 1), u]) });
      srvs.forEach(s => {
        steps.push({ title: `Surveiller ${s.a}`, path: ["Device", "User Identification", "User Mapping"], window: "Server Monitoring",
          action: "Dans la section Server Monitoring, cliquer sur Add.",
          fields: [["Name", s.n], ["Enabled", true], ["Type", s.t], ["Transport Protocol", T], ["Network Address", s.a]] });
        cli.push(`set user-id-collector server-monitor ${q(s.n)} ${s.k} host ${s.a}`,
          `set user-id-collector server-monitor ${q(s.n)} ${s.k} transport ${v.transport}`,
          `set user-id-collector server-monitor ${q(s.n)} enabled yes`);
      });
      const nets = [...v.incl.map(n => ["include", n]), ...v.excl.map(n => ["exclude", n])];
      nets.forEach(([d, n], i) => {
        steps.push({ title: `Réseau ${d === "include" ? "inclus" : "exclu"} ${n}`, path: ["Device", "User Identification", "User Mapping"], window: "Include/Exclude Network",
          action: "Dans la section Include/Exclude Networks, cliquer sur Add.",
          fields: [["Name", `${d === "include" ? "Incl" : "Excl"}-${n.replace(/[./]/g, "_")}`], ["Enabled", true], ["Discovery", d === "include" ? "Include" : "Exclude"], ["Network Address", n]] });
        cli.push(`set user-id-collector include-exclude-network ${q(`${d === "include" ? "Incl" : "Excl"}-${n.replace(/[./]/g, "_")}`)} discovery ${d} network-address ${n} enabled yes`);
      });
      cli.unshift(
        `set user-id-collector setting wmi-account ${qb(v.acct)}`,
        `set user-id-collector setting wmi-password ${q(v.pw)}`,
        v.dnsDomain && `set user-id-collector setting server-monitor-domain-dns-name ${v.dnsDomain}`,
        v.transport === "winrm-http" && `set user-id-collector setting kerberos-server-profile ${q(v.krb)}`,
        `set user-id-collector setting enable-security-log ${yes(v.secLog)}`,
        v.secLog && `set user-id-collector setting security-log-interval ${v.secFreq}`,
        `set user-id-collector setting enable-session ${yes(v.session)}`,
        `set user-id-collector setting enable-mapping-timeout yes ip-user-mapping-timeout ${v.timeout}`,
        v.ignore.length && `set user-id-collector setting ignore-user ${members(v.ignore)}`,
      );
      const notes = [
        { type: "warn", title: "Droits du compte de service (pas Domain Admin)", text:
          "• Event Log Readers (lecture du journal Sécurité des DC / Exchange) — toujours. " +
          (v.transport === "wmi" ? "• Distributed COM Users + droits Enable Account / Remote Enable sur l'espace de noms WMI root\\CIMV2. " :
            "• Remote Management Users (WinRM) + droits Enable Account / Remote Enable sur root\\CIMV2 ; WinRM activé sur les DC (winrm quickconfig, port 5985 HTTP / 5986 HTTPS). ") +
          (v.session ? "• Server Operators (lecture des sessions avec Enable Session). " : "") +
          "• Audit des ouvertures de session (4624, 4768, 4769, 4770) activé par GPO sur les DC." },
        { type: "or", text: "User-ID doit être activé sur les zones sources : module « Activer User-ID sur une zone » (#m12-enable-zone). Pour les groupes : #m12-ldap-group-mapping." },
      ];
      if (v.transport === "winrm-http") notes.push({ type: "or", text: "WinRM-HTTP + Kerberos : NTP synchronisé (écart < 5 min), DNS du pare-feu capable de résoudre les FQDN des DC." });
      if (v.transport === "winrm-https") notes.push({ type: "or", text: "WinRM-HTTPS : importer la CA racine qui a signé le certificat WinRM des DC (Device > Certificate Management)." });
      if (!v.incl.length) notes.push({ type: "warn", text: "Sans réseau inclus, des IP publiques / VPN peuvent être mappées. Définir au moins le LAN." });
      return { steps, cli: cli.filter(Boolean), notes,
        verify: ["show user server-monitor state all", "show user server-monitor statistics", "show user ip-user-mapping all", "show user ip-user-mapping-mp all"] };
    },
  });

  register({
    id: "m12-auth-portal",
    module: "M12",
    title: "Authentication Portal & Authentication Policy",
    icon: "🔐",
    desc: "Portail d'authentification (redirect/transparent) pour les utilisateurs non identifiés : profil d'authentification, certificat, objet Authentication Enforcement et règle Authentication.",
    tags: "authentication portal captive portal authentication policy enforcement web-form redirect transparent",
    fields: [
      { id: "mode", label: "Mode", type: "select", default: "redirect", options: [["redirect", "Redirect (recommandé)"], ["transparent", "Transparent"]] },
      { id: "redirHost", label: "Redirect Host / CN du certificat (IP de l'interface interne ou FQDN)", type: "text", required: true, validate: "host", default: "192.168.1.1" },
      { id: "iface", label: "Interface d'entrée des utilisateurs", type: "text", required: true, validate: "iface", default: "ethernet1/2" },
      { id: "mgmtProf", label: "Interface Management Profile (Response Pages)", type: "text", required: true, validate: NAME, default: "Mgmt-Portal" },
      { id: "cert", label: "Certificat du portail (généré)", type: "text", required: true, validate: NAME, default: "Cert-AuthPortal", group: "Certificat & profils" },
      { id: "signer", label: "Signé par (CA du pare-feu, vide = autosigné)", type: "text", validate: NAME, default: "Corp-Forward-Trust", hint: "Une CA déjà déployée sur les postes évite l'alerte navigateur (#m13-certificates)." },
      { id: "sslProf", label: "SSL/TLS Service Profile", type: "text", required: true, validate: NAME, default: "SSL-AuthPortal" },
      { id: "authProf", label: "Authentication Profile", type: "text", required: true, validate: NAME, default: "Auth-LDAP" },
      { id: "ldapProf", label: "LDAP Server Profile utilisé", type: "text", required: true, validate: NAME, default: "LDAP-AD", hint: "Créé dans #m12-ldap-group-mapping." },
      { id: "enfName", label: "Authentication Enforcement (objet)", type: "text", required: true, validate: NAME, default: "Enf-Web-Form", group: "Authentication Policy" },
      { id: "method", label: "Authentication Method", type: "select", default: "web-form", options: [["web-form", "web-form"], ["browser-challenge", "browser-challenge (Kerberos SSO)"]] },
      { id: "rule", label: "Nom de la règle Authentication", type: "text", required: true, validate: NAME, default: "Auth-Unknown-Users" },
      { id: "from", label: "Zone source", type: "text", required: true, validate: NAME, default: "Trust" },
      { id: "to", label: "Zone destination", type: "text", required: true, validate: NAME, default: "Untrust" },
      { id: "srcNet", label: "Source Address", type: "list", validate: addrList, default: ["192.168.1.0/24"] },
      { id: "timeout", label: "Timeout (min)", type: "number", min: 1, max: 1440, default: "60" },
    ],
    build(v) {
      const steps = [
        { title: "Générer le certificat du portail", path: ["Device", "Certificate Management", "Certificates"], window: "Generate Certificate",
          action: "Onglet Device Certificates → Generate (en bas).",
          fields: [["Certificate Name", v.cert], ["Common Name", v.redirHost], ["Signed By", v.signer], ["Certificate Authority", "☐ décoché"],
            ["Algorithm", "RSA"], ["Number of Bits", "2048"], ["Digest", "sha256"], ...(!PAN.ip.valid(v.redirHost) ? [["Certificate Attributes › Host Name", v.redirHost]] : [["Certificate Attributes › IP", v.redirHost]])] },
        { title: "Créer le SSL/TLS Service Profile", path: ["Device", "Certificate Management", "SSL/TLS Service Profile"], window: "SSL/TLS Service Profile",
          action: "Cliquer sur Add.", fields: [["Name", v.sslProf], ["Certificate", v.cert], ["Min Version", "TLSv1.2"], ["Max Version", "Max"]] },
        { title: "Créer le profil d'authentification", path: ["Device", "Authentication Profile"], tab: "Authentication", window: "Authentication Profile",
          action: "Cliquer sur Add. Onglet Advanced : Allow List = all.",
          fields: [["Name", v.authProf], ["Type", "LDAP"], ["Server Profile", v.ldapProf], ["Login Attribute", "sAMAccountName"], ["User Domain", ""], ["Advanced › Allow List", "all"]] },
        { title: "Autoriser les Response Pages sur l'interface", path: ["Network", "Network Profiles", "Interface Mgmt"], window: "Interface Management Profile",
          action: `Add (ou éditer le profil existant), puis l'affecter à ${v.iface} : Network > Interfaces > ${v.iface} > Advanced > Management Profile.`,
          fields: [["Name", v.mgmtProf], ["Response Pages", true], ["Permitted IP Addresses", v.srcNet]] },
        { title: "Paramètres de l'Authentication Portal", path: ["Device", "User Identification", "Authentication Portal Settings"], window: "Authentication Portal",
          action: "Cliquer sur l'icône ⚙.",
          fields: [["Enable Authentication Portal", true], ["Idle Timer (min)", "15"], ["Timer (min)", "60"], ["SSL/TLS Service Profile", v.sslProf], ["Authentication Profile", v.authProf],
            ["Mode", v.mode === "redirect" ? "Redirect" : "Transparent"], ["Redirect Host", v.mode === "redirect" ? v.redirHost : ""]] },
        { title: "Créer l'objet Authentication Enforcement", path: ["Objects", "Authentication"], window: "Authentication Enforcement",
          action: "Cliquer sur Add.",
          fields: [["Name", v.enfName], ["Authentication Method", v.method], ["Authentication Profile", v.authProf], ["Message", "Authentification requise pour accéder à Internet"]] },
        { title: "Règle Authentication — Source", path: ["Policies", "Authentication"], tab: "Source", window: "Authentication Policy Rule",
          action: `Add → onglet General : Name = ${v.rule}. Puis onglet Source.`,
          fields: [["Name", v.rule], ["Source Zone", v.from], ["Source Address", v.srcNet.length ? v.srcNet : "any"], ["Source User", "unknown"]] },
        { title: "Règle Authentication — Destination & Service", path: ["Policies", "Authentication"], tab: "Destination / Service/URL Category", window: "Authentication Policy Rule",
          fields: [["Destination Zone", v.to], ["Destination Address", "any"], ["Service", "service-http, service-https"], ["URL Category", "any"]] },
        { title: "Règle Authentication — Actions", path: ["Policies", "Authentication"], tab: "Actions", window: "Authentication Policy Rule",
          fields: [["Authentication Enforcement", v.enfName], ["Timeout (min)", v.timeout], ["Log Authentication Timeouts", true]] },
      ];
      const signed = v.signer ? ` signed-by ${q(v.signer)}` : "";
      const op = [`request certificate generate certificate-name ${q(v.cert)} name ${q(v.redirHost)}${signed} algorithm RSA rsa-nbits 2048 digest sha256`];
      const src = v.srcNet.length ? members(v.srcNet) : "any";
      const cfg = [
        `set shared ssl-tls-service-profile ${q(v.sslProf)} certificate ${q(v.cert)}`,
        `set shared ssl-tls-service-profile ${q(v.sslProf)} protocol-settings min-version tls1-2 max-version max`,
        `set shared authentication-profile ${q(v.authProf)} method ldap server-profile ${q(v.ldapProf)} login-attribute sAMAccountName`,
        `set shared authentication-profile ${q(v.authProf)} allow-list all`,
        `set network profiles interface-management-profile ${q(v.mgmtProf)} response-pages yes`,
        ...v.srcNet.map(n => `set network profiles interface-management-profile ${q(v.mgmtProf)} permitted-ip ${n}`),
        `set network interface ethernet ${v.iface.split(".")[0]} layer3${v.iface.includes(".") ? " units " + v.iface : ""} interface-management-profile ${q(v.mgmtProf)}`,
        `set captive-portal enable-captive-portal yes`,
        `set captive-portal mode ${v.mode}`,
        v.mode === "redirect" && `set captive-portal redirect-host ${v.redirHost}`,
        `set captive-portal ssl-tls-service-profile ${q(v.sslProf)}`,
        `set captive-portal authentication-profile ${q(v.authProf)}`,
        `set captive-portal idle-timer 15 timer 60`,
        `set authentication-object ${q(v.enfName)} authentication-method ${v.method} authentication-profile ${q(v.authProf)} message ${q("Authentification requise pour accéder à Internet")}`,
        `set rulebase authentication rules ${q(v.rule)} from ${q(v.from)} to ${q(v.to)} source ${src} destination any source-user unknown service [ service-http service-https ] category any`,
        `set rulebase authentication rules ${q(v.rule)} authentication-enforcement ${q(v.enfName)} timeout ${v.timeout} log-authentication-timeout yes`,
      ].filter(Boolean);
      const verify = ["show user ip-user-mapping all", "show running authentication-policy", "test authentication authentication-profile " + q(v.authProf) + " username jdupont password"];
      const notes = [];
      if (v.from === v.to) notes.push({ type: "warn", text: "Zones source et destination identiques : vérifier qu'il s'agit bien d'un flux intra-zone." });
      if (v.mode === "transparent") notes.push({ type: "warn", text: "Mode Transparent : le pare-feu usurpe l'URL demandée → erreurs de certificat pour HTTPS. Préférer Redirect." });
      notes.push({ type: "or", text: "Redirect : l'IP du Redirect Host doit appartenir à une interface L3 avec Response Pages ; si FQDN, il doit résoudre vers cette IP. Les cookies de session permettent la ré-auth transparente." });
      notes.push({ type: "or", text: "HTTPS des utilisateurs non identifiés : le portail ne s'affiche que si le trafic est décrypté (#m13-decryption-policy) ; sinon le premier accès doit être en HTTP." });
      if (v.method === "browser-challenge") notes.push({ type: "or", text: "browser-challenge : nécessite un keytab Kerberos dans le profil d'authentification et des navigateurs configurés pour le SSO." });
      return { steps, notes, cliRaw: rawCli(op, cfg, verify), verify };
    },
  });

  register({
    id: "m12-user-rule",
    module: "M12",
    title: "Règle de sécurité par groupe d'utilisateurs",
    icon: "👥",
    desc: "Règle de sécurité dont la source est un groupe AD (onglet Source › Source User), avec groupe d'applications et règle de refus explicite.",
    tags: "user-id security rule source user group ad application group",
    fields: [
      { id: "name", label: "Nom de la règle", type: "text", required: true, validate: NAME, default: "Allow-Marketing-Social" },
      { id: "desc", label: "Description", type: "text", default: "Réseaux sociaux réservés au groupe Marketing" },
      { id: "from", label: "Zone source", type: "list", required: true, validate: zoneList, default: ["Trust"], group: "Source" },
      { id: "srcUser", label: "Source User (groupe ou utilisateur)", type: "text", required: true, default: "corp\\gg-marketing",
        hint: "Format affiché par le pare-feu : domaine\\groupe ou DN (cn=…,dc=…). Mots-clés : known-user, unknown." },
      { id: "to", label: "Zone destination", type: "list", required: true, validate: zoneList, default: ["Untrust"], group: "Destination & application" },
      { id: "appGrp", label: "Nom du groupe d'applications (vide = applications directes)", type: "text", validate: NAME, default: "AppGrp-Social" },
      { id: "apps", label: "Applications", type: "list", required: true, default: ["facebook-base", "instagram-base", "linkedin-base", "twitter-base"] },
      { id: "secProf", label: "Groupe de profils de sécurité", type: "text", validate: NAME, default: "Std-Profiles" },
      { id: "deny", label: "Créer aussi une règle de refus explicite pour ces applications (autres utilisateurs)", type: "checkbox", default: true, group: "Refus" },
      { id: "denyName", label: "Nom de la règle de refus", type: "text", validate: (x, v) => PAN.cfg.V.name(x) || (x === v.name ? "Doit différer de la règle autorisée" : null), required: true, default: "Deny-Social-Others", show: v => v.deny },
    ],
    build(v) {
      const appRef = v.appGrp ? [v.appGrp] : v.apps;
      const steps = [];
      const cli = [];
      if (v.appGrp) {
        steps.push({ title: "Créer le groupe d'applications", path: ["Objects", "Application Groups"], window: "Application Group",
          action: "Cliquer sur Add, puis Add pour chaque application.", fields: [["Name", v.appGrp], ["Applications", v.apps]] });
        cli.push(`set application-group ${q(v.appGrp)} members ${members(v.apps)}`);
      }
      const ruleSteps = (n, user, action, desc) => [
        { title: `Règle ${n} — General`, path: ["Policies", "Security"], tab: "General", window: "Security Policy Rule",
          action: "Cliquer sur Add.", fields: [["Name", n], ["Rule Type", "universal (default)"], ["Description", desc]] },
        { title: `Règle ${n} — Source`, path: ["Policies", "Security"], tab: "Source", window: "Security Policy Rule",
          action: user === "any" ? "" : "Dans la colonne Source User, cliquer sur Add et commencer à taper le nom du groupe pour l'auto-complétion.",
          fields: [["Source Zone", v.from], ["Source Address", "Any"], ["Source User", user]] },
        { title: `Règle ${n} — Destination`, path: ["Policies", "Security"], tab: "Destination", window: "Security Policy Rule", fields: [["Destination Zone", v.to], ["Destination Address", "Any"]] },
        { title: `Règle ${n} — Application`, path: ["Policies", "Security"], tab: "Application", window: "Security Policy Rule",
          action: "Décocher Any, puis Add.", fields: [["Applications", appRef]],
          note: action === "allow" ? "Si un avertissement « dépendances » apparaît (onglet Application > Depends On), cliquer sur Add to Current Rule." : "" },
        { title: `Règle ${n} — Service/URL Category`, path: ["Policies", "Security"], tab: "Service/URL Category", window: "Security Policy Rule", fields: [["Service", "application-default"]] },
        { title: `Règle ${n} — Actions`, path: ["Policies", "Security"], tab: "Actions", window: "Security Policy Rule",
          fields: [["Action", action === "allow" ? "Allow" : "Deny"], ["Profile Type", action === "allow" && v.secProf ? "Group" : ""], ["Group Profile", action === "allow" ? v.secProf : ""], ["Log at Session End", true]] },
      ];
      steps.push(...ruleSteps(v.name, v.srcUser, "allow", v.desc));
      const R = n => `set rulebase security rules ${q(n)}`;
      cli.push(`${R(v.name)} from ${members(v.from)} to ${members(v.to)} source any destination any source-user ${qb(v.srcUser)} application ${members(appRef)} service application-default action allow`,
        v.desc && `${R(v.name)} description ${q(v.desc)}`,
        v.secProf && `${R(v.name)} profile-setting group ${q(v.secProf)}`);
      if (v.deny) {
        steps.push(...ruleSteps(v.denyName, "any", "deny", "Refus des mêmes applications pour les autres utilisateurs"));
        steps.push({ title: "Ordonner les règles", path: ["Policies", "Security"], action: `Sélectionner ${v.denyName} → Move → placer juste sous ${v.name} (avant toute règle plus large qui autoriserait ces applications).`, fields: [] });
        cli.push(`${R(v.denyName)} from ${members(v.from)} to ${members(v.to)} source any destination any source-user any application ${members(appRef)} service application-default action deny`,
          `move rulebase security rules ${q(v.denyName)} after ${q(v.name)}`);
      }
      const notes = [
        { type: "or", text: "Prérequis : User-ID activé sur la zone source (#m12-enable-zone), mapping IP→utilisateur (#m12-server-monitoring) et Group Mapping (#m12-ldap-group-mapping)." },
        { type: "warn", text: "Placer la règle utilisateur AU-DESSUS des règles générales (ex. LAN-to-Internet) qui autorisent déjà ces applications, sinon elle n'est jamais atteinte." },
      ];
      if (/^(any|known-user|unknown)$/.test(v.srcUser)) notes.push({ type: "or", text: `Source User « ${v.srcUser} » : mot-clé, pas un groupe.` });
      const grp = v.srcUser.includes("\\") || v.srcUser.includes("=") ? v.srcUser : null;
      return { steps, cli: cli.filter(Boolean), notes,
        verify: ["show user ip-user-mapping all", grp ? `show user group name ${qb(grp)}` : "show user group list",
          `test security-policy-match from ${v.from[0]} to ${v.to[0]} source 192.168.1.50 destination 157.240.1.35 protocol 6 destination-port 443 application ${v.apps[0]}`] };
    },
  });

  /* =====================================================================
     M13 · Décryptage
     ===================================================================== */
  register({
    id: "m13-certificates",
    module: "M13",
    title: "Certificats Forward Trust / Untrust",
    icon: "📜",
    desc: "Génération des CA de décryptage SSL Forward Proxy (Forward Trust et Forward Untrust), marquage des usages et export de la CA pour les postes.",
    tags: "certificat ca forward trust untrust generate export decryption ssl",
    fields: [
      { id: "trust", label: "Nom du certificat Forward Trust", type: "text", required: true, validate: NAME, default: "Corp-Forward-Trust" },
      { id: "trustCN", label: "Common Name (Forward Trust)", type: "text", required: true, default: "Corp Decryption CA" },
      { id: "org", label: "Organization (O)", type: "text", default: "Corp" },
      { id: "country", label: "Country (C, 2 lettres)", type: "text", default: "FR", validate: x => /^[A-Z]{2}$/.test(x) ? null : "Code pays ISO à 2 lettres majuscules" },
      { id: "untrust", label: "Nom du certificat Forward Untrust", type: "text", required: true, group: "Forward Untrust",
        validate: (x, v) => PAN.cfg.V.name(x) || (x === v.trust ? "Doit différer du Forward Trust" : null), default: "Corp-Forward-Untrust" },
      { id: "untrustCN", label: "Common Name (Forward Untrust)", type: "text", required: true, default: "UNTRUSTED - DO NOT TRUST" },
      { id: "bits", label: "Number of Bits", type: "select", default: "2048", group: "Clé", options: [["2048", "2048"], ["3072", "3072"], ["4096", "4096"]] },
      { id: "digest", label: "Digest", type: "select", default: "sha256", options: [["sha256", "sha256"], ["sha384", "sha384"], ["sha512", "sha512"]] },
      { id: "days", label: "Validité (jours)", type: "number", min: 1, max: 7300, default: "1825" },
    ],
    build(v) {
      const gen = (name, cn) => ({ title: `Générer ${name}`, path: ["Device", "Certificate Management", "Certificates"], tab: "Device Certificates", window: "Generate Certificate",
        action: "Cliquer sur Generate (en bas de page), puis Generate dans la fenêtre.",
        fields: [["Certificate Type", "Local"], ["Certificate Name", name], ["Common Name", cn], ["Signed By", "(vide = autosigné)"], ["Certificate Authority", true],
          ["Algorithm", "RSA"], ["Number of Bits", v.bits], ["Digest", v.digest], ["Expiration (days)", v.days], ["Certificate Attributes › Organization", v.org], ["Certificate Attributes › Country", v.country]] });
      const steps = [
        gen(v.trust, v.trustCN),
        { title: `Marquer ${v.trust} comme Forward Trust`, path: ["Device", "Certificate Management", "Certificates"], window: "Certificate information",
          action: `Cliquer sur ${v.trust} pour l'ouvrir.`, fields: [["Forward Trust Certificate", true]] },
        gen(v.untrust, v.untrustCN),
        { title: `Marquer ${v.untrust} comme Forward Untrust`, path: ["Device", "Certificate Management", "Certificates"], window: "Certificate information",
          action: `Cliquer sur ${v.untrust} pour l'ouvrir.`, fields: [["Forward Untrust Certificate", true]],
          warn: "Ne JAMAIS déployer ce certificat sur les postes : il doit rester non approuvé pour que l'utilisateur voie l'alerte sur les sites au certificat invalide." },
        { title: `Exporter la CA ${v.trust} pour les postes`, path: ["Device", "Certificate Management", "Certificates"], window: "Export Certificate",
          action: `Sélectionner (sans ouvrir) ${v.trust} → Export Certificate (en bas).`,
          fields: [["File Format", "Base64 Encoded Certificate (PEM)"], ["Export Private Key", "☐ décoché"]],
          note: "Déployer le fichier .crt dans « Autorités de certification racines de confiance » des postes (GPO : Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Stratégies de clé publique) ; Firefox : security.enterprise_roots.enabled = true ou import manuel." },
      ];
      const g = (name, cn) => `request certificate generate certificate-name ${q(name)} name ${q(cn)} ca yes algorithm RSA rsa-nbits ${v.bits} digest ${v.digest} days-till-expiry ${v.days}` +
        (v.org ? ` organization ${q(v.org)}` : "") + (v.country ? ` country-code ${v.country}` : "");
      const op = [g(v.trust, v.trustCN), g(v.untrust, v.untrustCN)];
      const cfg = [
        `set shared ssl-decrypt forward-trust-certificate rsa ${q(v.trust)}`,
        `set shared ssl-decrypt forward-untrust-certificate rsa ${q(v.untrust)}`,
      ];
      const verify = ["show system setting ssl-decrypt certificate", "show config running | match forward-"];
      const notes = [
        { type: "or", text: "Les deux certificats doivent avoir « Certificate Authority » coché : le pare-feu signe à la volée un certificat par site." },
        { type: "or", text: "Avec une PKI d'entreprise, préférer pour le Forward Trust une CA subordonnée signée par la CA interne (CSR : Generate avec Signed By = External Authority (CSR)) : aucun déploiement de certificat n'est alors nécessaire." },
        { type: "warn", text: "L'export de la CA se fait dans la WebUI (pas de commande CLI simple) ; ne jamais exporter la clé privée." },
      ];
      return { steps, notes, cliRaw: rawCli(op, cfg, verify), verify };
    },
  });

  register({
    id: "m13-decryption-profile",
    module: "M13",
    title: "Profil de décryptage",
    icon: "🧰",
    desc: "Objects > Decryption Profile : contrôles SSL Forward Proxy (certificats expirés / non approuvés, versions et chiffrements non supportés), versions TLS et algorithmes autorisés.",
    tags: "decryption profile ssl forward proxy tls version cipher expired untrusted",
    fields: [
      { id: "name", label: "Nom du profil", type: "text", required: true, validate: NAME, default: "Std-Decrypt" },
      { id: "expired", label: "Block sessions with expired certificates", type: "checkbox", default: true, group: "SSL Forward Proxy — Server Certificate Verification" },
      { id: "untrusted", label: "Block sessions with untrusted issuers", type: "checkbox", default: true },
      { id: "unknown", label: "Block sessions with unknown certificate status", type: "checkbox", default: false },
      { id: "timeout", label: "Block sessions on certificate status check timeout", type: "checkbox", default: false },
      { id: "restrict", label: "Restrict certificate extensions", type: "checkbox", default: false },
      { id: "unsVer", label: "Block sessions with unsupported versions", type: "checkbox", default: true, group: "SSL Forward Proxy — Unsupported Mode / Failure Checks" },
      { id: "unsCipher", label: "Block sessions with unsupported cipher suites", type: "checkbox", default: true },
      { id: "clientAuth", label: "Block sessions with client authentication", type: "checkbox", default: false },
      { id: "noRes", label: "Block sessions if resources not available", type: "checkbox", default: false },
      { id: "minVer", label: "Min Version", type: "select", default: "tls1-2", group: "SSL Protocol Settings",
        options: [["tls1-0", "TLSv1.0"], ["tls1-1", "TLSv1.1"], ["tls1-2", "TLSv1.2"], ["tls1-3", "TLSv1.3"]] },
      { id: "maxVer", label: "Max Version", type: "select", default: "max",
        options: [["tls1-2", "TLSv1.2"], ["tls1-3", "TLSv1.3"], ["max", "Max"]],
        validate: (x, v) => { const o = ["tls1-0", "tls1-1", "tls1-2", "tls1-3", "max"]; return o.indexOf(x) < o.indexOf(v.minVer) ? "Max Version inférieure à Min Version" : null; } },
      { id: "weak", label: "Désactiver les algorithmes faibles (RC4, 3DES, MD5, SHA1)", type: "checkbox", default: true },
      { id: "ndExpired", label: "No Decryption : Block sessions with expired certificates", type: "checkbox", default: true, group: "No Decryption" },
      { id: "ndUntrusted", label: "No Decryption : Block sessions with untrusted issuers", type: "checkbox", default: true },
    ],
    build(v) {
      const steps = [
        { title: "Créer le profil — SSL Forward Proxy", path: ["Objects", "Decryption Profile"], tab: "SSL Decryption › SSL Forward Proxy", window: "Decryption Profile",
          action: "Cliquer sur Add, saisir le nom, puis onglet SSL Decryption › SSL Forward Proxy.",
          fields: [["Name", v.name],
            ["Block sessions with expired certificates", v.expired], ["Block sessions with untrusted issuers", v.untrusted],
            ["Block sessions with unknown certificate status", v.unknown], ["Block sessions on certificate status check timeout", v.timeout],
            ["Restrict certificate extensions", v.restrict], ["Block sessions with unsupported versions", v.unsVer],
            ["Block sessions with unsupported cipher suites", v.unsCipher], ["Block sessions with client authentication", v.clientAuth],
            ["Block sessions if resources not available", v.noRes]],
          note: "Les cases non listées restent décochées." },
        { title: "Versions et algorithmes TLS", path: ["Objects", "Decryption Profile"], tab: "SSL Decryption › SSL Protocol Settings", window: "Decryption Profile",
          fields: [["Min Version", v.minVer.replace("tls", "TLSv").replace("-", ".")], ["Max Version", v.maxVer === "max" ? "Max" : v.maxVer.replace("tls", "TLSv").replace("-", ".")],
            ["Encryption Algorithms › RC4 / 3DES", v.weak ? "☐ décochés" : ""], ["Authentication Algorithms › MD5 / SHA1", v.weak ? "☐ décochés" : ""]] },
        { title: "Contrôles des sessions non décryptées", path: ["Objects", "Decryption Profile"], tab: "No Decryption", window: "Decryption Profile",
          fields: [["Block sessions with expired certificates", v.ndExpired], ["Block sessions with untrusted issuers", v.ndUntrusted]] },
      ];
      const P = `set profiles decryption ${q(v.name)}`;
      const fp = `${P} ssl-forward-proxy`;
      const cli = [
        `${fp} block-expired-certificate ${yes(v.expired)}`,
        `${fp} block-untrusted-issuer ${yes(v.untrusted)}`,
        `${fp} block-unknown-cert ${yes(v.unknown)}`,
        `${fp} block-timeout-cert ${yes(v.timeout)}`,
        `${fp} restrict-cert-exts ${yes(v.restrict)}`,
        `${fp} block-unsupported-version ${yes(v.unsVer)}`,
        `${fp} block-unsupported-cipher ${yes(v.unsCipher)}`,
        `${fp} block-client-cert ${yes(v.clientAuth)}`,
        `${fp} block-if-no-resource ${yes(v.noRes)}`,
        `${P} ssl-protocol-settings min-version ${v.minVer} max-version ${v.maxVer}`,
        v.weak && `${P} ssl-protocol-settings enc-algo-rc4 no enc-algo-3des no auth-algo-md5 no auth-algo-sha1 no`,
        `${P} ssl-no-proxy block-expired-certificate ${yes(v.ndExpired)} block-untrusted-issuer ${yes(v.ndUntrusted)}`,
      ].filter(Boolean);
      const notes = [{ type: "or", text: "À appliquer dans l'onglet Options des règles de décryptage (#m13-decryption-policy), y compris les règles No Decrypt (onglet No Decryption)." }];
      if (v.minVer === "tls1-3" ) notes.push({ type: "warn", text: "Min TLSv1.3 : les sites encore en TLS 1.2 seront bloqués." });
      if (["tls1-0", "tls1-1"].includes(v.minVer)) notes.push({ type: "warn", text: "TLS 1.0/1.1 sont obsolètes : TLSv1.2 minimum recommandé." });
      if (!v.untrusted) notes.push({ type: "bad", text: "Sans blocage des émetteurs non approuvés, l'utilisateur reçoit le certificat Forward Untrust : vérifier que celui-ci est bien configuré." });
      if (v.unknown || v.timeout) notes.push({ type: "or", text: "Statut inconnu / timeout OCSP-CRL : peut bloquer des sites légitimes si les répondeurs OCSP sont injoignables." });
      return { steps, cli, notes, verify: [`show config running | match "${v.name}"`, "show counter global filter delta yes | match proxy"] };
    },
  });

  register({
    id: "m13-decryption-policy",
    module: "M13",
    title: "Règle de décryptage (+ No Decrypt)",
    icon: "🔓",
    desc: "Policies > Decryption : règle SSL Forward Proxy, SSL Inbound Inspection ou SSH Proxy, avec règle No Decrypt pour les catégories sensibles placée en tête.",
    tags: "decryption policy ssl forward proxy inbound inspection ssh proxy no-decrypt financial-services health-and-medicine",
    fields: [
      { id: "type", label: "Type", type: "select", default: "ssl-forward-proxy",
        options: [["ssl-forward-proxy", "SSL Forward Proxy (trafic sortant)"], ["ssl-inbound-inspection", "SSL Inbound Inspection (serveur interne)"], ["ssh-proxy", "SSH Proxy"]] },
      { id: "name", label: "Nom de la règle", type: "text", required: true, validate: NAME, default: "Decrypt-LAN-Internet" },
      { id: "desc", label: "Description", type: "text", default: "Décryptage du trafic web sortant du LAN" },
      { id: "from", label: "Zone(s) source", type: "list", required: true, validate: zoneList, default: ["Trust"], group: "Correspondance" },
      { id: "src", label: "Source Address", type: "list", validate: addrList, default: ["any"] },
      { id: "to", label: "Zone(s) destination", type: "list", required: true, validate: zoneList, default: ["Untrust"] },
      { id: "dst", label: "Destination Address", type: "list", validate: addrList, default: ["any"], hint: "Inbound : IP pré-NAT (publique) du serveur, zone post-NAT." },
      { id: "service", label: "Service", type: "select", default: "service-https", options: [["any", "any"], ["service-https", "service-https"], ["application-default", "application-default"]] },
      { id: "cats", label: "URL Category", type: "list", validate: catList, default: ["any"], show: v => v.type === "ssl-forward-proxy" },
      { id: "profile", label: "Decryption Profile", type: "text", validate: NAME, default: "Std-Decrypt", hint: "« default » ou profil créé dans #m13-decryption-profile." },
      { id: "srvCert", label: "Certificat du serveur (avec clé privée)", type: "text", required: true, validate: NAME, default: "Cert-Web-DMZ", show: v => v.type === "ssl-inbound-inspection" },
      { id: "logOk", label: "Log Successful TLS Handshakes", type: "checkbox", default: false, group: "Journalisation" },
      { id: "logKo", label: "Log Unsuccessful TLS Handshakes", type: "checkbox", default: true },
      { id: "nd", label: "Créer une règle No Decrypt pour les catégories sensibles", type: "checkbox", default: true, group: "No Decrypt", show: v => v.type === "ssl-forward-proxy" },
      { id: "ndName", label: "Nom de la règle No Decrypt", type: "text", required: true, default: "No-Decrypt-Sensitive", show: v => v.type === "ssl-forward-proxy" && v.nd,
        validate: (x, v) => PAN.cfg.V.name(x) || (x === v.name ? "Doit différer de la règle de décryptage" : null) },
      { id: "ndCats", label: "Catégories exclues", type: "list", required: true, validate: catList, show: v => v.type === "ssl-forward-proxy" && v.nd,
        default: ["financial-services", "health-and-medicine", "government"] },
    ],
    build(v) {
      const TL = { "ssl-forward-proxy": "SSL Forward Proxy", "ssl-inbound-inspection": "SSL Inbound Inspection", "ssh-proxy": "SSH Proxy" }[v.type];
      const fwd = v.type === "ssl-forward-proxy";
      const src = v.src.length ? v.src : ["any"], dst = v.dst.length ? v.dst : ["any"], cats = fwd && v.cats.length ? v.cats : ["any"];
      const ruleSteps = (n, desc, c, action) => [
        { title: `Règle ${n} — General`, path: ["Policies", "Decryption"], tab: "General", window: "Decryption Policy Rule",
          action: "Cliquer sur Add.", fields: [["Name", n], ["Description", desc]] },
        { title: `Règle ${n} — Source`, path: ["Policies", "Decryption"], tab: "Source", window: "Decryption Policy Rule",
          fields: [["Source Zone", v.from], ["Source Address", src.includes("any") ? "Any" : src], ["Source User", "any"]] },
        { title: `Règle ${n} — Destination`, path: ["Policies", "Decryption"], tab: "Destination", window: "Decryption Policy Rule",
          fields: [["Destination Zone", v.to], ["Destination Address", dst.includes("any") ? "Any" : dst]] },
        { title: `Règle ${n} — Service/URL Category`, path: ["Policies", "Decryption"], tab: "Service/URL Category", window: "Decryption Policy Rule",
          fields: [["Service", v.service], ["URL Category", c.includes("any") ? "Any" : c]] },
        { title: `Règle ${n} — Options`, path: ["Policies", "Decryption"], tab: "Options", window: "Decryption Policy Rule",
          fields: [["Action", action === "decrypt" ? "Decrypt" : "No Decrypt"], ["Type", TL], ["Certificate", v.type === "ssl-inbound-inspection" ? v.srvCert : ""],
            ["Decryption Profile", v.profile], ["Log Successful TLS Handshakes", v.logOk], ["Log Unsuccessful TLS Handshakes", v.logKo]] },
      ];
      const steps = [];
      if (v.type === "ssl-inbound-inspection") steps.push({ title: "Importer le certificat du serveur", path: ["Device", "Certificate Management", "Certificates"], window: "Import Certificate",
        action: "Onglet Device Certificates → Import.",
        fields: [["Certificate Type", "Local"], ["Certificate Name", v.srvCert], ["Certificate File", "serveur.p12 (ou .crt)"], ["File Format", "PKCS12 (ou PEM + Key File)"], ["Import Private Key", true], ["Passphrase", "••••••••"]],
        note: "Certificat identique à celui du serveur (même clé privée) ; importer aussi la chaîne intermédiaire." });
      steps.push(...ruleSteps(v.name, v.desc, cats, "decrypt"));
      const R = n => `set rulebase decryption rules ${q(n)}`;
      const typeCli = v.type === "ssl-inbound-inspection" ? `type ssl-inbound-inspection ${q(v.srvCert)}` : `type ${v.type}`;
      const rule = (n, desc, c, action) => [
        `${R(n)} from ${members(v.from)} to ${members(v.to)} source ${members(src)} destination ${members(dst)} source-user any service ${v.service} category ${members(c)}`,
        `${R(n)} action ${action} ${action === "decrypt" ? typeCli : "type ssl-forward-proxy"}`,
        desc && `${R(n)} description ${q(desc)}`,
        v.profile && `${R(n)} profile ${q(v.profile)}`,
        `${R(n)} log-successful-tls-handshakes ${yes(v.logOk)} log-failed-tls-handshakes ${yes(v.logKo)}`,
      ];
      const cli = rule(v.name, v.desc, cats, "decrypt");
      if (fwd && v.nd) {
        steps.push(...ruleSteps(v.ndName, "Pas de décryptage des catégories sensibles (vie privée)", v.ndCats, "no-decrypt"));
        steps.push({ title: "Placer la règle No Decrypt en tête", path: ["Policies", "Decryption"], action: `Sélectionner ${v.ndName} → Move → Move Top.`, fields: [] });
        cli.push(...rule(v.ndName, "Pas de décryptage des catégories sensibles (vie privée)", v.ndCats, "no-decrypt"), `move rulebase decryption rules ${q(v.ndName)} top`);
      }
      const notes = [];
      if (fwd) notes.push({ type: "or", text: "Prérequis : certificats Forward Trust / Untrust (#m13-certificates) et CA Forward Trust déployée sur les postes." });
      if (v.profile && v.profile !== "default") notes.push({ type: "or", text: `Profil « ${v.profile} » : module « Profil de décryptage » (#m13-decryption-profile).` });
      if (v.type === "ssl-inbound-inspection") notes.push({ type: "warn", text: "Inbound : le certificat importé doit être exactement celui du serveur. Les suites ECDHE/DHE sont supportées (mode proxy). La règle de sécurité autorisant le serveur doit porter des profils de sécurité, sinon le décryptage n'apporte rien." });
      if (v.type === "ssh-proxy") notes.push({ type: "or", text: "SSH Proxy : utilise les clés Forward Trust/Untrust ; à réserver à des usages ciblés (détection de tunnels SSH)." });
      if (fwd && cats.includes("any") && !v.nd) notes.push({ type: "warn", text: "Tout le trafic est décrypté : prévoir une exclusion des catégories sensibles (santé, finance) — exigences RGPD / CNIL." });
      notes.push({ type: "or", text: "Sites incompatibles (certificate pinning, auth client) : exclusion via #m13-decryption-exclusion." });
      return { steps, cli: cli.filter(Boolean), notes,
        verify: ["show session all filter ssl-decrypt yes", "show system setting ssl-decrypt certificate", "show counter global filter delta yes | match proxy"] };
    },
  });

  register({
    id: "m13-decryption-exclusion",
    module: "M13",
    title: "Exclusions de décryptage (SSL Decryption Exclusion)",
    icon: "🚫",
    desc: "Device > Certificate Management > SSL Decryption Exclusion : sites exclus du décryptage par nom d'hôte (applications à certificate pinning, authentification mutuelle).",
    tags: "ssl decryption exclusion hostname pinning exclude",
    fields: [
      { id: "hosts", label: "Noms d'hôte à exclure", type: "list", required: true, default: ["*.update.microsoft.com", "*.banque-exemple.fr"],
        validate: v => { for (const h of v) { if (!/^(\*\.)?([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$/.test(h)) return `« ${h} » : FQDN ou *.domaine attendu`; } return null; },
        hint: "Joker accepté en tête : *.exemple.com" },
      { id: "desc", label: "Description", type: "text", default: "Exclusion client (pinning / mTLS)" },
    ],
    build(v) {
      const steps = v.hosts.map(h => ({ title: `Exclure ${h}`, path: ["Device", "Certificate Management", "SSL Decryption Exclusion"], window: "SSL Decryption Exclusion",
        action: "Cliquer sur Add.", fields: [["Hostname", h], ["Description", v.desc], ["Exclude", true]] }));
      const cli = v.hosts.flatMap(h => [`set shared ssl-decrypt ssl-exclude-cert ${q(h)} exclude yes`, v.desc && `set shared ssl-decrypt ssl-exclude-cert ${q(h)} description ${q(v.desc)}`]).filter(Boolean);
      const notes = [
        { type: "or", text: "Les exclusions prédéfinies Palo Alto (mises à jour de contenu) apparaissent dans la même liste ; décocher Exclude pour en réactiver le décryptage." },
        { type: "or", text: "Pour exclure par catégorie, zone ou adresse, utiliser plutôt une règle No Decrypt (#m13-decryption-policy)." },
      ];
      return { steps, cli, notes, verify: ["show system setting ssl-decrypt exclude-cache"] };
    },
  });

  /* =====================================================================
     M14 · Logs & rapports
     ===================================================================== */
  const LOGTYPES = [["traffic", "Traffic"], ["threat", "Threat"], ["url", "URL"], ["wildfire", "WildFire"], ["data", "Data"], ["auth", "Authentication"]];
  const lfFilter = (x, v) => /^(All Logs|\(.*\))$/.test(x) ? null : "« All Logs » ou une expression entre parenthèses, ex. ( severity geq high )";
  /* étape + CLI d'un Log Forwarding Profile */
  function lfp(name, desc, lines, rule, kind) {
    const steps = [{ title: "Créer le Log Forwarding Profile", path: ["Objects", "Log Forwarding"], window: "Log Forwarding Profile",
      action: "Cliquer sur Add, saisir le nom puis Add dans la liste Match List.", fields: [["Name", name], ["Description", desc]] }];
    lines.forEach(l => steps.push({ title: `Match List ${l.n}`, path: ["Objects", "Log Forwarding"], window: "Log Forwarding Profile Match List",
      action: "Dans le profil : Add. Le filtre se construit avec Filter Builder ou se saisit directement.",
      fields: [["Name", l.n], ["Log Type", l.label], ["Filter", l.filter], [kind.gui, kind.target]] }));
    const cli = [desc && `set log-settings profiles ${q(name)} description ${q(desc)}`,
      ...lines.map(l => `set log-settings profiles ${q(name)} match-list ${q(l.n)} log-type ${l.t} filter ${q(l.filter)} ${kind.cli} ${q(kind.target)}`)];
    if (rule) {
      steps.push({ title: "Rattacher le profil à la règle de sécurité", path: ["Policies", "Security"], tab: "Actions", window: "Security Policy Rule",
        action: `Ouvrir la règle ${rule} → onglet Actions → section Log Setting.`, fields: [["Log at Session End", true], ["Log Forwarding", name]] });
      cli.push(`set rulebase security rules ${q(rule)} log-setting ${q(name)}`, `set rulebase security rules ${q(rule)} log-end yes`);
    }
    return { steps, cli: cli.filter(Boolean) };
  }

  register({
    id: "m14-syslog",
    module: "M14",
    title: "Syslog & Log Forwarding",
    icon: "📤",
    desc: "Syslog Server Profile, Log Forwarding Profile (traffic, threat, url, wildfire…) appliqué aux règles, et transfert des logs System / Configuration.",
    tags: "syslog siem log forwarding server profile log settings system config",
    fields: [
      { id: "prof", label: "Nom du Syslog Server Profile", type: "text", required: true, validate: NAME, default: "Syslog-SIEM" },
      { id: "srvName", label: "Nom du serveur", type: "text", required: true, validate: NAME, default: "SIEM" },
      { id: "srv", label: "Syslog Server (IP/FQDN)", type: "text", required: true, validate: "host", default: "192.168.1.30" },
      { id: "transport", label: "Transport", type: "select", default: "UDP", options: [["UDP", "UDP"], ["TCP", "TCP"], ["SSL", "SSL (TLS)"]] },
      { id: "port", label: "Port", type: "port", required: true, default: "514",
        validate: (x, v) => v.transport === "SSL" && x === "514" ? "SSL : port 6514 habituellement" : null },
      { id: "format", label: "Format", type: "select", default: "BSD", options: [["BSD", "BSD"], ["IETF", "IETF"]] },
      { id: "facility", label: "Facility", type: "select", default: "LOG_USER", options: ["LOG_USER", ...[0, 1, 2, 3, 4, 5, 6, 7].map(i => "LOG_LOCAL" + i)].map(f => [f, f]) },
      { id: "lfp", label: "Nom du Log Forwarding Profile", type: "text", required: true, validate: NAME, default: "LFP-SIEM", group: "Log Forwarding Profile" },
      ...LOGTYPES.map(([k, l], i) => ({ id: "lt_" + k, label: `Transférer ${l}`, type: "checkbox", default: ["traffic", "threat", "url", "wildfire"].includes(k) })),
      { id: "thFilter", label: "Filtre Threat", type: "text", default: "All Logs", validate: lfFilter, show: v => v.lt_threat, hint: "Ex. ( severity geq medium )" },
      { id: "rule", label: "Règle de sécurité à rattacher", type: "text", validate: NAME, default: "LAN-to-Internet" },
      { id: "sys", label: "Transférer les logs System", type: "checkbox", default: true, group: "Device > Log Settings" },
      { id: "sysFilter", label: "Filtre System", type: "text", default: "( severity geq medium )", validate: lfFilter, show: v => v.sys },
      { id: "cfg", label: "Transférer les logs Configuration", type: "checkbox", default: true },
      { id: "uid", label: "Transférer les logs User-ID", type: "checkbox", default: false },
    ],
    build(v) {
      const steps = [{ title: "Créer le Syslog Server Profile", path: ["Device", "Server Profiles", "Syslog"], tab: "Servers", window: "Syslog Server Profile",
        action: "Cliquer sur Add, puis Add dans l'onglet Servers.",
        fields: [["Name", v.prof], ["Servers › Name", v.srvName], ["Syslog Server", v.srv], ["Transport", v.transport], ["Port", v.port], ["Format", v.format], ["Facility", v.facility]],
        note: "Onglet Custom Log Format : laisser vide sauf exigence du SIEM (formats CEF/LEEF fournis par l'éditeur)." }];
      const cli = [`set shared log-settings syslog ${q(v.prof)} server ${q(v.srvName)} server ${v.srv} transport ${v.transport} port ${v.port} format ${v.format} facility ${v.facility}`];
      const lines = LOGTYPES.filter(([k]) => v["lt_" + k]).map(([k, l]) => ({ n: `${l}-SIEM`, t: k, label: k, filter: k === "threat" ? v.thFilter || "All Logs" : "All Logs" }));
      if (lines.length) {
        const r = lfp(v.lfp, "Transfert vers le SIEM", lines, v.rule, { gui: "Syslog", cli: "send-syslog", target: v.prof });
        steps.push(...r.steps); cli.push(...r.cli);
      }
      const dev = [v.sys && ["system", "System", v.sysFilter || "All Logs"], v.cfg && ["config", "Configuration", "All Logs"], v.uid && ["userid", "User-ID", "All Logs"]].filter(Boolean);
      dev.forEach(([k, l, f]) => {
        steps.push({ title: `Transférer les logs ${l}`, path: ["Device", "Log Settings"], window: `Log Settings - ${l}`,
          action: `Dans la section ${l}, cliquer sur Add.`, fields: [["Name", `${l}-SIEM`], ["Filter", f], ["Syslog", v.prof]] });
        cli.push(`set shared log-settings ${k} match-list ${q(l + "-SIEM")} filter ${q(f)} send-syslog ${q(v.prof)}`);
      });
      const notes = [
        { type: "or", text: "Les logs sont émis depuis l'interface de management par défaut. Pour passer par une interface data : Device > Setup > Services > Service Route Configuration > Syslog." },
        { type: "or", text: "Nommer un Log Forwarding Profile « default » l'applique automatiquement aux nouvelles règles de sécurité." },
      ];
      if (v.transport === "UDP") notes.push({ type: "warn", text: "UDP : pas d'accusé de réception ni de chiffrement. Préférer SSL (6514) pour un SIEM hors du LAN." });
      if (v.transport === "SSL") notes.push({ type: "or", text: "SSL : importer la CA du serveur Syslog dans Device > Certificate Management > Certificates (format IETF recommandé)." });
      if (!lines.length && !dev.length) notes.push({ type: "warn", text: "Aucun type de log sélectionné : seul le profil serveur est créé." });
      return { steps, cli, notes, verify: ["show log system direction equal backward | match syslog", "show log config direction equal backward"] };
    },
  });

  register({
    id: "m14-email-alerts",
    module: "M14",
    title: "Alertes e-mail",
    icon: "✉️",
    desc: "Email Server Profile et Log Forwarding vers e-mail pour les menaces critiques (et logs System critiques).",
    tags: "email smtp alert log forwarding critical threat",
    fields: [
      { id: "prof", label: "Nom de l'Email Server Profile", type: "text", required: true, validate: NAME, default: "Email-SOC" },
      { id: "srvName", label: "Nom du serveur", type: "text", required: true, validate: NAME, default: "SMTP-Relay" },
      { id: "display", label: "Email Display Name", type: "text", default: "PA-Firewall" },
      { id: "from", label: "From", type: "text", required: true, validate: "email", default: "paloalto@corp.local" },
      { id: "to", label: "To", type: "text", required: true, validate: "email", default: "soc@corp.local" },
      { id: "also", label: "Additional Recipient", type: "text", validate: "email", default: "" },
      { id: "gw", label: "Email Gateway (IP/FQDN)", type: "text", required: true, validate: "host", default: "192.168.1.25" },
      { id: "proto", label: "Protocol", type: "select", default: "SMTP", options: [["SMTP", "SMTP"], ["TLS", "TLS"]] },
      { id: "port", label: "Port", type: "port", required: true, default: "25" },
      { id: "user", label: "Username (TLS)", type: "text", default: "", show: v => v.proto === "TLS" },
      { id: "pw", label: "Password (TLS)", type: "password", default: "", show: v => v.proto === "TLS",
        validate: (x, v) => v.user && !x ? "Mot de passe requis si un utilisateur est renseigné" : null },
      { id: "lfp", label: "Nom du Log Forwarding Profile", type: "text", required: true, validate: NAME, default: "LFP-Alert-Mail", group: "Déclencheurs" },
      { id: "sev", label: "Sévérité Threat minimale", type: "select", default: "critical", options: [["critical", "critical"], ["high", "high et plus"], ["medium", "medium et plus"]] },
      { id: "wf", label: "Alerter aussi sur les verdicts WildFire malicious", type: "checkbox", default: true },
      { id: "rule", label: "Règle de sécurité à rattacher", type: "text", validate: NAME, default: "LAN-to-Internet" },
      { id: "sys", label: "Alerter sur les logs System critiques", type: "checkbox", default: true },
    ],
    build(v) {
      const thf = v.sev === "critical" ? "( severity eq critical )" : `( severity geq ${v.sev} )`;
      const steps = [{ title: "Créer l'Email Server Profile", path: ["Device", "Server Profiles", "Email"], tab: "Servers", window: "Email Server Profile",
        action: "Cliquer sur Add, puis Add dans l'onglet Servers.",
        fields: [["Name", v.prof], ["Servers › Name", v.srvName], ["Email Display Name", v.display], ["From", v.from], ["To", v.to], ["Additional Recipient(s)", v.also],
          ["Email Gateway", v.gw], ["Protocol", v.proto], ["Port", v.port], ["TLS Version", v.proto === "TLS" ? "1.2" : ""], ["Authentication", v.proto === "TLS" && v.user ? "Auto" : ""], ["Username", v.user], ["Password", v.pw ? "••••••••" : ""]],
        note: "Bouton « Test Connection » (TLS) pour valider avant de fermer." }];
      const E = `set shared log-settings email ${q(v.prof)} server ${q(v.srvName)}`;
      const cli = [
        `${E} display-name ${q(v.display || v.srvName)} from ${v.from} to ${v.to} gateway ${v.gw}`,
        v.also && `${E} and-also-to ${v.also}`,
        `${E} protocol ${v.proto} port ${v.port}`,
        v.proto === "TLS" && `${E} tls-version 1.2`,
        v.proto === "TLS" && v.user && `${E} auth Auto username ${q(v.user)} password ${q(v.pw)}`,
      ].filter(Boolean);
      const lines = [{ n: "Threat-Mail", t: "threat", label: "threat", filter: thf }];
      if (v.wf) lines.push({ n: "WildFire-Malicious-Mail", t: "wildfire", label: "wildfire", filter: "( verdict eq malicious )" });
      const r = lfp(v.lfp, "Alertes e-mail SOC", lines, v.rule, { gui: "Email", cli: "send-email", target: v.prof });
      steps.push(...r.steps); cli.push(...r.cli);
      if (v.sys) {
        steps.push({ title: "Alerter sur les logs System critiques", path: ["Device", "Log Settings"], window: "Log Settings - System",
          action: "Dans la section System, cliquer sur Add.", fields: [["Name", "System-Critical-Mail"], ["Filter", "( severity eq critical )"], ["Email", v.prof]] });
        cli.push(`set shared log-settings system match-list System-Critical-Mail filter ${q("( severity eq critical )")} send-email ${q(v.prof)}`);
      }
      const notes = [{ type: "or", text: "Envoi depuis l'interface de management par défaut (service route « Email » sinon) ; le relais SMTP doit accepter l'IP du pare-feu." }];
      if (v.sev !== "critical") notes.push({ type: "warn", text: "Un seuil inférieur à critical peut générer un volume d'e-mails important : préférer le SIEM (#m14-syslog) pour le volume." });
      if (v.proto === "SMTP" && v.port !== "25") notes.push({ type: "or", text: "Protocole SMTP en clair sur un port autre que 25 : vérifier l'attente du relais (587 = soumission avec TLS en général)." });
      if (v.proto === "TLS" && v.port === "25") notes.push({ type: "or", text: "TLS : port 587 en général." });
      return { steps, cli, notes, verify: ["show log system direction equal backward | match email"] };
    },
  });

  register({
    id: "m14-snmp",
    module: "M14",
    title: "SNMP (supervision & traps)",
    icon: "📈",
    desc: "SNMP Setup (v2c ou v3) pour la supervision, SNMP Trap Server Profile et envoi des logs System en trap.",
    tags: "snmp v2c v3 trap monitoring supervision community",
    fields: [
      { id: "version", label: "Version", type: "select", default: "v3", options: [["v2c", "V2c"], ["v3", "V3"]] },
      { id: "location", label: "Physical Location", type: "text", default: "Paris - Salle serveurs" },
      { id: "contact", label: "Contact", type: "text", default: "noc@corp.local" },
      { id: "eventTraps", label: "Use Specific Trap Definitions", type: "checkbox", default: true },
      { id: "community", label: "SNMP Community String", type: "password", required: true, show: v => v.version === "v2c",
        validate: x => /^(public|private)$/i.test(x) ? "Ne pas utiliser public/private" : null },
      { id: "view", label: "Nom de la vue (v3)", type: "text", required: true, validate: NAME, default: "View-All", show: v => v.version === "v3", group: "SNMPv3" },
      { id: "user", label: "Utilisateur v3", type: "text", required: true, validate: NAME, default: "snmp-nms", show: v => v.version === "v3" },
      { id: "authpwd", label: "Auth Password (8 car. min)", type: "password", required: true, show: v => v.version === "v3", validate: x => x.length < 8 ? "8 caractères minimum" : null },
      { id: "privpwd", label: "Priv Password (8 car. min)", type: "password", required: true, show: v => v.version === "v3", validate: x => x.length < 8 ? "8 caractères minimum" : null },
      { id: "authproto", label: "Authentication Protocol", type: "select", default: "SHA-256", show: v => v.version === "v3", options: [["SHA", "SHA"], ["SHA-224", "SHA-224"], ["SHA-256", "SHA-256"], ["SHA-384", "SHA-384"], ["SHA-512", "SHA-512"], ["MD5", "MD5"]] },
      { id: "privproto", label: "Privacy Protocol", type: "select", default: "AES-256", show: v => v.version === "v3", options: [["AES", "AES"], ["AES-192", "AES-192"], ["AES-256", "AES-256"], ["DES", "DES"]] },
      { id: "trap", label: "Créer un SNMP Trap Server Profile", type: "checkbox", default: true, group: "Traps" },
      { id: "trapProf", label: "Nom du profil Trap", type: "text", required: true, validate: NAME, default: "Trap-NMS", show: v => v.trap },
      { id: "nms", label: "SNMP Manager (IP/FQDN)", type: "text", required: true, validate: "host", default: "192.168.1.40", show: v => v.trap },
      { id: "engine", label: "EngineID du manager (v3, optionnel, hex)", type: "text", show: v => v.trap && v.version === "v3", validate: x => /^(0x)?[0-9a-fA-F]{10,64}$/.test(x) ? null : "Hexadécimal (ex. 0x80001f8880…)" },
      { id: "sysTrap", label: "Envoyer les logs System en trap", type: "checkbox", default: true, show: v => v.trap },
      { id: "sysFilter", label: "Filtre System", type: "text", default: "( severity geq high )", validate: lfFilter, show: v => v.trap && v.sysTrap },
    ],
    example: { authpwd: "Snmp-Auth-2024!", privpwd: "Snmp-Priv-2024!" },
    build(v) {
      const v3 = v.version === "v3";
      const steps = [
        { title: "Autoriser SNMP sur l'interface de management", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
          action: "Cliquer sur Management. Restreindre aussi Permitted IP Addresses aux postes d'administration et au NMS.",
          fields: [["Administrative Management Services › SNMP", true], ["Permitted IP Addresses", v.trap ? v.nms : ""]] },
        { title: "SNMP Setup", path: ["Device", "Setup", "Operations"], window: "SNMP Setup",
          action: "Section Miscellaneous → SNMP Setup.",
          fields: [["Physical Location", v.location], ["Contact", v.contact], ["Use Specific Trap Definitions", v.eventTraps], ["Version", v3 ? "V3" : "V2c"],
            ...(v3 ? [["Views › Name", v.view], ["View › OID", "1.3.6.1"], ["View › Option", "include"], ["View › Mask", "0xf0"],
              ["Users › Users", v.user], ["Users › View", v.view], ["Auth Password", "••••••••"], ["Priv Password", "••••••••"], ["Authentication Protocol", v.authproto], ["Privacy Protocol", v.privproto]]
              : [["SNMP Community String", "••••••••"]])] },
      ];
      const S = "set deviceconfig system snmp-setting";
      const cli = [
        "set deviceconfig system service disable-snmp no",
        `${S} snmp-system location ${q(v.location)} contact ${q(v.contact)} send-event-specific-traps ${yes(v.eventTraps)}`,
        ...(v3 ? [
          `${S} access-setting version v3 views ${q(v.view)} view ${q(v.view)} oid 1.3.6.1 option include mask 0xf0`,
          `${S} access-setting version v3 users ${q(v.user)} view ${q(v.view)} authpwd ${q(v.authpwd)} privpwd ${q(v.privpwd)} authproto ${v.authproto} privproto ${v.privproto}`,
        ] : [`${S} access-setting version v2c snmp-community-string ${q(v.community)}`]),
      ];
      if (v.trap) {
        steps.push({ title: "Créer le SNMP Trap Server Profile", path: ["Device", "Server Profiles", "SNMP Trap"], window: "SNMP Trap Server Profile",
          action: "Cliquer sur Add, choisir la version puis Add dans la liste des serveurs.",
          fields: [["Name", v.trapProf], ["Version", v3 ? "V3" : "V2c"], ["Server › Name", "NMS"], ["SNMP Manager", v.nms],
            ...(v3 ? [["User", v.user], ["EngineID", v.engine], ["Auth Password", "••••••••"], ["Priv Password", "••••••••"], ["Authentication Protocol", v.authproto], ["Privacy Protocol", v.privproto]] : [["Community", "••••••••"]])] });
        const T = `set shared log-settings snmptrap ${q(v.trapProf)} version`;
        cli.push(v3 ? `${T} v3 server NMS manager ${v.nms} user ${q(v.user)}${v.engine ? " engineid " + v.engine : ""} authpwd ${q(v.authpwd)} privpwd ${q(v.privpwd)} authproto ${v.authproto} privproto ${v.privproto}`
          : `${T} v2c server NMS manager ${v.nms} community ${q(v.community)}`);
        if (v.sysTrap) {
          steps.push({ title: "Envoyer les logs System en trap", path: ["Device", "Log Settings"], window: "Log Settings - System",
            action: "Dans la section System, cliquer sur Add.", fields: [["Name", "System-Trap"], ["Filter", v.sysFilter], ["SNMP Trap", v.trapProf]] });
          cli.push(`set shared log-settings system match-list System-Trap filter ${q(v.sysFilter)} send-snmptrap ${q(v.trapProf)}`);
        }
      }
      const notes = [
        { type: "or", text: "Télécharger les MIB PAN-OS (PAN-COMMON-MIB, PAN-TRAPS-MIB…) depuis le site Palo Alto et les charger dans le NMS." },
        { type: "or", text: "Port UDP 161 (polling) sur l'interface de management ; traps vers UDP 162 du manager (service route « SNMP Trap » si interface data)." },
      ];
      if (!v3) notes.push({ type: "warn", text: "SNMPv2c : communauté en clair, pas de chiffrement. Préférer V3 (authPriv)." });
      if (v3 && (v.authproto === "MD5" || v.privproto === "DES")) notes.push({ type: "warn", text: "MD5 / DES sont faibles : choisir SHA-256 et AES-256 si le NMS les supporte." });
      if (v3 && v.authpwd && v.authpwd === v.privpwd) notes.push({ type: "warn", text: "Auth et Priv Password identiques : utiliser deux secrets distincts." });
      return { steps, cli, notes, verify: ["show counter global | match snmp", "show log system direction equal backward | match snmp"] };
    },
  });

  const COLS = { "source zone": "from", "destination zone": "to", "source address": "src", "destination address": "dst", "source user": "srcuser",
    "application": "app", "rule": "rule", "action": "action", "destination port": "dport", "url category": "category",
    "threat/content name": "threatid", "severity": "severity", "bytes": "bytes", "sessions": "sessions", "count": "count" };
  const NUMCOLS = ["bytes", "sessions", "count"];
  const COLLABEL = { from: "Source Zone", to: "Destination Zone", src: "Source address", dst: "Destination address", srcuser: "Source User", app: "Application",
    rule: "Rule", action: "Action", category: "URL Category", threatid: "Threat/Content Name", severity: "Severity" };
  const PERIODS = [["last-24-hrs", "Last 24 Hrs"], ["last-calendar-day", "Last Calendar Day"], ["last-7-days", "Last 7 Days"], ["last-7-calendar-days", "Last 7 Calendar Days"],
    ["last-calendar-week", "Last Calendar Week"], ["last-30-days", "Last 30 Days"], ["last-calendar-month", "Last Calendar Month"]];

  register({
    id: "m14-custom-report",
    module: "M14",
    title: "Rapport personnalisé & envoi planifié",
    icon: "📊",
    desc: "Monitor > Manage Custom Reports (base, période, tri, regroupement, colonnes, filtre, planification) puis Report Group et Email Scheduler.",
    tags: "custom report rapport personnalise report group email scheduler pdf",
    fields: [
      { id: "name", label: "Nom du rapport", type: "text", required: true, validate: NAME, default: "Apps-Internal-Zones" },
      { id: "db", label: "Database", type: "select", default: "trsum", options: [["trsum", "Traffic Summary"], ["thsum", "Threat Summary"], ["urlsum", "URL Summary"]] },
      { id: "period", label: "Time Frame", type: "select", default: "last-7-days", options: PERIODS },
      { id: "sortBy", label: "Sort By", type: "select", default: "sessions", options: [["sessions", "Sessions"], ["bytes", "Bytes"], ["count", "Count"]],
        validate: (x, v) => v.db === "trsum" ? (x === "count" ? "Traffic Summary : trier par Sessions ou Bytes" : null) : (x !== "count" ? "Threat/URL Summary : trier par Count" : null) },
      { id: "topN", label: "Top N", type: "select", default: "100", options: ["5", "10", "25", "50", "100", "250", "500", "1000"].map(x => [x, "Top " + x]) },
      { id: "groupBy", label: "Group By", type: "select", default: "from", options: [["", "None"], ...Object.entries(COLLABEL).map(([k, l]) => [k, l])] },
      { id: "topM", label: "Nombre de groupes", type: "select", default: "5", options: ["5", "10", "25", "50"].map(x => [x, x + " Groups"]), show: v => !!v.groupBy },
      { id: "cols", label: "Selected Columns (dans l'ordre)", type: "list", required: true, default: ["Source Zone", "Application", "Bytes", "Action"], wide: true,
        hint: "Parmi : " + Object.keys(COLS).map(k => k.replace(/\b\w/g, c => c.toUpperCase())).join(", "),
        validate: (arr, v) => { const bad = arr.find(c => !COLS[c.toLowerCase()]); if (bad) return `« ${bad} » : colonne non reconnue`;
          if (v.db !== "trsum" && arr.some(c => ["bytes", "sessions"].includes(COLS[c.toLowerCase()]))) return "Bytes/Sessions : uniquement en Traffic Summary"; return null; } },
      { id: "query", label: "Query Builder (filtre)", type: "text", default: "( zone.src neq Untrust )", validate: x => /^\(.*\)$/.test(x) ? null : "Expression entre parenthèses, ex. ( zone.src neq Untrust )", wide: true },
      { id: "sched", label: "Scheduled (génération quotidienne)", type: "checkbox", default: true },
      { id: "rg", label: "Report Group (vide = pas d'envoi)", type: "text", validate: NAME, default: "RG-Weekly-SOC", group: "Envoi par e-mail" },
      { id: "emailProf", label: "Email Profile", type: "text", validate: NAME, default: "Email-SOC", show: v => !!v.rg, required: true, hint: "Créé dans #m14-email-alerts." },
      { id: "recur", label: "Recurrence", type: "select", default: "Every Monday", show: v => !!v.rg,
        options: ["Every Day", "Every Monday", "Every Tuesday", "Every Wednesday", "Every Thursday", "Every Friday", "Every Saturday", "Every Sunday"].map(x => [x, x]) },
    ],
    build(v) {
      const fields = v.cols.map(c => COLS[c.toLowerCase()]);
      const agg = fields.filter(f => !NUMCOLS.includes(f)), vals = fields.filter(f => NUMCOLS.includes(f));
      const DBL = { trsum: "Traffic Summary", thsum: "Threat Summary", urlsum: "URL Summary" }[v.db];
      const steps = [
        { title: "Créer le rapport personnalisé", path: ["Monitor", "Manage Custom Reports"], window: "Custom Report",
          action: "Cliquer sur Add.",
          fields: [["Name", v.name], ["Database", DBL], ["Scheduled", v.sched], ["Time Frame", PERIODS.find(p => p[0] === v.period)[1]],
            ["Sort By", `${v.sortBy[0].toUpperCase() + v.sortBy.slice(1)} — Top ${v.topN}`], ["Group By", v.groupBy ? `${COLLABEL[v.groupBy]} — ${v.topM} Groups` : "None"],
            ["Selected Columns", v.cols]] },
        { title: "Filtrer avec le Query Builder", path: ["Monitor", "Manage Custom Reports"], window: "Custom Report",
          action: "En bas de la fenêtre : Filter Builder → construire le filtre → Add → Apply (ou saisir directement dans Query Builder).",
          fields: [["Query Builder", v.query]] },
        { title: "Tester le rapport", path: ["Monitor", "Manage Custom Reports"], action: `Ouvrir ${v.name} → Run Now. Le résultat s'ouvre dans un nouvel onglet de la fenêtre.`, fields: [] },
      ];
      const R = `set reports ${q(v.name)}`;
      const cli = [
        `${R} type ${v.db} aggregate-by ${members(agg.length ? agg : ["app"])}${vals.length ? " values " + members(vals) : ""} sortby ${v.sortBy}${v.groupBy ? " group-by " + v.groupBy : ""}`,
        `${R} period ${v.period} topn ${v.topN}${v.groupBy ? " topm " + v.topM : ""}`,
        v.query && `${R} query ${q(v.query)}`,
        v.sched && `${R} frequency daily`,
      ].filter(Boolean);
      if (v.rg) {
        steps.push(
          { title: "Créer le Report Group", path: ["Monitor", "PDF Reports", "Report Groups"], window: "Report Group",
            action: `Cliquer sur Add ; dans la liste de gauche (Custom Reports), sélectionner ${v.name} → Add.`,
            fields: [["Name", v.rg], ["Title Page", true], ["Title", v.name], ["Selected", v.name]] },
          { title: "Planifier l'envoi par e-mail", path: ["Monitor", "PDF Reports", "Email Scheduler"], window: "Email Scheduler",
            action: "Cliquer sur Add.", fields: [["Name", "Send-" + v.rg], ["Report Group", v.rg], ["Email Profile", v.emailProf], ["Recurrence", v.recur]] },
        );
        cli.push(`# Report Group « ${v.rg} » et Email Scheduler : à créer via la WebUI (Monitor > PDF Reports).`);
      }
      const notes = [];
      if (!v.sched && v.rg) notes.push({ type: "warn", text: "Seuls les rapports « Scheduled » peuvent être ajoutés à un Report Group." });
      if (v.groupBy && !agg.includes(v.groupBy)) notes.push({ type: "or", text: "La colonne de regroupement n'a pas besoin d'être dans Selected Columns (elle apparaît en tête de chaque groupe)." });
      notes.push({ type: "or", text: "Les rapports planifiés sont générés chaque nuit (vers 2 h) ; les bases Summary sont plus rapides que les logs détaillés." });
      return { steps, cli, notes, verify: [] };
    },
  });

  /* ---------- générateur de filtre de logs ---------- */
  const qv = x => /[\s()'"]/.test(x) || x.includes("\\") ? `'${x}'` : x;
  register({
    id: "m14-log-filter",
    module: "M14",
    title: "Générateur de filtre de logs",
    icon: "🔎",
    desc: "Construit le filtre Monitor > Logs (Traffic, Threat, URL) à partir d'IP, port, application, action, règle, utilisateur… et la commande CLI show log équivalente.",
    tags: "log filter monitor traffic threat url query show log addr.src port.dst action",
    noCommit: true,
    fields: [
      { id: "log", label: "Journal", type: "select", default: "traffic", options: [["traffic", "Traffic"], ["threat", "Threat"], ["url", "URL Filtering"]] },
      { id: "src", label: "Source (IP ou réseau)", type: "text", validate: "ipcidr", default: "192.168.1.50", group: "Critères (vides = ignorés)" },
      { id: "dst", label: "Destination (IP ou réseau)", type: "text", validate: "ipcidr", default: "" },
      { id: "zsrc", label: "Zone source", type: "text", validate: NAME, default: "" },
      { id: "zdst", label: "Zone destination", type: "text", validate: NAME, default: "" },
      { id: "dport", label: "Port destination", type: "port", default: "443" },
      { id: "app", label: "Application", type: "text", default: "", validate: x => /^[a-z0-9][a-z0-9._-]*$/.test(x) ? null : "Nom d'application App-ID (minuscules, ex. ssl)" },
      { id: "action", label: "Action", type: "select", default: "deny",
        options: [["", "(toutes)"], ["allow", "allow"], ["deny", "deny"], ["drop", "drop"], ["reset-both", "reset-both"], ["reset-client", "reset-client"], ["reset-server", "reset-server"], ["alert", "alert"], ["block-url", "block-url"]] },
      { id: "rule", label: "Règle", type: "text", default: "" },
      { id: "user", label: "Utilisateur source (domaine\\user)", type: "text", default: "" },
      { id: "sev", label: "Sévérité minimale (Threat)", type: "select", default: "", show: v => v.log === "threat",
        options: [["", "(toutes)"], ["critical", "critical"], ["high", "high et plus"], ["medium", "medium et plus"], ["low", "low et plus"]] },
      { id: "cat", label: "Catégorie URL", type: "text", default: "", show: v => v.log === "url", validate: x => catList([x]) },
      { id: "conn", label: "Connecteur", type: "select", default: "and", options: [["and", "and"], ["or", "or"]] },
    ],
    build(v) {
      const crit = [];  // [attribute GUI, operator GUI, value, filtre, cli]
      const add = (attr, op, val, f, c) => crit.push({ attr, op, val, f, c });
      if (v.src) add("Source Address", "in", v.src, `( addr.src in ${v.src} )`, `src in ${v.src}`);
      if (v.dst) add("Destination Address", "in", v.dst, `( addr.dst in ${v.dst} )`, `dst in ${v.dst}`);
      if (v.zsrc) add("Source Zone", "equal", v.zsrc, `( zone.src eq ${qv(v.zsrc)} )`, `from equal ${q(v.zsrc)}`);
      if (v.zdst) add("Destination Zone", "equal", v.zdst, `( zone.dst eq ${qv(v.zdst)} )`, `to equal ${q(v.zdst)}`);
      if (v.dport) add("Destination Port", "equal", v.dport, `( port.dst eq ${v.dport} )`, `dport equal ${v.dport}`);
      if (v.app) add("Application", "equal", v.app, `( app eq ${v.app} )`, `app equal ${v.app}`);
      if (v.action) add("Action", "equal", v.action, `( action eq ${v.action} )`, `action equal ${v.action}`);
      if (v.rule) add("Rule", "equal", v.rule, `( rule eq ${qv(v.rule)} )`, `rule equal ${q(v.rule)}`);
      if (v.user) add("Source User", "equal", v.user, `( user.src eq ${qv(v.user)} )`, `srcuser equal ${qb(v.user)}`);
      if (v.log === "threat" && v.sev) add("Severity", v.sev === "critical" ? "equal" : "greater than or equal", v.sev,
        v.sev === "critical" ? "( severity eq critical )" : `( severity geq ${v.sev} )`, `severity ${v.sev === "critical" ? "equal" : "greater-or-equal"} ${v.sev}`);
      if (v.log === "url" && v.cat) add("Category", "equal", v.cat, `( category eq ${v.cat} )`, `category equal ${v.cat}`);
      const filter = crit.map(c => c.f).join(` ${v.conn} `) || "(aucun critère)";
      const LOG = { traffic: "Traffic", threat: "Threat", url: "URL Filtering" }[v.log];
      const steps = [
        { title: `Ouvrir le journal ${LOG}`, path: ["Monitor", "Logs", LOG], action: "Cliquer sur ✕ à droite de la barre de filtre pour effacer un filtre existant.", fields: [] },
        { title: "Coller le filtre et l'appliquer", path: ["Monitor", "Logs", LOG], window: "Filtre",
          action: "Coller dans la barre de filtre en haut du journal, puis cliquer sur la flèche → (Apply Filter).", fields: [["Filtre", filter]] },
        ...(crit.length ? [{ title: "Équivalent avec Add Log Filter", path: ["Monitor", "Logs", LOG], window: "Add Log Filter",
          action: `Icône ➕ de la barre de filtre : pour chaque ligne choisir Connector = ${v.conn}, Attribute, Operator, Value → Add ; puis Apply.`,
          fields: crit.map(c => [`${c.attr} · ${c.op}`, c.val]) }] : []),
        { title: "Exploiter le résultat", path: ["Monitor", "Logs", LOG],
          action: "Loupe 🔍 d'une ligne = Detailed Log View. Icône « Save Filter » pour réutiliser le filtre ; « Export to CSV » pour l'extraire.", fields: [] },
      ];
      const cliOp = crit.length ? (v.conn === "and"
        ? [`show log ${v.log} direction equal backward ${crit.map(c => c.c).join(" ")}`]
        : crit.map(c => `show log ${v.log} direction equal backward ${c.c}`)) : [`show log ${v.log} direction equal backward`];
      const notes = [{ type: "ok", title: "Filtre", html: `<code>${PAN.esc(filter)}</code>` }];
      if (!crit.length) notes.push({ type: "warn", text: "Aucun critère : renseigner au moins un champ." });
      if (v.conn === "or" && crit.length > 1) notes.push({ type: "or", text: "Connecteur « or » : la CLI show log ne combine qu'en ET ; une commande par critère est proposée." });
      if (v.log === "traffic" && ["alert", "block-url"].includes(v.action)) notes.push({ type: "warn", text: `L'action « ${v.action} » n'existe que dans les journaux Threat/URL.` });
      if (v.log !== "traffic" && v.action === "deny") notes.push({ type: "or", text: "Threat/URL : les blocages apparaissent souvent en reset-both, drop ou block-url plutôt que deny." });
      notes.push({ type: "or", text: "Opérateurs utiles : eq, neq, in (IP/réseau), notin, geq/leq, contains ; négation : not ( … )." });
      return { steps, notes, cliRaw: ["# --- Mode opérationnel (admin@pa>) ---", ...cliOp] };
    },
  });
})();
