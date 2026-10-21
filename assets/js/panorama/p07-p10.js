/* PANW Config Builder — Panorama 11.1
   Catégories P07 (Comptes administrateurs), P08 (Rapports), P09 (Dépannage), P10 (Avancé / annexe A).
   Source : cours EDU-220 11.1 (MOD-07, MOD-08, MOD-09, Appendix A) et Lab Guide (labs 7, 8, 9 + bonus).
   Format des modules : voir l'en-tête de assets/js/engine.js et assets/js/modules/m02-m04.js. */
(function () {
  const C = window.PAN && PAN.cfg;
  if (!C) return;
  const { register, q, members, yn } = C;
  const cat = typeof C.category === "function" ? C.category : () => {};
  cat("P07", "Comptes administrateurs");
  cat("P08", "Rapports");
  cat("P09", "Dépannage");
  cat("P10", "Avancé (annexe)");

  /* =====================================================================
     Helpers communs
     ===================================================================== */
  const ipOf = s => String(s || "").split("/")[0].trim();
  const ipOk = s => PAN.ip.valid(ipOf(s));
  const vIpOrCidr = s => {
    const [a, m] = String(s).split("/");
    if (!PAN.ip.valid(a)) return "Adresse IPv4 attendue (ex. 192.168.1.252 ou 192.168.1.252/24)";
    if (m !== undefined && !(/^\d+$/.test(m) && +m <= 32)) return "Masque /0 à /32";
    return null;
  };
  const serial = s => /^\d{12,15}$/.test(String(s).trim()) ? null : "Numéro de série : 12 à 15 chiffres (Panorama > Managed Devices > Summary ou Dashboard du pare-feu)";
  const serialList = arr => { for (const s of arr) { const e = serial(s); if (e) return `« ${s} » : ${e}`; } return null; };
  const nameList = arr => { for (const s of arr) { const e = C.V.name(s); if (e) return `« ${s} » : ${e}`; } return null; };
  const hhmm = v => /^([01]\d|2[0-3]):[0-5]\d$/.test(v) ? null : "Heure au format HH:MM (24 h), ex. 01:30";
  const absPath = p => /^[~\/][^\s]*$/.test(p) ? null : "Chemin absolu sans espace (ex. /backup/panorama/)";
  const MASKED = "•••••••• (valeur saisie)";
  const strongPwd = v => (v.length >= 8 && /[A-Z]/.test(v) && /[a-z]/.test(v) && /\d/.test(v) && /[^A-Za-z0-9]/.test(v)) ? null
    : "8 caractères min. avec majuscule, minuscule, chiffre et caractère spécial";
  const lbl = (opts, k) => (opts.find(o => o[0] === k) || [k, k])[1];
  const UNSURE = "# (syntaxe à valider avec « ? » sur ta version de Panorama)";

  /* Rôles dynamiques Panorama (MOD-07) */
  const PDYN = [["superuser", "Superuser"], ["superreader", "Superuser (read-only)"], ["panorama-admin", "Panorama administrator"]];

  /* =====================================================================
     P07 · Admin Role Profiles (Panorama / Device Group and Template)
     ===================================================================== */
  const PSEC = [
    ["dashboard", "Dashboard"], ["acc", "ACC"], ["monitor", "Monitor"], ["policies", "Policies"], ["objects", "Objects"],
    ["network", "Network"], ["device", "Device"], ["panorama", "Panorama"], ["privacy", "Privacy"], ["validate", "Validate"],
    ["save", "Save"], ["commit", "Commit (dont Push All Changes)"], ["tasks", "Tasks"], ["global", "Global"],
  ];
  const DGT_EXCL = ["panorama"]; // pas d'accès à la configuration Panorama pour un rôle Device Group and Template
  const LVL = [["enable", "Enable (lecture/écriture)"], ["read-only", "Read Only"], ["disable", "Disable"]];
  const LVLGUI = { enable: "Enable ✎", "read-only": "Read Only 👁", disable: "Disable ⛔" };
  const PRESETS = {
    monitor: { dashboard: "enable", acc: "enable", monitor: "enable" },
    secpol: { dashboard: "enable", acc: "enable", monitor: "read-only", policies: "enable", objects: "enable", validate: "enable", commit: "enable", tasks: "enable" },
    netops: { dashboard: "enable", acc: "read-only", monitor: "read-only", network: "enable", device: "enable", validate: "enable", commit: "enable", tasks: "enable" },
    readonly: Object.fromEntries(PSEC.map(s => [s[0], "read-only"])),
  };
  const PRESETOPTS = [["monitor", "Supervision seule (Dashboard, ACC, Monitor) — ex. « Intern » du lab 7"],
    ["secpol", "Admin des politiques (Policies, Objects, Commit)"], ["netops", "Admin réseau (Network, Device, Commit)"],
    ["readonly", "Tout en lecture seule"], ["custom", "Personnalisé (section par section)"]];

  register({
    id: "p07-roles",
    module: "P07",
    title: "Admin Role Profiles (Panorama / DG & Template)",
    icon: "🎭",
    desc: "Rôles personnalisés : Custom Panorama Admin (Web UI, XML/REST API, CLI) ou Device Group and Template (accès limité aux DG/templates via access domain).",
    tags: "admin role profile custom panorama admin device group template rbac rôle permissions web ui xml api cli",
    fields: [
      { id: "role", label: "Nom du rôle", type: "text", required: true, validate: "name", default: "Intern", group: "Rôle" },
      { id: "roleDesc", label: "Description", type: "text", default: "Acces limite au Dashboard, ACC et Logs" },
      { id: "rtype", label: "Role", type: "select", default: "panorama",
        options: [["panorama", "Panorama (→ Custom Panorama Admin)"], ["dgt", "Device Group and Template (→ DG & Template Admin)"]],
        hint: "Panorama = accès à Panorama et à tous les DG/templates selon les droits ; Device Group and Template = Web UI uniquement, limité aux DG/templates d'un access domain." },
      { id: "preset", label: "Modèle de droits Web UI", type: "select", default: "monitor", options: PRESETOPTS, group: "Web UI" },
      ...PSEC.map(([k, l]) => ({ id: "w_" + k, label: l, type: "select", default: (PRESETS.monitor[k] || "disable"), options: LVL,
        show: v => v.preset === "custom" && !(v.rtype === "dgt" && DGT_EXCL.includes(k)) })),
      { id: "cliPerm", label: "Command Line", type: "select", default: "none", show: v => v.rtype === "panorama", group: "Autres interfaces",
        options: [["none", "None"], ["superuser", "superuser"], ["superreader", "superreader"], ["panorama-admin", "panorama-admin"]],
        hint: "Un rôle Device Group and Template n'a jamais accès à la CLI ni aux plugins." },
      { id: "xmlapi", label: "XML API (toutes les catégories activées)", type: "checkbox", default: false },
      { id: "restapi", label: "REST API (activer)", type: "checkbox", default: false },
    ],
    build(v) {
      const isP = v.rtype === "panorama";
      const secs = PSEC.filter(([k]) => isP || !DGT_EXCL.includes(k));
      const lv = k => v.preset === "custom" ? (v["w_" + k] || "disable") : ((PRESETS[v.preset] || {})[k] || "disable");
      const steps = [
        { title: "Créer l'Admin Role Profile", path: ["Panorama", "Admin Roles"], window: "Admin Role Profile",
          action: "Cliquer sur Add.", fields: [["Name", v.role], ["Description", v.roleDesc], ["Role", isP ? "Panorama" : "Device Group and Template"]],
          note: "Le choix Panorama / Device Group and Template n'est plus modifiable ensuite : recrée le rôle si tu te trompes." },
        { title: "Droits Web UI", path: ["Panorama", "Admin Roles"], tab: "Web UI", window: "Admin Role Profile",
          action: "Cliquer sur l'icône à gauche de chaque élément pour basculer Enable / Read Only / Disable (les sous-éléments héritent du parent, ajustables ensuite).",
          fields: secs.map(([k, l]) => [l, LVLGUI[lv(k)]]) },
        { title: "XML API / REST API", path: ["Panorama", "Admin Roles"], tab: "XML API", window: "Admin Role Profile",
          action: "Onglets XML API puis REST API : régler chaque élément.",
          fields: [["XML API", v.xmlapi ? "Toutes les catégories : Enable" : "Toutes les catégories : Disable"], ["REST API", v.restapi ? "Enable (ajuster par objet)" : "Tout Disable"]] },
      ];
      if (isP) steps.push({ title: "Command Line", path: ["Panorama", "Admin Roles"], tab: "Command Line", window: "Admin Role Profile",
        action: "Onglet Command Line.", fields: [["Command Line", v.cliPerm === "none" ? "None" : v.cliPerm]] });
      steps.push({ title: "Plugins", path: ["Panorama", "Admin Roles"], tab: "Web UI", window: "Admin Role Profile",
        action: "En bas de la liste Web UI : Plugins → Disable sauf besoin (SD-WAN, Cloud Services…). Puis OK.", fields: [] });

      const rk = isP ? "panorama" : "device-group";
      const R = `set panorama admin-role ${q(v.role)}`;
      const cli = [
        UNSURE,
        v.roleDesc && `${R} description ${q(v.roleDesc)}`,
        ...secs.map(([k]) => `${R} role ${rk} webui ${k} ${lv(k)}`),
        `${R} role ${rk} xmlapi report ${v.xmlapi ? "enable" : "disable"} log ${v.xmlapi ? "enable" : "disable"} config ${v.xmlapi ? "enable" : "disable"} op ${v.xmlapi ? "enable" : "disable"} commit ${v.xmlapi ? "enable" : "disable"} user-id ${v.xmlapi ? "enable" : "disable"} export ${v.xmlapi ? "enable" : "disable"} import ${v.xmlapi ? "enable" : "disable"}`,
        isP && v.cliPerm !== "none" && `${R} role panorama cli ${v.cliPerm}`,
        "# REST API : droits par objet, à régler de préférence dans l'onglet REST API de la WebUI",
      ].filter(Boolean);

      const notes = [
        { type: "or", title: "Trois familles de rôles (MOD-07)", text: "Dynamic (intégrés : Superuser, Superuser read-only, Panorama administrator) — Custom Panorama Admin (rôle « Panorama » : Web UI, API, CLI, plugins) — Device Group and Template Admin (Web UI seulement, sur les DG/templates d'un access domain)." },
        { type: "or", text: "Un compte n'a qu'un seul rôle Panorama : pour cumuler deux jeux de droits, crée un troisième rôle qui les réunit." },
        { type: "warn", text: "Les nœuds parents de la Web UI (Monitor, Policies, Objects…) contiennent des sous-éléments : si le commit refuse une ligne CLI, descends au niveau voulu avec « set panorama admin-role … role … webui monitor ? »." },
      ];
      if (!isP) notes.push({ type: "or", title: "Étape suivante", text: "Un rôle Device Group and Template n'a d'effet qu'associé à un access domain sur le compte administrateur (#p07-access-domain puis #p07-admin)." });
      if (isP && v.cliPerm === "superuser") notes.push({ type: "warn", text: "CLI « superuser » : l'administrateur pourra tout modifier en CLI, quels que soient les droits Web UI. Préfère None ou superreader." });
      if (v.xmlapi) notes.push({ type: "warn", text: "XML API complète = configuration et commit possibles par script : réserve-la aux comptes de service." });
      return { steps, cli, notes, verify: [`show config running | match ${q(v.role)}`] };
    },
  });

  /* =====================================================================
     P07 · Access domains (MSSP / délégation par client ou par région)
     ===================================================================== */
  register({
    id: "p07-access-domain",
    module: "P07",
    title: "Access domains (délégation MSSP)",
    icon: "🏢",
    desc: "Limiter un administrateur à certains device groups, templates / template stacks, objets partagés et contextes de pare-feu (multi-clients, multi-régions).",
    tags: "access domain domaine d'accès mssp délégation multi-tenant device group template shared objects device context",
    fields: [
      { id: "accessDomain", label: "Nom de l'access domain", type: "text", required: true, validate: "name", default: "AD-Client-A", group: "Access domain" },
      { id: "sharedAccess", label: "Shared Objects", type: "select", default: "read",
        options: [["read", "Read — lecture des objets Shared"], ["write", "Write — modification des objets Shared"], ["shared-only", "Shared Only — n'utiliser que les objets Shared"]],
        hint: "Write sur Shared = l'admin peut impacter TOUS les clients : à éviter en contexte MSSP." },
      { id: "dg", label: "Device group principal", type: "text", required: true, validate: "name", default: "DG-Client-A", group: "Device Groups" },
      { id: "dgExtra", label: "Autres device groups (optionnel)", type: "list", validate: nameList, default: [],
        hint: "Les DG enfants ne sont pas inclus automatiquement : coche chaque DG nécessaire." },
      { id: "stack", label: "Template stack", type: "text", validate: "name", default: "TS-Client-A", group: "Templates" },
      { id: "tplExtra", label: "Autres templates / stacks (optionnel)", type: "list", validate: nameList, default: [] },
      { id: "devCtx", label: "Device Context : pare-feux accessibles en context switch (séries, optionnel)", type: "list", validate: serialList, default: [],
        group: "Device Context", hint: "Permet à l'admin de basculer sur la WebUI locale de ces pare-feux depuis Panorama (Context)." },
    ],
    build(v) {
      const dgs = [v.dg, ...v.dgExtra].filter(Boolean);
      const tpls = [v.stack, ...v.tplExtra].filter(Boolean);
      const SA = { read: "Read", write: "Write", "shared-only": "Shared Only" }[v.sharedAccess];
      const steps = [
        { title: "Créer l'access domain", path: ["Panorama", "Access Domain"], window: "Access Domain", action: "Cliquer sur Add.",
          fields: [["Name", v.accessDomain]] },
        { title: "Objets partagés", path: ["Panorama", "Access Domain"], tab: "Shared Objects", window: "Access Domain",
          action: "Onglet Shared Objects.", fields: [["Shared Objects", SA]] },
        { title: "Device groups autorisés", path: ["Panorama", "Access Domain"], tab: "Device Groups", window: "Access Domain",
          action: "Onglet Device Groups : cocher les device groups suivants.", fields: [["Device Groups", dgs]] },
        { title: "Templates autorisés", path: ["Panorama", "Access Domain"], tab: "Templates", window: "Access Domain",
          action: "Onglet Templates : Add pour chaque template ou template stack.", fields: [["Templates", tpls]] },
      ];
      if (v.devCtx.length) steps.push({ title: "Contexte des pare-feux", path: ["Panorama", "Access Domain"], tab: "Device Context", window: "Access Domain",
        action: "Onglet Device Context : cocher les pare-feux, puis OK.", fields: [["Device Context", v.devCtx]] });
      const A = `set mgt-config access-domain ${q(v.accessDomain)}`;
      const cli = [
        UNSURE,
        `${A} shared-access ${v.sharedAccess}`,
        `${A} device-groups ${members(dgs)}`,
        tpls.length && `${A} templates ${members(tpls)}`,
        v.devCtx.length && `${A} devices ${members(v.devCtx)}`,
      ].filter(Boolean);
      const notes = [
        { type: "or", title: "Principe (MOD-07)", text: "Un access domain définit QUOI (DG, templates, objets partagés, contextes) ; le rôle Device Group and Template définit COMMENT (droits). Sur le compte, on associe des paires « access domain → rôle » : ex. adminHelga en écriture sur West-Domain et en lecture seule sur East-Domain." },
        { type: "or", text: "Avec RADIUS/SAML, l'access domain peut être attribué par attribut : VSA PaloAlto-Panorama-Admin-Access-Domain (et PaloAlto-Panorama-Admin-Role pour le rôle)." },
      ];
      if (v.sharedAccess === "write") notes.push({ type: "warn", text: "Shared Objects en Write : les objets Shared sont poussés vers tous les pare-feux de tous les DG. En MSSP, laisse Read ou Shared Only." });
      if (!tpls.length) notes.push({ type: "or", text: "Aucun template : l'administrateur ne pourra pas modifier la configuration réseau/device des pare-feux de ce domaine (politiques et objets uniquement)." });
      return { steps, cli, notes, verify: [`show config running | match ${q(v.accessDomain)}`] };
    },
  });

  /* =====================================================================
     P07 · Authentification des administrateurs (RADIUS / LDAP / TACACS+ / SAML)
     ===================================================================== */
  const AKIND = { radius: "RADIUS", ldap: "LDAP", tacplus: "TACACS+", saml: "SAML" };
  register({
    id: "p07-auth",
    module: "P07",
    title: "Authentification externe (RADIUS / LDAP / TACACS+ / SAML)",
    icon: "🗝️",
    desc: "Server Profile, Authentication Profile (Allow List, verrouillage), séquence optionnelle et test CLI — pour les admins Panorama ou, via template, pour les admins des pare-feux.",
    tags: "authentication profile radius ldap tacacs saml server profile authentication sequence allow list test authentication vsa",
    fields: [
      { id: "scope", label: "Pour qui ?", type: "select", default: "panorama", group: "Portée",
        options: [["panorama", "Administrateurs de Panorama (Panorama > Server Profiles)"], ["template", "Administrateurs des pare-feux (via un template, Device > …)"]] },
      { id: "template", label: "Template", type: "text", required: true, validate: "name", default: "TPL-Common", show: v => v.scope === "template" },
      { id: "stack", label: "Template stack à pousser", type: "text", required: true, validate: "name", default: "TS-Paris", show: v => v.scope === "template" },
      { id: "kind", label: "Type de serveur", type: "select", default: "radius", group: "Server Profile",
        options: [["radius", "RADIUS"], ["ldap", "LDAP / Active Directory"], ["tacplus", "TACACS+"], ["saml", "SAML (IdP : Entra ID, Okta…)"]] },
      { id: "sp", label: "Nom du Server Profile", type: "text", required: true, validate: "name", default: "Panorama_RADIUS_Servers" },
      { id: "srvName", label: "Nom du serveur", type: "text", required: true, validate: "name", default: "radius.panw.lab", show: v => v.kind !== "saml" },
      { id: "srvIp", label: "Adresse du serveur (IP/FQDN)", type: "text", required: true, validate: "host", default: "192.168.50.150", show: v => v.kind !== "saml" },
      { id: "srvPort", label: "Port", type: "port", required: true, default: "1812", show: v => v.kind !== "saml", hint: "RADIUS 1812 · LDAP 389 / LDAPS 636 · TACACS+ 49." },
      { id: "secret", label: "Secret partagé / mot de passe Bind", type: "password", required: true, default: "Pal0Alt0!", show: v => v.kind !== "saml" },
      { id: "radProto", label: "Authentication Protocol", type: "select", default: "CHAP", show: v => v.kind === "radius",
        options: [["PEAP-MSCHAPv2", "PEAP-MSCHAPv2"], ["PEAP-with-GTC", "PEAP with GTC"], ["EAP-TTLS-with-PAP", "EAP-TTLS with PAP"], ["CHAP", "CHAP"], ["PAP", "PAP"]] },
      { id: "tacProto", label: "Authentication Protocol", type: "select", default: "CHAP", show: v => v.kind === "tacplus", options: [["CHAP", "CHAP"], ["PAP", "PAP"]] },
      { id: "timeout", label: "Timeout (s)", type: "number", min: 1, max: 30, default: "3", show: v => v.kind === "radius" || v.kind === "tacplus" },
      { id: "retries", label: "Retries", type: "number", min: 1, max: 5, default: "3", show: v => v.kind === "radius" },
      { id: "ldapType", label: "Type LDAP", type: "select", default: "active-directory", show: v => v.kind === "ldap",
        options: [["active-directory", "active-directory"], ["e-directory", "e-directory"], ["sun", "sun"], ["other", "other"]] },
      { id: "base", label: "Base DN", type: "text", required: true, default: "DC=panw,DC=lab", show: v => v.kind === "ldap",
        validate: d => /^([A-Za-z]+=[^,]+)(,[A-Za-z]+=[^,]+)*$/.test(d) ? null : "Format DN attendu (ex. DC=corp,DC=local)" },
      { id: "bind", label: "Bind DN", type: "text", required: true, default: "svc-panorama@panw.lab", show: v => v.kind === "ldap", hint: "Compte de service en lecture, à créer aussi sur l'annuaire." },
      { id: "ldapSsl", label: "Require SSL/TLS secured connection", type: "checkbox", default: true, show: v => v.kind === "ldap" },
      { id: "idpEntity", label: "Identity Provider Identifier (Entity ID)", type: "text", required: true, default: "https://sts.windows.net/00000000-0000-0000-0000-000000000000/", show: v => v.kind === "saml", wide: true },
      { id: "idpSso", label: "Identity Provider SSO URL", type: "text", required: true, validate: "url", default: "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/saml2", show: v => v.kind === "saml", wide: true },
      { id: "idpCert", label: "Certificat de l'IdP (nom importé)", type: "text", required: true, validate: "name", default: "IdP-SAML-Cert", show: v => v.kind === "saml",
        hint: "Le plus simple : bouton Import du SAML Identity Provider avec le fichier metadata de l'IdP (remplit Entity ID, SSO URL et certificat)." },
      { id: "ap", label: "Nom de l'Authentication Profile", type: "text", required: true, validate: "name", default: "RADIUS_Auth_Profile", group: "Authentication Profile" },
      { id: "userDomain", label: "User Domain (optionnel)", type: "text", placeholder: "panw", show: v => v.kind !== "saml", validate: d => /^[A-Za-z0-9.-]+$/.test(d) ? null : "Nom de domaine NetBIOS ou DNS" },
      { id: "loginAttr", label: "Login Attribute", type: "text", default: "sAMAccountName", show: v => v.kind === "ldap" },
      { id: "samlUser", label: "Username Attribute", type: "text", default: "username", show: v => v.kind === "saml", group: "Attributs SAML" },
      { id: "samlRole", label: "Admin Role Attribute (optionnel)", type: "text", default: "adminrole", show: v => v.kind === "saml" },
      { id: "samlAd", label: "Access Domain Attribute (optionnel)", type: "text", default: "accessdomain", show: v => v.kind === "saml" && v.scope === "panorama" },
      { id: "allow", label: "Allow List (utilisateurs/groupes, ou all)", type: "list", required: true, default: ["all"], group: "Advanced" },
      { id: "fails", label: "Failed Attempts (0 = pas de verrouillage)", type: "number", min: 0, max: 10, default: "5" },
      { id: "lockT", label: "Lockout Time (minutes)", type: "number", min: 0, max: 60, default: "30", show: v => +v.fails > 0 },
      { id: "seq", label: "Créer une Authentication Sequence", type: "checkbox", default: false, group: "Séquence & usage" },
      { id: "seqName", label: "Nom de la séquence", type: "text", required: true, validate: "name", default: "Admin-Auth-Sequence", show: v => v.seq },
      { id: "seqOthers", label: "Profils suivants (dans l'ordre, déjà existants)", type: "list", required: true, validate: nameList, default: ["LDAP_Auth_Profile"], show: v => v.seq,
        hint: "Le profil ci-dessus est essayé en premier, puis ceux-ci si le serveur est injoignable ou le compte inconnu." },
      { id: "applyDefault", label: "Profil par défaut (Authentication Settings) pour les admins non déclarés", type: "checkbox", default: false,
        hint: "Les comptes absents de la liste Administrators reçoivent alors leur rôle par attribut (VSA RADIUS/TACACS+, attribut SAML)." },
      { id: "testUser", label: "Compte de test", type: "text", default: "adminHelga", show: v => v.kind !== "saml" },
    ],
    build(v) {
      const k = v.kind, isT = v.scope === "template";
      const root = isT ? ["Device"] : ["Panorama"];
      const tplF = isT ? [["Template (en haut)", v.template]] : [];
      const steps = [];
      const spPath = [...root, "Server Profiles", k === "saml" ? "SAML Identity Provider" : AKIND[k]];
      if (k === "radius") steps.push({ title: "Créer le RADIUS Server Profile", path: spPath, window: "RADIUS Server Profile", action: "Cliquer sur Add, puis Servers → Add.",
        fields: [...tplF, ["Profile Name", v.sp], ["Timeout", v.timeout], ["Retries", v.retries], ["Authentication Protocol", v.radProto.replace(/-/g, " ").replace("PEAP MSCHAPv2", "PEAP-MSCHAPv2")],
          ["Name", v.srvName], ["RADIUS Server", v.srvIp], ["Secret / Confirm Secret", MASKED], ["Port", v.srvPort]] });
      else if (k === "tacplus") steps.push({ title: "Créer le TACACS+ Server Profile", path: spPath, window: "TACACS+ Server Profile", action: "Cliquer sur Add, puis Servers → Add.",
        fields: [...tplF, ["Profile Name", v.sp], ["Timeout", v.timeout], ["Authentication Protocol", v.tacProto], ["Name", v.srvName], ["TACACS+ Server", v.srvIp], ["Secret / Confirm Secret", MASKED], ["Port", v.srvPort]] });
      else if (k === "ldap") steps.push({ title: "Créer le LDAP Server Profile", path: spPath, window: "LDAP Server Profile", action: "Cliquer sur Add, puis Server List → Add.",
        fields: [...tplF, ["Profile Name", v.sp], ["Name", v.srvName], ["LDAP Server", v.srvIp], ["Port", v.srvPort], ["Type", v.ldapType], ["Base DN", v.base], ["Bind DN", v.bind],
          ["Password / Confirm Password", MASKED], ["Require SSL/TLS secured connection", v.ldapSsl ? true : "☐ décoché"]],
        note: "Si la connexion au serveur fonctionne, la liste déroulante Base DN se remplit automatiquement." });
      else steps.push({ title: "Créer le SAML Identity Provider", path: spPath, window: "SAML Identity Provider Server Profile",
        action: "Recommandé : bouton Import (en bas) → nom du profil + fichier metadata XML de l'IdP. Sinon Add et saisie manuelle.",
        fields: [...tplF, ["Profile Name", v.sp], ["Identity Provider Identifier", v.idpEntity], ["Identity Provider Certificate", v.idpCert], ["Identity Provider SSO URL", v.idpSso], ["SAML HTTP Binding for SSO Requests to IdP", "Post"]],
        note: "Côté IdP, l'ACS URL est https://<IP-ou-FQDN-Panorama>/SAML20/SP/ACS et l'Entity ID https://<IP-ou-FQDN-Panorama>:443/SAML20/SP." });
      steps.push({ title: "Créer l'Authentication Profile", path: [...root, "Authentication Profile"], tab: "Authentication", window: "Authentication Profile", action: "Cliquer sur Add.",
        fields: [...tplF, ["Name", v.ap], ["Type", AKIND[k]], [k === "saml" ? "IdP Server Profile" : "Server Profile", v.sp], ["Login Attribute", k === "ldap" && v.loginAttr], ["User Domain", k !== "saml" && v.userDomain],
          ["Username Attribute", k === "saml" && v.samlUser], ["Admin Role Attribute", k === "saml" && v.samlRole], ["Access Domain Attribute", k === "saml" && !isT && v.samlAd]] });
      steps.push({ title: "Allow List et verrouillage", path: [...root, "Authentication Profile"], tab: "Advanced", window: "Authentication Profile",
        action: "Allow List → Add (ou « all »), régler le verrouillage, puis OK.",
        fields: [["Allow List", v.allow], ["Failed Attempts", v.fails], ["Lockout Time (min)", +v.fails > 0 && v.lockT]] });
      if (v.seq) steps.push({ title: "Créer l'Authentication Sequence", path: [...root, "Authentication Sequence"], window: "Authentication Sequence", action: "Cliquer sur Add, puis Add pour chaque profil (ordre = ordre d'essai).",
        fields: [...tplF, ["Name", v.seqName], ["Authentication Profiles", [v.ap, ...v.seqOthers]]] });
      if (v.applyDefault) steps.push({ title: "Profil par défaut des administrateurs", path: isT ? ["Device", "Setup", "Management"] : ["Panorama", "Setup", "Management"], window: "Authentication Settings",
        action: "Cadre Authentication Settings → icône ⚙.", fields: [...tplF, ["Authentication Profile", v.seq ? v.seqName : v.ap]] });
      if (k !== "saml" && !isT) steps.push({ title: "Tester avant de committer", path: ["CLI Panorama (SSH)"], action: `test authentication authentication-profile ${v.ap} username ${v.testUser || "<compte>"} password → saisir le mot de passe. Attendu : « Authentication succeeded for user … ».`, fields: [],
        note: "Le test fonctionne sur la configuration candidate : pas besoin de commit pour valider le Server Profile (lab 7)." });

      const P = isT ? `set template ${q(v.template)} config shared` : "set panorama";
      const S = `${P} server-profile ${k === "saml" ? "saml-idp" : k} ${q(v.sp)}`;
      const cli = [];
      if (!isT) cli.push(UNSURE);
      if (k === "radius") cli.push(`${S} server ${q(v.srvName)} ip-address ${v.srvIp} port ${v.srvPort} secret ${q(v.secret)}`, `${S} timeout ${v.timeout || 3} retries ${v.retries || 3}`, `${S} protocol ${v.radProto}`);
      else if (k === "tacplus") cli.push(`${S} server ${q(v.srvName)} address ${v.srvIp} port ${v.srvPort} secret ${q(v.secret)}`, `${S} timeout ${v.timeout || 3}`, `${S} protocol ${v.tacProto}`);
      else if (k === "ldap") cli.push(`${S} server ${q(v.srvName)} address ${v.srvIp} port ${v.srvPort}`, `${S} ldap-type ${v.ldapType} base ${q(v.base)} bind-dn ${q(v.bind)} bind-password ${q(v.secret)}`, `${S} ssl ${yn(v.ldapSsl)}`);
      else cli.push(`# Import conseillé via la WebUI (metadata). Équivalent CLI indicatif :`, `${S} entity-id ${q(v.idpEntity)} sso-url ${q(v.idpSso)} certificate ${q(v.idpCert)} sso-bindings post`);
      const A = `${P} authentication-profile ${q(v.ap)}`;
      if (k === "saml") cli.push(`${A} method saml-idp server-profile ${q(v.sp)}${v.samlUser ? " attribute-name-username " + q(v.samlUser) : ""}${v.samlRole ? " attribute-name-admin-role " + q(v.samlRole) : ""}${!isT && v.samlAd ? " attribute-name-access-domain " + q(v.samlAd) : ""}`);
      else cli.push(`${A} method ${k} server-profile ${q(v.sp)}${k === "ldap" && v.loginAttr ? " login-attribute " + q(v.loginAttr) : ""}`);
      if (k !== "saml" && v.userDomain) cli.push(`${A} user-domain ${q(v.userDomain)}`);
      cli.push(`${A} allow-list ${members(v.allow)}`);
      if (v.fails !== "") cli.push(`${A} lockout failed-attempts ${v.fails}${+v.fails > 0 && v.lockT !== "" ? " lockout-time " + v.lockT : ""}`);
      if (v.seq) cli.push(`${P} authentication-sequence ${q(v.seqName)} authentication-profiles ${members([v.ap, ...v.seqOthers])}`);
      if (v.applyDefault) cli.push(isT ? `set template ${q(v.template)} config devices localhost.localdomain deviceconfig system authentication-profile ${q(v.seq ? v.seqName : v.ap)}`
        : `set deviceconfig system authentication-profile ${q(v.seq ? v.seqName : v.ap)}`);

      const notes = [
        { type: "or", title: "Chaîne d'authentification (MOD-07)", text: "Server Profile (serveurs) → Authentication Profile (domaine, Allow List, verrouillage) → Authentication Sequence optionnelle (ex. LDAP puis RADIUS lors d'une fusion d'annuaires) → compte administrateur." },
        { type: "or", text: "Le trafic d'authentification part de l'interface MGT de Panorama : autorise UDP 1812 (RADIUS), TCP 389/636 (LDAP) ou TCP 49 (TACACS+) vers les serveurs." },
        { type: "warn", title: "Garde un compte de secours", text: "Conserve au moins un superuser local (Authentication Profile = None) : si le serveur RADIUS/LDAP tombe, c'est ton seul accès." },
      ];
      if (k === "saml") notes.push({ type: "warn", text: "SAML ne s'applique qu'à la WebUI : pour la CLI/SSH, prévois un autre profil (RADIUS/LDAP local) ou un compte local." });
      if (k === "radius" && ["CHAP", "PAP"].includes(v.radProto)) notes.push({ type: "warn", text: `${v.radProto} est utilisé dans le lab ; en production préfère PEAP-MSCHAPv2 ou EAP-TTLS (identifiants protégés par TLS).` });
      if (k === "ldap" && !v.ldapSsl) notes.push({ type: "warn", text: "LDAP sans TLS : mots de passe administrateurs en clair sur le réseau. Préfère LDAPS (636)." });
      if (v.applyDefault && k !== "ldap") notes.push({ type: "or", text: "VSA Palo Alto (RADIUS) : PaloAlto-Panorama-Admin-Role, PaloAlto-Panorama-Admin-Access-Domain pour Panorama ; PaloAlto-Admin-Role / PaloAlto-Admin-Access-Domain pour les pare-feux." });
      if (isT) notes.push({ type: "or", text: "Portée template : le profil existe sur les pare-feux après le push. Lance le test d'authentification depuis la CLI d'un pare-feu." });
      if (v.allow.includes("all") && v.allow.length > 1) notes.push({ type: "warn", text: "« all » dans l'Allow List rend les autres entrées inutiles." });
      const res = { steps, cli, notes, verify: k === "saml" ? ["show admins"] : [
        isT ? "# Sur un pare-feu, après le push :" : "# Sur Panorama :",
        `test authentication authentication-profile ${q(v.ap)} username ${q(v.testUser || "utilisateur")} password`] };
      if (isT) res.push = [`commit-all template-stack name ${q(v.stack)}`];
      return res;
    },
  });

  /* =====================================================================
     P07 · Compte administrateur Panorama
     ===================================================================== */
  register({
    id: "p07-admin",
    module: "P07",
    title: "Compte administrateur Panorama",
    icon: "👤",
    desc: "Créer un administrateur : base locale ou Authentication Profile, type Dynamic / Custom Panorama Admin / Device Group and Template Admin (paires access domain → rôle).",
    tags: "administrator admin compte panorama dynamic superuser custom panorama admin device group template admin access domain password profile",
    fields: [
      { id: "adminUser", label: "Nom du compte (login)", type: "text", required: true, validate: "name", default: "internBob", group: "Compte",
        hint: "Avec RADIUS/LDAP, doit correspondre exactement au login côté serveur." },
      { id: "adminDesc", label: "Description", type: "text", default: "Intern Bob" },
      { id: "auth", label: "Authentification", type: "select", default: "profile",
        options: [["profile", "Authentication Profile (RADIUS/LDAP/TACACS+/SAML ou séquence)"], ["local", "Base locale Panorama (Authentication Profile = None)"]] },
      { id: "ap", label: "Authentication Profile", type: "text", required: true, validate: "name", default: "RADIUS_Auth_Profile", show: v => v.auth === "profile", hint: "Créé avec #p07-auth." },
      { id: "pwd", label: "Mot de passe", type: "password", required: true, default: "Pal0Alt0!", validate: strongPwd, show: v => v.auth === "local" },
      { id: "pwd2", label: "Confirmation", type: "password", required: true, default: "Pal0Alt0!", show: v => v.auth === "local", validate: (p, v) => p !== v.pwd ? "Les deux mots de passe diffèrent" : null },
      { id: "pwProfile", label: "Password Profile (optionnel)", type: "text", validate: "name", show: v => v.auth === "local", placeholder: "Admin-90d" },
      { id: "atype", label: "Administrator Type", type: "select", default: "custom", group: "Droits",
        options: [["dynamic", "Dynamic"], ["custom", "Custom Panorama Admin"], ["dgt", "Device Group and Template Admin"]] },
      { id: "dyn", label: "Admin Role", type: "select", default: "superuser", options: PDYN, show: v => v.atype === "dynamic" },
      { id: "role", label: "Profile (Admin Role Profile)", type: "text", required: true, validate: "name", default: "Intern", show: v => v.atype !== "dynamic",
        hint: "Rôle de type Panorama (Custom) ou Device Group and Template (DG & T), créé avec #p07-roles." },
      { id: "accessDomain", label: "Access domain", type: "text", required: true, validate: "name", default: "AD-Client-A", show: v => v.atype === "dgt", hint: "Créé avec #p07-access-domain." },
      { id: "extraPairs", label: "Autres paires « access domain:rôle » (optionnel)", type: "list", default: [], show: v => v.atype === "dgt",
        validate: arr => { for (const p of arr) if (!/^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._-]*$/.test(p)) return `« ${p} » : format attendu AD-East:ReadOnly-DGT`; return null; },
        hint: "Ex. AD-East:DGT-ReadOnly — même admin, droits différents selon le domaine (switch en haut de la WebUI)." },
    ],
    build(v) {
      const loc = v.auth === "local";
      const pairs = v.atype === "dgt" ? [[v.accessDomain, v.role], ...v.extraPairs.map(p => p.split(":"))] : [];
      const typeL = { dynamic: "Dynamic", custom: "Custom Panorama Admin", dgt: "Device Group and Template Admin" }[v.atype];
      const steps = [{ title: "Créer l'administrateur", path: ["Panorama", "Administrators"], window: "Administrator", action: "Cliquer sur Add.",
        fields: [["Name", v.adminUser], ["Description", v.adminDesc], ["Authentication Profile", loc ? "None" : v.ap], ["Password / Confirm Password", loc && MASKED],
          ["Administrator Type", typeL], ["Admin Role", v.atype === "dynamic" && lbl(PDYN, v.dyn)], ["Profile", v.atype === "custom" && v.role], ["Password Profile", loc && v.pwProfile]],
        note: loc ? null : "Avec un Authentication Profile, les champs Password disparaissent : le mot de passe est vérifié par le serveur externe." }];
      if (pairs.length) steps.push({ title: "Associer access domains et rôles", path: ["Panorama", "Administrators"], window: "Administrator",
        action: "Tableau « Access Domain to Administrator Role » : Add pour chaque paire, puis OK.", fields: pairs.map(([a, r]) => [`Access Domain ${a}`, `Admin Role ${r}`]) });
      steps.push({ title: "Valider l'accès", path: ["Monitor", "Logs", "System"], action: `Commit to Panorama, se déconnecter, se reconnecter avec ${v.adminUser} ; vérifier que seuls les onglets prévus apparaissent. En admin : Device Group = All, filtre ( subtype eq auth ) → événement auth-success.`, fields: [] });

      const u = `set mgt-config users ${q(v.adminUser)}`;
      const sets = [
        v.atype === "dynamic" && `${u} permissions role-based ${v.dyn} yes`,
        v.atype === "custom" && `${u} permissions role-based custom profile ${q(v.role)}`,
        pairs.length && UNSURE,
        ...pairs.map(([a, r]) => `${u} permissions role-based dg-template-profiles ${q(a)} profile ${q(r)}`),
        !loc && `${u} authentication-profile ${q(v.ap)}`,
        loc && v.pwProfile && `${u} password-profile ${q(v.pwProfile)}`,
      ].filter(Boolean);
      const cliRaw = ["configure", ...sets];
      if (loc) cliRaw.push("", "# --- Ligne interactive : la coller SEULE, puis saisir le mot de passe deux fois ---", `${u} password`, "# --- Puis ---");
      cliRaw.push("commit", "exit", "", "# --- Vérification ---", "show admins all", !loc ? `test authentication authentication-profile ${q(v.ap)} username ${q(v.adminUser)} password` : "show system info | match hostname");
      const notes = [
        { type: "or", title: "Ordre de création (MOD-07)", text: "Authentication Profile → Admin Role (et access domain) → compte administrateur : les éléments référencés doivent exister pour apparaître dans les listes déroulantes." },
        { type: "or", text: "Modifications limitées à Panorama : un Commit to Panorama suffit, aucun push vers les pare-feux n'est nécessaire." },
      ];
      if (v.atype === "dynamic" && v.dyn === "panorama-admin") notes.push({ type: "or", text: "« Panorama administrator » ne peut ni gérer les administrateurs/rôles, ni exporter/charger/importer la configuration, ni configurer le Scheduled Config Export." });
      if (v.atype === "dynamic" && v.dyn === "superuser") notes.push({ type: "warn", text: "Superuser = lecture/écriture sur Panorama et tous les DG, templates et pare-feux. Limite ces comptes et active la traçabilité (Monitor > Logs > Configuration)." });
      if (v.atype === "dgt") notes.push({ type: "warn", text: "Paires access domain → rôle : syntaxe CLI variable selon les versions, la WebUI est la référence." });
      if (loc) notes.push({ type: "warn", title: "Commande interactive", text: "« set mgt-config users … password » demande le mot de passe au clavier : colle-la seule." });
      return { steps, cli: sets, cliRaw, notes };
    },
  });

  /* =====================================================================
     P07 · Config lock / Commit lock (administration concurrente)
     ===================================================================== */
  register({
    id: "p07-lock",
    module: "P07",
    title: "Verrous de configuration (Config / Commit lock)",
    icon: "🔒",
    desc: "Administration concurrente : prendre, consulter et retirer un Config lock ou un Commit lock (global, template ou device group), commit des seules modifications de l'admin.",
    tags: "lock config lock commit lock verrou cadenas concurrent administration commit changes made by",
    noCommit: true,
    fields: [
      { id: "lockType", label: "Type", type: "select", default: "config",
        options: [["config", "Config — personne d'autre ne peut modifier"], ["commit", "Commit — les autres modifient mais ne peuvent pas committer"]] },
      { id: "location", label: "Location", type: "select", default: "all",
        options: [["all", "All Configuration"], ["template", "Un template"], ["dg", "Un device group"]] },
      { id: "template", label: "Template", type: "text", required: true, validate: "name", default: "TPL-Common", show: v => v.location === "template" },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "Corp-DG", show: v => v.location === "dg" },
      { id: "lockComment", label: "Comments", type: "text", required: true, default: "JD - Travail sur les profils de securite, fin prevue 12h", wide: true,
        hint: "Qui, quoi, jusqu'à quand : les autres admins le voient en cliquant sur le cadenas." },
      { id: "autoLock", label: "Activer « Automatically Acquire Commit Lock » (prise automatique dès la 1re modification)", type: "checkbox", default: false },
    ],
    build(v) {
      const where = v.location === "all" ? "All Configuration" : v.location === "template" ? `Template ${v.template}` : `Device Group ${v.dg}`;
      const T = v.lockType === "config" ? "Config" : "Commit";
      const steps = [
        { title: "Vérifier les verrous existants", path: ["Cadenas (en haut à droite)"], action: "Cadenas ouvert = aucun verrou ; cadenas fermé avec un chiffre = verrous en place. Cliquer dessus pour voir qui, quand et pourquoi.", fields: [] },
        { title: "Prendre le verrou", path: ["Cadenas", "Take Lock"], window: "Take lock", action: "Fenêtre Locks → Take Lock (en bas à gauche).",
          fields: [["Type", T], ["Location", where], ["Comments", v.lockComment]], note: "Aucun commit n'est nécessaire pour prendre ou retirer un verrou." },
        { title: "Travailler puis committer", path: ["Commit", "Commit to Panorama"], action: "Le commit de l'admin qui détient le verrou le libère automatiquement. Les autres admins peuvent committer leurs propres changements via « Commit Changes Made By » (si seul un Config lock est en place).", fields: [] },
        { title: "Retirer un verrou (si besoin)", path: ["Cadenas"], window: "Locks", action: "Sélectionner le verrou → Remove Lock → OK. Un superuser peut retirer le verrou d'un autre : préviens-le d'abord.", fields: [] },
      ];
      if (v.autoLock) steps.push({ title: "Prise automatique du Commit lock", path: ["Panorama", "Setup", "Management"], window: "General Settings",
        action: "Cadre General Settings → ⚙ → cocher Automatically Acquire Commit Lock → OK → Commit to Panorama.", fields: [["Automatically Acquire Commit Lock", true]] });
      const kind = v.lockType === "config" ? "config-lock" : "commit-lock";
      const cliRaw = [
        `# --- Mode opérationnel Panorama ---`,
        `show ${kind}s`,
        `request ${kind} add comment ${q(v.lockComment)}`,
        v.location !== "all" ? `# Verrou limité à ${where} : à prendre via la WebUI (Location), la CLI pose un verrou global` : null,
        "",
        "# --- Libérer son propre verrou (sans commit) ---",
        `request ${kind} remove`,
        "# Retirer le verrou d'un autre administrateur (superuser) : " + UNSURE.slice(2),
        `request ${kind} remove admin <nom-admin>`,
      ].filter(x => x !== null);
      if (v.autoLock) cliRaw.push("", "# --- Prise automatique du commit lock ---", "configure", UNSURE, "set deviceconfig setting management auto-acquire-commit-lock yes", "commit", "exit");
      const notes = [
        { type: "or", title: "Pourquoi un verrou ? (lab 7)", text: "Tous les admins éditent la MÊME configuration candidate ; sans verrou, le commit d'admin-2 peut embarquer ou écraser le travail d'admin-1." },
        { type: "warn", text: "Les verrous n'expirent pas : ils restent jusqu'au commit de leur propriétaire ou jusqu'à leur retrait manuel." },
        { type: "or", text: v.lockType === "commit" ? "Commit lock : les autres admins ne découvrent le verrou qu'au moment de committer." : "Config lock : les autres admins reçoivent « Operation Failed » dès qu'ils tentent une modification (ex. ajout d'un objet Address)." },
      ];
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P08 · Rapport personnalisé (Manage Custom Reports)
     ===================================================================== */
  const RCOLS = { "application": "app", "action": "action", "bytes": "bytes", "sessions": "sessions", "count": "count", "severity": "severity",
    "threat id/name": "threatid", "source zone": "from", "destination zone": "to", "source address": "src", "destination address": "dst",
    "source user": "srcuser", "rule": "rule", "category": "category", "url": "url", "url category list": "url_category_list",
    "device name": "device_name", "destination port": "dport" };
  const RNUM = ["bytes", "sessions", "count"];
  const RPERIODS = [["last-15-minutes", "Last 15 Minutes"], ["last-hour", "Last Hour"], ["last-6-hrs", "Last 6 Hrs"], ["last-12-hrs", "Last 12 Hrs"], ["last-24-hrs", "Last 24 Hrs"],
    ["last-calendar-day", "Last Calendar Day"], ["last-7-days", "Last 7 Days"], ["last-7-calendar-days", "Last 7 Calendar Days"], ["last-calendar-week", "Last Calendar Week"],
    ["last-30-days", "Last 30 Days"], ["last-calendar-month", "Last Calendar Month"]];
  const RDB = [["traffic", "Traffic"], ["threat", "Threat"], ["url", "URL"], ["wildfire", "WildFire Submissions"], ["data", "Data Filtering"], ["userid", "User-ID"]];
  const SUMDB = { traffic: "trsum", threat: "thsum", url: "urlsum" };
  const RPRESET = {
    threats24: { src: "remote", dbKind: "summary", db: "threat", period: "last-24-hrs", sortBy: "count", topN: "10", groupBy: "severity", topM: "10", cols: ["Threat ID/Name", "Action"], query: "" },
    apps7: { src: "panorama", dbKind: "summary", db: "traffic", period: "last-7-days", sortBy: "bytes", topN: "100", groupBy: "device_name", topM: "10", cols: ["Application", "Bytes", "Action"], query: "" },
    urls7: { src: "panorama", dbKind: "detailed", db: "url", period: "last-7-days", sortBy: "count", topN: "100", groupBy: "device_name", topM: "10", cols: ["Action", "URL Category List", "Category", "URL"], query: "( action eq block-url )" },
  };
  const GROUPBY = [["", "None"], ["severity", "Severity"], ["device_name", "Device Name"], ["app", "Application"], ["from", "Source Zone"], ["to", "Destination Zone"],
    ["srcuser", "Source User"], ["category", "Category"], ["rule", "Rule"], ["action", "Action"]];

  register({
    id: "p08-report",
    module: "P08",
    title: "Rapport personnalisé (Custom Report)",
    icon: "📊",
    desc: "Monitor > Manage Custom Reports sur Panorama : source (Panorama Data / Remote Device Data), base Summary ou Detailed, période, tri, regroupement, colonnes, filtre, Run Now et export PDF.",
    tags: "custom report rapport personnalisé manage custom reports summary database remote device data panorama data pdf query",
    fields: [
      { id: "preset", label: "Modèle", type: "select", default: "threats24", group: "Rapport",
        options: [["threats24", "Menaces des dernières 24 h (lab 8)"], ["apps7", "Applications des 7 derniers jours (lab 8)"], ["urls7", "URL bloquées sur 7 jours (lab 8)"], ["custom", "Personnalisé"]] },
      { id: "rptName", label: "Name", type: "text", required: true, validate: "name", default: "Threats Last 24 Hours" },
      { id: "rptDesc", label: "Description", type: "text", default: "Provides details about threats detected in 24 hours" },
      { id: "allDg", label: "Device Group : All (rapport global)", type: "checkbox", default: true },
      { id: "dg", label: "Device group du rapport", type: "text", required: true, validate: "name", default: "Corp-DG", show: v => !v.allDg },
      { id: "src", label: "Source des données", type: "select", default: "panorama", show: v => v.preset === "custom", group: "Base de données",
        options: [["panorama", "Panorama Data (logs collectés — recommandé, plus rapide)"], ["remote", "Remote Device Data (requête sur les pare-feux)"]] },
      { id: "dbKind", label: "Type de base", type: "select", default: "summary", show: v => v.preset === "custom",
        options: [["summary", "Summary Databases (rapide)"], ["detailed", "Detailed Logs (plus lent)"]] },
      { id: "db", label: "Database", type: "select", default: "traffic", options: RDB, show: v => v.preset === "custom",
        validate: (d, v) => v.dbKind === "summary" && !SUMDB[d] ? "Summary : Traffic, Threat ou URL uniquement" : null },
      { id: "period", label: "Time Frame", type: "select", default: "last-7-days", options: RPERIODS, show: v => v.preset === "custom" },
      { id: "sortBy", label: "Sort By", type: "select", default: "bytes", options: [["count", "Count"], ["bytes", "Bytes"], ["sessions", "Sessions"]], show: v => v.preset === "custom",
        validate: (s, v) => v.db !== "traffic" && s !== "count" ? "Threat/URL : trier par Count" : null },
      { id: "topN", label: "Top N", type: "select", default: "100", options: ["5", "10", "25", "50", "100", "250", "500", "1000"].map(x => [x, "Top " + x]), show: v => v.preset === "custom" },
      { id: "groupBy", label: "Group By", type: "select", default: "device_name", options: GROUPBY, show: v => v.preset === "custom" },
      { id: "topM", label: "Nombre de groupes", type: "select", default: "10", options: ["5", "10", "25", "50"].map(x => [x, x + " Groups"]), show: v => v.preset === "custom" && !!v.groupBy },
      { id: "cols", label: "Selected Columns (dans l'ordre)", type: "list", required: true, default: ["Application", "Bytes", "Action"], wide: true, show: v => v.preset === "custom",
        hint: "Parmi : " + Object.keys(RCOLS).map(k => k.replace(/\b\w/g, c => c.toUpperCase())).join(", "),
        validate: arr => { const bad = arr.find(c => !RCOLS[c.toLowerCase()]); return bad ? `« ${bad} » : colonne non reconnue` : null; } },
      { id: "query", label: "Query Builder (filtre, optionnel)", type: "text", default: "", placeholder: "( action eq block-url )", wide: true, show: v => v.preset === "custom",
        validate: x => /^\(.*\)$/.test(x) ? null : "Expression entre parenthèses, ex. ( action eq block-url )" },
      { id: "sched", label: "Scheduled (généré chaque nuit, requis pour l'envoi planifié)", type: "checkbox", default: false, group: "Planification" },
    ],
    build(v) {
      const p = v.preset === "custom" ? { src: v.src, dbKind: v.dbKind, db: v.db, period: v.period, sortBy: v.sortBy, topN: v.topN, groupBy: v.groupBy, topM: v.topM, cols: v.cols, query: v.query } : RPRESET[v.preset];
      const dbGui = `${lbl(RDB, p.db)} (${p.dbKind === "summary" ? "Summary Databases" : "Detailed Logs (Slower)"} › ${p.src === "panorama" ? "Panorama Data" : "Remote Device Data"})`;
      const fields = p.cols.map(c => RCOLS[c.toLowerCase()]);
      const agg = fields.filter(f => !RNUM.includes(f)), vals = fields.filter(f => RNUM.includes(f));
      const dbCli = (p.src === "panorama" ? "panorama-" : "") + (p.dbKind === "summary" ? SUMDB[p.db] : p.db);
      const steps = [
        { title: "Créer le rapport", path: ["Monitor", "Manage Custom Reports"], window: "Custom Report",
          action: `Sélectionner « ${v.allDg ? "All" : v.dg} » dans la liste Device Group (en haut), puis Add.`,
          fields: [["Name", v.rptName], ["Description", v.rptDesc], ["Database", dbGui], ["Scheduled", v.sched ? true : "☐ décoché"], ["Time Frame", lbl(RPERIODS, p.period)],
            ["Sort By", `${lbl([["count", "Count"], ["bytes", "Bytes"], ["sessions", "Sessions"]], p.sortBy)} — Top ${p.topN}`],
            ["Group By", p.groupBy ? `${lbl(GROUPBY, p.groupBy)} — ${p.topM} Groups` : "None"], ["Selected Columns", p.cols], ["Query Builder", p.query]],
          note: "Colonnes : sélectionner dans Available Columns puis bouton Add (flèche) ; l'ordre de la liste Selected Columns = ordre dans le rapport." },
        { title: "Tester et exporter", path: ["Monitor", "Manage Custom Reports"], window: "Custom Report",
          action: "Avant OK : Run Now → onglet du résultat → Export to PDF (autoriser les pop-ups du navigateur). Puis OK pour enregistrer.", fields: [] },
      ];
      const R = v.allDg ? `set shared reports ${q(v.rptName)}` : `set device-group ${q(v.dg)} reports ${q(v.rptName)}`;
      const cli = [
        UNSURE,
        v.rptDesc && `${R} description ${q(v.rptDesc)}`,
        `${R} type ${dbCli} aggregate-by ${members(agg.length ? agg : ["app"])}${vals.length ? " values " + members(vals) : ""} sortby ${p.sortBy}${p.groupBy ? " group-by " + p.groupBy : ""}`,
        `${R} period ${p.period} topn ${p.topN}${p.groupBy ? " topm " + p.topM : ""}`,
        p.query && `${R} query ${q(p.query)}`,
        v.sched && `${R} frequency daily`,
      ].filter(Boolean);
      const notes = [
        { type: "or", title: "Sources de données (MOD-08)", text: "Panorama Data = logs déjà reçus par Panorama / Log Collectors / Strata Logging Service (rapide). Remote Device Data = Panorama interroge les pare-feux (fonctionne même sans log forwarding, mais plus lent et pare-feux connectés requis)." },
        { type: "or", text: "Un rapport = une seule base. Pour croiser trafic et menaces, crée deux rapports et regroupe-les dans un Report Group (#p08-report-group)." },
      ];
      if (p.dbKind === "detailed") notes.push({ type: "warn", text: "Detailed Logs : génération plus lente ; les logs détaillés Panorama sont vides si les pare-feux ne transfèrent pas leurs logs (#p05-fwd)." });
      if (!v.sched) notes.push({ type: "or", text: "Non planifié : rapport à la demande (Run Now). Coche Scheduled pour qu'il soit généré chaque nuit et exploitable dans un envoi e-mail." });
      return { steps, cli, notes, verify: [] };
    },
  });

  /* =====================================================================
     P08 · Report Group + Email Profile + Email Scheduler
     ===================================================================== */
  const RECUR = [["daily", "Every Day"], ["weekly monday", "Every Monday"], ["weekly tuesday", "Every Tuesday"], ["weekly wednesday", "Every Wednesday"],
    ["weekly thursday", "Every Thursday"], ["weekly friday", "Every Friday"], ["weekly saturday", "Every Saturday"], ["weekly sunday", "Every Sunday"], ["disable", "Disable"]];
  register({
    id: "p08-report-group",
    module: "P08",
    title: "Report Group & envoi planifié par e-mail",
    icon: "📧",
    desc: "Regrouper rapports prédéfinis et personnalisés dans un PDF (Report Group), créer l'Email Server Profile de Panorama et planifier l'envoi (Email Scheduler).",
    tags: "report group email scheduler pdf email profile smtp envoi planifié hebdomadaire rapport",
    fields: [
      { id: "rgName", label: "Nom du Report Group", type: "text", required: true, validate: "name", default: "Weekly Reports", group: "Report Group" },
      { id: "titlePage", label: "Title Page", type: "checkbox", default: true },
      { id: "rgTitle", label: "Title", type: "text", default: "Rapport hebdomadaire securite", show: v => v.titlePage },
      { id: "predef", label: "Rapports prédéfinis", type: "list", default: ["Top applications", "Top blocked URL user behavior"], wide: true,
        hint: "Libellés de la colonne Predefined Report (ex. Top applications, Top threats, Top attackers, Top blocked URL categories)." },
      { id: "custom", label: "Rapports personnalisés", type: "list", validate: nameList, default: ["Apps Identified in Last 7 Days", "URLs Blocked in Last 7 Days"], wide: true,
        hint: "Créés avec #p08-report." },
      { id: "mkProfile", label: "Créer l'Email Server Profile", type: "checkbox", default: true, group: "Email Server Profile (Panorama)" },
      { id: "emailProfile", label: "Email Profile", type: "text", required: true, validate: "name", default: "Panorama-Email" },
      { id: "smtpName", label: "Nom du serveur", type: "text", required: true, validate: "name", default: "smtp-relay", show: v => v.mkProfile },
      { id: "smtpGw", label: "Email Gateway (IP/FQDN)", type: "text", required: true, validate: "host", default: "192.168.50.25", show: v => v.mkProfile },
      { id: "smtpProto", label: "Protocol", type: "select", default: "SMTP", show: v => v.mkProfile, options: [["SMTP", "SMTP (25)"], ["TLS", "TLS (587)"]] },
      { id: "fromAddr", label: "From", type: "text", required: true, validate: "email", default: "panorama@corp.local", show: v => v.mkProfile },
      { id: "toAddr", label: "To", type: "text", required: true, validate: "email", default: "secu-manager@corp.local", show: v => v.mkProfile },
      { id: "alsoTo", label: "Additional Recipient (optionnel)", type: "text", validate: "email", default: "", show: v => v.mkProfile },
      { id: "schedName", label: "Nom de la planification", type: "text", required: true, validate: "name", default: "Weekly Reports", group: "Email Scheduler" },
      { id: "recur", label: "Recurrence", type: "select", default: "weekly monday", options: RECUR },
      { id: "override", label: "Override Email Addresses (optionnel)", type: "list", validate: arr => { for (const a of arr) { const e = C.V.email(a); if (e) return `« ${a} » : ${e}`; } return null; }, default: [] },
    ],
    build(v) {
      const steps = [
        { title: "Créer le Report Group", path: ["Monitor", "PDF Reports", "Report Groups"], window: "Report Group",
          action: "Cliquer sur Add. Dans la colonne de gauche, sélectionner chaque rapport (Predefined Report, puis Custom Reports plus bas) → Add.",
          fields: [["Name", v.rgName], ["Title Page", v.titlePage], ["Title", v.titlePage && v.rgTitle], ["Predefined Report", v.predef], ["Custom Report", v.custom]] },
      ];
      if (v.mkProfile) steps.push({ title: "Créer l'Email Server Profile", path: ["Panorama", "Server Profiles", "Email"], window: "Email Server Profile",
        action: "Cliquer sur Add, puis Add dans la liste des serveurs.",
        fields: [["Name", v.emailProfile], ["Name (serveur)", v.smtpName], ["Email Display Name", "Panorama"], ["From", v.fromAddr], ["To", v.toAddr], ["Additional Recipient", v.alsoTo],
          ["Email Gateway", v.smtpGw], ["Protocol", v.smtpProto], ["Port", v.smtpProto === "TLS" ? "587" : "25"]],
        note: v.smtpProto === "TLS" ? "TLS : renseigner aussi l'authentification (Username/Password) et le profil de certificat si le relais l'exige." : null });
      steps.push({ title: "Planifier l'envoi", path: ["Monitor", "PDF Reports", "Email Scheduler"], window: "Email Scheduler", action: "Cliquer sur Add.",
        fields: [["Name", v.schedName], ["PDF Report / Report Group", v.rgName], ["Email Profile", v.emailProfile], ["Recurrence", lbl(RECUR, v.recur)], ["Override Email Addresses", v.override]] });
      steps.push({ title: "Tester l'envoi", path: ["Monitor", "PDF Reports", "Email Scheduler"], action: "Rouvrir la planification → Send test email pour valider le relais SMTP.", fields: [] });

      const cli = [UNSURE];
      if (v.mkProfile) cli.push(`set panorama server-profile email ${q(v.emailProfile)} server ${q(v.smtpName)} display-name Panorama from ${v.fromAddr} to ${v.toAddr}${v.alsoTo ? " and-also-to " + v.alsoTo : ""} gateway ${v.smtpGw} protocol ${v.smtpProto} port ${v.smtpProto === "TLS" ? 587 : 25}`);
      cli.push(`set shared report-group ${q(v.rgName)} title-page ${yn(v.titlePage)}`);
      cli.push(`# Contenu du Report Group (${[...v.predef, ...v.custom].length} rapports) : à composer dans la WebUI (Monitor > PDF Reports > Report Groups)`);
      cli.push(`set shared email-scheduler ${q(v.schedName)} report-group ${q(v.rgName)} email-profile ${q(v.emailProfile)} recurrence ${v.recur}`);
      if (v.override.length) cli.push(`set shared email-scheduler ${q(v.schedName)} recipient-emails ${q(v.override.join(","))}`);
      const notes = [
        { type: "or", title: "Pourquoi (MOD-08)", text: "Tout le monde n'a pas (et ne doit pas avoir) accès à la WebUI Panorama : les Report Groups envoyés par e-mail diffusent le bon jeu de rapports aux bons destinataires." },
        { type: "or", text: "Le PDF est construit à partir des données de la nuit (rapports prédéfinis générés quotidiennement, rapports personnalisés « Scheduled »)." },
        { type: "or", text: "Modification locale à Panorama : Commit to Panorama suffit, pas de push vers les pare-feux." },
      ];
      if (!v.predef.length && !v.custom.length) notes.push({ type: "warn", text: "Report Group vide : ajoute au moins un rapport." });
      if (v.smtpProto === "SMTP") notes.push({ type: "warn", text: "SMTP en clair sur le port 25 : les rapports (IP, utilisateurs, menaces) transitent non chiffrés. Préfère TLS si le relais le permet." });
      return { steps, cli, notes, verify: [] };
    },
  });

  /* =====================================================================
     P08 · Rapports prédéfinis : désactiver les inutiles (soulager Panorama)
     ===================================================================== */
  const PREDEF = [["top-application-categories", "Application Categories"], ["top-technology-categories", "Technology Categories"], ["top-hr-applications", "HTTP Applications"],
    ["top-attacker-sources", "Attacker Sources"], ["top-attacker-destinations", "Attacker Destinations"], ["top-attackers-by-source-countries", "Attackers by Source Countries"],
    ["top-victims-by-destination-countries", "Victims by Destination Countries"], ["top-egress-interfaces", "Egress Interfaces"], ["top-ingress-interfaces", "Ingress Interfaces"],
    ["top-egress-zones", "Destination Zones"], ["top-ingress-zones", "Source Zones"], ["unknown-tcp-connections", "Unknown TCP Sessions"], ["unknown-udp-connections", "Unknown UDP Sessions"],
    ["wildfire-file-digests", "WildFire File Digest"]];
  register({
    id: "p08-predefined",
    module: "P08",
    title: "Rapports prédéfinis : désactiver les inutiles",
    icon: "🧹",
    desc: "Panorama génère chaque nuit plus de 40 rapports prédéfinis ; désactiver ceux qui ne servent pas réduit la charge (piste du MOD-09 « Panorama surchargé »).",
    tags: "predefined reports rapports prédéfinis logging and reporting settings performance cpu charge",
    fields: PREDEF.map(([k, l], i) => ({ id: "pd_" + k.replace(/-/g, "_"), label: l, type: "checkbox", default: ["top-hr-applications", "top-egress-interfaces", "top-ingress-interfaces", "unknown-udp-connections"].includes(k),
      group: i === 0 ? "Rapports à DÉSACTIVER" : undefined })),
    build(v) {
      const off = PREDEF.filter(([k]) => v["pd_" + k.replace(/-/g, "_")]);
      const steps = [{ title: "Désactiver les rapports", path: ["Panorama", "Setup", "Management"], window: "Logging and Reporting Settings",
        action: "Cadre Logging and Reporting Settings → ⚙ → onglet Pre-Defined Reports : décocher les rapports suivants → OK.",
        fields: [["Rapports décochés", off.map(o => o[1])]], note: "Même onglet de la fenêtre : Report Runtime (heure de génération nocturne, par défaut 02:00)." }];
      const cli = off.length ? [UNSURE, `set deviceconfig setting management disable-predefined-reports ${members(off.map(o => o[0]))}`] : ["# Aucun rapport sélectionné"];
      const notes = [
        { type: "or", title: "Autres leviers si Panorama sature (MOD-09)", text: "Matériel/VM plus puissant, moins de types de logs envoyés (ou filtres de sévérité), Strata Logging Service, Log Collectors dédiés (mode Management Only), requêtes de logs limitées en heures ouvrées." },
      ];
      if (!off.length) notes.push({ type: "warn", text: "Aucun rapport coché : rien ne sera désactivé." });
      return { steps, cli, notes, verify: [] };
    },
  });

  /* =====================================================================
     P09 · Assistant de dépannage par symptôme (noCommit)
     ===================================================================== */
  const SYMPT = [
    ["disconnected", "Pare-feu « Disconnected » dans Managed Devices"],
    ["register", "Nouveau pare-feu qui n'apparaît pas / enregistrement refusé"],
    ["push", "Commit to Panorama ou Push to Devices en échec"],
    ["oos", "Template ou Device Group « Out of Sync »"],
    ["logs", "Logs des pare-feux non reçus sur Panorama"],
    ["deploy", "Déploiement logiciel / contenu / licence en échec"],
    ["slow", "Panorama lent / surchargé (push > 30 min, CPU > 85 %)"],
    ["ha", "Panorama HA : pairs désynchronisés ou bascule inattendue"],
    ["adminauth", "Connexion administrateur refusée (RADIUS/LDAP)"],
  ];
  register({
    id: "p09-troubleshoot",
    module: "P09",
    title: "Assistant de dépannage par symptôme",
    icon: "🩺",
    desc: "Choisis le symptôme : causes probables, vérifications WebUI et commandes show / test / debug adaptées côté Panorama et côté pare-feu (d'après MOD-09 et le lab 9).",
    tags: "troubleshooting dépannage disconnected out of sync commit failed push logs not received show devices panorama-status tcpdump jobs",
    noCommit: true,
    fields: [
      { id: "symptom", label: "Symptôme", type: "select", default: "disconnected", options: SYMPT, wide: true, group: "Symptôme" },
      { id: "panoIp", label: "IP de management de Panorama", type: "text", required: true, validate: vIpOrCidr, default: "192.168.1.252/24", group: "Contexte" },
      { id: "fwName", label: "Nom du pare-feu", type: "text", validate: "hostname", default: "berlin-fw", show: v => !["slow", "ha", "adminauth"].includes(v.symptom) },
      { id: "fwSerial", label: "Série du pare-feu", type: "text", required: true, validate: serial, default: "007051000123456", show: v => !["slow", "ha", "adminauth"].includes(v.symptom) },
      { id: "fwMgmtIp", label: "IP de management du pare-feu", type: "ip", required: true, default: "192.168.1.253", show: v => ["disconnected", "register", "logs", "deploy"].includes(v.symptom) },
      { id: "viaData", label: "Le pare-feu joint Panorama via une interface data (service route)", type: "checkbox", default: false, show: v => ["disconnected", "register", "logs"].includes(v.symptom) },
      { id: "dg", label: "Device group", type: "text", validate: "name", default: "Corp-DG", show: v => ["push", "oos"].includes(v.symptom) },
      { id: "stack", label: "Template stack", type: "text", validate: "name", default: "Germany-Stack", show: v => ["push", "oos"].includes(v.symptom) },
      { id: "jobId", label: "Job ID en échec (Tasks / System log, optionnel)", type: "number", min: 1, default: "", show: v => ["push", "deploy"].includes(v.symptom) },
      { id: "collector", label: "Série du Log Collector (vide = Panorama local)", type: "text", validate: serial, default: "", show: v => v.symptom === "logs" },
      { id: "cg", label: "Collector group", type: "text", validate: "name", default: "default", show: v => v.symptom === "logs" },
      { id: "panoIp2", label: "IP du pair HA", type: "text", validate: vIpOrCidr, default: "192.168.1.151", show: v => v.symptom === "ha" },
      { id: "ap", label: "Authentication Profile", type: "text", validate: "name", default: "RADIUS_Auth_Profile", show: v => v.symptom === "adminauth" },
      { id: "adminUser", label: "Compte administrateur", type: "text", validate: "name", default: "internBob", show: v => v.symptom === "adminauth" },
    ],
    build(v) {
      const P = ipOf(v.panoIp), F = v.fwMgmtIp, S = v.fwSerial, s = v.symptom;
      const steps = [], pano = [], fw = [], fix = [], notes = [];
      const causes = (...c) => notes.push({ type: "warn", title: "Causes probables", text: c.map((x, i) => `${i + 1}) ${x}`).join("  ") });
      const portsNote = () => notes.push({ type: "or", title: "Ports de management (MOD-09)", text: "TCP 3978 : pare-feux et Log Collectors ↔ Panorama · TCP 28443 : mises à jour logicielles poussées par Panorama · HA Panorama : TCP 28 (chiffré) ou 28260/28769 (non chiffré)." });

      if (s === "disconnected" || s === "register") {
        steps.push({ title: "État dans Panorama", path: ["Panorama", "Managed Devices", "Summary"], action: `Repérer ${v.fwName || S} : Device State, IP, Shared Policy / Template, Last Commit State. Cliquer sur les liens pour le détail.`, fields: [] });
        steps.push({ title: "Logs système des deux côtés", path: ["Monitor", "Logs", "System"], action: "Sur Panorama ET sur le pare-feu : filtrer ( eventid contains panorama ) ou ( description contains Panorama ) pour les pertes de connexion et erreurs de certificat.", fields: [] });
        pano.push(`show devices all`, `# → colonne « Connected » = yes/no pour ${S}`,
          `ping count 5 source ${P} host ${F}`,
          `show netstat numeric-ports yes | match 3978`,
          `tcpdump filter "host ${F} and port 3978"`, "# Ctrl+C après quelques secondes, puis :", `view-pcap mgmt-pcap mgmt.pcap`);
        fw.push(`show panorama-status`, `# → « Connected : yes », IP Panorama correcte`,
          `show system info | match "serial|ip-address|sw-version"`,
          `ping count 5 host ${P}`,
          `show config running | match panorama-server`,
          `show clock`, `# → écart d'heure important = échec TLS (configurer NTP)`);
        if (s === "register") {
          steps.push({ title: "Clé d'enregistrement", path: ["Panorama", "Device Registration Auth Key"], action: "Vérifier que la clé n'a pas expiré (Lifetime) et qu'il reste des utilisations (Count), et que le numéro de série du pare-feu est bien saisi dans Managed Devices.", fields: [] });
          fix.push("# Sur Panorama : nouvelle clé (60 min, 1 pare-feu)", `request authkey add name fw-onboarding lifetime 60 count 1`, `request authkey list`,
            "# Sur le pare-feu : appliquer la clé puis valider la config Panorama", `request authkey set <clé-affichée>`);
          causes("Numéro de série absent ou mal saisi dans Panorama > Managed Devices", "Device Registration Auth Key expirée ou épuisée", "IP Panorama erronée côté pare-feu (Device > Setup > Management > Panorama Settings)", "Port TCP 3978 filtré entre MGT pare-feu et MGT Panorama", "Version PAN-OS du pare-feu supérieure à celle de Panorama");
        } else {
          causes("Coupure réseau / ACL ou pare-feu intermédiaire bloquant TCP 3978", "IP Panorama modifiée ou mauvaise IP configurée sur le pare-feu", "Gestion via interface data sans règle autorisant l'application « panorama »", "Écart d'horloge (NTP) ou certificat de communication expiré", "Processus de management du pare-feu bloqué");
          fix.push("# Dernier recours, sur le pare-feu (impact WebUI/CLI quelques minutes) :", `debug software restart process management-server`);
        }
        if (v.viaData) {
          steps.push({ title: "Service route et règle de sécurité", path: ["Device", "Setup", "Services", "Service Route Configuration"], action: "Côté pare-feu : vérifier la service route « Panorama » et qu'une règle de sécurité autorise l'application panorama (les flux depuis une interface data passent par la politique de sécurité).", fields: [] });
          fw.push(`test security-policy-match from <zone-src> to <zone-dst> source <ip-interface-service-route> destination ${P} protocol 6 destination-port 3978 application panorama`);
        }
        portsNote();
      }

      if (s === "push") {
        steps.push({ title: "Identifier le job en échec", path: ["Tasks (en bas à droite)"], action: "Repérer les commits « Failed » → cliquer sur le lien Commit All → Job Status → lien « commit failed » → Last Push State Details : le message donne la cause (objet, interface, routeur…).", fields: [] });
        steps.push({ title: "Localiser l'élément fautif", path: ["Global Find (loupe en haut à droite)"], action: "Rechercher le nom cité dans l'erreur (ex. LR-1) : Global Find indique le template/stack ou DG qui le contient. Corriger, Commit to Panorama, puis Push.", fields: [] });
        steps.push({ title: "Prévisualiser avant de repousser", path: ["Commit", "Push to Devices", "Edit Selections"], action: "Preview Changes / Validate pour voir le diff par pare-feu. Options utiles : Merge with Device Candidate Config, Include Device and Network Templates, Force Template Values (écrase les overrides locaux).", fields: [] });
        pano.push(`show jobs all`, v.jobId ? `show jobs id ${v.jobId}` : `show jobs id <job-id>`, `show devicegroups name ${q(v.dg || "<dg>")}`, `show templates name ${q(v.stack || "<stack>")}`,
          `show log system direction equal backward subtype equal general`);
        fw.push(`show jobs all`, `show system info | match "sw-version|app-version|serial"`, `show config pushed-template`, `show config pushed-shared-policy`);
        fix.push("# Repousser une fois la cause corrigée (après Commit to Panorama)", UNSURE,
          `commit-all template-stack name ${q(v.stack || "<stack>")}`, `commit-all shared-policy device-group ${q(v.dg || "<dg>")} include-template yes`);
        causes("Objet déjà défini localement sur le pare-feu (doublon, ex. tag ou adresse « DNS »)", "Interface inexistante sur le modèle cible (ex. ethernet1/19)", "Référence incomplète dans le template (route statique sans interface, zone sans interface…)", "Contenu App-ID/Threat du pare-feu plus ancien que celui de Panorama (application inconnue)", "Commit lock d'un autre administrateur");
      }

      if (s === "oos") {
        steps.push({ title: "Voir ce qui diffère", path: ["Panorama", "Managed Devices", "Summary"], action: "Colonnes Shared Policy et Template : « Out of Sync ». Cliquer dessus, puis Commit → Push to Devices → Edit Selections → Preview Changes pour le diff.", fields: [] });
        steps.push({ title: "Repérer les overrides locaux", path: ["Device / Network (WebUI du pare-feu ou Context switch)"], action: "Les valeurs modifiées localement sur un réglage poussé par template portent l'icône d'override : les supprimer (Revert) ou pousser avec Force Template Values.", fields: [] });
        pano.push(`show devicegroups name ${q(v.dg)}`, `show templates name ${q(v.stack)}`, `show devices all`);
        fw.push(`show config pushed-template`, `show config pushed-shared-policy`, "# Comparer running vs candidate locale :", `show config diff`);
        fix.push(UNSURE, `commit-all template-stack name ${q(v.stack)} force-template-values yes`, `commit-all shared-policy device-group ${q(v.dg)}`);
        causes("Modifications Panorama committées mais jamais poussées", "Push précédent en échec (voir Tasks)", "Override local sur le pare-feu (valeur de template modifiée localement)", "Pare-feu déplacé de DG ou de template stack sans push");
        notes.push({ type: "warn", text: "Force Template Values écrase toutes les valeurs locales des réglages gérés par le template : prévenir l'équipe locale avant." });
      }

      if (s === "logs") {
        steps.push({ title: "Statut de collecte", path: ["Panorama", "Managed Collectors"], action: "Vérifier Connected, Configuration Status In Sync et le détail Statistics/Health du collecteur. Puis Panorama > Managed Devices > Summary : colonne Logging.", fields: [] });
        steps.push({ title: "Côté pare-feu : profils de transfert", path: ["Objects", "Log Forwarding"], action: "Vérifier que les règles de sécurité ont un Log Forwarding Profile avec « Panorama » coché et que Device > Log Settings (System/Config/User-ID…) envoie aussi vers Panorama. Le pare-feu doit être dans un Collector Group (Device Log Forwarding).", fields: [] });
        pano.push(`show logging-status device ${S}`, v.collector ? `show log-collector serial-number ${v.collector}` : `show log-collector detail`, `show log-collector-group name ${q(v.cg || "default")}`,
          `debug log-collector log-collection-stats show incoming-logs`, `show system logdb-quota`, `show system disk-space`);
        fw.push(`show logging-status`, `show log-collector preference-list`, `debug log-receiver statistics`, `show panorama-status`);
        causes("Règles sans Log Forwarding Profile (ou profil sans Panorama coché)", "Pare-feu non rattaché à un Collector Group (Device Log Forwarding) ou CG non poussé", "Collecteur déconnecté, disques pleins / quotas", "Panorama en mode Management Only sans Log Collector", "Pare-feu déconnecté : les logs sont mis en tampon puis peuvent être perdus");
        notes.push({ type: "or", text: "Les logs détaillés de Panorama (Monitor > Logs) sont vides tant que le log forwarding n'est pas actif ; les rapports « Remote Device Data » fonctionnent malgré tout." });
        portsNote();
      }

      if (s === "deploy") {
        steps.push({ title: "Prérequis du déploiement", path: ["Panorama", "Device Deployment", "Software"], action: "Le fichier doit d'abord être téléchargé SUR Panorama (Check Now → Download), puis Install → sélection des pare-feux. Idem Dynamic Updates et Licenses (Refresh).", fields: [] });
        steps.push({ title: "Détail de l'échec", path: ["Tasks (en bas à droite)"], action: "Ouvrir la tâche en échec → détail par pare-feu.", fields: [] });
        pano.push(`show jobs all`, v.jobId ? `show jobs id ${v.jobId}` : `show jobs id <job-id>`, `show system disk-space`, `ping count 5 source ${P} host ${F}`);
        fw.push(`show system info | match "sw-version|app-version|av-version"`, `request license info`, `show system disk-space`, `request content upgrade check`);
        causes("TCP 28443 bloqué entre Panorama et le pare-feu (mises à jour logicielles)", "Chemin de mise à niveau non respecté (version de base requise non installée)", "Panorama en version inférieure au PAN-OS visé", "Espace disque insuffisant (pare-feu ou Panorama)", "Licence/abonnement absent pour le contenu (Threat, WildFire…)");
        portsNote();
      }

      if (s === "slow") {
        steps.push({ title: "Ressources", path: ["Dashboard", "System Resources"], action: "CPU, mémoire, logging rate. Une seule lecture ne suffit pas : superviser en SNMP sur la durée (#p09-snmp).", fields: [] });
        pano.push(`show system resources`, `show system disk-space`, `show jobs processed`, `debug log-collector log-collection-stats show incoming-logs`);
        fix.push("# Libérer de l'espace (voir #p09-cleanup)", `delete software version <ancienne-version>`);
        causes("Croissance du parc (plus de configs à pousser, plus de logs à ingérer)", "Tous les types de logs envoyés à Panorama", "Rapports prédéfinis inutiles générés chaque nuit (#p08-predefined)", "Requêtes de logs lourdes en heures ouvrées");
        notes.push({ type: "or", title: "Solutions (MOD-09)", text: "Upgrade matériel / ressources VM · filtrer les logs envoyés · Strata Logging Service · Log Collectors dédiés (mode Management Only) · désactiver les rapports inutiles." });
      }

      if (s === "ha") {
        steps.push({ title: "Widget High Availability", path: ["Dashboard", "High Availability"], action: "État local/pair (Active/Passive, Primary/Secondary), Running Config synchronized. Les changements d'état sont aussi dans Monitor > Logs > System.", fields: [] });
        pano.push(`show high-availability state`, `show high-availability all`, `ping count 5 source ${P} host ${ipOf(v.panoIp2)}`, `show system info | match "sw-version|model|system-mode"`);
        fix.push("# Resynchroniser depuis le pair actif :", `request high-availability sync-to-remote running-config`,
          "# Test / retour à la normale :", `request high-availability state suspend`, `request high-availability state functional`);
        causes("Modèle, version PAN-OS, mode ou licences différents entre pairs", "Contenus dynamiques / base URL différents", "Ports HA bloqués (TCP 28 chiffré, 28260/28769 non chiffré)", "Path monitoring trop sensible (bascule sur perte d'un serveur surveillé)", "Clés de chiffrement HA non échangées");
        portsNote();
      }

      if (s === "adminauth") {
        steps.push({ title: "Log d'authentification", path: ["Monitor", "Logs", "System"], action: "Device Group = All, filtre ( subtype eq auth ) : auth-fail avec la raison (serveur injoignable, compte non autorisé par l'Allow List, verrouillage…).", fields: [] });
        pano.push(`test authentication authentication-profile ${q(v.ap)} username ${q(v.adminUser)} password`, `show admins all`, `less mp-log authd.log`, `show clock`);
        causes("Compte absent de l'Allow List du profil", "Secret RADIUS ou Bind DN erroné, serveur injoignable depuis le MGT", "Nom du compte Panorama différent du login serveur (casse, domaine)", "Compte verrouillé (Failed Attempts)", "Rôle/VSA non renvoyé pour un admin non déclaré localement");
        notes.push({ type: "or", text: "Débloquer un compte verrouillé : Panorama > Administrators (colonne Locked User) ou « request authentication unlock-admin user <nom> »." });
      }

      const cliRaw = ["# ===== Sur Panorama (mode opérationnel) ====="];
      pano.forEach(l => cliRaw.push(l));
      if (fw.length) { cliRaw.push("", `# ===== Sur le pare-feu ${v.fwName || ""} (mode opérationnel) =====`); fw.forEach(l => cliRaw.push(l)); }
      if (fix.length) { cliRaw.push("", "# ===== Remédiation ====="); fix.forEach(l => cliRaw.push(l)); }
      notes.push({ type: "or", text: "Méthode : 1) l'appareil est-il connecté ? 2) quel job a échoué et pourquoi (Tasks, System log des deux côtés) ? 3) corriger dans Panorama, Commit to Panorama, puis Push." });
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P09 · Tests de politique et de connectivité (Managed Devices > Troubleshooting)
     ===================================================================== */
  const PTEST = [["security", "Security Policy Match"], ["nat", "NAT Policy Match"], ["pbf", "Policy Based Forwarding Policy Match"], ["ping", "Ping"], ["traceroute", "Trace Route"]];
  const PROTO = [["6", "TCP (6)"], ["17", "UDP (17)"], ["1", "ICMP (1)"]];
  register({
    id: "p09-policy-test",
    module: "P09",
    title: "Tester une politique depuis Panorama",
    icon: "🧪",
    desc: "Panorama > Managed Devices > Troubleshooting : Security/NAT/PBF Policy Match, Ping, Trace Route sur un pare-feu géré, et la commande test équivalente sur le pare-feu.",
    tags: "test security-policy-match nat-policy-match troubleshooting managed devices policy match ping traceroute",
    noCommit: true,
    fields: [
      { id: "test", label: "Select Test", type: "select", default: "security", options: PTEST, group: "Test" },
      { id: "fwSerial", label: "Pare-feu (série)", type: "text", required: true, validate: serial, default: "007051000123456" },
      { id: "fromZone", label: "From (zone source)", type: "text", validate: "name", default: "Users", show: v => ["security", "nat", "pbf"].includes(v.test), group: "Flux" },
      { id: "toZone", label: "To (zone destination)", type: "text", validate: "name", default: "Internet", show: v => ["security", "nat"].includes(v.test) },
      { id: "srcIp", label: "Source", type: "ip", required: true, default: "192.168.1.20", show: v => ["security", "nat", "pbf"].includes(v.test) },
      { id: "dstIp", label: "Destination", type: "ip", required: true, default: "8.8.8.8" },
      { id: "proto", label: "Protocol", type: "select", default: "6", options: PROTO, show: v => ["security", "nat", "pbf"].includes(v.test) },
      { id: "dport", label: "Destination Port", type: "port", required: true, default: "443", show: v => ["security", "nat", "pbf"].includes(v.test) && v.proto !== "1" },
      { id: "app", label: "Application (optionnel)", type: "text", default: "ssl", show: v => v.test === "security",
        validate: x => /^[a-z0-9][a-z0-9._-]*$/.test(x) ? null : "Nom App-ID en minuscules (ex. ssl, web-browsing)" },
      { id: "srcUser", label: "Source User (optionnel)", type: "text", default: "", placeholder: "panw\\bob", show: v => v.test === "security" },
    ],
    build(v) {
      const L = lbl(PTEST, v.test);
      const steps = [{ title: "Lancer le test depuis Panorama", path: ["Panorama", "Managed Devices", "Troubleshooting"], action: "Choisir le test, le pare-feu, renseigner les critères puis Execute. Le résultat indique la règle qui correspond.",
        fields: [["Select Test", L], ["Select Device", v.fwSerial], ["From", ["security", "nat", "pbf"].includes(v.test) && v.fromZone], ["To", ["security", "nat"].includes(v.test) && v.toZone],
          ["Source", ["security", "nat", "pbf"].includes(v.test) && v.srcIp], ["Destination", v.dstIp], ["Protocol", ["security", "nat", "pbf"].includes(v.test) && lbl(PROTO, v.proto)],
          ["Destination Port", ["security", "nat", "pbf"].includes(v.test) && v.proto !== "1" && v.dport], ["Application", v.test === "security" && v.app], ["Source User", v.test === "security" && v.srcUser]] }];
      const base = [v.fromZone && `from ${q(v.fromZone)}`, v.toZone && v.test !== "pbf" && `to ${q(v.toZone)}`, `source ${v.srcIp}`, `destination ${v.dstIp}`, `protocol ${v.proto}`, v.proto !== "1" && `destination-port ${v.dport}`].filter(Boolean).join(" ");
      const cliRaw = [`# ===== Sur le pare-feu ${v.fwSerial} (mode opérationnel) =====`];
      if (v.test === "security") cliRaw.push(`test security-policy-match ${base}${v.app ? " application " + v.app : ""}${v.srcUser ? " source-user " + q(v.srcUser) : ""}`);
      if (v.test === "nat") cliRaw.push(`test nat-policy-match ${base}`);
      if (v.test === "pbf") cliRaw.push(`test pbf-policy-match ${base.replace(/ ?to \S+/, "")}`);
      if (v.test === "ping") cliRaw.push(`ping count 5 host ${v.dstIp}`, "# depuis une interface data :", `ping source <ip-interface> count 5 host ${v.dstIp}`);
      if (v.test === "traceroute") cliRaw.push(`traceroute host ${v.dstIp}`);
      const notes = [
        { type: "or", text: "Le test s'exécute sur la configuration du pare-feu sélectionné : une règle créée dans Panorama mais pas encore poussée n'apparaît pas dans le résultat." },
        { type: "or", text: "Les règles pre-rulebase (Panorama) sont évaluées avant les règles locales, puis les post-rulebase : le résultat montre la première règle correspondante, quelle que soit sa provenance." },
      ];
      if (v.test === "security" && !v.app) notes.push({ type: "warn", text: "Sans application, la correspondance se fait sur any/application-default : précise l'App-ID pour tester une règle applicative." });
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P09 · Supervision SNMP de Panorama (lab 9)
     ===================================================================== */
  register({
    id: "p09-snmp",
    module: "P09",
    title: "Supervision SNMP de Panorama",
    icon: "📈",
    desc: "SNMP Setup de Panorama (v2c ou v3), activation sur l'interface MGT et OID à surveiller (CPU, taux d'ingestion de logs) pour détecter un Panorama sous-dimensionné.",
    tags: "snmp panorama monitoring supervision cpu oid mib v2c v3 community",
    fields: [
      { id: "location", label: "Physical Location", type: "text", default: "Chicago, IL, USA", group: "SNMP Setup" },
      { id: "contact", label: "Contact", type: "text", default: "John Doe" },
      { id: "eventTraps", label: "Use Event-specific Trap Definitions", type: "checkbox", default: true },
      { id: "version", label: "Version", type: "select", default: "v2c", options: [["v2c", "V2c"], ["v3", "V3 (chiffré, recommandé)"]] },
      { id: "community", label: "SNMP Community String", type: "password", required: true, default: "notpublic", show: v => v.version === "v2c",
        validate: x => /^(public|private)$/i.test(x) ? "Ne jamais laisser public/private" : null },
      { id: "view", label: "Nom de la vue", type: "text", required: true, validate: "name", default: "View-All", show: v => v.version === "v3", group: "SNMPv3" },
      { id: "snmpUser", label: "Utilisateur v3", type: "text", required: true, validate: "name", default: "snmp-nms", show: v => v.version === "v3" },
      { id: "authpwd", label: "Auth Password (8 car. min)", type: "password", required: true, default: "Snmp-Auth-2026!", show: v => v.version === "v3", validate: x => x.length < 8 ? "8 caractères minimum" : null },
      { id: "privpwd", label: "Priv Password (8 car. min)", type: "password", required: true, default: "Snmp-Priv-2026!", show: v => v.version === "v3", validate: x => x.length < 8 ? "8 caractères minimum" : null },
      { id: "authproto", label: "Authentication Protocol", type: "select", default: "SHA-256", show: v => v.version === "v3", options: [["SHA", "SHA"], ["SHA-256", "SHA-256"], ["SHA-512", "SHA-512"]] },
      { id: "privproto", label: "Privacy Protocol", type: "select", default: "AES-256", show: v => v.version === "v3", options: [["AES", "AES"], ["AES-256", "AES-256"]] },
      { id: "panoIp", label: "IP de management de Panorama", type: "text", required: true, validate: vIpOrCidr, default: "192.168.1.252/24", group: "Test depuis le NMS" },
    ],
    build(v) {
      const v3 = v.version === "v3", P = ipOf(v.panoIp);
      const steps = [
        { title: "SNMP Setup", path: ["Panorama", "Setup", "Operations"], window: "SNMP Setup", action: "Section Miscellaneous → SNMP Setup.",
          fields: [["Physical Location", v.location], ["Contact", v.contact], ["Use Event-specific Trap Definitions", v.eventTraps], ["Version", v3 ? "V3" : "V2c"],
            ...(v3 ? [["Views › Name", v.view], ["OID", "1.3.6.1"], ["Option", "include"], ["Mask", "0xf0"], ["Users", v.snmpUser], ["View", v.view],
              ["Auth Password / Priv Password", MASKED], ["Authentication Protocol", v.authproto], ["Privacy Protocol", v.privproto]] : [["SNMP Community String", MASKED]])] },
        { title: "Autoriser SNMP sur le MGT", path: ["Panorama", "Setup", "Interfaces"], window: "Management Interface Settings",
          action: "Cliquer sur Management → Network Services : cocher SNMP. Restreindre Permitted IP Addresses au NMS et aux postes d'admin.", fields: [["SNMP", true]] },
      ];
      const S = "set deviceconfig system snmp-setting";
      const cli = [
        "set deviceconfig system service disable-snmp no",
        `${S} snmp-system location ${q(v.location)} contact ${q(v.contact)} send-event-specific-traps ${yn(v.eventTraps)}`,
        ...(v3 ? [`${S} access-setting version v3 views ${q(v.view)} view ${q(v.view)} oid 1.3.6.1 option include mask 0xf0`,
          `${S} access-setting version v3 users ${q(v.snmpUser)} view ${q(v.view)} authpwd ${q(v.authpwd)} privpwd ${q(v.privpwd)} authproto ${v.authproto} privproto ${v.privproto}`]
          : [`${S} access-setting version v2c snmp-community-string ${q(v.community)}`]),
      ];
      const nms = v3 ? `snmpget -v3 -l authPriv -u ${v.snmpUser} -a ${v.authproto.replace("-", "")} -A '<auth>' -x ${v.privproto.replace("-", "")} -X '<priv>' ${P} .1.3.6.1.2.1.25.3.3.1.2.1`
        : `snmpget -v2c -c '<communauté>' ${P} .1.3.6.1.2.1.25.3.3.1.2.1`;
      const notes = [
        { type: "or", title: "À surveiller (MOD-09)", text: "CPU (HOST-RESOURCES-MIB hrProcessorLoad, ex. .1.3.6.1.2.1.25.3.3.1.2.1 — lab 9), taux d'ingestion de logs, erreurs d'interface. Alerte si CPU > 85 % de façon soutenue ou push > 30 min." },
        { type: "or", text: "MIB entreprise Palo Alto : rechercher « enterprise SNMP MIB files » sur paloaltonetworks.com et choisir la version de PAN-OS (fichiers .my à charger dans le NMS)." },
        { type: "or", text: `Test depuis le NMS : ${nms}` },
      ];
      if (!v3) notes.push({ type: "warn", text: "SNMPv2c : communauté et données en clair. V3 est chiffré mais demande plus de configuration côté NMS." });
      return { steps, cli, notes, verify: ["show system state | match snmp", "show interface management"] };
    },
  });

  /* =====================================================================
     P09 · Libérer de l'espace (logiciels et contenus inutilisés)
     ===================================================================== */
  const ver = x => /^\d+\.\d+\.\d+(-h\d+)?$/.test(x) ? null : "Version au format 10.2.4 ou 10.2.4-h2";
  register({
    id: "p09-cleanup",
    module: "P09",
    title: "Supprimer logiciels et contenus inutilisés",
    icon: "🗑️",
    desc: "Libérer le disque de Panorama : anciennes versions de PAN-OS Panorama, images et contenus stockés pour le déploiement vers les pare-feux (lab 9).",
    tags: "delete software version content update disk space espace disque nettoyage cleanup",
    noCommit: true,
    fields: [
      { id: "curVer", label: "Version actuellement installée (protégée)", type: "text", required: true, validate: ver, default: "11.1.2" },
      { id: "delVers", label: "Versions Panorama à supprimer", type: "list", default: ["10.2.0", "11.0.0"],
        validate: (arr, v) => { for (const x of arr) { const e = ver(x); if (e) return `« ${x} » : ${e}`; if (x === v.curVer) return `${x} est la version en cours : suppression impossible`; } return null; } },
      { id: "delContent", label: "Fichiers de contenu à supprimer (optionnel)", type: "list", default: [], placeholder: "panupv2-all-contents-8700-8400",
        validate: arr => { for (const x of arr) if (!/^[A-Za-z0-9._-]+$/.test(x)) return `« ${x} » : nom de fichier invalide`; return null; } },
    ],
    build(v) {
      const steps = [
        { title: "Logiciels Panorama", path: ["Panorama", "Software"], action: "Pour chaque ancienne version téléchargée, cliquer sur l'icône de suppression (colonne de droite) → Yes. La version en cours n'est pas supprimable.", fields: [["Versions", v.delVers]] },
        { title: "Contenus dynamiques", path: ["Panorama", "Dynamic Updates"], action: "Icône de suppression en bout de ligne pour les anciens paquets.", fields: [["Fichiers", v.delContent]] },
        { title: "Images destinées aux pare-feux", path: ["Panorama", "Device Deployment", "Software"], action: "Supprimer aussi les images PAN-OS de pare-feux devenues inutiles.", fields: [] },
      ];
      const cliRaw = ["show system disk-space", "# Lister ce qui est supprimable (touche TAB) :", "delete software version <TAB>",
        ...v.delVers.map(x => `delete software version ${x}`), "delete content update <TAB>", ...v.delContent.map(x => `delete content update ${x}`), "show system disk-space"];
      const notes = [{ type: "warn", text: "La CLI ne demande AUCUNE confirmation : vérifie chaque version avant d'appuyer sur Entrée." },
        { type: "or", text: "Garde la version précédente tant que la mise à niveau actuelle n'est pas validée (retour arrière possible)." }];
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P10 · Panorama HA (annexe A)
     ===================================================================== */
  register({
    id: "p10-ha",
    module: "P10",
    title: "Haute disponibilité Panorama (HA)",
    icon: "🛟",
    desc: "Paire active/passive de Panorama : priorité primary/secondary, préemption, timers, chiffrement, path monitoring, et ajout du 2e Panorama sur les pare-feux.",
    tags: "high availability ha panorama primary secondary active passive preemptive path monitoring heartbeat encryption failover suspend",
    fields: [
      { id: "localRole", label: "Panorama configuré ici", type: "select", default: "primary", group: "Paire HA",
        options: [["primary", "Primary (sera Active)"], ["secondary", "Secondary (sera Passive)"]],
        hint: "La configuration se fait sur CHAQUE Panorama : génère d'abord le primary, puis rebascule ce champ sur secondary." },
      { id: "panoName", label: "Hostname de ce Panorama", type: "text", validate: "hostname", default: "Panorama-01" },
      { id: "panoIp", label: "IP MGT de ce Panorama", type: "text", required: true, validate: vIpOrCidr, default: "192.168.1.252/24" },
      { id: "panoIp2", label: "Peer HA IP Address (MGT du pair)", type: "text", required: true, validate: vIpOrCidr, default: "192.168.1.151" },
      { id: "peerSerial", label: "Peer HA Serial (optionnel)", type: "text", validate: serial, default: "" },
      { id: "preempt", label: "Preemptive (identique sur les deux)", type: "checkbox", default: false, group: "Election Settings",
        hint: "Décoché : après une panne, le secondary reste actif — temps de diagnostiquer le primary avant de rebasculer manuellement." },
      { id: "timers", label: "HA Timer Settings", type: "select", default: "recommended", options: [["recommended", "Recommended"], ["aggressive", "Aggressive"]] },
      { id: "encrypt", label: "Encryption Enabled (chiffrer la synchro HA)", type: "checkbox", default: true,
        hint: "Nécessite l'export/import de la clé HA de chaque pair (Panorama > Certificate Management > Certificates > Export HA Key / Import HA Key)." },
      { id: "pathMon", label: "Activer le path monitoring", type: "checkbox", default: false, group: "Path Monitoring" },
      { id: "pmCond", label: "Failure Condition (globale)", type: "select", default: "any", options: [["any", "Any"], ["all", "All"]], show: v => v.pathMon },
      { id: "pgName", label: "Nom du path group", type: "text", required: true, validate: "name", default: "Infra-Auth", show: v => v.pathMon },
      { id: "pgCond", label: "Failure Condition du groupe", type: "select", default: "any", options: [["any", "Any"], ["all", "All"]], show: v => v.pathMon },
      { id: "pgDest", label: "Destination IP (ping)", type: "list", required: true, validate: "ip", default: ["192.168.50.150", "192.168.50.10"], show: v => v.pathMon,
        hint: "Ex. serveurs RADIUS/LDAP : bascule si le Panorama actif ne les joint plus." },
      { id: "pgInt", label: "Ping Interval (ms)", type: "number", min: 200, max: 60000, default: "5000", show: v => v.pathMon },
      { id: "pgCount", label: "Ping Count", type: "number", min: 2, max: 10, default: "10", show: v => v.pathMon },
      { id: "fwUpd", label: "Déclarer le 2e Panorama sur les pare-feux", type: "select", default: "template", group: "Pare-feux gérés",
        options: [["template", "Via un template (recommandé)"], ["manual", "Sur chaque pare-feu (CLI locale)"], ["none", "Déjà fait"]] },
      { id: "template", label: "Template", type: "text", required: true, validate: "name", default: "TPL-Common", show: v => v.fwUpd === "template" },
      { id: "stack", label: "Template stack à pousser", type: "text", required: true, validate: "name", default: "TS-Paris", show: v => v.fwUpd === "template" },
    ],
    build(v) {
      const pri = v.localRole === "primary";
      const me = ipOf(v.panoIp), peer = ipOf(v.panoIp2);
      const ipPri = pri ? me : peer, ipSec = pri ? peer : me;
      const steps = [
        { title: "Prérequis", path: ["Dashboard", "General Information"], action: "Les deux Panorama : même modèle (ou mêmes ressources VM), même version, même mode (Panorama / Management Only), mêmes licences, mêmes contenus dynamiques et même base URL. MGT des deux joignables entre eux et vers les pare-feux.", fields: [] },
        { title: `Activer la HA sur ${v.panoName || "ce Panorama"} (${pri ? "primary" : "secondary"})`, path: ["Panorama", "High Availability", "Setup"], window: "Setup",
          action: "Cadre Setup → ⚙.", fields: [["Enable HA", true], ["Peer HA IP Address", peer], ["Peer HA Serial", v.peerSerial], ["Encryption Enabled", v.encrypt], ["Monitor Hold Time (ms)", "3000 (défaut)"]] },
        { title: "Election Settings", path: ["Panorama", "High Availability", "Election Settings"], window: "Election Settings", action: "Cadre Election Settings → ⚙.",
          fields: [["Priority", pri ? "primary" : "secondary"], ["Preemptive", v.preempt ? true : "☐ décoché"], ["HA Timer Settings", v.timers === "recommended" ? "Recommended" : "Aggressive"]] },
      ];
      if (v.encrypt) steps.push({ title: "Échanger les clés HA", path: ["Panorama", "Certificate Management", "Certificates"], action: "Export HA Key sur chaque pair, puis Import HA Key de la clé de l'AUTRE pair. À faire avant le commit qui active le chiffrement.", fields: [] });
      if (v.pathMon) steps.push({ title: "Path Monitoring", path: ["Panorama", "High Availability", "Path Monitoring"], window: "Path Group",
        action: "Path Monitoring → ⚙ (Enabled, Failure Condition), puis Path Group → Add.",
        fields: [["Enabled", true], ["Failure Condition", v.pmCond], ["Name", v.pgName], ["Failure Condition (groupe)", v.pgCond], ["Ping Interval", v.pgInt], ["Ping Count", v.pgCount], ["Destination IPs", v.pgDest]] });
      if (v.fwUpd === "template") steps.push({ title: "Ajouter le 2e Panorama sur les pare-feux", path: ["Device", "Setup", "Management"], window: "Panorama Settings",
        action: `Sélecteur Template = ${v.template} → cadre Panorama Settings → ⚙.`, fields: [["Panorama Servers", `${ipPri} / ${ipSec}`]] });
      steps.push({ title: "Vérifier puis tester la bascule", path: ["Dashboard", "High Availability"], action: "Widget High Availability (voyants local/peer, Running Config synchronized). Test planifié : Panorama > High Availability > Operational Commands > Suspend local Panorama, puis Make local Panorama functional.", fields: [] });

      const H = "set deviceconfig high-availability";
      const cli = [
        `${H} enabled yes`,
        `${H} peer-ip ${peer}`,
        v.peerSerial && `# Peer HA Serial ${v.peerSerial} : à saisir dans la WebUI si le champ est proposé par ta version`,
        `${H} election-option priority ${v.localRole} preemptive ${yn(v.preempt)} timers ${v.timers}`,
        v.encrypt && `${H} encryption enabled yes`,
        ...(v.pathMon ? [UNSURE, `${H} path-monitoring enabled yes failure-condition ${v.pmCond}`,
          `${H} path-monitoring path-group ${q(v.pgName)} failure-condition ${v.pgCond} ping-interval ${v.pgInt} ping-count ${v.pgCount}`,
          ...v.pgDest.map(d => `${H} path-monitoring path-group ${q(v.pgName)} destination-ip ${d}`)] : []),
      ].filter(Boolean);
      const res = { steps, cli, verify: ["show high-availability state", "show high-availability all"] };
      if (v.fwUpd === "template") {
        cli.push(`set template ${q(v.template)} config devices localhost.localdomain deviceconfig system panorama local-panorama panorama-server ${ipPri} panorama-server-2 ${ipSec}`);
        if (pri) res.push = [`commit-all template-stack name ${q(v.stack)}`];
      }
      if (v.fwUpd === "manual") res.fwCli = [`set deviceconfig system panorama local-panorama panorama-server ${ipPri} panorama-server-2 ${ipSec}`];
      res.notes = [
        { type: "or", title: "Priorité ≠ état", text: "Primary/Secondary = priorité configurée (fixe). Active/Passive = état courant. Seul l'actif modifie la configuration et pousse vers les pare-feux ; au commit HA, le secondary reçoit la configuration du primary (la sienne est écrasée)." },
        { type: "or", text: "Détection de panne : hello (8 000 ms) et heartbeat (1 000 ms) sur le MGT ; path monitoring optionnel (ping toutes les 5 000 ms)." },
        { type: "or", text: "Ports : TCP 28 si la synchro est chiffrée, 28260/28769 sinon." },
        { type: "warn", text: "La HA Panorama protège la GESTION. La redondance des LOGS se règle dans le Collector Group (Log Redundancy, #p05-cg)." },
        { type: "or", text: pri ? "Étape suivante : bascule le champ « Panorama configuré ici » sur Secondary pour générer la configuration du pair, puis commit sur chacun." : "Sur le secondary, ne fais aucune autre modification : il recevra la configuration du primary." },
      ];
      if (ipOf(v.panoIp) === ipOf(v.panoIp2)) res.notes.unshift({ type: "bad", text: "L'IP du pair est identique à l'IP locale." });
      if (v.timers === "aggressive" && v.pathMon) res.notes.push({ type: "warn", text: "Timers agressifs + path monitoring : risque de bascules intempestives sur un réseau instable." });
      return res;
    },
  });

  /* =====================================================================
     P10 · Export planifié de la configuration (+ exports manuels)
     ===================================================================== */
  register({
    id: "p10-backup",
    module: "P10",
    title: "Export planifié de la configuration",
    icon: "💾",
    desc: "Panorama > Scheduled Config Export : sauvegarde quotidienne (Panorama + configurations des pare-feux) vers SCP ou FTP, plus exports manuels (snapshot, device state).",
    tags: "scheduled config export backup sauvegarde scp ftp bundle device state snapshot",
    fields: [
      { id: "expName", label: "Name", type: "text", required: true, validate: "name", default: "Daily-Export-SCP", group: "Export planifié" },
      { id: "expDesc", label: "Description", type: "text", default: "Panorama and firewall configurations" },
      { id: "enable", label: "Enable", type: "checkbox", default: true },
      { id: "startTime", label: "Scheduled Export Start Time (Daily)", type: "text", required: true, validate: hhmm, default: "01:30" },
      { id: "proto", label: "Protocol", type: "select", default: "scp", options: [["scp", "SCP (recommandé)"], ["ftp", "FTP"]] },
      { id: "host", label: "Hostname", type: "text", required: true, validate: "host", default: "192.168.50.150" },
      { id: "bkPort", label: "Port", type: "port", required: true, default: "22" },
      { id: "path", label: "Path", type: "text", required: true, validate: absPath, default: "/home/paloalto42/" },
      { id: "passive", label: "Enable FTP Passive Mode", type: "checkbox", default: true, show: v => v.proto === "ftp" },
      { id: "bkUser", label: "Username", type: "text", required: true, validate: "name", default: "paloalto42" },
      { id: "bkPwd", label: "Password", type: "password", required: true, default: "Pal0Alt0!" },
      { id: "snapNow", label: "Créer aussi un snapshot nommé maintenant (avant changement)", type: "checkbox", default: true, group: "Exports manuels" },
      { id: "snapName", label: "Nom du snapshot", type: "text", required: true, default: "pre-change.xml", show: v => v.snapNow,
        validate: n => /^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.xml$/.test(n) ? null : "Nom de fichier .xml (ex. pre-change.xml)" },
      { id: "devState", label: "Exporter le device state de ces pare-feux (séries, optionnel)", type: "list", validate: serialList, default: [],
        hint: "Indispensable pour remplacer un pare-feu en panne (RMA, #p10-replace-fw)." },
    ],
    build(v) {
      const scp = v.proto === "scp";
      const steps = [
        { title: "Créer l'export planifié", path: ["Panorama", "Scheduled Config Export"], window: "Scheduled Config Export", action: "Cliquer sur Add (en bas).",
          fields: [["Name", v.expName], ["Description", v.expDesc], ["Enable", v.enable], ["Scheduled Export Start Time (Daily)", v.startTime], ["Protocol", scp ? "SCP" : "FTP"],
            ["Hostname", v.host], ["Port", v.bkPort], ["Path", v.path], ["Enable FTP Passive Mode", !scp && v.passive], ["Username", v.bkUser], ["Password / Confirm Password", MASKED]] },
      ];
      if (scp) steps.push({ title: "Tester la connexion SCP", path: ["Panorama", "Scheduled Config Export"], window: "Scheduled Config Export",
        action: "Bouton Test SCP server connection → accepter l'empreinte de la clé hôte du serveur.", fields: [], note: "Après Commit to Panorama : le test peut échouer tant que la configuration n'est pas committée." });
      if (v.snapNow) steps.push({ title: "Snapshot nommé", path: ["Panorama", "Setup", "Operations"], action: "Configuration Management → Save named Panorama configuration snapshot → Export named Panorama configuration snapshot.", fields: [["Name", v.snapName]] });
      steps.push({ title: "Bundle Panorama + pare-feux (manuel)", path: ["Panorama", "Setup", "Operations"], action: "Export Panorama and devices config bundle : archive de la running config de Panorama et de la dernière config de chaque pare-feu.", fields: [] });
      if (v.devState.length) steps.push({ title: "Device state des pare-feux", path: ["CLI Panorama"], action: "Exporter via SCP/TFTP (voir CLI) : le device state contient la config locale + celle poussée par Panorama, nécessaire à un remplacement matériel.", fields: [["Pare-feux", v.devState]] });

      const E = `set panorama scheduled-config-export ${q(v.expName)}`;
      const cli = [
        UNSURE,
        v.expDesc && `${E} description ${q(v.expDesc)}`,
        `${E} enable ${yn(v.enable)} start-time ${v.startTime}`,
        `${E} protocol ${v.proto} hostname ${v.host} port ${v.bkPort} path ${q(v.path)} username ${q(v.bkUser)} password ${q(v.bkPwd)}${!scp ? " passive-mode " + yn(v.passive) : ""}`,
        v.snapNow && `save config to ${v.snapName}`,
      ].filter(Boolean);
      const tgt = `${v.bkUser}@${v.host}:${v.path}`;
      const verify = [];
      if (scp) verify.push(`test scp-server-connection initiate hostname ${v.host} port ${v.bkPort} path ${q(v.path)} username ${q(v.bkUser)}`);
      if (v.snapNow) verify.push(scp ? `scp export configuration from ${v.snapName} to ${tgt}` : `ftp export configuration from ${v.snapName} to ${tgt}`);
      v.devState.forEach(s => verify.push(`scp export device-state device ${s} to ${tgt}`));
      const notes = [
        { type: "or", title: "Pourquoi (MOD-01)", text: "À chaque commit, Panorama conserve localement sa config et celle des pare-feux gérés — mais uniquement sur son propre disque. L'export planifié en sort une copie quotidienne." },
        { type: "or", text: "Rôle requis : Superuser. Le rôle dynamique « Panorama administrator » ne peut pas configurer le Scheduled Config Export." },
      ];
      if (!scp) notes.push({ type: "warn", text: "FTP transmet identifiants et configuration en clair : préfère SCP." });
      if (!v.enable) notes.push({ type: "warn", text: "Export désactivé : aucune sauvegarde ne partira tant que Enable n'est pas coché." });
      return { steps, cli, notes, verify };
    },
  });

  /* =====================================================================
     P10 · Remplacer un pare-feu géré (RMA) — annexe A
     ===================================================================== */
  register({
    id: "p10-replace-fw",
    module: "P10",
    title: "Remplacer un pare-feu géré (RMA)",
    icon: "🔁",
    desc: "Remplacement matériel : préparation du nouveau pare-feu, transfert de licences, export du device state, « replace device » sur Panorama, import sur le nouveau, puis Commit and Push.",
    tags: "rma remplacement replace device serial device state licence transfer remplacer pare-feu",
    fields: [
      { id: "fwSerial", label: "Série de l'ANCIEN pare-feu", type: "text", required: true, validate: serial, default: "007051000123456", group: "Pare-feux" },
      { id: "newSerial", label: "Série du NOUVEAU pare-feu", type: "text", required: true, default: "007051000654321",
        validate: (s, v) => serial(s) || (s === v.fwSerial ? "Doit différer de l'ancien numéro de série" : null) },
      { id: "fwName", label: "Hostname", type: "text", validate: "hostname", default: "berlin-fw" },
      { id: "fwMgmtIp", label: "IP MGT (reprise par le nouveau)", type: "ip", required: true, default: "192.168.1.253" },
      { id: "xfer", label: "Transfert du device state", type: "select", default: "scp", options: [["scp", "SCP"], ["tftp", "TFTP"]], group: "Serveur de transfert" },
      { id: "srvUser", label: "Utilisateur", type: "text", required: true, validate: "name", default: "backup", show: v => v.xfer === "scp" },
      { id: "srvHost", label: "Serveur", type: "text", required: true, validate: "host", default: "192.168.50.150" },
      { id: "srvPath", label: "Répertoire", type: "text", required: true, validate: absPath, default: "/backup/device-state/" },
      { id: "dg", label: "Device group du pare-feu", type: "text", required: true, validate: "name", default: "Branch-DG", group: "Synchronisation" },
      { id: "stack", label: "Template stack", type: "text", required: true, validate: "name", default: "Germany-Stack" },
    ],
    build(v) {
      const file = `${v.fwSerial}-device-state.tgz`;
      const dst = v.xfer === "scp" ? `${v.srvUser}@${v.srvHost}:${v.srvPath}` : `${v.srvHost}:${v.srvPath}`;
      const steps = [
        { title: "Préparer le nouveau pare-feu", path: ["Device", "Setup", "Interfaces", "Management"], action: `Sur le NOUVEAU pare-feu (WebUI locale) : IP MGT ${v.fwMgmtIp}, puis mêmes versions PAN-OS et contenus dynamiques que l'ancien. Ne PAS encore l'ajouter dans Panorama.`, fields: [] },
        { title: "Transférer les licences", path: ["Customer Support Portal", "Assets"], action: `Transférer les licences de ${v.fwSerial} vers ${v.newSerial} (procédure « Transfer Licenses to a Spare Device »), puis Device > Licenses > Retrieve license keys sur le nouveau.`, fields: [] },
        { title: "Exporter le device state de l'ancien", path: ["CLI Panorama"], action: `Commande ${v.xfer} export device-state (voir CLI) : Panorama génère l'état à partir de sa copie de la configuration.`, fields: [] },
        { title: "Remplacer le numéro de série dans Panorama", path: ["CLI Panorama"], action: `replace device old ${v.fwSerial} new ${v.newSerial}, puis configure → commit : toutes les références (DG, template stack, collector group) basculent sur la nouvelle série.`, fields: [] },
        { title: "Importer sur le nouveau pare-feu", path: ["Device", "Setup", "Operations"], action: "Import device state → sélectionner le fichier exporté → OK, puis Commit sur le pare-feu.", fields: [["Fichier", file]] },
        { title: "Vérifier la connexion", path: ["Panorama", "Managed Devices", "Summary"], action: `${v.fwName || v.newSerial} doit apparaître Connected.`, fields: [] },
      ];
      const cliRaw = [
        "# ===== Sur Panorama (mode opérationnel) =====",
        `${v.xfer} export device-state device ${v.fwSerial} to ${dst}`,
        `replace device old ${v.fwSerial} new ${v.newSerial}`,
        "configure",
        "commit",
        "exit",
        "",
        `# ===== Sur le NOUVEAU pare-feu (${v.newSerial}) — mode opérationnel =====`,
        `${v.xfer} import device-state from ${dst}${file}`,
        "# puis : Device > Setup > Operations > Import device state (WebUI) si l'import CLI n'est pas proposé, et Commit",
        "show panorama-status",
      ];
      const notes = [
        { type: "or", title: "Synchronisation finale", text: "Lors du push : Edit Selections → onglet Device Groups → cocher le DG du pare-feu ET « Include Device and Network Templates », puis vérifier In Sync dans Panorama > Managed Devices > Summary." },
        { type: "warn", text: "Ne déclare pas le nouveau numéro de série dans Managed Devices avant le « replace device » : la commande remplace l'ancien partout." },
        { type: "or", text: "Le device state ne restaure pas tout pour les pare-feux LSVPN (GlobalProtect satellite/portail) : vérifier ces éléments après coup." },
        { type: "or", text: "Pense au certificat / à la clé d'enregistrement si le pare-feu ne se connecte pas (#p09-troubleshoot, symptôme « enregistrement refusé »)." },
      ];
      return { steps, cliRaw, notes,
        push: [UNSURE, `commit-all shared-policy device-group ${q(v.dg)} include-template yes`, `commit-all template-stack name ${q(v.stack)}`] };
    },
  });

  /* =====================================================================
     P10 · Migrer une paire HA de pare-feux sous Panorama — annexe A
     ===================================================================== */
  register({
    id: "p10-fw-ha-migrate",
    module: "P10",
    title: "Migrer une paire HA de pare-feux sous Panorama",
    icon: "👯",
    desc: "Désactiver la synchro de configuration HA, ajouter les deux pare-feux, importer la config d'un seul, les placer dans le même DG / template stack, pousser, puis réactiver la synchro si besoin.",
    tags: "ha pair firewall migration config sync panorama import active passive",
    fields: [
      { id: "fwSerial", label: "Série du pare-feu ACTIF", type: "text", required: true, validate: serial, default: "007051000111111", group: "Paire HA" },
      { id: "fwSerial2", label: "Série du pare-feu PASSIF", type: "text", required: true, default: "007051000222222",
        validate: (s, v) => serial(s) || (s === v.fwSerial ? "Les deux séries doivent différer" : null) },
      { id: "panoIp", label: "IP MGT de Panorama", type: "text", required: true, validate: vIpOrCidr, default: "192.168.1.252/24" },
      { id: "authKey", label: "Device registration auth key (nom)", type: "text", validate: "name", default: "HA-Pair-Key" },
      { id: "dg", label: "Device group (commun aux deux)", type: "text", required: true, validate: "name", default: "DG-Paris", group: "Placement" },
      { id: "stack", label: "Template stack (commun aux deux)", type: "text", required: true, validate: "name", default: "TS-Paris" },
      { id: "reSync", label: "Réactiver Enable Config Sync après la migration", type: "checkbox", default: false,
        hint: "Utile seulement si des réglages locaux non gérés par Panorama doivent rester synchronisés entre les deux pare-feux." },
    ],
    build(v) {
      const P = ipOf(v.panoIp);
      const steps = [
        { title: "Désactiver la synchro sur les DEUX pare-feux", path: ["Device", "High Availability", "General", "Setup"], window: "Setup",
          action: "Sur l'actif puis sur le passif (WebUI locale) : décocher Enable Config Sync → OK → Commit sur chacun.", fields: [["Enable Config Sync", "☐ décoché"]] },
        { title: "Ajouter les deux pare-feux", path: ["Panorama", "Managed Devices", "Summary"], action: "Add → saisir les deux numéros de série (et la clé d'enregistrement), puis configurer Panorama Servers sur chaque pare-feu (voir CLI côté pare-feu).",
          fields: [["Devices", [v.fwSerial, v.fwSerial2]], ["Device registration auth key", v.authKey]] },
        { title: "Importer la configuration de l'ACTIF uniquement", path: ["Panorama", "Setup", "Operations"], action: "Import device configuration to Panorama → pare-feu actif → noms de template / DG (voir #p02-migrate). Le passif utilisera la même configuration.", fields: [["Device", v.fwSerial]] },
        { title: "Placer les deux pare-feux", path: ["Panorama", "Device Groups"], action: `Les deux dans ${v.dg} (Panorama > Device Groups) et dans ${v.stack} (Panorama > Templates).`, fields: [["Device Group", v.dg], ["Template Stack", v.stack]] },
      ];
      if (v.reSync) steps.push({ title: "Réactiver la synchro (optionnel)", path: ["Device", "High Availability", "General", "Setup"], action: "Après un push réussi : recocher Enable Config Sync sur les deux pare-feux, commit local.", fields: [["Enable Config Sync", true]] });
      const cli = [
        `set mgt-config devices ${v.fwSerial}`, `set mgt-config devices ${v.fwSerial2}`,
        `set device-group ${q(v.dg)} devices ${v.fwSerial}`, `set device-group ${q(v.dg)} devices ${v.fwSerial2}`,
        `set template-stack ${q(v.stack)} devices ${v.fwSerial}`, `set template-stack ${q(v.stack)} devices ${v.fwSerial2}`,
      ];
      const fwCli = [
        "# Sur CHAQUE pare-feu de la paire (actif puis passif) :",
        "set deviceconfig high-availability group configuration-synchronization enabled no",
        `set deviceconfig system panorama local-panorama panorama-server ${P}`,
      ];
      const notes = [
        { type: "warn", title: "Pourquoi couper la synchro (annexe A)", text: "Pendant la migration, la paire ne doit pas tenter de se synchroniser : les configurations locale et Panorama se mélangeraient de façon imprévisible." },
        { type: "or", text: "Une fois gérés par Panorama, les deux pare-feux reçoivent la même configuration poussée : la synchro HA locale devient généralement inutile." },
        { type: "or", text: `Clé d'enregistrement : « request authkey add name ${v.authKey || "HA-Pair-Key"} lifetime 60 count 2 » sur Panorama, puis « request authkey set <clé> » sur chaque pare-feu.` },
      ];
      return { steps, cli, fwCli, notes, push: [`commit-all template-stack name ${q(v.stack)}`, `commit-all shared-policy device-group ${q(v.dg)}`], verify: ["show devices all"] };
    },
  });

  /* =====================================================================
     P10 · Dimensionner le stockage des logs (calculateur, annexe A)
     ===================================================================== */
  register({
    id: "p10-log-sizing",
    module: "P10",
    title: "Dimensionner le stockage des logs",
    icon: "🧮",
    desc: "Calculateur : débit agrégé (logs/s) × jours de rétention × taille moyenne → To nécessaires, avec redondance et nombre de Log Collectors indicatif ; commandes pour mesurer le débit réel.",
    tags: "log sizing dimensionnement stockage lps logs per second retention log collector disque to",
    noCommit: true,
    fields: [
      { id: "lps", label: "Débit agrégé (logs/s, tous pare-feux)", type: "number", min: 1, max: 1000000, required: true, default: "1500", group: "Hypothèses" },
      { id: "days", label: "Rétention des logs détaillés (jours)", type: "number", min: 1, max: 3650, required: true, default: "30" },
      { id: "logSize", label: "Taille moyenne d'un log (octets)", type: "number", min: 100, max: 5000, required: true, default: "500", hint: "500 octets = valeur de référence Palo Alto (cours EDU-220)." },
      { id: "redund", label: "Log Redundancy dans le Collector Group (chaque log stocké 2 fois)", type: "checkbox", default: false },
      { id: "margin", label: "Marge de croissance (%)", type: "number", min: 0, max: 200, default: "20" },
      { id: "lcCap", label: "Capacité utile par Log Collector (To, optionnel)", type: "number", min: 1, max: 1000, default: "", hint: "Selon le modèle / les disques virtuels ajoutés (voir #p01-mode)." },
    ],
    build(v) {
      const TB = 1099511627776;
      const raw = (+v.lps * 86400 * +v.days * +v.logSize) / TB;
      const tot = raw * (v.redund ? 2 : 1) * (1 + (+v.margin || 0) / 100);
      const f = x => x.toLocaleString("fr-FR", { maximumFractionDigits: 2 });
      const nLc = +v.lcCap ? Math.ceil(tot / +v.lcCap) : 0;
      const steps = [
        { title: "Résultat", path: ["Calcul"], action: `[(${v.lps} logs/s × 86 400 s) × ${v.days} j] × ${v.logSize} o ÷ 1 099 511 627 776 o/To`,
          fields: [["Logs détaillés (brut)", `${f(raw)} To`], ["Avec redondance", v.redund ? `${f(raw * 2)} To` : ""], ["Total avec marge", `${f(tot)} To`],
            ["Log Collectors (indicatif)", nLc ? `${nLc} × ${v.lcCap} To${v.redund && nLc < 2 ? " → minimum 2 pour la redondance" : ""}` : ""]] },
        { title: "Mesurer le débit réel", path: ["Pare-feux existants"], action: "Sur chaque pare-feu : « debug log-receiver statistics » (Log incoming rate) aux heures de pointe, ou ACC/SNMP. Additionner tous les pare-feux. Sans pare-feu en place : estimer à partir de clients comparables.", fields: [] },
      ];
      const cliRaw = ["# ===== Sur chaque pare-feu (heure de pointe) =====", "debug log-receiver statistics", "# → « Log incoming rate » = logs/s",
        "", "# ===== Sur Panorama / Log Collector existant =====", "debug log-collector log-collection-stats show incoming-logs", "show system logdb-quota", "show system disk-space"];
      const notes = [
        { type: "ok", title: `≈ ${f(tot)} To à prévoir`, text: `Exemple du cours : 1 500 logs/s sur 30 jours à 500 o/log ≈ 1,768 To de logs détaillés (Traffic et Threat).` },
        { type: "or", text: "Les logs résumés (summary) et les autres types (System, Config…) s'ajoutent : garde une marge, et répartis les quotas dans Panorama > Collector Groups > Log Storage." },
      ];
      if (v.redund) notes.push({ type: "or", text: "Log Redundancy : chaque log est écrit sur deux collecteurs du groupe → stockage doublé, et tous les collecteurs du groupe doivent avoir le même nombre et type de disques." });
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P10 · Certificat de génération des clés API (bonus lab 9)
     ===================================================================== */
  register({
    id: "p10-api-key-cert",
    module: "P10",
    title: "Certificat des clés API (API Key Certificate)",
    icon: "🔐",
    desc: "Générer un certificat dédié à la génération des clés API (supprime l'avertissement « API KeyGen » au commit) et régler la durée de vie des clés.",
    tags: "api key certificate keygen avertissement commit authentication settings xml api",
    fields: [
      { id: "certName", label: "Certificate Name", type: "text", required: true, validate: "name", default: "API-KEY-GEN" },
      { id: "cn", label: "Common Name", type: "text", required: true, default: "API-KEY-GEN" },
      { id: "bits", label: "Number of Bits", type: "select", default: "4096", options: [["2048", "2048"], ["3072", "3072"], ["4096", "4096"]] },
      { id: "keyLife", label: "API Key Lifetime (minutes, 0 = illimité)", type: "number", min: 0, max: 525600, default: "0" },
    ],
    build(v) {
      const steps = [
        { title: "Générer le certificat depuis Authentication Settings", path: ["Panorama", "Setup", "Management"], window: "Authentication Settings",
          action: "Cadre Authentication Settings → ⚙ → API Key Certificate → Generate.",
          fields: [["Certificate Name", v.certName], ["Common Name", v.cn], ["Certificate Authority", true], ["Number of Bits", v.bits], ["API Key Lifetime (min)", v.keyLife]] },
        { title: "Sauvegarder", path: ["Panorama", "Setup", "Operations"], action: "Après le commit : Save named Panorama configuration snapshot — les configurations sauvegardées ensuite utilisent le nouveau certificat.", fields: [] },
      ];
      const cliRaw = [
        "# ===== Mode opérationnel : génération du certificat =====", UNSURE,
        `request certificate generate certificate-name ${q(v.certName)} name ${q(v.cn)} algorithm RSA rsa-nbits ${v.bits} ca yes`,
        "", "configure", UNSURE,
        `set deviceconfig system api-key-certificate ${q(v.certName)}`,
        +v.keyLife > 0 ? `set deviceconfig setting management api key lifetime ${v.keyLife}` : null,
        "commit", "exit",
      ].filter(x => x !== null);
      const notes = [
        { type: "warn", text: "Changer le certificat ou la durée de vie invalide les clés API existantes : prévenir les équipes qui ont des scripts / intégrations (SOAR, Terraform, Ansible…)." },
        { type: "or", text: "Même procédure sur un pare-feu (Device > Setup > Management > Authentication Settings)." },
      ];
      return { steps, cliRaw, notes };
    },
  });
})();
