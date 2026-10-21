/* PANW Config Builder — Panorama 11.1
   Catégorie P11 : Zero Touch Provisioning (ZTP).
   Hors cours EDU-220 : contenu établi d'après la documentation officielle Palo Alto Networks
   (Panorama Administrator's Guide 11.1 > Manage Firewalls > Set Up Zero Touch Provisioning :
   ZTP Configuration Elements, Install the ZTP Plugin, Register Panorama with the ZTP Service,
   Configure the ZTP Installer Administrator Account, Add a ZTP Firewall to Panorama (11.1),
   Import Multiple ZTP Firewalls, Configure ZTP for Firewalls in HA, Use the CLI for ZTP Tasks ;
   Install the Panorama Device Certificate).
   Champs partagés (contrat) : client, panoIp, panoIp2, ntp1, dns1, dns2, fwSerial, fwName, fwMgmtIp,
   template, stack, dg, adminUser. Champs ZTP partagés entre modules P11 : panoSerial, panoPublic,
   panoPublic2, claimKey, ztpModel, ztpZone. */
(function () {
  const C = PAN.cfg;
  const { register, q } = C;
  const V = C.V;
  if (typeof C.category === "function") C.category("P11", "Zero Touch Provisioning (ZTP)");
  else if (C.MODNAMES) C.MODNAMES.P11 = "Zero Touch Provisioning (ZTP)";

  /* ---------- helpers ---------- */
  const bare = s => String(s || "").trim().split("/")[0];
  const ipOk = s => PAN.ip.valid(String(s).trim());
  const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
  const serial = s => /^\d{12,15}$/.test(String(s).trim()) ? null : "Numéro de série : 12 à 15 chiffres (étiquette du boîtier ou Dashboard > General Information)";
  const claim = s => /^\d{8}$/.test(String(s).trim()) ? null : "Claim key : 8 chiffres (étiquette au dos du pare-feu)";
  const objName = n => /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(String(n)) ? null : "Nom : 63 caractères max, lettres/chiffres/. _ - (sans espace), commence par une lettre ou un chiffre";
  const swVer = v => /^\d{1,2}\.\d\.\d{1,2}(-h\d{1,2})?$/.test(String(v)) ? null : "Version PAN-OS, ex. 11.1.6 ou 11.1.4-h7";
  const host = v => V.host(v);
  const pubHost = v => { const e = host(v); if (e) return e; return ipOk(v) && isPrivate(v) ? "Adresse privée : le service ZTP la pousse à des pare-feux sur Internet, ils ne pourront pas la joindre. Indique l'IP publique (NAT) ou un FQDN public." : null; };
  const rows = s => String(s || "").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#")).map(l => l.split(/\s*[,;]\s*/));
  const maskStr = n => { n = +n; const m = n === 0 ? 0 : (~0 << (32 - n)) >>> 0; return [m >>> 24, (m >>> 16) & 255, (m >>> 8) & 255, m & 255].join("."); };
  const maskOf = c => maskStr(String(c).split("/")[1] ?? 32);
  const TPL = t => `set template ${q(t)} config devices localhost.localdomain`;
  const VALIDATE = "à valider avec « ? » sur ta version";
  const UNSURE = "# (syntaxe à valider avec « ? » sur ta version)";
  const DOCREF = "Source : Panorama Administrator's Guide 11.1 > Set Up Zero Touch Provisioning (docs.paloaltonetworks.com).";

  const MODELS = [
    ["pa400", "PA-400 Series (PA-410/415/440/445/450/460, modèles 5G)"],
    ["pa1400", "PA-1400 Series"],
    ["pa3400", "PA-3400 Series"],
    ["pa5400", "PA-5400 Series / PA-5450"],
    ["pa800z", "PA-820-ZTP / PA-850-ZTP"],
    ["pa3200z", "PA-3220-ZTP / PA-3250-ZTP / PA-3260-ZTP"],
    ["other", "Autre modèle (VM-Series, PA-220, version non -ZTP…)"],
  ];
  const modelLbl = m => (MODELS.find(x => x[0] === m) || [m, m])[1];
  // commande de (dés)activation de la machine à états ZTP selon la famille (doc « Use the CLI for ZTP Tasks »)
  const ztpOff = m => ["pa800z", "pa3200z"].includes(m) ? "request disable-ztp" : "set system ztp disable";

  const PREREQ_NOTE = { type: "or", title: "Prérequis ZTP (doc 11.1)",
    text: "Pare-feu d'un modèle compatible ZTP, licence Device Management + licence Support sur Panorama, compte Panorama superuser (seuls les superusers voient les réglages ZTP), plugin ZTP installé, certificat de device Panorama installé, Panorama joignable depuis Internet (IP publique/NAT ou FQDN public)." };
  const PROXY_NOTE = { type: "warn", title: "Pas de proxy explicite",
    text: "Le service ZTP exige un accès Internet direct : l'onboarding échoue si un proxy web explicite est configuré pour les pare-feux ou pour Panorama." };

  /* =====================================================================
     P11 · Plugin ZTP + certificat de device Panorama
     ===================================================================== */
  register({
    id: "p11-plugin",
    module: "P11",
    title: "Installer le plugin ZTP & le certificat Panorama",
    icon: "🧩",
    desc: "Prérequis ZTP, certificat de device de Panorama via un OTP généré sur le Customer Support Portal, puis téléchargement et installation du plugin ZTP (y compris sur le pair HA).",
    tags: "ztp zero touch provisioning plugin install device certificate otp one time password csp customer support portal prerequisites",
    fields: [
      { id: "client", label: "Nom du client (optionnel)", type: "text", default: "", placeholder: "ACME", group: "Contexte" },
      { id: "panoSerial", label: "Numéro de série de Panorama", type: "text", required: true, default: "000710012345", validate: serial,
        hint: "Panorama > Dashboard > General Information > Serial #. C'est cette série que l'on sélectionne sur le CSP (OTP puis association ZTP)." },
      { id: "panoIp", label: "IP de management Panorama (privée)", type: "ipcidr", required: true, default: "192.168.1.252/24" },
      { id: "ha", label: "Panorama en haute disponibilité (paire HA)", type: "checkbox", default: false,
        hint: "La doc impose d'installer le plugin ET d'enregistrer les deux pairs auprès du service ZTP." },
      { id: "panoIp2", label: "IP du Panorama pair HA", type: "ipcidr", default: "192.168.1.253/24", show: v => v.ha },
      { id: "ntp1", label: "Serveur NTP de Panorama", type: "text", required: true, validate: "host", default: "0.pool.ntp.org", group: "Certificat de device (OTP)",
        hint: "Obligatoire : la validité du certificat est contrôlée par rapport à l'heure de Panorama." },
      { id: "certDone", label: "Certificat de device déjà installé (Panorama > Setup > Management > Device Certificate = Valid)", type: "checkbox", default: false, wide: true,
        hint: "Les appliances M-300 / M-700 l'installent automatiquement à l'enregistrement sur le CSP." },
      { id: "plugMethod", label: "Mode d'installation du plugin", type: "select", default: "online", group: "Plugin ZTP",
        options: [["online", "En ligne (Check Now → Download → Install)"], ["upload", "Upload manuel (fichier téléchargé sur le CSP)"]] },
      { id: "plugVer", label: "Version du plugin", type: "text", required: true, default: "ztp-2.0.6",
        validate: x => /^ztp-\d+\.\d+\.\d+(-[a-z]?\d+)?$/.test(String(x)) ? null : "Format attendu : ztp-<version>, ex. ztp-2.0.6",
        hint: "Prends la version la plus récente compatible avec ta version de Panorama (Compatibility Matrix > Panorama Plugins). À valider sur ta version." },
    ],
    example: { client: "ACME Retail", panoSerial: "000710098765", panoIp: "10.10.0.10/24", ha: true, panoIp2: "10.10.0.11/24", plugVer: "ztp-2.0.6" },
    build(v) {
      const steps = [
        { title: "Vérifier les prérequis", path: ["Panorama", "Licenses"], action: "Contrôler : licence Device Management active, licence Support active, compte connecté = superuser.",
          fields: [["Device Management License", "Active (nombre de pare-feux suffisant)"], ["Support", "Active"], ["Rôle de l'administrateur", "Superuser"]],
          note: "Seuls les administrateurs superuser accèdent aux réglages ZTP. Le service ZTP ne fonctionne pas derrière un proxy web explicite." },
      ];
      if (!v.certDone) steps.push(
        { title: "CSP : générer un OTP pour Panorama", path: ["support.paloaltonetworks.com", "Products", "Device Certificates", "Generate OTP"],
          action: "Se connecter au Customer Support Portal avec un rôle autorisé à générer un OTP.",
          fields: [["Device Type", "Generate OTP for Panorama → Next"], ["Panorama Device Serial Number", v.panoSerial], ["Action", "Generate OTP → copier l'OTP"]],
          note: "L'OTP est valable 60 minutes et Panorama ne tente de le récupérer qu'une seule fois : prépare l'étape suivante avant de le générer." },
        { title: "Panorama : NTP opérationnel", path: ["Panorama", "Setup", "Services"], tab: "NTP", window: "Services",
          action: "Renseigner au moins un serveur NTP, OK, puis Commit to Panorama (module P01 Management si besoin).", fields: [["Primary NTP Server Address", v.ntp1]] },
        { title: "Panorama : récupérer le certificat de device", path: ["Panorama", "Setup", "Management"], window: "Device Certificate Settings",
          action: "Cadre « Device Certificate Settings » → Get certificate → coller l'OTP → OK.",
          fields: [["One-time Password (OTP)", "(OTP copié depuis le CSP)"], ["Résultat attendu", "Current Device Certificate Status : Valid"]],
          note: "Flux sortants nécessaires depuis Panorama : TCP 443 vers api / apitrusted / certificate / certificatetrusted.paloaltonetworks.com, TCP 80 vers ocsp / crl.paloaltonetworks.com et ocsp.godaddy.com. Certificat valable 90 jours, renouvelé automatiquement 15 jours avant expiration." });
      if (!v.certDone && v.ha) steps.push({ title: "Pair HA : même opération", path: ["Panorama (pair HA)", "Setup", "Management"], window: "Device Certificate Settings",
        action: `Générer un second OTP sur le CSP pour la série du pair, puis Get certificate sur le pair (${bare(v.panoIp2)}).`, fields: [] });
      steps.push(v.plugMethod === "online"
        ? { title: "Télécharger et installer le plugin ZTP", path: ["Panorama", "Plugins"],
            action: "Check Now, saisir « ztp » dans le champ de recherche, Download sur la version voulue puis Install.",
            fields: [["Recherche", "ztp"], ["Version", v.plugVer], ["Actions", "Download → Install"]],
            note: "Une fois le plugin installé, le nœud « Zero Touch Provisioning » apparaît sous l'onglet Panorama et le rôle d'admin « installeradmin » est créé automatiquement." }
        : { title: "Uploader puis installer le plugin ZTP", path: ["Panorama", "Plugins"],
            action: "Télécharger le fichier du plugin sur le CSP (Updates > Software Updates, filtre Panorama Integration Plug In), puis Upload → choisir le fichier → OK → Install.",
            fields: [["Fichier", v.plugVer], ["Actions", "Upload → Install"]] });
      if (v.ha) steps.push({ title: "Installer le plugin sur le pair HA", path: ["Panorama (pair HA)", "Plugins"],
        action: "Même version de plugin sur les deux pairs : les plugins ne sont pas synchronisés par le lien HA.", fields: [["Version", v.plugVer]] });
      steps.push({ title: "Contrôler l'installation", path: ["Panorama", "Zero Touch Provisioning"], action: "Le menu Zero Touch Provisioning (Setup, Firewall Registration…) est visible ; Panorama > Admin Roles contient « installeradmin ».", fields: [] });

      const cliRaw = [
        "# --- Mode opérationnel Panorama ---",
        ...(v.certDone ? [] : [
          "# Certificat de device (OTP généré sur le CSP)  " + UNSURE.slice(2),
          "request certificate fetch otp <OTP-COPIE-DEPUIS-LE-CSP>",
          "show device-certificate status",
          "",
        ]),
        "# Plugin ZTP  " + UNSURE.slice(2),
        "request plugins check",
        v.plugMethod === "online" ? `request plugins download file ${v.plugVer}` : `# (fichier ${v.plugVer} importé via la WebUI : Panorama > Plugins > Upload)`,
        `request plugins install ${v.plugVer}`,
        "show plugins installed",
      ];
      if (v.ha) cliRaw.push("", `# Répéter sur le pair HA (${bare(v.panoIp2)})`);
      const notes = [
        PREREQ_NOTE,
        { type: "or", title: "Pourquoi le certificat de device ?", text: "Il authentifie Panorama auprès des services cloud Palo Alto Networks (CSP et service ZTP). Sans certificat valide, l'enregistrement de Panorama et des pare-feux ZTP échoue." },
        { type: "warn", title: "Compatibilité du plugin", text: `Vérifie dans la Compatibility Matrix (Panorama Plugins) la version du plugin ZTP supportée par ta version de Panorama ; la doc demande « la version la plus récente ». Version proposée ici (${v.plugVer}) : à valider sur ta version.` },
        PROXY_NOTE,
        { type: "or", text: `Syntaxes CLI « request certificate fetch otp » et « request plugins … » : ${VALIDATE}. La WebUI reste la référence de la doc.` },
      ];
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P11 · Enregistrer Panorama auprès du service ZTP
     ===================================================================== */
  register({
    id: "p11-register",
    module: "P11",
    title: "Enregistrer Panorama auprès du service ZTP",
    icon: "☁️",
    desc: "Association de Panorama au service ZTP sur le CSP, réglages ZTP généraux (adresse publique de Panorama), génération du device group et du template ZTP, commit puis « Sync to ZTP Service ».",
    tags: "ztp register panorama csp assets ztp service associate panorama fqdn public ip general ztp settings add device group and template sync to ztp service in sync",
    fields: [
      { id: "deploy", label: "Type de déploiement", type: "select", default: "new", group: "Contexte",
        options: [["new", "Nouveau déploiement ZTP"], ["existing", "Déploiement ZTP existant (Panorama remplacé / ajouté)"]] },
      { id: "panoSerial", label: "Numéro de série de Panorama", type: "text", required: true, default: "000710012345", validate: serial },
      { id: "panoIp", label: "IP de management Panorama (privée, info)", type: "ipcidr", default: "192.168.1.252/24" },
      { id: "panoPublic", label: "Panorama FQDN or IP Address (publique)", type: "text", required: true, default: "panorama.acme.fr", validate: pubHost, group: "Adresse de Panorama poussée aux pare-feux",
        hint: "Adresse que le service ZTP envoie aux pare-feux : elle doit être joignable depuis Internet en TCP 3978 (NAT de destination vers l'IP de management de Panorama)." },
      { id: "ha", label: "Panorama en HA", type: "checkbox", default: false },
      { id: "panoSerial2", label: "Série du Panorama pair HA", type: "text", required: true, default: "000710012346", validate: serial, show: v => v.ha },
      { id: "panoPublic2", label: "Peer FQDN or IP Address (publique)", type: "text", required: true, default: "panorama2.acme.fr", validate: pubHost, show: v => v.ha },
      { id: "oldFw", label: "Pare-feux managés en PAN-OS 10.1.4 ou antérieur", type: "checkbox", default: false,
        hint: "La doc recommande alors une IP plutôt qu'un FQDN (sinon déconnexion possible après reboot ou mise à jour)." },
      { id: "dg", label: "Device group ZTP (généré par le plugin)", type: "text", required: true, default: "DG-ZTP", validate: objName, group: "Device group & template ZTP",
        hint: "« Add Device Group and Template » crée ce DG avec la règle de sécurité rule1 et la règle NAT ztp-nat nécessaires à la connexion vers Panorama." },
      { id: "template", label: "Template ZTP (généré par le plugin)", type: "text", required: true, default: "TPL-ZTP", validate: objName,
        hint: "Contient ethernet1/1 et sa zone, loopback.900, le virtual router, l'adresse de Panorama et la service route. Choisis un nom explicite : il sera réutilisé longtemps." },
      { id: "cellular", label: "Onboarding via interface cellulaire (modèles 5G)", type: "checkbox", default: false,
        hint: "Nécessite un objet DNS Proxy (Shared, héritage ethernet1/1 puis cellular1/1) et un APN public à IP dynamique." },
    ],
    example: { deploy: "new", panoSerial: "000710098765", panoIp: "10.10.0.10/24", panoPublic: "pano.acme-retail.fr", ha: false, dg: "DG-ZTP-Agences", template: "TPL-ZTP-Agences" },
    build(v) {
      const isIp = ipOk(v.panoPublic);
      const steps = [
        { title: v.deploy === "new" ? "CSP : associer Panorama au service ZTP" : "CSP : modifier l'association ZTP",
          path: ["support.paloaltonetworks.com", "Assets", "ZTP Service", v.deploy === "new" ? "Associate Panorama(s)" : "Modify Association"],
          action: "Sélectionner la (ou les) série(s) Panorama puis OK.",
          fields: [["Panorama", v.panoSerial], ["Panorama pair HA", v.ha ? v.panoSerial2 : ""]],
          note: "Le service ZTP accepte au plus deux Panorama, et uniquement s'ils forment une paire HA." },
      ];
      if (v.cellular) steps.push({ title: "ZTP cellulaire : objet DNS Proxy", path: ["Network", "DNS Proxy"], action: "Add (Template = template ZTP), puis OK.",
        fields: [["Location", "Shared"], ["Inheritance Source", "ethernet1/1"], ["Secondary Inheritance Source", "cellular1/1"], ["Primary / Secondary DNS", "inherited"]],
        warn: "APN privé, APN à IP fixe ou mauvaise couverture radio = échec de l'onboarding cellulaire." });
      steps.push(
        { title: "Activer le service ZTP sur Panorama", path: ["Panorama", "Zero Touch Provisioning", "Setup"], window: "General",
          action: "Cadre « General » → ⚙ (Edit).",
          fields: [["ZTP Service", true], ["Panorama FQDN or IP Address", v.panoPublic], ["Peer FQDN or IP Address", v.ha ? v.panoPublic2 : ""]],
          note: "C'est l'adresse publique (ou le FQDN public) que le CSP poussera aux pare-feux ZTP, pas forcément l'IP de management interne." },
      );
      if (v.deploy === "new") steps.push({ title: "Générer le device group et le template ZTP", path: ["Panorama", "Zero Touch Provisioning", "Setup"],
        action: "Bouton « Add Device Group and Template » → saisir les deux noms → OK.",
        fields: [["Device Group", v.dg], ["Template", v.template]],
        note: "Le plugin génère la configuration par défaut de connexion : ethernet1/1 (client DHCP) et sa zone, loopback.900, virtual router, adresse de Panorama, service route, règle de sécurité rule1 et règle NAT ztp-nat." });
      else steps.push({ title: "Réutiliser le device group et le template ZTP existants", path: ["Panorama", "Device Groups / Templates"],
        action: "Pas de nouvelle génération : les pare-feux ZTP seront ajoutés au DG et au template stack ZTP existants.", fields: [["Device Group", v.dg], ["Template", v.template]] });
      steps.push(
        { title: "Créer le template stack (module P03 Template stack)", path: ["Panorama", "Templates"], action: "Add Stack : y placer le template ZTP EN HAUT (priorité la plus forte), puis les templates « métier » du site.",
          fields: [["Templates (ordre)", `${v.template} (1er), puis templates du site`]],
          note: "Dès la 11.2, une option « Automatically push content when software device registers to Panorama » existe sur le stack ; elle n'est pas décrite pour la 11.1." },
        { title: "Commit to Panorama", path: ["Commit", "Commit to Panorama"], action: "Valider avant la synchronisation avec le service ZTP.", fields: [] },
        { title: "Synchroniser avec le service ZTP", path: ["Panorama", "Zero Touch Provisioning", "Setup"],
          action: "Bouton « Sync to ZTP Service » → attendre que « Panorama Sync Status » affiche « In Sync ».", fields: [["Panorama Sync Status", "In Sync"]] },
      );
      const cliRaw = [
        "# --- Mode opérationnel Panorama ---",
        "# Les réglages « General » (ZTP Service, Panorama FQDN/IP, Peer) et le bouton « Sync to ZTP Service » : WebUI uniquement (pas de commande documentée).",
        "request plugins ztp panorama-registration",
        ...(v.deploy === "new" ? [
          `request plugins ztp create dgroup-template device-group ${q(v.dg)}`,
          `request plugins ztp create dgroup-template template ${q(v.template)}`,
        ] : []),
        "",
        "# --- Vérification ---",
        "request plugins ztp ztp-sync-status",
        `show device-group name ${q(v.dg)}`,
        `show template name ${q(v.template)}`,
      ];
      const notes = [
        { type: "warn", title: "Ne pas modifier la configuration ZTP générée", text: `Ne touche pas, dans ${v.template} / ${v.dg}, à : adresse de Panorama, virtual router, ethernet1/1 et sa zone, loopback.900, règle de sécurité rule1, règle NAT ztp-nat, service route. Ce sont eux qui maintiennent la connexion pare-feu → Panorama après le premier push.` },
        { type: "warn", title: "Priorité", text: "Place le DG ZTP et le template ZTP en priorité la plus haute (template en tête du stack, pas de règle parent qui bloquerait rule1) pour qu'aucun autre réglage ne les écrase." },
        { type: "or", title: "Flux réseau à ouvrir", text: `Depuis Internet vers Panorama : TCP 3978 (connexion des pare-feux, logs) et TCP 28443 (distribution logiciel/contenu par Panorama) vers ${v.panoPublic}, NATés vers ${bare(v.panoIp) || "l'IP de management"}. Depuis Panorama vers Internet : HTTPS vers les services cloud Palo Alto Networks (CSP, service ZTP, certificats). Liste exacte des FQDN du service ZTP : à valider sur ta version.` },
        PROXY_NOTE,
      ];
      if (!isIp && v.oldFw) notes.push({ type: "bad", title: "FQDN + pare-feux ≤ 10.1.4", text: "La doc recommande une IP pour ces versions ; si tu gardes un FQDN, ajoute une route statique de destination vers Panorama dans le template, sinon le pare-feu peut se déconnecter après un reboot ou une mise à jour." });
      if (!isIp) notes.push({ type: "or", text: `Le FQDN ${v.panoPublic} doit être résolu par les DNS publics (ceux fournis par le DHCP du site).` });
      notes.push({ type: "or", text: `Commandes « request plugins ztp … » issues de la page « Use the CLI for ZTP Tasks » ; « show device-group/template name » : ${VALIDATE}.` });
      return { steps, cliRaw, notes };
    },
  });

  /* =====================================================================
     P11 · Compte administrateur « installer »
     ===================================================================== */
  register({
    id: "p11-installer",
    module: "P11",
    title: "Compte installateur ZTP (installeradmin)",
    icon: "🦺",
    desc: "Créer le compte limité destiné à l'installateur ou au prestataire sur site : il ne voit que l'écran de saisie série + claim key des pare-feux ZTP.",
    tags: "ztp installer installeradmin admin role custom panorama admin administrator prestataire contractor",
    fields: [
      { id: "adminUser", label: "Nom du compte installateur", type: "text", required: true, default: "ztp-installer", validate: objName, group: "Compte",
        hint: "Un compte par prestataire / société d'installation facilite la traçabilité (Monitor > Logs > Configuration)." },
      { id: "auth", label: "Authentification", type: "select", default: "local",
        options: [["local", "Mot de passe local Panorama"], ["ext", "Authentication Profile (RADIUS, SAML ou TACACS+)"]] },
      { id: "ap", label: "Authentication Profile", type: "text", required: true, default: "AP-RADIUS", validate: objName, show: v => v.auth === "ext" },
      { id: "pwProfile", label: "Password Profile (optionnel, ex. expiration)", type: "text", default: "", validate: objName, show: v => v.auth === "local" },
    ],
    example: { adminUser: "installateur-acme", auth: "local" },
    build(v) {
      const loc = v.auth === "local";
      const steps = [
        { title: "Vérifier le rôle installeradmin", path: ["Panorama", "Admin Roles"], action: "Le rôle « installeradmin » est créé automatiquement à l'installation du plugin ZTP : ne pas le modifier.", fields: [["Admin Role", "installeradmin"]] },
        { title: "Créer le compte installateur", path: ["Panorama", "Administrators"], window: "Administrator", action: "Add, puis OK.",
          fields: [["Name", v.adminUser], ["Authentication Profile", loc ? "None" : v.ap], ["Password / Confirm Password", loc && "(mot de passe robuste, transmis hors bande)"],
            ["Administrator Type", "Custom Panorama Admin"], ["Profile", "installeradmin"], ["Password Profile", loc && v.pwProfile]] },
        { title: "Tester le compte", path: ["Navigateur", "https://<Panorama>"], action: `Après le commit, se connecter avec ${v.adminUser} : seul l'écran Zero Touch Provisioning > Firewall Registration doit être accessible.`, fields: [] },
      ];
      const u = `set mgt-config users ${q(v.adminUser)}`;
      const sets = [`${u} permissions role-based custom profile installeradmin`, !loc && `${u} authentication-profile ${q(v.ap)}`, loc && v.pwProfile && `${u} password-profile ${q(v.pwProfile)}`].filter(Boolean);
      const cliRaw = ["configure", ...sets];
      if (loc) cliRaw.push("", "# --- Ligne interactive : la coller SEULE, puis saisir le mot de passe deux fois ---", `${u} password`);
      cliRaw.push("commit", "exit", "", "# --- Vérification ---", "show admins all");
      const notes = [
        { type: "ok", title: "Usage", text: "Ce compte est fait pour du personnel non-IT ou un installateur : il saisit uniquement la série et la claim key du pare-feu. Il ne voit ni les policies, ni les templates, ni les autres pare-feux." },
        { type: "warn", text: "Ne donne jamais un rôle superuser à l'installateur ; désactive ou supprime le compte à la fin de la campagne de déploiement." },
        { type: "or", text: "Modification limitée à Panorama : un Commit to Panorama suffit." },
      ];
      if (loc) notes.push({ type: "warn", title: "Commande interactive", text: "« set mgt-config users … password » demande le mot de passe au clavier : colle-la seule." });
      return { steps, cli: sets, cliRaw, notes };
    },
  });

  /* =====================================================================
     P11 · Template de connectivité (garder le lien vers Panorama)
     ===================================================================== */
  register({
    id: "p11-template",
    module: "P11",
    title: "Template ZTP : garder la connexion à Panorama",
    icon: "🛰️",
    desc: "Configuration minimale à garantir dans le template stack d'un pare-feu ZTP (ethernet1/1 en DHCP, zone, routage, management, adresse de Panorama) pour qu'il ne perde pas Panorama après le premier push.",
    tags: "ztp template ethernet1/1 dhcp client zone virtual router service route loopback.900 rule1 ztp-nat management dhcp connectivity first push",
    fields: [
      { id: "tplMode", label: "Approche", type: "select", default: "auto", wide: true, group: "Approche",
        options: [["auto", "Template ZTP généré par le plugin (recommandé) + template site en dessous"], ["custom", "Template « non ZTP » construit à la main"]],
        hint: "La doc 11.1 décrit les deux : DG/template générés par « Add Device Group and Template », ou templates cibles où tu configures au moins une interface (de préférence ethernet1/1)." },
      { id: "template", label: "Template ciblé", type: "text", required: true, default: "TPL-ZTP", validate: objName,
        hint: "Mode auto : le template ZTP généré (à contrôler, pas à modifier). Mode manuel : le template que tu construis." },
      { id: "stack", label: "Template stack du site", type: "text", required: true, default: "TS-ZTP-Agences", validate: objName },
      { id: "ztpZone", label: "Zone d'ethernet1/1", type: "text", required: true, default: "untrust", validate: "name", show: v => v.tplMode === "custom", group: "Interface d'onboarding (ethernet1/1)" },
      { id: "vr", label: "Virtual router", type: "text", required: true, default: "default", validate: "name", show: v => v.tplMode === "custom" },
      { id: "panoPublic", label: "Adresse de Panorama (publique)", type: "text", required: true, default: "panorama.acme.fr", validate: pubHost, show: v => v.tplMode === "custom",
        hint: "La même que dans Zero Touch Provisioning > Setup. Sans elle dans le template, le prochain push peut retirer la cible Panorama." },
      { id: "panoPublic2", label: "Adresse du Panorama pair HA (optionnel)", type: "text", default: "", validate: pubHost, show: v => v.tplMode === "custom" },
      { id: "svcRoute", label: "Service route « Panorama » via ethernet1/1", type: "checkbox", default: true, show: v => v.tplMode === "custom",
        hint: "Le pare-feu sort vers Panorama par l'interface data ethernet1/1 tant que le port MGT n'est pas raccordé." },
      { id: "dns1", label: "DNS primaire (vide = DNS reçus du DHCP)", type: "ip", default: "", show: v => v.tplMode === "custom" },
      { id: "dns2", label: "DNS secondaire", type: "ip", default: "", show: v => v.tplMode === "custom" && !!v.dns1 },
      { id: "mgmtMode", label: "Port de management (MGT / eth0)", type: "select", default: "keep", group: "Interface de management (optionnel)",
        options: [["keep", "Ne pas configurer (reste par défaut)"], ["dhcp", "DHCP Client"], ["static", "IP statique"]],
        hint: "Optionnel : la doc propose DHCP Client ou IP statique, à condition que cette interface joigne Panorama." },
      { id: "fwMgmtIp", label: "IP de management (IP/masque)", type: "cidr", required: true, default: "10.20.1.10/24", show: v => v.mgmtMode === "static" },
      { id: "mgmtGw", label: "Passerelle de management", type: "ip", required: true, default: "10.20.1.1", show: v => v.mgmtMode === "static" },
    ],
    example: { tplMode: "auto", template: "TPL-ZTP-Agences", stack: "TS-Agence-Lyon", mgmtMode: "dhcp" },
    build(v) {
      const custom = v.tplMode === "custom";
      const T = TPL(v.template);
      const steps = [];
      if (!custom) {
        steps.push(
          { title: "Contrôler le template ZTP généré", path: ["Network", "Interfaces"], action: `Sélecteur Template = ${v.template} : vérifier les objets générés par le plugin, sans les modifier.`,
            fields: [["ethernet1/1", "Layer3, client DHCP, dans la zone générée"], ["loopback.900", "présent"], ["Virtual Router", "présent, ethernet1/1 et loopback.900 rattachés"],
              ["Device > Setup > Services > Service Route Configuration", "présente"], ["Device > Setup > Management > Panorama Settings", "adresse de Panorama renseignée"]],
            note: "Le détail exact des valeurs générées (noms de zone, adressage de loopback.900) dépend de la version du plugin : à valider sur ta version." },
          { title: "Contrôler le device group ZTP", path: ["Policies", "Security / NAT"], action: "Sélecteur Device Group = DG ZTP : la règle de sécurité « rule1 » et la règle NAT « ztp-nat » doivent être présentes et actives.", fields: [["Security", "rule1"], ["NAT", "ztp-nat"]] },
          { title: "Ordonner le template stack", path: ["Panorama", "Templates"], window: "Template Stack", action: `Ouvrir ${v.stack} : ${v.template} en première position (priorité la plus forte), templates du site en dessous.`,
            fields: [["Templates", `1. ${v.template}  2. (templates du site)`]] },
        );
      } else {
        steps.push(
          { title: "ethernet1/1 en client DHCP", path: ["Network", "Interfaces", "Ethernet"], window: "Ethernet Interface", action: `Template = ${v.template} → ethernet1/1.`,
            fields: [["Interface Type", "Layer3"], ["Config > Virtual Router", v.vr], ["Config > Security Zone", v.ztpZone], ["IPv4 > Type", "DHCP Client"],
              ["Automatically create default route pointing to default gateway provided by server", true]],
            note: "La doc demande au minimum une interface configurée, de préférence ethernet1/1 (celle qui a servi à l'onboarding). Tu pourras la retirer plus tard si elle n'est plus utile." },
          { title: "Zone d'ethernet1/1", path: ["Network", "Zones"], action: `Template = ${v.template} → Add.`, fields: [["Name", v.ztpZone], ["Type", "Layer3"], ["Interfaces", "ethernet1/1"]] },
          { title: "Virtual router", path: ["Network", "Virtual Routers"], action: `Template = ${v.template} → ${v.vr} → onglet Router Settings.`, fields: [["Interfaces", "ethernet1/1"]] },
          { title: "Adresse de Panorama", path: ["Device", "Setup", "Management"], window: "Panorama Settings", action: `Template = ${v.template} → cadre Panorama Settings → ⚙.`,
            fields: [["Panorama Servers", [v.panoPublic, v.panoPublic2].filter(Boolean)]] },
        );
        if (v.svcRoute) steps.push({ title: "Service route vers Panorama", path: ["Device", "Setup", "Services"], window: "Service Route Configuration",
          action: `Template = ${v.template} → Service Route Configuration → Customize → IPv4 → Panorama.`, fields: [["Source Interface", "ethernet1/1"], ["Source Address", "(adresse DHCP de l'interface)"]] });
        if (v.dns1) steps.push({ title: "Serveurs DNS", path: ["Device", "Setup", "Services"], window: "Services", action: `Template = ${v.template}.`, fields: [["Primary DNS Server", v.dns1], ["Secondary DNS Server", v.dns2]] });
        steps.push({ title: "Template stack", path: ["Panorama", "Templates"], action: `Ajouter ${v.template} au stack ${v.stack} (module P03 Template stack).`, fields: [["Template Stack", v.stack], ["Template", v.template]] });
      }
      if (v.mgmtMode !== "keep") steps.push({ title: "Interface de management", path: ["Device", "Setup", "Interfaces"], window: "Management Interface Settings",
        action: `Template = ${v.template} → Management.`,
        fields: v.mgmtMode === "dhcp" ? [["IP Type", "DHCP Client"]] : [["IP Type", "Static"], ["IP Address", bare(v.fwMgmtIp)], ["Netmask", maskOf(v.fwMgmtIp)], ["Default Gateway", v.mgmtGw]],
        note: "Garantis que cette interface joint Panorama avant de pousser, sinon l'automated commit recovery (ou la perte de connexion) te forcera à intervenir sur site." });

      const cli = [];
      if (custom) {
        cli.push(
          `${T} network interface ethernet ethernet1/1 layer3 dhcp-client create-default-route yes`,
          `${T} vsys vsys1 zone ${q(v.ztpZone)} network layer3 ethernet1/1`,
          `${T} vsys vsys1 import network interface ethernet1/1`,
          `${T} network virtual-router ${q(v.vr)} interface ethernet1/1`,
          `${T} deviceconfig system panorama local-panorama panorama-server ${v.panoPublic}`,
          v.panoPublic2 && `${T} deviceconfig system panorama local-panorama panorama-server-2 ${v.panoPublic2}`,
          v.svcRoute && UNSURE,
          v.svcRoute && `${T} deviceconfig system route service panorama source interface ethernet1/1`,
          v.dns1 && `${T} deviceconfig system dns-setting servers primary ${v.dns1}`,
          v.dns1 && v.dns2 && `${T} deviceconfig system dns-setting servers secondary ${v.dns2}`,
        );
      } else {
        cli.push(`# Template ${v.template} généré par le plugin : rien à saisir, contrôle uniquement (show template name ${v.template}).`);
      }
      if (v.mgmtMode === "dhcp") cli.push(UNSURE, `${T} deviceconfig system type dhcp-client send-hostname yes`);
      if (v.mgmtMode === "static") cli.push(`${T} deviceconfig system ip-address ${bare(v.fwMgmtIp)} netmask ${maskOf(v.fwMgmtIp)} default-gateway ${v.mgmtGw}`);
      if (custom || v.mgmtMode !== "keep") cli.push(`set template-stack ${q(v.stack)} templates ${q(v.template)}`);
      const filtered = cli.filter(Boolean);
      const notes = [
        { type: "or", title: "Ce qui maintient le lien", text: "Après la première connexion, Panorama pousse le DG et le template stack (Auto Push on 1st Connect). Si ce push ne contient pas une interface vers Internet, une route par défaut et l'adresse de Panorama, le pare-feu perd Panorama et l'automated commit recovery revient à la config précédente (ou il faut intervenir sur site)." },
        { type: "warn", title: "À ne pas faire", text: "Ne déplace pas un pare-feu ZTP vers un autre DG / template stack que ceux qui contiennent la config ZTP ; ne modifie pas ethernet1/1, sa zone, loopback.900, rule1, ztp-nat, la service route ni l'adresse de Panorama générés par le plugin." },
        { type: "or", text: "Pas de push à ce stade : les pare-feux ZTP ne sont pas encore connectés. Le push se fera automatiquement à leur première connexion (module « Ajouter des pare-feux ZTP »)." },
      ];
      if (custom) notes.push({ type: "warn", title: "Template manuel", text: "La doc 11.1 admet un template « non ZTP » mais le plugin génère aussi loopback.900, rule1 et ztp-nat : sans équivalent, vérifie sur un pare-feu pilote que la connexion à Panorama survit au premier push avant de généraliser." });
      if (custom && v.svcRoute) notes.push({ type: "or", text: `Syntaxe de la service route « panorama » : ${VALIDATE}.` });
      return { steps, cli: filtered, notes, verify: [`show template name ${q(v.template)}`, `show template-stack name ${q(v.stack)}`] };
    },
  });

  /* =====================================================================
     P11 · Ajouter des pare-feux ZTP (série + claim key, CSV)
     ===================================================================== */
  register({
    id: "p11-add-fw",
    module: "P11",
    title: "Ajouter des pare-feux ZTP (série + claim key)",
    icon: "📦",
    desc: "Enregistrer un ou plusieurs pare-feux ZTP (saisie unitaire ou import CSV), contrôler leur enregistrement auprès du CSP, puis les réassocier au device group et au template stack ZTP avec Auto Push on 1st Connect.",
    tags: "ztp add firewall serial claim key firewall registration register csv import bulk reassociate auto push on 1st connect to sw version",
    fields: [
      { id: "mode", label: "Méthode", type: "select", default: "single", group: "Pare-feux",
        options: [["single", "Un pare-feu (saisie unitaire)"], ["csv", "Plusieurs pare-feux (import CSV)"]] },
      { id: "ztpModel", label: "Modèle", type: "select", default: "pa400", options: MODELS },
      { id: "fwSerial", label: "Numéro de série", type: "text", required: true, default: "026701001234", validate: serial, show: v => v.mode === "single",
        hint: "Sur l'étiquette du boîtier / le bon de livraison : inutile de démarrer le pare-feu." },
      { id: "claimKey", label: "Claim key (8 chiffres)", type: "text", required: true, default: "12345678", validate: claim, show: v => v.mode === "single",
        hint: "Clé numérique de 8 chiffres collée au dos du pare-feu. Photographie-la à la réception du matériel." },
      { id: "ztpList", label: "Pare-feux (une ligne par pare-feu : série, claim key)", type: "textarea", required: true, wide: true, show: v => v.mode === "csv",
        default: "026701001234, 12345678\n026701001235, 23456789\n026701001236, 34567890",
        hint: "Lignes commençant par # ignorées. La doc conseille d'exporter d'abord un fichier vide (PDF/CSV) pour reprendre les en-têtes exacts.",
        validate: t => {
          const r = rows(t); if (!r.length) return "Au moins un pare-feu";
          const seen = new Set();
          for (const [s, k] of r) {
            if (serial(s)) return `« ${s} » : ${serial(s)}`;
            if (!k || claim(k)) return `Série ${s} : ${claim(k || "")}`;
            if (seen.has(s)) return `Série en double : ${s}`; seen.add(s);
          }
          return null;
        } },
      { id: "byInstaller", label: "Saisie faite par l'installateur (compte installeradmin)", type: "checkbox", default: false, wide: true },
      { id: "dg", label: "Device group ZTP", type: "text", required: true, default: "DG-ZTP", validate: objName, group: "Association (Reassociate)" },
      { id: "stack", label: "Template stack (contenant le template ZTP)", type: "text", required: true, default: "TS-ZTP-Agences", validate: objName },
      { id: "autoPush", label: "Auto Push on 1st Connect", type: "checkbox", default: true,
        hint: "Indispensable en ZTP : c'est ce push automatique qui livre la configuration du site à la première connexion." },
      { id: "toSw", label: "To SW Version (optionnel)", type: "text", default: "", validate: swVer,
        hint: "Le pare-feu mettra à jour (ou rétrogradera !) PAN-OS vers cette version. Doit être ≥ 10.0.1 et ≤ version de Panorama (11.1.x)." },
    ],
    example: { mode: "csv", ztpModel: "pa400", byInstaller: true, dg: "DG-ZTP-Agences", stack: "TS-Agences", toSw: "11.1.6" },
    build(v) {
      const list = v.mode === "single" ? [{ s: v.fwSerial, k: v.claimKey }] : rows(v.ztpList).map(([s, k]) => ({ s, k }));
      const serials = list.map(x => x.s);
      const who = v.byInstaller ? "Compte installateur (installeradmin)" : "Administrateur superuser / Panorama admin";
      const steps = [];
      if (v.mode === "single") steps.push({ title: "Ajouter le pare-feu ZTP", path: ["Panorama", "Zero Touch Provisioning", "Firewall Registration"], window: "Add a new ZTP firewall",
        action: `Connecté en : ${who}. Bouton Add (« Add a new ZTP firewall »), puis OK.`,
        fields: [["Serial Number", v.fwSerial], ["Claim Key", v.claimKey]],
        note: "Selon la version de la doc 11.1, le menu est libellé « Panorama > Firewall Registration » ou « Panorama > Zero Touch Provisioning > Firewall Registration ». Le champ Auth Code n'existe qu'à partir de la 11.2." });
      else {
        const csv = ["serial-number,claim-key", ...list.map(x => `${x.s},${x.k}`)].join("\n");
        steps.push(
          { title: "Exporter un fichier d'import vide", path: ["Panorama", "Zero Touch Provisioning", "Firewall Registration"], action: "Bouton PDF/CSV → export au format CSV : il donne les en-têtes exacts attendus par ta version du plugin.", fields: [] },
          { title: "Préparer le fichier CSV", path: ["Poste d'administration"], action: "Colonne 1 = numéro de série, colonne 2 = claim key. Remplace la ligne d'en-tête ci-dessous par celle du fichier exporté.",
            fields: [["ztp-import.csv", csv]], note: "En-têtes indicatifs : reprends ceux du fichier exporté (à valider sur ta version)." },
          { title: "Importer le fichier", path: ["Panorama", "Zero Touch Provisioning", "Firewall Registration"], action: `Connecté en : ${who}. Import → Browse → ztp-import.csv → OK.`, fields: [["Pare-feux importés", serials.length]] },
        );
      }
      steps.push(
        { title: "Enregistrer auprès du CSP", path: ["Panorama", "Zero Touch Provisioning", "Firewall Registration"], action: "Sélectionner le(s) pare-feu(x) → Register → Yes.", fields: [["Pare-feux", serials]] },
        { title: "Contrôler l'enregistrement", path: ["Panorama", "Zero Touch Provisioning", "Firewall Registration"], action: "Colonne / bouton « Registration Status » : chaque pare-feu doit être enregistré (condition pour qu'il obtienne son certificat de device).",
          fields: [["Registration Status", "Success / Registered"]] },
        { title: "Vérifier l'apparition dans Managed Devices", path: ["Panorama", "Managed Devices", "Summary"], action: "Connecté en administrateur : les séries apparaissent, Device State = Disconnected (normal, le pare-feu n'est pas encore allumé).",
          fields: [["Device State", "Disconnected (attendu)"], ["Colonne To SW Version", "vérifier qu'aucune montée/descente de version non voulue n'est prévue"]] },
        { title: "Réassocier DG et template stack", path: ["Panorama", "Managed Devices", "Summary"], window: "Reassociate",
          action: "Sélectionner le(s) pare-feu(x) ZTP → Reassociate.",
          fields: [["Device Group", v.dg], ["Template Stack", v.stack], ["Auto Push on 1st Connect", v.autoPush], ["To SW Version", v.toSw]] },
      );
      const cliRaw = ["# --- Mode opérationnel Panorama ---"];
      if (v.mode === "single") cliRaw.push(`request plugins ztp firewall-add ${v.fwSerial} claim-key ${v.claimKey}`);
      else cliRaw.push("# Import CSV (fichier préalablement copié sur Panorama)", "request plugins ztp ztp-add-import import-path <chemin/ztp-import.csv>",
        "# ou ajout unitaire :", ...list.map(x => `request plugins ztp firewall-add ${x.s} claim-key ${x.k}`));
      cliRaw.push("show plugins ztp device-add-list", "", "# Enregistrement auprès du CSP / service ZTP",
        ...list.map(x => `request plugins ztp firewall-registration firewall ${x.s} claim-key ${x.k}`),
        "show plugins ztp device-reg-status",
        "",
        "# --- Association DG / template stack (équivalent de Reassociate) ---", UNSURE,
        "configure",
        ...serials.map(s => `set device-group ${q(v.dg)} devices ${s}`),
        ...serials.map(s => `set template-stack ${q(v.stack)} devices ${s}`),
        "# Auto Push on 1st Connect et To SW Version : WebUI uniquement (fenêtre Reassociate)",
        "commit", "exit",
        "", "# --- Vérification ---", "show devices all", "request plugins ztp ztp-service-info");
      const notes = [
        { type: "bad", title: "N'allume pas encore le pare-feu", text: "Ne mets pas le pare-feu sous tension avant d'avoir terminé enregistrement + association + commit : sinon l'onboarding échoue et il faut le remettre en configuration d'usine." },
        { type: "warn", title: "To SW Version", text: "ZTP exige PAN-OS 10.0.1 ou plus et une version ≤ à celle de Panorama. Une valeur erronée provoque une montée ou une descente de version (voire une boucle de mise à jour) à la première connexion." },
        { type: "warn", text: `Garde ces pare-feux dans ${v.dg} et ${v.stack} (qui contient le template ZTP) : les déplacer peut couper la connexion à Panorama ou faire revenir leur configuration.` },
        { type: "or", title: "Après la première connexion", text: "Activer la licence Support sur le pare-feu, activer les licences complémentaires depuis Panorama, puis installer les contenus (Panorama > Device Deployment > Dynamic Updates > Check Now > Download > Install, cibler les nouveaux pare-feux)." },
        { type: "or", text: "Un pare-feu ajouté par ZTP ne peut pas être migré vers un autre Panorama. Les pare-feux onboardés par ZTP ne supportent pas la HA telle quelle : pour une paire HA, suivre la procédure « Configure ZTP for Firewalls in HA » (actif/passif uniquement, un template stack par pair)." },
        { type: "or", text: `Commandes « request plugins ztp … » d'après la page « Use the CLI for ZTP Tasks » ; association en CLI : ${VALIDATE}.` },
      ];
      if (v.ztpModel === "other") notes.unshift({ type: "bad", title: "Modèle non compatible ZTP", text: "La doc 11.1 liste : PA-400, PA-1400, PA-3400, PA-5400/PA-5450 et les références -ZTP des PA-820/850 et PA-3220/3250/3260. Un modèle non -ZTP ou un VM-Series s'ajoute par la méthode classique (module P02 Ajouter un pare-feu)." });
      if (!v.autoPush) notes.unshift({ type: "warn", title: "Auto Push désactivé", text: "Sans Auto Push on 1st Connect, le pare-feu se connecte avec la seule config ZTP : il faudra pousser DG et stack manuellement une fois « Connected »." });
      const push = v.autoPush ? [] : ["# Une fois le(s) pare-feu(x) « Connected » :", `commit-all shared-policy device-group ${q(v.dg)} include-template yes`];
      return { steps, cliRaw, push, notes };
    },
  });

  /* =====================================================================
     P11 · Sur site : checklist installateur + dépannage (noCommit)
     ===================================================================== */
  const SYMPT = [
    ["none", "Aucun : déroulé nominal / checklist"],
    ["reg", "Registration Status en échec (CSP)"],
    ["disc", "Pare-feu toujours « Disconnected » après le démarrage"],
    ["lost", "Connecté puis perdu après le premier push"],
    ["loop", "Mises à jour / redémarrages en boucle"],
    ["local", "Quelqu'un a fait un commit local sur le pare-feu"],
  ];
  register({
    id: "p11-onsite",
    module: "P11",
    title: "Mise en service sur site & dépannage ZTP",
    icon: "🧰",
    desc: "Checklist de l'installateur (branchement d'ethernet1/1, mise sous tension, attente), ce qui se passe côté cloud et Panorama, vérifications et commandes de diagnostic par symptôme.",
    tags: "ztp onsite installer checklist power on ethernet1/1 dhcp troubleshooting show system ztp status show panorama-status ms.log registration disconnected factory reset",
    noCommit: true,
    fields: [
      { id: "fwSerial", label: "Série du pare-feu", type: "text", required: true, default: "026701001234", validate: serial, group: "Pare-feu" },
      { id: "fwName", label: "Nom / site (optionnel)", type: "text", validate: "hostname", default: "FW-Agence-Lyon" },
      { id: "ztpModel", label: "Modèle", type: "select", default: "pa400", options: MODELS },
      { id: "panoPublic", label: "Adresse publique de Panorama", type: "text", required: true, default: "panorama.acme.fr", validate: pubHost },
      { id: "mgmtCable", label: "Port MGT aussi raccordé (réseau de management du site)", type: "checkbox", default: false },
      { id: "symptom", label: "Symptôme", type: "select", default: "none", options: SYMPT, wide: true, group: "Dépannage" },
    ],
    example: { fwSerial: "026701001234", fwName: "FW-Agence-Lyon", ztpModel: "pa400", panoPublic: "pano.acme-retail.fr", symptom: "disc" },
    build(v) {
      const steps = [
        { title: "Avant le déplacement (administrateur)", path: ["Panorama", "Managed Devices", "Summary"],
          action: "Le pare-feu doit être enregistré (Registration Status OK), associé au DG/stack ZTP avec Auto Push on 1st Connect, et le tout commité.",
          fields: [["Série", v.fwSerial], ["Device State attendu", "Disconnected (pas encore allumé)"]] },
        { title: "Prérequis réseau du site", path: ["Site"], action: "Vérifier avec le client avant l'intervention.",
          fields: [["DHCP sur le lien Internet", "obligatoire (IP, passerelle, DNS publics)"], ["Proxy web explicite", "interdit"], ["Sortie Internet", "HTTPS vers les services Palo Alto Networks + TCP 3978 / 28443 vers " + v.panoPublic]] },
        { title: "Branchement", path: ["Pare-feu", "Face avant"], action: "Câbler ethernet1/1 vers la box / le routeur Internet du site (port qui distribue le DHCP)." + (v.mgmtCable ? " Câbler aussi le port MGT sur le réseau de management." : ""),
          fields: [["ethernet1/1", "→ accès Internet (DHCP)"], ["MGT", v.mgmtCable ? "→ réseau de management du site" : "(non utilisé)"]],
          warn: "Ne pas se connecter à la WebUI/CLI du pare-feu et ne JAMAIS faire de commit local : cela désactive ZTP." },
        { title: "Mise sous tension et attente", path: ["Pare-feu"], action: "Allumer, puis attendre sans intervenir. Le pare-feu obtient une IP en DHCP sur ethernet1/1, demande son certificat de device au CSP, contacte le service ZTP qui lui donne l'adresse de Panorama, se connecte à Panorama qui pousse DG + template stack (puis la version To SW Version si définie).",
          fields: [["Durée indicative", "de l'ordre de 15 à 30 min sans changement de version ; nettement plus avec une mise à jour PAN-OS (plusieurs redémarrages). Valeurs non documentées : à valider sur ta version"]] },
        { title: "Confirmation (administrateur)", path: ["Panorama", "Managed Devices", "Summary"], action: "Rafraîchir : Device State = Connected, Shared Policy et Template = In sync.",
          fields: [["Device State", "Connected"], ["Shared Policy / Template", "In sync"]] },
        { title: "Finalisation", path: ["Panorama", "Device Deployment"], action: "Activer la licence Support sur le pare-feu, puis les licences et les contenus depuis Panorama (Licenses, Dynamic Updates → Install sur le nouveau pare-feu).", fields: [] },
      ];
      const fw = ["# --- CÔTÉ PARE-FEU (console, en lecture seule : AUCUN commit) ---", "show system ztp status", "show panorama-status", "show system info | match \"serial|model|sw-version|ztp\"", "show interface ethernet1/1"];
      const pano = ["# --- CÔTÉ PANORAMA ---", "show plugins ztp device-reg-status", "request plugins ztp ztp-service-info", "request plugins ztp ztp-sync-status", `show devices all | match ${v.fwSerial}`];
      const extra = [];
      const notes = [];
      switch (v.symptom) {
        case "reg":
          notes.push({ type: "warn", title: "Échec d'enregistrement CSP", text: "Causes fréquentes : série ou claim key mal recopiée, pare-feu non rattaché au compte CSP, Panorama non associé au service ZTP (Assets > ZTP Service), certificat de device Panorama expiré/absent." });
          extra.push("# Corriger puis relancer l'enregistrement", `request plugins ztp firewall-re-enter-info firewall ${v.fwSerial} claim-key <CLAIM-KEY>`, `request plugins ztp firewall-register-retry firewall ${v.fwSerial} claim-key <CLAIM-KEY>`, "tail follow yes mp-log ms.log");
          break;
        case "disc":
          notes.push({ type: "warn", title: "Pare-feu non connecté", text: `Vérifier dans l'ordre : IP DHCP reçue sur ethernet1/1 (show interface), DNS publics fonctionnels, absence de proxy, statut ZTP (show system ztp status), puis joignabilité de ${v.panoPublic} en TCP 3978 depuis Internet (NAT, règle du pare-feu périmétrique de Panorama). Côté Panorama : Sync Status « In Sync » et adresse publique correcte dans Zero Touch Provisioning > Setup.` });
          extra.push("# Côté pare-feu", `ping host ${v.panoPublic}`, "show dhcp client state all", "# Côté Panorama", "tail follow yes mp-log ms.log", "show panorama-status");
          break;
        case "lost":
          notes.push({ type: "bad", title: "Connexion perdue après le premier push", text: "Le template stack ou le DG poussé a écrasé la configuration ZTP (ethernet1/1, zone, route, loopback.900, rule1, ztp-nat, service route, adresse Panorama) ou le pare-feu a été placé hors du DG/stack ZTP. Remets le template ZTP en tête du stack, corrige, puis recommence (l'automated commit recovery peut avoir restauré la config précédente)." });
          extra.push("# Côté Panorama", `show devices all | match ${v.fwSerial}`, "# Monitor > Logs > System : rechercher les événements de commit/push du pare-feu");
          break;
        case "loop":
          notes.push({ type: "warn", title: "Boucle de mise à jour", text: "« To SW Version » est définie sur une version incohérente (supérieure à Panorama, image absente ou chemin de mise à jour impossible). Corrige la valeur dans Managed Devices > Summary > Reassociate, commit, puis laisse le pare-feu terminer." });
          extra.push("show jobs all", "# Côté pare-feu", "show system info | match sw-version");
          break;
        case "local":
          notes.push({ type: "bad", title: "Commit local = ZTP désactivé", text: "Le pare-feu ne participera plus au ZTP. Il faut réactiver la machine à états ZTP (soft factory reset, la configuration est effacée) ou le remettre en configuration d'usine, puis le laisser redémarrer sans intervention." });
          extra.push("# Côté pare-feu — EFFACE LA CONFIGURATION", ["pa800z", "pa3200z"].includes(v.ztpModel) ? "# PA-800-ZTP / PA-3200-ZTP : pas de réactivation CLI documentée → remise en configuration d'usine (maintenance mode > Factory Reset)" : "set system ztp enable");
          break;
        default:
          notes.push({ type: "ok", title: "Déroulé nominal", text: "Sur site, l'installateur ne fait que brancher ethernet1/1 et allumer. Toute la configuration vient de Panorama." });
      }
      notes.push(
        { type: "or", title: "Désactiver ZTP (pare-feu à gérer autrement)", text: `Commande sur ce modèle : « ${ztpOff(v.ztpModel)} ». Elle déclenche une remise à zéro logicielle (configuration effacée).${v.ztpModel === "other" ? " Modèle non compatible ZTP : commande non applicable." : ""}` },
        PROXY_NOTE,
        { type: "or", text: `Commandes issues de « Use the CLI for ZTP Tasks » (show system ztp status, show panorama status, request plugins ztp …) ; ${VALIDATE} pour les autres (ping, show dhcp client, show interface). ${DOCREF}` },
      );
      const cliRaw = [...fw, "", ...pano];
      if (extra.length) cliRaw.push("", `# --- Symptôme : ${(SYMPT.find(x => x[0] === v.symptom) || [, ""])[1]} ---`, ...extra);
      return { steps, cliRaw, notes };
    },
  });
})();
