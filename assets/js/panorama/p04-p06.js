/* PANW Config Builder — Panorama 11.1
   P04 « Device groups », P05 « Collecte & transfert de logs », P06 « Utilisation des logs »
   Source : EDU-220 11.1 (MOD-04, MOD-05, MOD-06, Annexe A) et Labs 4 à 6 du Lab Guide.
   CLI = mode configuration de Panorama ; `push` = commandes commit-all exécutées après le commit Panorama. */
(function () {
  const { register, q, members, yn } = PAN.cfg;
  const V = PAN.cfg.V;

  PAN.cfg.category("P04", "Device groups");
  PAN.cfg.category("P05", "Collecte & transfert de logs");
  PAN.cfg.category("P06", "Utilisation des logs");

  /* =====================================================================
     Helpers communs
     ===================================================================== */
  const SERIAL = v => /^\d{12,15}$/.test(String(v).trim()) ? null : "Numéro de série : 12 à 15 chiffres (Dashboard > General Information)";
  const serialList = arr => {
    for (const s of arr) { const e = SERIAL(s); if (e) return `« ${s} » : ${e}`; }
    return new Set(arr).size === arr.length ? null : "Numéro de série en double";
  };
  const nameList = arr => {
    for (const x of arr) { const e = V.name(x); if (e) return `« ${x} » : ${e}`; }
    return new Set(arr).size === arr.length ? null : "Nom en double";
  };
  const optName = v => (v === "" || v == null) ? null : V.name(v);
  const ipOnly = s => String(s || "").split("/")[0].trim();
  const ipOrCidr = v => V.ipcidr(v);
  const base = v => v.loc === "shared" ? "shared" : `device-group ${q(v.dg)}`;
  const where = v => v.loc === "shared" ? "Shared" : v.dg;
  const pickDg = dg => `Sélectionner « ${dg} » dans la liste déroulante Device Group en haut de la page.`;
  const pushDg = dg => `commit-all shared-policy device-group ${q(dg)}`;
  const pushTs = ts => `commit-all template-stack name ${q(ts)}`;
  const pushCg = cg => `commit-all log-collector-config log-collector-group ${q(cg)}`;
  const uniq = a => [...new Set(a.filter(Boolean))];
  const TOVAL = "à valider avec « ? » (auto-complétion) sur ta version";
  const LOCS = [["dg", "Device Group"], ["shared", "Shared (tous les device groups)"]];
  const COLORS = [["color1", "Red"], ["color2", "Green"], ["color3", "Blue"], ["color4", "Yellow"], ["color5", "Copper"], ["color6", "Orange"],
    ["color7", "Purple"], ["color8", "Gray"], ["color9", "Light Green"], ["color10", "Cyan"], ["color11", "Light Gray"], ["color12", "Blue Gray"],
    ["color13", "Lime"], ["color14", "Black"], ["color15", "Gold"], ["color16", "Brown"]];
  const colorName = c => (COLORS.find(x => x[0] === c) || [, c])[1];
  const preBlock = s => `<pre style="margin:8px 0 0;white-space:pre-wrap;font-family:var(--mono,monospace);font-size:.9em">${PAN.esc(s)}</pre>`;

  /* =====================================================================
     P04 · Device group (création + parent + template de référence)
     ===================================================================== */
  register({
    id: "p04-dg",
    module: "P04",
    title: "Device group & hiérarchie",
    icon: "🗂️",
    desc: "Créer un device group (et son parent), y rattacher les pare-feux, ajouter un template de référence pour disposer des zones et définir le master device User-ID.",
    tags: "device group dg parent ancestor descendant hierarchy reference template master device shared",
    fields: [
      { id: "dg", label: "Nom du device group", type: "text", required: true, validate: "name", default: "HQ-DG",
        hint: "Unique dans tout Panorama, même sous des parents différents. Ex. par site, région ou fonction." },
      { id: "dgDesc", label: "Description", type: "text", default: "Objets et règles des pare-feux du siège", hint: "Optionnelle mais fortement conseillée dès qu'il y a beaucoup de DG." },
      { id: "parentDg", label: "Parent Device Group (vide = Shared)", type: "text", validate: optName, default: "Corp-DG", group: "Hiérarchie",
        hint: "Le DG hérite des objets et règles du parent (ancêtre). 4 niveaux max sous Shared, 1 024 DG max." },
      { id: "createParent", label: "Créer aussi le device group parent", type: "checkbox", default: true, show: v => !!v.parentDg },
      { id: "parentDesc", label: "Description du parent", type: "text", default: "Objets et règles communs à tous les pare-feux", show: v => !!v.parentDg && v.createParent },
      { id: "fwSerial", label: "Pare-feu à rattacher (n° de série)", type: "text", validate: SERIAL, default: "012801000201", group: "Pare-feux membres",
        hint: "Un pare-feu n'appartient qu'à UN seul device group. Laisser vide pour un DG « structurel » sans pare-feu." },
      { id: "fwOthers", label: "Autres pare-feux (séparés par des virgules)", type: "list", validate: serialList, placeholder: "012801000202, 012801000203" },
      { id: "template", label: "Template de référence (zones)", type: "text", validate: optName, default: "Global-Settings", group: "Template de référence & User-ID",
        hint: "Permet de choisir les zones source/destination dans les règles d'un DG qui ne contient aucun pare-feu." },
      { id: "refOn", label: "Ajouter le template de référence sur", type: "select", default: "parent",
        options: [["parent", "le DG parent (ancêtre sans pare-feu)"], ["dg", "ce device group"], ["both", "les deux"]], show: v => !!v.template },
      { id: "master", label: "Définir le pare-feu comme Master Device (groupes User-ID dans les règles)", type: "checkbox", default: false, show: v => !!v.fwSerial },
    ],
    build(v) {
      const fws = uniq([v.fwSerial, ...v.fwOthers]);
      const parent = v.parentDg || "";
      const mkParent = parent && v.createParent;
      const refParent = v.template && mkParent && (v.refOn === "parent" || v.refOn === "both");
      const refDg = v.template && (v.refOn === "dg" || v.refOn === "both" || (!mkParent && v.refOn === "parent"));
      const steps = [];
      if (mkParent) steps.push({ title: `Créer le device group parent ${parent}`, path: ["Panorama", "Device Groups"], window: "Device Group",
        action: "Cliquer sur Add en bas de la liste.",
        fields: [["Name", parent], ["Description", v.parentDesc], ["Parent Device Group", "Shared"], ["Devices", "(ne cocher aucun pare-feu)"], ["Reference Templates (Add)", refParent ? v.template : ""]],
        note: "Dès le premier DG créé, les onglets Policies et Objects apparaissent dans l'interface Panorama." });
      steps.push({ title: `Créer le device group ${v.dg}`, path: ["Panorama", "Device Groups"], window: "Device Group",
        action: parent ? `Sélectionner la ligne ${parent} SANS l'ouvrir, puis cliquer sur Add : le parent est pré-rempli.` : "Cliquer sur Add.",
        fields: [["Name", v.dg], ["Description", v.dgDesc], ["Parent Device Group", parent || "Shared"], ["Devices (cocher)", fws],
          ["Reference Templates (Add)", refDg ? v.template : ""], ["Master Device", v.master && v.fwSerial ? v.fwSerial : ""]],
        note: "Seuls les pare-feux qui ne sont encore dans aucun device group sont proposés dans la liste Devices." });
      steps.push({ title: "Contrôler la hiérarchie", path: ["Panorama", "Device Groups"],
        action: `Vérifier que ${v.dg} apparaît en retrait sous ${parent || "Shared"}. Si le parent est faux : ouvrir ${v.dg} et changer Parent Device Group (le DG est déplacé avec son contenu).`, fields: [] });

      const cli = [];
      if (mkParent) {
        cli.push(`# Device group parent (créé sous Shared)`, `set device-group ${q(parent)} description ${q(v.parentDesc || parent)}`);
        if (refParent) cli.push(`set device-group ${q(parent)} reference-templates ${q(v.template)}`);
      }
      cli.push(`# Device group ${v.dg}`, `set device-group ${q(v.dg)} description ${q(v.dgDesc || v.dg)}`);
      fws.forEach(s => cli.push(`set device-group ${q(v.dg)} devices ${s}`));
      if (refDg) cli.push(`set device-group ${q(v.dg)} reference-templates ${q(v.template)}`);
      if (v.master && v.fwSerial) cli.push(`set device-group ${q(v.dg)} master-device device ${v.fwSerial}`);
      if (parent) cli.push(`# Rattachement au parent (la hiérarchie est stockée hors config « set » : commande opérationnelle — ${TOVAL})`,
        `run request move-dg entry name ${q(v.dg)} new-parent-dg ${q(parent)}`);

      const notes = [
        { type: "or", title: "Héritage", text: `${v.dg} hérite de tout ce qui est défini dans ${parent ? parent + " puis " : ""}Shared. Un objet de même nom défini plus bas dans la hiérarchie l'emporte par défaut (voir « Override d'objet hérité »).` },
        { type: "warn", text: "Planifie l'arborescence (géographie, fonction, département) AVANT le déploiement : la restructurer ensuite est long et risqué." },
      ];
      if (!fws.length && !refDg && !refParent) notes.push({ type: "warn", title: "Zones introuvables", text: "DG sans pare-feu ni template de référence : les listes Source/Destination Zone des règles seront vides." });
      if (v.master) notes.push({ type: "or", text: "Le Master Device fournit à Panorama les groupes d'utilisateurs (User-ID) utilisables dans les règles et rapports du DG." });
      notes.push({ type: "or", text: "Syntaxes à valider : « reference-templates », « master-device » et « request move-dg ». Le chemin WebUI reste la méthode de référence." });
      const push = fws.length ? [pushDg(v.dg)] : [];
      return { steps, cli, push, notes, verify: [`show devicegroups name ${q(v.dg)}`, "show dg-hierarchy"] };
    },
  });

  /* =====================================================================
     P04 · Hiérarchie multi-sites (arborescence complète)
     ===================================================================== */
  function parseTree(txt) {
    const nodes = [], errs = [], stack = [];
    String(txt || "").split(/\r?\n/).forEach((raw, i) => {
      if (!raw.trim() || /^\s*#/.test(raw)) return;
      const ind = raw.match(/^[\t ]*/)[0].replace(/\t/g, "  ").length;
      const m = /^\s*([^:|]+?)\s*(?::\s*([^|]*?))?\s*(?:\|\s*(.*))?$/.exec(raw);
      if (!m) { errs.push(`Ligne ${i + 1} illisible`); return; }
      const lvl = Math.floor(ind / 2);
      const name = m[1].trim();
      const fws = (m[2] || "").split(",").map(s => s.trim()).filter(Boolean);
      if (lvl > stack.length) { errs.push(`Ligne ${i + 1} (« ${name} ») : indentation trop profonde (2 espaces par niveau)`); return; }
      stack.length = lvl;
      const parent = lvl ? stack[lvl - 1] : null;
      nodes.push({ name, lvl, parent, fws, desc: (m[3] || "").trim(), line: i + 1 });
      stack.push(name);
    });
    return { nodes, errs };
  }
  const treeV = txt => {
    const { nodes, errs } = parseTree(txt);
    if (errs.length) return errs[0];
    if (!nodes.length) return "Au moins un device group";
    const seen = new Set(), sns = new Set();
    for (const n of nodes) {
      const e = V.name(n.name); if (e) return `Ligne ${n.line} : ${e}`;
      if (n.name.toLowerCase() === "shared") return `Ligne ${n.line} : « Shared » existe déjà, c'est la racine implicite`;
      if (seen.has(n.name)) return `Ligne ${n.line} : « ${n.name} » en double (les noms de DG sont uniques)`;
      seen.add(n.name);
      if (n.lvl > 3) return `Ligne ${n.line} : « ${n.name} » est au niveau ${n.lvl + 1} — 4 niveaux maximum sous Shared`;
      for (const s of n.fws) {
        const se = SERIAL(s); if (se) return `Ligne ${n.line} : « ${s} » : ${se}`;
        if (sns.has(s)) return `Ligne ${n.line} : le pare-feu ${s} est déjà dans un autre DG (un seul DG par pare-feu)`;
        sns.add(s);
      }
    }
    return nodes.length > 1024 ? "1 024 device groups maximum" : null;
  };

  register({
    id: "p04-hierarchy",
    module: "P04",
    title: "Hiérarchie de DG multi-sites",
    icon: "🌳",
    desc: "Décrire toute l'arborescence (Shared > global > région > site) en une fois : contrôle des 4 niveaux, unicité des noms et des pare-feux, CLI de création et ordre de push.",
    tags: "hierarchy hiérarchie multi-sites région site arborescence ancestor descendant device groups",
    fields: [
      { id: "tree", label: "Arborescence (2 espaces d'indentation par niveau)", type: "textarea", required: true, validate: treeV, wide: true,
        default: "Corp-DG | Règles et objets communs à toute l'entreprise\n  Europe-DG | Spécificités RGPD\n    Paris-DG : 012801000101 | Siège Paris\n    Berlin-DG : 012801000102\n  NorthAm-DG\n    Chicago-DG : 012801000201, 012801000202\n    NewYork-DG : 012801000203",
        hint: "Format d'une ligne : Nom-DG [: série1, série2] [| description]. Shared est la racine implicite (niveau 0). Lignes commençant par # ignorées." },
      { id: "template", label: "Template de référence pour les DG sans pare-feu", type: "text", validate: optName, default: "Global-Settings",
        hint: "Ajouté aux DG « structurels » (sans pare-feu) pour pouvoir choisir des zones dans leurs règles." },
    ],
    build(v) {
      const { nodes } = parseTree(v.tree);
      const tree = ["Shared"].concat(nodes.map(n => `${"   ".repeat(n.lvl)}└─ ${n.name}${n.fws.length ? "  [" + n.fws.join(", ") + "]" : ""}`)).join("\n");
      const steps = nodes.map(n => ({
        title: `Créer ${n.name}`, path: ["Panorama", "Device Groups"], window: "Device Group",
        action: n.parent ? `Sélectionner ${n.parent} sans l'ouvrir puis Add (parent pré-rempli).` : "Cliquer sur Add.",
        fields: [["Name", n.name], ["Description", n.desc], ["Parent Device Group", n.parent || "Shared"], ["Devices (cocher)", n.fws],
          ["Reference Templates", !n.fws.length && v.template ? v.template : ""]],
      }));
      const cli = [];
      nodes.forEach(n => {
        cli.push(`# ${"  ".repeat(n.lvl)}${n.name}`);
        cli.push(`set device-group ${q(n.name)} description ${q(n.desc || "DG " + n.name)}`);
        n.fws.forEach(s => cli.push(`set device-group ${q(n.name)} devices ${s}`));
        if (!n.fws.length && v.template) cli.push(`set device-group ${q(n.name)} reference-templates ${q(v.template)}`);
      });
      const moves = nodes.filter(n => n.parent);
      if (moves.length) {
        cli.push(`# Parents (du haut vers le bas de l'arbre) — ${TOVAL}`);
        moves.forEach(n => cli.push(`run request move-dg entry name ${q(n.name)} new-parent-dg ${q(n.parent)}`));
      }
      const withFw = nodes.filter(n => n.fws.length);
      const depth = Math.max(...nodes.map(n => n.lvl)) + 1;
      const nFw = withFw.reduce((a, n) => a + n.fws.length, 0);
      const notes = [
        { type: "ok", title: `${nodes.length} device groups · ${depth} niveau(x) sous Shared · ${nFw} pare-feu(x)`, html: preBlock(tree) },
        { type: "or", text: "Mets un objet ou une règle le plus HAUT possible (ex. blocage des IP malveillantes dans Corp-DG) : tous les descendants en héritent, sans duplication." },
        { type: "or", text: "Par défaut la table Panorama > Device Groups est triée par nom : l'indentation (affichage décalé) montre la vraie hiérarchie." },
      ];
      if (depth === 4) notes.push({ type: "warn", text: "Tu utilises les 4 niveaux : aucune marge pour une future subdivision." });
      const leafNoFw = nodes.filter(n => !n.fws.length && !nodes.some(c => c.parent === n.name));
      if (leafNoFw.length) notes.push({ type: "warn", text: `DG feuille(s) sans pare-feu : ${leafNoFw.map(n => n.name).join(", ")}. Inutile tant qu'aucun pare-feu n'y est affecté.` });
      return { steps, cli, notes, push: withFw.map(n => pushDg(n.name)), verify: ["show dg-hierarchy", ...withFw.slice(0, 3).map(n => `show devicegroups name ${q(n.name)}`)] };
    },
  });

  /* =====================================================================
     P04 · Objets (adresses, groupes, services, tag) en Shared ou DG
     ===================================================================== */
  const parseLines = (txt, n) => String(txt || "").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#")).map(l => l.split(/\s*[,;]\s*/)).map(a => a.slice(0, n).concat(a.length > n ? [a.slice(n).join(", ")] : []));
  const addrType = val => /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(val) ? "ip-netmask" : /^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$/.test(val) ? "ip-range" : "fqdn";
  const addrLinesV = txt => {
    const rows = parseLines(txt, 2), seen = new Set();
    for (const [n, val] of rows) {
      const e = V.name(n || ""); if (e) return `« ${n} » : ${e}`;
      if (seen.has(n)) return `« ${n} » en double`; seen.add(n);
      if (!val) return `« ${n} » : valeur manquante (Nom, valeur[, description])`;
      const t = addrType(val);
      if (t === "ip-netmask" && !PAN.ip.validCidr(val)) return `« ${val} » : IP ou IP/masque invalide`;
      if (t === "ip-range") { const [a, b] = val.split(/\s*-\s*/); if (!PAN.ip.valid(a) || !PAN.ip.valid(b) || PAN.ip.toInt(a) > PAN.ip.toInt(b)) return `« ${val} » : plage invalide (début ≤ fin)`; }
      if (t === "fqdn" && V.fqdn(val)) return `« ${val} » : ni IP, ni plage, ni FQDN valide`;
    }
    return null;
  };
  const svcLinesV = txt => {
    for (const [n, p, port] of parseLines(txt, 3)) {
      const e = V.name(n || ""); if (e) return `« ${n} » : ${e}`;
      if (!/^(tcp|udp)$/i.test(p || "")) return `« ${n} » : protocole tcp ou udp`;
      if (V.portrange((port || "").replace(/\s/g, ""))) return `« ${n} » : port, plage ou liste (ex. 8080, 8000-8080)`;
    }
    return null;
  };

  register({
    id: "p04-objects",
    module: "P04",
    title: "Objets Shared / device group",
    icon: "📦",
    desc: "Créer en masse des objets adresse (IP, plage, FQDN), un groupe d'adresses statique ou dynamique, des services et un tag, dans Shared ou un device group, avec Disable override.",
    tags: "objects objets address adresse address group dynamic tag service shared disable override",
    fields: [
      { id: "loc", label: "Emplacement", type: "select", default: "dg", options: LOCS,
        hint: "Shared = visible dans tous les DG (non surchargeable). Un DG = visible dans ce DG et ses descendants." },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "Corp-DG", show: v => v.loc === "dg" },
      { id: "addrs", label: "Objets adresse — une ligne : Nom, valeur[, description]", type: "textarea", validate: addrLinesV, wide: true, group: "Adresses",
        default: "Production-Servers, 172.16.1.15-172.16.1.214, Serveurs de production\nFinance-Servers, 10.0.1.20-10.0.1.34, Serveurs finance\nIntranet-Server, 10.1.1.80/32\nInternal-DNS-1, 10.1.1.53\nIntranet-FQDN, intranet.corp.local",
        hint: "Type détecté automatiquement : IP ou IP/masque → IP Netmask ; a.b.c.d-e.f.g.h → IP Range ; sinon FQDN." },
      { id: "tag", label: "Tag à créer et appliquer aux adresses (optionnel)", type: "text", validate: optName, default: "Prod", group: "Tag & groupe" },
      { id: "tagColor", label: "Couleur du tag", type: "select", default: "color3", options: COLORS, show: v => !!v.tag },
      { id: "grpType", label: "Groupe d'adresses", type: "select", default: "static",
        options: [["none", "Aucun"], ["static", "Statique (toutes les adresses ci-dessus)"], ["dynamic", "Dynamique (filtre sur le tag)"]] },
      { id: "grpName", label: "Nom du groupe", type: "text", required: true, validate: "name", default: "Corp-Servers", show: v => v.grpType !== "none" },
      { id: "svcs", label: "Services — une ligne : Nom, tcp|udp, port(s)", type: "textarea", validate: svcLinesV, wide: true, group: "Services",
        default: "tcp-8443, tcp, 8443", placeholder: "tcp-8080, tcp, 8080\nsyslog-udp, udp, 514" },
      { id: "noOverride", label: "Disable override (interdit la modification dans les DG descendants)", type: "checkbox", default: false, group: "Protection", show: v => v.loc === "dg" },
    ],
    build(v) {
      const b = base(v), W = where(v);
      const addrs = parseLines(v.addrs, 2).map(([n, val, d]) => ({ n, val: val.replace(/\s*-\s*/, "-"), t: addrType(val), d }));
      const svcs = parseLines(v.svcs, 3).map(([n, p, port, d]) => ({ n, p: p.toLowerCase(), port: port.replace(/\s/g, ""), d }));
      const dyn = v.grpType === "dynamic";
      const TYPEGUI = { "ip-netmask": "IP Netmask", "ip-range": "IP Range", fqdn: "FQDN" };
      const sel = v.loc === "shared" ? "Choisir n'importe quel DG dans la liste puis cocher la case Shared dans chaque fenêtre (Shared n'est pas dans la liste déroulante)." : pickDg(v.dg);
      const steps = [];
      if (v.tag) steps.push({ title: `Créer le tag ${v.tag}`, path: ["Objects", "Tags"], window: "Tag", action: sel + " Puis Add.",
        fields: [["Name", v.tag], ["Shared", v.loc === "shared"], ["Disable override", v.loc === "dg" && v.noOverride], ["Color", colorName(v.tagColor)]] });
      addrs.forEach(a => steps.push({ title: `Adresse ${a.n}`, path: ["Objects", "Addresses"], window: "Address", action: (steps.length ? "" : sel + " ") + "Cliquer sur Add.",
        fields: [["Name", a.n], ["Shared", v.loc === "shared"], ["Disable override", v.loc === "dg" && v.noOverride], ["Description", a.d], ["Type", TYPEGUI[a.t]], ["Valeur", a.val], ["Tags", v.tag]] }));
      if (v.grpType !== "none") steps.push({ title: `Groupe d'adresses ${v.grpName}`, path: ["Objects", "Address Groups"], window: "Address Group", action: "Cliquer sur Add.",
        fields: [["Name", v.grpName], ["Shared", v.loc === "shared"], ["Type", dyn ? "Dynamic" : "Static"],
          [dyn ? "Match" : "Addresses (Add)", dyn ? (v.tag ? `'${v.tag}'` : "(tag requis)") : addrs.map(a => a.n)]],
        note: dyn ? "Le groupe dynamique inclut automatiquement toute adresse (ou IP enregistrée via User-ID/VM Monitoring) portant le tag." : "" });
      svcs.forEach(s => steps.push({ title: `Service ${s.n}`, path: ["Objects", "Services"], window: "Service", action: "Cliquer sur Add.",
        fields: [["Name", s.n], ["Shared", v.loc === "shared"], ["Protocol", s.p.toUpperCase()], ["Destination Port", s.port]] }));

      const cli = [`# Emplacement : ${W}`];
      const lock = v.loc === "dg" && v.noOverride;
      if (v.tag) cli.push(`set ${b} tag ${q(v.tag)} color ${v.tagColor}`);
      if (v.tag && lock) cli.push(`set ${b} tag ${q(v.tag)} disable-override yes`);
      addrs.forEach(a => {
        cli.push(`set ${b} address ${q(a.n)} ${a.t} ${a.val}`);
        if (a.d) cli.push(`set ${b} address ${q(a.n)} description ${q(a.d)}`);
        if (v.tag) cli.push(`set ${b} address ${q(a.n)} tag ${q(v.tag)}`);
        if (lock) cli.push(`set ${b} address ${q(a.n)} disable-override yes`);
      });
      if (v.grpType === "static" && addrs.length) cli.push(`set ${b} address-group ${q(v.grpName)} static ${members(addrs.map(a => a.n))}`);
      if (dyn && v.tag) cli.push(`set ${b} address-group ${q(v.grpName)} dynamic filter "'${v.tag}'"`);
      if (v.grpType !== "none" && lock) cli.push(`set ${b} address-group ${q(v.grpName)} disable-override yes`);
      svcs.forEach(s => {
        cli.push(`set ${b} service ${q(s.n)} protocol ${s.p} port ${s.port}`);
        if (lock) cli.push(`set ${b} service ${q(s.n)} disable-override yes`);
      });

      const notes = [{ type: "or", title: "Toujours choisir le bon Device Group avant Add", text: "Un objet créé au mauvais endroit se corrige avec le bouton Move (Destination = bon DG), sans le recréer." }];
      if (v.loc === "shared") notes.push({ type: "or", text: "Objets Shared : visibles partout, non surchargeables dans les DG. Par défaut Panorama pousse tous les objets Shared, même inutilisés (Panorama > Setup > Management > Panorama Settings)." });
      if (lock) notes.push({ type: "ok", text: "Disable override : les DG descendants voient l'objet (fond jaune, engrenage vert) mais ne peuvent pas le modifier ; on le change uniquement dans " + v.dg + "." });
      if (dyn && !v.tag) notes.push({ type: "bad", text: "Groupe dynamique sans tag : renseigne un tag pour construire le filtre Match." });
      notes.push({ type: "or", text: "Un administrateur local du pare-feu ne peut JAMAIS modifier un objet poussé par un device group (contrairement aux valeurs de template)." });
      const push = v.loc === "dg" ? [pushDg(v.dg)] : [];
      if (v.loc === "shared") notes.push({ type: "or", text: "Objets Shared : pousse ensuite chaque device group concerné (Commit > Push to Devices > Edit Selections)." });
      return { steps, cli, notes, push, verify: [`show config candidate | match ${addrs[0] ? q(addrs[0].n) : "address"}`] };
    },
  });

  /* =====================================================================
     P04 · Override d'un objet hérité / précédence
     ===================================================================== */
  const SCHED = v => /^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$/.test(v) ? null : "Plage HH:MM-HH:MM (ex. 08:00-17:00)";
  const OVTYPES = { schedule: { gui: ["Objects", "Schedules"], kw: "schedule", label: "Schedule (plage horaire)" },
    address: { gui: ["Objects", "Addresses"], kw: "address", label: "Adresse (IP/masque)" },
    service: { gui: ["Objects", "Services"], kw: "service", label: "Service TCP (port)" } };
  const ovVal = (t, val) => t === "schedule" ? `schedule-type recurring daily ${val}` : t === "address" ? `ip-netmask ${val}` : `protocol tcp port ${val}`;
  const ovV = (val, v) => v.objType === "schedule" ? SCHED(val) : v.objType === "address" ? V.cidr(val) : V.portrange(val);

  register({
    id: "p04-override",
    module: "P04",
    title: "Override d'objet hérité & précédence",
    icon: "🧬",
    desc: "Surcharger dans un DG descendant un objet hérité d'un ancêtre, revenir à la valeur héritée, ou verrouiller l'objet (Disable override) — et comprendre quelle valeur atteint le pare-feu.",
    tags: "override surcharge inherited hérité revert disable override precedence précédence ancestor descendant conflict",
    fields: [
      { id: "action", label: "Opération", type: "select", default: "override",
        options: [["override", "Override : modifier l'objet dans le descendant"], ["revert", "Revert : revenir à la valeur héritée"], ["lock", "Verrouiller dans l'ancêtre (Disable override)"]] },
      { id: "parentDg", label: "DG ancêtre (où l'objet est créé)", type: "text", required: true, validate: "name", default: "Corp-DG" },
      { id: "dg", label: "DG descendant", type: "text", required: true, validate: "name", default: "Branch-DG", show: v => v.action !== "lock" },
      { id: "objType", label: "Type d'objet", type: "select", default: "schedule", options: Object.entries(OVTYPES).map(([k, o]) => [k, o.label]), group: "Objet" },
      { id: "objName", label: "Nom de l'objet", type: "text", required: true, validate: "name", default: "Business-Hours" },
      { id: "valParent", label: "Valeur dans l'ancêtre", type: "text", required: true, default: "08:00-17:00", validate: ovV },
      { id: "valChild", label: "Nouvelle valeur dans le descendant", type: "text", required: true, default: "08:00-18:00", validate: ovV, show: v => v.action === "override" },
      { id: "ancestorWins", label: "Option « Objects defined in ancestors will take higher precedence »", type: "checkbox", default: false, group: "Précédence",
        hint: "Désactivée par défaut : en cas de conflit de nom, c'est la valeur du DG le plus BAS qui est poussée." },
    ],
    build(v) {
      const o = OVTYPES[v.objType];
      const pre = `set device-group ${q(v.parentDg)} ${o.kw} ${q(v.objName)}`;
      const steps = [], cli = [];
      if (v.action === "lock") {
        steps.push({ title: `Verrouiller ${v.objName} dans ${v.parentDg}`, path: o.gui, window: o.label, action: pickDg(v.parentDg) + ` Ouvrir ${v.objName}.`,
          fields: [["Name", v.objName], ["Disable override", true]], note: "Les DG descendants ne pourront plus surcharger cet objet ; une surcharge existante doit d'abord être supprimée (Revert)." });
        cli.push(`${pre} ${ovVal(v.objType, v.valParent)}`, `${pre} disable-override yes`);
      } else if (v.action === "override") {
        steps.push({ title: `Surcharger ${v.objName} dans ${v.dg}`, path: o.gui, action: pickDg(v.dg) + ` Sélectionner ${v.objName} (fond jaune, engrenage vert = hérité de ${v.parentDg}) SANS l'ouvrir, puis cliquer sur Override en bas.`,
          fields: [] });
        steps.push({ title: "Modifier la valeur", path: o.gui, window: o.label, action: "Dans la fenêtre ouverte, modifier la valeur puis OK.",
          fields: [["Name", v.objName + " (non modifiable)"], [v.objType === "schedule" ? "Recurrence / Time" : v.objType === "address" ? "IP Netmask" : "Destination Port", v.valChild]],
          note: "L'objet surchargé affiche deux engrenages (orange sur vert) et n'est plus grisé ; survoler l'icône indique l'objet d'origine." });
        cli.push(`# Objet d'origine (ancêtre)`, `${pre} ${ovVal(v.objType, v.valParent)}`,
          `# Surcharge : même nom, définie dans le descendant`, `set device-group ${q(v.dg)} ${o.kw} ${q(v.objName)} ${ovVal(v.objType, v.valChild)}`);
      } else {
        steps.push({ title: `Revenir à la valeur héritée dans ${v.dg}`, path: o.gui, action: pickDg(v.dg) + ` Sélectionner ${v.objName} (double engrenage) puis cliquer sur Revert.`, fields: [] });
        cli.push(`# Supprimer la surcharge : le DG reprend la valeur de ${v.parentDg}`, `delete device-group ${q(v.dg)} ${o.kw} ${q(v.objName)}`);
      }
      if (v.ancestorWins) {
        steps.push({ title: "Donner la priorité aux objets des ancêtres", path: ["Panorama", "Setup", "Management"], window: "Panorama Settings",
          action: "Cadre Panorama Settings → ⚙.", fields: [["Objects defined in ancestors will take higher precedence", true]],
          warn: "Option globale : elle change le résultat de TOUS les conflits de nom entre DG." });
        cli.push(`# Précédence des ancêtres : réglage Panorama Settings (chemin CLI ${TOVAL})`);
      }
      const eff = v.action === "override" ? (v.ancestorWins ? v.valParent : v.valChild) : v.valParent;
      const res = v.action === "lock" ? `Valeur ${v.valParent} imposée à tous les descendants de ${v.parentDg}.`
        : `Pare-feux de ${v.dg} : ${o.kw} ${v.objName} = ${eff}${v.action === "override" ? (v.ancestorWins ? " (l'ancêtre l'emporte)" : " (la valeur du DG le plus bas l'emporte)") : " (valeur héritée)"}.`;
      const notes = [{ type: "ok", title: "Valeur effective après push", text: res }];
      if (v.action === "override") notes.push({ type: "warn", text: "Si l'objet est verrouillé (Disable override) dans l'ancêtre, le bouton Override est grisé : modifie-le dans l'ancêtre ou retire le verrou." });
      notes.push({ type: "or", text: "Panorama n'empêche pas de créer le même nom à deux niveaux avec des valeurs différentes : documente-le, ou évite-le par une bonne planification." });
      return { steps, cli, notes, push: [pushDg(v.action === "lock" ? v.parentDg : v.dg)] };
    },
  });

  /* =====================================================================
     P04 · Profils de sécurité & groupe de profils (Lab 4)
     ===================================================================== */
  const URL_ALL = ["abortion", "abused-drugs", "adult", "alcohol-and-tobacco", "auctions", "business-and-economy", "command-and-control", "computer-and-internet-info",
    "content-delivery-networks", "copyright-infringement", "cryptocurrency", "dating", "dynamic-dns", "educational-institutions", "entertainment-and-arts", "extremism",
    "financial-services", "gambling", "games", "government", "grayware", "hacking", "health-and-medicine", "high-risk", "home-and-garden", "hunting-and-fishing",
    "insufficient-content", "internet-communications-and-telephony", "internet-portals", "job-search", "legal", "low-risk", "malware", "medium-risk", "military",
    "motor-vehicles", "music", "newly-registered-domain", "news", "not-resolved", "nudity", "online-storage-and-backup", "parked", "peer-to-peer",
    "personal-sites-and-blogs", "philosophy-and-political-advocacy", "phishing", "private-ip-addresses", "proxy-avoidance-and-anonymizers", "questionable",
    "real-estate", "recreation-and-hobbies", "reference-and-research", "religion", "search-engines", "sex-education", "shareware-and-freeware", "shopping",
    "social-networking", "society", "sports", "stock-advice-and-tools", "streaming-media", "swimsuits-and-intimate-apparel", "training-and-tools", "translation",
    "travel", "unknown", "weapons", "web-advertisements", "web-based-email", "web-hosting"];
  const URL_BLOCK_LAB6 = ["adult", "command-and-control", "copyright-infringement", "extremism", "gambling", "hacking", "high-risk", "malware", "phishing",
    "proxy-avoidance-and-anonymizers", "shareware-and-freeware", "unknown", "weapons"];
  const catList = arr => { for (const c of arr) if (!/^[a-z0-9-]+$/.test(c)) return `« ${c} » : catégorie en minuscules avec tirets (ex. proxy-avoidance-and-anonymizers)`; return null; };
  const FB_STRICT = ["7z", "bat", "cab", "chm", "class", "cpl", "dll", "exe", "flash", "hlp", "hta", "jar", "msi", "Multi-Level-Encoding", "ocx", "PE", "pif", "rar", "scr", "tar", "encrypted-zip", "torrent", "vbe", "wsf"];
  const AV_DECODERS = ["ftp", "http", "http2", "imap", "pop3", "smb", "smtp"];

  register({
    id: "p04-profiles",
    module: "P04",
    title: "Profils de sécurité & groupe de profils",
    icon: "🛡️",
    desc: "Profils Antivirus, Anti-Spyware, Vulnerability, URL Filtering, File Blocking et WildFire (clones des profils prédéfinis) regroupés dans un Security Profile Group commun à tous les pare-feux.",
    tags: "security profile group profils antivirus anti-spyware vulnerability url filtering file blocking wildfire corp-profiles",
    fields: [
      { id: "loc", label: "Emplacement", type: "select", default: "dg", options: LOCS },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "Corp-DG", show: v => v.loc === "dg" },
      { id: "prefix", label: "Préfixe des profils", type: "text", required: true, default: "Corp", validate: v => /^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$/.test(v) ? null : "Lettres, chiffres, - et _ (40 caractères max)",
        hint: "Donne Corp-AV, Corp-AntiSpy, Corp-Vuln, Corp-URL, Corp-FB, Corp-WF." },
      { id: "pg", label: "Nom du Security Profile Group", type: "text", required: true, validate: "name", default: "Corp-Profiles",
        hint: "Astuce : un groupe nommé « default » est appliqué automatiquement à chaque nouvelle règle de sécurité." },
      { id: "av", label: "Antivirus (clone de default)", type: "checkbox", default: true, group: "Profils inclus" },
      { id: "as", label: "Anti-Spyware (clone de strict)", type: "checkbox", default: true },
      { id: "vp", label: "Vulnerability Protection (clone de strict)", type: "checkbox", default: true },
      { id: "url", label: "URL Filtering (clone de default)", type: "checkbox", default: true },
      { id: "fb", label: "File Blocking (clone de strict file blocking)", type: "checkbox", default: true },
      { id: "wf", label: "WildFire Analysis (clone de default)", type: "checkbox", default: true },
      { id: "urlAlert", label: "Passer toutes les autres catégories en alert (journalisées)", type: "checkbox", default: true, group: "URL Filtering", show: v => v.url,
        hint: "« allow » autorise sans journaliser ; « alert » autorise ET écrit dans le log URL Filtering." },
      { id: "urlBlock", label: "Catégories bloquées (block)", type: "list", validate: catList, default: URL_BLOCK_LAB6, show: v => v.url },
    ],
    build(v) {
      const b = base(v), P = v.prefix;
      const N = { av: `${P}-AV`, as: `${P}-AntiSpy`, vp: `${P}-Vuln`, url: `${P}-URL`, fb: `${P}-FB`, wf: `${P}-WF` };
      const DEF = { av: ["Antivirus", "default"], as: ["Anti-Spyware", "strict"], vp: ["Vulnerability Protection", "strict"], url: ["URL Filtering", "default"], fb: ["File Blocking", "strict file blocking"], wf: ["WildFire Analysis", "default"] };
      const on = Object.keys(N).filter(k => v[k]);
      const steps = on.map((k, i) => ({
        title: `Profil ${N[k]}`, path: ["Objects", "Security Profiles", DEF[k][0]], window: DEF[k][0] + " Profile",
        action: (i ? "" : (v.loc === "shared" ? "Cocher Shared dans chaque profil. " : pickDg(v.dg) + " ")) + `Sélectionner le profil prédéfini « ${DEF[k][1]} » → Clone → OK, puis ouvrir le clone et le renommer.`,
        fields: [["Name", N[k]], ["Description", `Profil ${DEF[k][0]} standard des règles de sécurité`],
          ["Site Access (Set All Actions)", k === "url" && v.urlAlert ? "alert" : ""], ["Catégories en block", k === "url" ? v.urlBlock : ""]],
        note: k === "url" ? "Flèche de la colonne Site Access → Set All Actions → alert, puis passer les catégories listées en block." : "",
      }));
      steps.push({ title: `Groupe ${v.pg}`, path: ["Objects", "Security Profile Groups"], window: "Security Profile Group", action: "Cliquer sur Add.",
        fields: [["Name", v.pg], ["Shared", v.loc === "shared"], ["Antivirus Profile", v.av && N.av], ["Anti-Spyware Profile", v.as && N.as], ["Vulnerability Protection Profile", v.vp && N.vp],
          ["URL Filtering Profile", v.url && N.url], ["File Blocking Profile", v.fb && N.fb], ["Data Filtering Profile", "None"], ["WildFire Analysis Profile", v.wf && N.wf]] });

      const p = `set ${b} profiles`, cli = [`# Équivalent CLI des clones (le clone WebUI reprend exactement les règles prédéfinies)`];
      if (v.av) AV_DECODERS.forEach(d => cli.push(`${p} virus ${q(N.av)} decoder ${d} action default wildfire-action default`));
      if (v.as) cli.push(
        `${p} spyware ${q(N.as)} rules strict-crit-high-med threat-name any category any severity [ critical high medium ] action reset-both packet-capture disable`,
        `${p} spyware ${q(N.as)} rules strict-low-info threat-name any category any severity [ low informational ] action default packet-capture disable`,
        `${p} spyware ${q(N.as)} botnet-domains lists default-paloalto-dns action sinkhole`,
        `${p} spyware ${q(N.as)} botnet-domains sinkhole ipv4-address sinkhole.paloaltonetworks.com ipv6-address ::1`);
      if (v.vp) cli.push(
        `${p} vulnerability ${q(N.vp)} rules strict-crit-high-med vendor-id any cve any host any threat-name any category any severity [ critical high medium ] action reset-both packet-capture disable`,
        `${p} vulnerability ${q(N.vp)} rules strict-low-info vendor-id any cve any host any threat-name any category any severity [ low informational ] action default packet-capture disable`);
      if (v.url) {
        const alert = v.urlAlert ? URL_ALL.filter(c => !v.urlBlock.includes(c)) : [];
        if (alert.length) cli.push(`${p} url-filtering ${q(N.url)} alert ${members(alert)}`);
        if (v.urlBlock.length) cli.push(`${p} url-filtering ${q(N.url)} block ${members(v.urlBlock)}`);
      }
      if (v.fb) cli.push(
        `${p} file-blocking ${q(N.fb)} rules block-risky application any file-type ${members(FB_STRICT)} direction both action block`,
        `${p} file-blocking ${q(N.fb)} rules alert-all application any file-type any direction both action alert`);
      if (v.wf) cli.push(`${p} wildfire-analysis ${q(N.wf)} rules default application any file-type any direction both analysis public-cloud`);
      const g = [v.av && `virus ${q(N.av)}`, v.as && `spyware ${q(N.as)}`, v.vp && `vulnerability ${q(N.vp)}`, v.url && `url-filtering ${q(N.url)}`, v.fb && `file-blocking ${q(N.fb)}`, v.wf && `wildfire-analysis ${q(N.wf)}`].filter(Boolean);
      cli.push(`set ${b} profile-group ${q(v.pg)} ${g.join(" ")}`);

      const notes = [
        { type: "or", text: `Créés dans ${where(v)}, les profils et le groupe sont hérités par tous les DG descendants : applique « ${v.pg} » dans les règles (Actions > Profile Type = Group).` },
        { type: "warn", text: "Les règles CLI ci-dessus approximent les profils prédéfinis « strict ». Pour une copie exacte (exceptions, règles brute-force, DNS Security), préfère le Clone en WebUI." },
      ];
      if (v.url) notes.push({ type: "or", text: `Liste « alert » générée à partir de ${URL_ALL.length} catégories PAN-DB courantes : une catégorie inconnue de ta version fait échouer le commit — retire-la si besoin.` });
      if (!on.length) notes.push({ type: "bad", text: "Aucun profil sélectionné : le groupe serait vide." });
      return { steps, cli, notes, push: v.loc === "dg" ? [pushDg(v.dg)] : [] };
    },
  });

  /* =====================================================================
     P04 · Règle de sécurité pre/post, target, tags
     ===================================================================== */
  const ACTIONS = [["allow", "Allow"], ["deny", "Deny"], ["drop", "Drop"], ["reset-client", "Reset client"], ["reset-server", "Reset server"], ["reset-both", "Reset both"]];
  const addrList = arr => { for (const x of arr) if (x !== "any" && V.ipcidr(x) && V.name(x)) return `« ${x} » : IP, IP/masque, nom d'objet ou any`; return null; };

  register({
    id: "p04-policy",
    module: "P04",
    title: "Règle de sécurité pre/post-rule",
    icon: "📜",
    desc: "Règle de sécurité dans Shared ou un device group (Pre Rules / Post Rules), avec tags, Group Rules By Tag, profil de sécurité, log forwarding et ciblage (Target) par pare-feu ou par tag de pare-feu.",
    tags: "policy security rule pre-rule post-rule target tag group-tag rulebase profile group log forwarding negate",
    fields: [
      { id: "loc", label: "Emplacement", type: "select", default: "dg", options: LOCS },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "Corp-DG",
        hint: "En Shared, ce DG sert uniquement de portée de push." },
      { id: "rb", label: "Rulebase", type: "select", default: "pre", options: [["pre", "Pre Rules (avant les règles locales)"], ["post", "Post Rules (après les règles locales)"]],
        hint: "Pre : l'admin local ne peut rien placer au-dessus. Post : l'admin local peut créer des exceptions avant." },
      { id: "name", label: "Nom de la règle", type: "text", required: true, validate: "name", default: "Block-Bad-IPs-Outbound", group: "Général" },
      { id: "desc", label: "Description", type: "text", default: "Bloque le trafic vers les IP malveillantes (listes PANW)", wide: true },
      { id: "tags", label: "Tags de règle", type: "list", validate: nameList, default: ["Security"], placeholder: "Security, Internet" },
      { id: "mkTags", label: "Créer ces tags dans le même emplacement", type: "checkbox", default: true, show: v => v.tags.length > 0 },
      { id: "groupTag", label: "Group Rules By Tag (optionnel)", type: "text", default: "",
        validate: (g, v) => !g ? null : V.name(g) || (v.tags.includes(g) ? null : "Doit faire partie des tags de la règle") },
      { id: "srcZ", label: "Zones source", type: "list", required: true, validate: nameList, default: ["Users_Net", "Extranet"], group: "Source / destination",
        hint: "Zones issues des templates des pare-feux du DG (ou du template de référence)." },
      { id: "src", label: "Adresses source", type: "list", validate: addrList, default: ["any"] },
      { id: "dstZ", label: "Zones destination", type: "list", required: true, validate: nameList, default: ["Internet"] },
      { id: "dst", label: "Adresses destination", type: "list", validate: addrList, default: ["panw-bulletproof-ip-list", "panw-highrisk-ip-list", "panw-known-ip-list"],
        hint: "Les EDL prédéfinies panw-* (Bulletproof, High Risk, Known Malicious) sont disponibles via la licence Threat Prevention." },
      { id: "apps", label: "Applications", type: "list", default: ["any"], group: "Application & service" },
      { id: "svc", label: "Service", type: "select", default: "any", options: [["application-default", "application-default (recommandé)"], ["any", "any"], ["custom", "Services nommés…"]] },
      { id: "svcList", label: "Services", type: "list", validate: nameList, default: ["service-https"], show: v => v.svc === "custom" },
      { id: "action", label: "Action", type: "select", default: "deny", options: ACTIONS, group: "Actions" },
      { id: "pg", label: "Profile Group (vide = aucun)", type: "text", validate: optName, default: "", show: v => v.action === "allow", placeholder: "Corp-Profiles" },
      { id: "logSet", label: "Log Forwarding", type: "text", validate: optName, default: "default", hint: "Profil créé dans le module « Log forwarding des pare-feux »." },
      { id: "logEnd", label: "Log at Session End", type: "checkbox", default: true },
      { id: "disabled", label: "Créer la règle désactivée", type: "checkbox", default: false },
      { id: "target", label: "Target (pare-feux qui reçoivent la règle)", type: "select", default: "all", group: "Target",
        options: [["all", "Tous les pare-feux du DG (défaut)"], ["devices", "Pare-feux choisis (n° de série)"], ["tags", "Pare-feux portant un tag"]] },
      { id: "tgtSerials", label: "Numéros de série ciblés", type: "list", required: true, validate: serialList, default: ["012801000201"], show: v => v.target === "devices" },
      { id: "tgtTags", label: "Tags de pare-feu ciblés", type: "list", required: true, validate: nameList, default: ["Site-HQ"], show: v => v.target === "tags",
        hint: "Tags attribués aux pare-feux dans Panorama > Managed Devices > Summary." },
      { id: "negate", label: "Install on all but specified devices (negate)", type: "checkbox", default: false, show: v => v.target !== "all" },
    ],
    build(v) {
      const b = base(v), rbN = v.rb === "pre" ? "Pre Rules" : "Post Rules";
      const r = `set ${b} ${v.rb}-rulebase security rules ${q(v.name)}`;
      const svc = v.svc === "custom" ? v.svcList : [v.svc];
      const allow = v.action === "allow";
      const steps = [];
      if (v.tags.length && v.mkTags) steps.push({ title: "Créer les tags de règle", path: ["Objects", "Tags"], action: (v.loc === "shared" ? "Cocher Shared." : pickDg(v.dg)) + " Add pour chaque tag.", fields: [["Name", v.tags], ["Shared", v.loc === "shared"]] });
      steps.push(
        { title: `Nouvelle règle dans ${where(v)} › ${rbN}`, path: ["Policies", "Security", rbN], tab: "General", window: "Security Policy Rule",
          action: (v.loc === "shared" ? "Choisir Shared dans la liste Device Group." : pickDg(v.dg)) + " Puis Add.",
          fields: [["Name", v.name], ["Description", v.desc], ["Tags", v.tags], ["Group Rules By Tag", v.groupTag], ["Rule Type", "universal (default)"]] },
        { title: "Source", path: ["Policies", "Security", rbN, v.name], tab: "Source", fields: [["Source Zone", v.srcZ], ["Source Address", v.src.length ? v.src : "Any"]] },
        { title: "Destination", path: ["Policies", "Security", rbN, v.name], tab: "Destination", fields: [["Destination Zone", v.dstZ], ["Destination Address", v.dst.length ? v.dst : "Any"]] },
        { title: "Application & service", path: ["Policies", "Security", rbN, v.name], tab: "Application / Service/URL Category", fields: [["Application", v.apps.length ? v.apps : "Any"], ["Service", svc]] },
        { title: "Actions", path: ["Policies", "Security", rbN, v.name], tab: "Actions",
          fields: [["Action", ACTIONS.find(a => a[0] === v.action)[1]], ["Profile Type", allow && v.pg ? "Group" : "None"], ["Group Profile", allow && v.pg], ["Log at Session End", v.logEnd], ["Log Forwarding", v.logSet], ["Disable this rule", v.disabled]] });
      if (v.target !== "all") steps.push({ title: "Ciblage", path: ["Policies", "Security", rbN, v.name], tab: "Target",
        fields: [["Any (target to all devices)", "décoché"], [v.target === "devices" ? "Devices (cocher)" : "Tags", v.target === "devices" ? v.tgtSerials : v.tgtTags], ["Install on all but specified devices", v.negate]],
        note: "La colonne Target de la rulebase montre ensuite quels pare-feux reçoivent la règle." });
      steps.push({ title: "Prévisualiser la rulebase d'un pare-feu", path: ["Policies", "Security"], action: "Bouton Preview Rules en bas → Rulebase = security, choisir le DG puis le pare-feu : règles poussées (jaune) et locales (blanc) dans l'ordre réel.", fields: [] });

      const cli = [];
      if (v.tags.length && v.mkTags) v.tags.forEach(t => cli.push(`set ${b} tag ${q(t)} color color1`));
      cli.push(`${r} from ${members(v.srcZ)} to ${members(v.dstZ)} source ${members(v.src)} destination ${members(v.dst)} source-user any category any application ${members(v.apps)} service ${members(svc)} action ${v.action}`);
      if (v.desc) cli.push(`${r} description ${q(v.desc)}`);
      if (v.tags.length) cli.push(`${r} tag ${members(v.tags)}`);
      if (v.groupTag) cli.push(`${r} group-tag ${q(v.groupTag)}`);
      if (allow && v.pg) cli.push(`${r} profile-setting group ${q(v.pg)}`);
      cli.push(`${r} log-start no log-end ${yn(v.logEnd)}`);
      if (v.logSet) cli.push(`${r} log-setting ${q(v.logSet)}`);
      if (v.disabled) cli.push(`${r} disabled yes`);
      if (v.target === "devices") v.tgtSerials.forEach(s => cli.push(`${r} target devices ${s}`));
      if (v.target === "tags") cli.push(`# Ciblage par tag de pare-feu — ${TOVAL}`, `${r} target tags ${members(v.tgtTags)}`);
      if (v.target !== "all") cli.push(`${r} target negate ${yn(v.negate)}`);

      const notes = [];
      notes.push({ type: "or", title: "Ordre d'évaluation sur le pare-feu", text: "Shared pre → pre des DG (ancêtre → descendant) → règles locales → post des DG (descendant → ancêtre) → Shared post → règles par défaut. Première règle qui correspond = action appliquée." });
      if (allow && v.apps.includes("any")) notes.push({ type: "warn", text: "Allow + application any : acceptable en lab, à restreindre aux seules applications nécessaires en production." });
      if (allow && !v.pg) notes.push({ type: "warn", text: "Règle allow sans groupe de profils : aucune inspection antivirus/IPS/URL du trafic autorisé." });
      if (allow && v.svc === "any") notes.push({ type: "or", text: "Service any avec allow : préfère application-default pour empêcher les applications sur des ports non standard." });
      if (v.rb === "pre" && allow) notes.push({ type: "or", text: "Allow en Pre Rule : l'admin local ne pourra pas restreindre ce flux. Les autorisations larges vont plutôt en Post Rules." });
      if (v.target === "tags") notes.push({ type: "or", text: "Ciblage par tag : un nouveau pare-feu tagué reçoit automatiquement la règle au prochain push, sans modifier la règle." });
      notes.push({ type: "or", text: "Les règles poussées par Panorama sont en lecture seule sur le pare-feu (fond jaune) : ni modification ni override en local." });
      return { steps, cli, notes, push: [pushDg(v.dg)], verify: ["show jobs all"] };
    },
  });

  /* =====================================================================
     P04 · Règle NAT (post-rule) avec variable de template
     ===================================================================== */
  register({
    id: "p04-nat",
    module: "P04",
    title: "Règle NAT source (pre/post)",
    icon: "🔁",
    desc: "NAT source Dynamic IP and Port sur l'adresse de l'interface de sortie, renseignée par une variable de template ($Internet-Interface) pour une seule règle valable sur tous les sites.",
    tags: "nat source dynamic ip and port interface address variable template post-rule device group",
    fields: [
      { id: "loc", label: "Emplacement", type: "select", default: "dg", options: LOCS },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "Corp-DG" },
      { id: "rb", label: "Rulebase", type: "select", default: "post", options: [["pre", "Pre Rules"], ["post", "Post Rules"]] },
      { id: "name", label: "Nom de la règle", type: "text", required: true, validate: "name", default: "NAT_Users_Net_to_Internet", group: "Paquet d'origine" },
      { id: "desc", label: "Description", type: "text", default: "Traduit Users_Net vers Internet avec l'IP de ethernet1/1", wide: true },
      { id: "srcZ", label: "Zones source", type: "list", required: true, validate: nameList, default: ["Users_Net"] },
      { id: "dstZ", label: "Zone destination (une seule)", type: "text", required: true, validate: "name", default: "Internet" },
      { id: "src", label: "Adresses source", type: "list", validate: addrList, default: ["any"] },
      { id: "egress", label: "Interface de sortie", type: "text", required: true, validate: "iface", default: "ethernet1/1", group: "Paquet traduit" },
      { id: "ipMode", label: "Adresse de traduction", type: "select", default: "var", options: [["var", "Variable de template ($...)"], ["ip", "IP/masque fixe"], ["none", "Aucune (première IP de l'interface)"]] },
      { id: "ipVar", label: "Variable", type: "text", required: true, default: "$Internet-Interface", show: v => v.ipMode === "var",
        validate: x => /^\$[A-Za-z0-9_-]{1,62}$/.test(x) ? null : "Variable : $ suivi de lettres, chiffres, - ou _ (ex. $Internet-Interface)",
        hint: "Définie dans le template / template stack (module « Variables ») : 203.0.113.20/24 à Chicago, 203.0.113.25/24 à Berlin…" },
      { id: "ipFix", label: "IP/masque", type: "cidr", required: true, default: "203.0.113.20/24", show: v => v.ipMode === "ip" },
      { id: "tgtSerials", label: "Target : n° de série (vide = tous les pare-feux du DG)", type: "list", validate: serialList, group: "Target" },
    ],
    build(v) {
      const b = base(v), rbN = v.rb === "pre" ? "Pre Rules" : "Post Rules";
      const r = `set ${b} ${v.rb}-rulebase nat rules ${q(v.name)}`;
      const ip = v.ipMode === "var" ? v.ipVar : v.ipMode === "ip" ? v.ipFix : "";
      const steps = [
        { title: `Nouvelle règle NAT (${rbN})`, path: ["Policies", "NAT", rbN], tab: "General", window: "NAT Policy Rule", action: (v.loc === "shared" ? "Choisir Shared." : pickDg(v.dg)) + " Puis Add.",
          fields: [["Name", v.name], ["Description", v.desc], ["NAT Type", "ipv4"]] },
        { title: "Paquet d'origine", path: ["Policies", "NAT", rbN, v.name], tab: "Original Packet", fields: [["Source Zone (Add)", v.srcZ], ["Destination Zone", v.dstZ], ["Destination Interface", "any"], ["Service", "any"], ["Source Address", v.src.length ? v.src : "Any"], ["Destination Address", "Any"]] },
        { title: "Paquet traduit", path: ["Policies", "NAT", rbN, v.name], tab: "Translated Packet",
          fields: [["Translation Type", "Dynamic IP And Port"], ["Address Type", "Interface Address"], ["Interface", v.egress], ["IP Type", ip ? "IP" : ""], ["IP Address", ip]] },
      ];
      if (v.tgtSerials.length) steps.push({ title: "Ciblage", path: ["Policies", "NAT", rbN, v.name], tab: "Target", fields: [["Devices (cocher)", v.tgtSerials]] });
      const cli = [
        `${r} nat-type ipv4 from ${members(v.srcZ)} to ${q(v.dstZ)} to-interface any source ${members(v.src)} destination any service any`,
        `${r} source-translation dynamic-ip-and-port interface-address interface ${v.egress}${ip ? " ip " + ip : ""}`,
        v.desc && `${r} description ${q(v.desc)}`,
        ...v.tgtSerials.map(s => `${r} target devices ${s}`),
      ].filter(Boolean);
      const notes = [
        { type: "or", text: "Rappel NAT : zone de destination = zone de l'adresse de destination AVANT traduction (ici " + v.dstZ + "). La règle de sécurité correspondante utilise les zones/IP d'origine." },
      ];
      if (v.ipMode === "var") notes.push({ type: "warn", title: "Variable obligatoire", text: `${v.ipVar} doit exister dans le template ou le template stack de CHAQUE pare-feu ciblé, sinon le push échoue sur ce pare-feu.` });
      if (v.ipMode === "ip" && v.loc === "dg") notes.push({ type: "warn", text: "IP fixe dans un DG multi-pare-feux : tous les sites traduiraient vers la même adresse. Utilise plutôt une variable." });
      return { steps, cli, notes, push: [pushDg(v.dg)] };
    },
  });

  /* =====================================================================
     P04 · Règles par défaut (intrazone / interzone)
     ===================================================================== */
  register({
    id: "p04-default-rules",
    module: "P04",
    title: "Règles par défaut intrazone / interzone",
    icon: "⚖️",
    desc: "Override des règles intrazone-default et interzone-default depuis un device group : journalisation en fin de session et profils de sécurité sur le trafic intrazone.",
    tags: "default rules intrazone-default interzone-default override log at session end security policy",
    fields: [
      { id: "loc", label: "Emplacement", type: "select", default: "dg", options: LOCS },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "Corp-DG" },
      { id: "intra", label: "Override intrazone-default", type: "checkbox", default: true, group: "intrazone-default (allow par défaut)" },
      { id: "intraLog", label: "Log at Session End", type: "checkbox", default: true, show: v => v.intra },
      { id: "intraPg", label: "Group Profile", type: "text", validate: optName, default: "Corp-Profiles", show: v => v.intra },
      { id: "inter", label: "Override interzone-default", type: "checkbox", default: true, group: "interzone-default (deny par défaut)" },
      { id: "interLog", label: "Log at Session End", type: "checkbox", default: true, show: v => v.inter },
      { id: "logSet", label: "Log Forwarding (les deux règles)", type: "text", validate: optName, default: "default", group: "Commun" },
    ],
    build(v) {
      const b = `set ${base(v)} post-rulebase default-security-rules rules`;
      const steps = [], cli = [];
      const one = (rule, action, log, pg) => {
        steps.push({ title: `Override ${rule}`, path: ["Policies", "Security", "Default Rules"], tab: "Actions", window: "Security Policy Rule",
          action: (v.loc === "shared" ? "Choisir Shared." : pickDg(v.dg)) + ` Sélectionner ${rule} SANS l'ouvrir → bouton Override → onglet Actions.`,
          fields: [["Action", action === "allow" ? "Allow" : "Deny"], ["Log at Session End", log], ["Log Forwarding", v.logSet], ["Profile Type", pg ? "Group" : ""], ["Group Profile", pg]] });
        cli.push(`${b} ${rule} action ${action} log-end ${yn(log)}`);
        if (v.logSet) cli.push(`${b} ${rule} log-setting ${q(v.logSet)}`);
        if (pg) cli.push(`${b} ${rule} profile-setting group ${q(pg)}`);
      };
      if (v.intra) one("intrazone-default", "allow", v.intraLog, v.intraPg);
      if (v.inter) one("interzone-default", "deny", v.interLog, "");
      const notes = [
        { type: "or", text: "Par défaut le pare-feu ne journalise AUCUN hit des règles par défaut : sans override, le trafic refusé interzone est invisible dans le Traffic log." },
        { type: "or", text: "Les règles par défaut s'évaluent après toutes les post-rules. On ne peut pas en créer de nouvelles, seulement surcharger les deux existantes (Revert pour annuler)." },
      ];
      if (!v.intra && !v.inter) notes.push({ type: "bad", text: "Aucune règle sélectionnée." });
      return { steps, cli, notes, push: [pushDg(v.dg)] };
    },
  });

  /* =====================================================================
     P04 · Ordre d'évaluation pre / local / post (simulateur, noCommit)
     ===================================================================== */
  const levelLines = txt => String(txt || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => {
    const m = /^([^:]+):\s*(.*)$/.exec(l);
    return m ? { loc: m[1].trim(), rules: m[2].split(",").map(s => s.trim()).filter(Boolean) } : { loc: "?", rules: [l] };
  });
  const levelV = (txt, v) => {
    const chain = ["Shared", ...v.chain];
    for (const x of levelLines(txt)) if (!chain.includes(x.loc)) return `« ${x.loc} » n'est pas dans la chaîne (Shared, ${v.chain.join(", ")}) — format « DG: règle1, règle2 »`;
    return null;
  };

  register({
    id: "p04-order",
    module: "P04",
    title: "Ordre d'évaluation pre / local / post",
    icon: "🧮",
    desc: "Simulateur : à partir de la chaîne de device groups d'un pare-feu et des règles de chaque niveau, calcule la rulebase finale dans l'ordre exact où le pare-feu l'évalue.",
    tags: "order ordre evaluation pre-rule post-rule local rules default preview rules hierarchy simulateur",
    noCommit: true,
    fields: [
      { id: "chain", label: "Chaîne de DG du pare-feu (de l'ancêtre au DG du pare-feu)", type: "list", required: true, validate: nameList, default: ["Corp-DG", "HQ-DG"],
        hint: "Shared est implicite en tête. Ex. Corp-DG, Europe-DG, Paris-DG." },
      { id: "pre", label: "Pre Rules — une ligne par niveau « DG: règle1, règle2 »", type: "textarea", validate: levelV, wide: true, group: "Règles",
        default: "Shared: Block-Bad-Countries\nCorp-DG: Block-Bad-IPs-Outbound\nHQ-DG: Block_Unauthorized_File_Storage_Apps" },
      { id: "local", label: "Règles locales du pare-feu", type: "list", default: ["Allow_Ping", "Allow_Trace"], hint: "Créées directement sur le pare-feu (fond blanc)." },
      { id: "post", label: "Post Rules — une ligne par niveau « DG: règle1, règle2 »", type: "textarea", validate: levelV, wide: true,
        default: "Corp-DG: Allow-Internet-Access\nHQ-DG: Users_to_Extranet, Extranet_to_Internet" },
      { id: "fwName", label: "Pare-feu (pour la vérification)", type: "text", validate: "hostname", default: "chicago-fw", group: "Test de correspondance (optionnel)" },
      { id: "tFrom", label: "Zone source", type: "text", validate: optName, default: "Users_Net" },
      { id: "tTo", label: "Zone destination", type: "text", validate: optName, default: "Internet" },
      { id: "tSrc", label: "IP source", type: "ip", default: "192.168.1.20" },
      { id: "tDst", label: "IP destination", type: "ip", default: "8.8.8.8" },
      { id: "tPort", label: "Port destination", type: "port", default: "443" },
      { id: "tApp", label: "Application", type: "text", default: "ssl" },
    ],
    build(v) {
      const chain = ["Shared", ...v.chain];
      const by = (txt) => { const m = {}; levelLines(txt).forEach(x => (m[x.loc] = (m[x.loc] || []).concat(x.rules))); return m; };
      const pre = by(v.pre), post = by(v.post);
      const order = [];
      chain.forEach(l => (pre[l] || []).forEach(r => order.push([`Pre · ${l}`, r])));
      v.local.forEach(r => order.push(["Locale", r]));
      chain.slice().reverse().forEach(l => (post[l] || []).forEach(r => order.push([`Post · ${l}`, r])));
      order.push(["Default", "intrazone-default"], ["Default", "interzone-default"]);
      const fields = order.map(([w, r], i) => [`${String(i + 1).padStart(2, "0")} · ${w}`, r]);
      const steps = [
        { title: `Rulebase finale de ${v.fwName || "ce pare-feu"}`, path: ["Policies", "Security"], window: "Combined Rules Preview",
          action: "Ordre d'évaluation de haut en bas : la première règle qui correspond est appliquée, les suivantes sont ignorées.", fields },
        { title: "Contrôler dans Panorama avec Preview Rules", path: ["Policies", "Security", "Pre Rules"],
          action: `Bouton Preview Rules en bas → Rulebase = security → Device Group = ${v.chain[v.chain.length - 1]} → Device = ${v.fwName || "le pare-feu"}.`, fields: [] },
        { title: "Contrôler sur le pare-feu", path: ["Policies", "Security"], action: "Sur le pare-feu : règles Panorama en jaune (lecture seule), règles locales en blanc.", fields: [] },
      ];
      const cliRaw = ["# --- Sur le pare-feu (mode opérationnel) ---", "show running security-policy"];
      if (v.tFrom && v.tTo && v.tSrc && v.tDst) cliRaw.push(`test security-policy-match from ${q(v.tFrom)} to ${q(v.tTo)} source ${v.tSrc} destination ${v.tDst} protocol 6 destination-port ${v.tPort || 443}${v.tApp ? " application " + q(v.tApp) : ""}`);
      cliRaw.push("", "# --- Sur Panorama : compteurs d'utilisation des règles (rafraîchis toutes les 5 min) ---", "# Policies > Security > colonne Rule Usage → lien Used/Unused");
      const notes = [
        { type: "ok", title: `${order.length} règles évaluées`, text: "Pre-rules : Shared puis du DG le plus haut au plus bas. Post-rules : ordre inverse, du DG du pare-feu jusqu'à Shared." },
        { type: "or", text: "Les règles d'un DG ne descendent que vers ses descendants : un DG « frère » (ex. Branch-DG) ne voit pas les règles de HQ-DG." },
      ];
      if (!Object.keys(pre).length && !Object.keys(post).length) notes.push({ type: "warn", text: "Aucune règle Panorama : seules les règles locales et par défaut s'appliquent." });
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P04 · Policy Rulebase Settings (tag / description / audit comment)
     ===================================================================== */
  register({
    id: "p04-rulebase",
    module: "P04",
    title: "Documentation obligatoire des règles",
    icon: "📝",
    desc: "Imposer tag, description et audit comment (avec expression régulière, ex. n° de ticket) à chaque création ou modification de règle dans Panorama.",
    tags: "policy rulebase settings require tag description audit comment regex fail commit rule changes archive",
    fields: [
      { id: "reqTag", label: "Require Tag on policies", type: "checkbox", default: true },
      { id: "reqDesc", label: "Require description on policies", type: "checkbox", default: true },
      { id: "failCommit", label: "Fail commit if policies have no tags or description", type: "checkbox", default: true, show: v => v.reqTag || v.reqDesc },
      { id: "reqAudit", label: "Require audit comment on policies", type: "checkbox", default: true },
      { id: "regex", label: "Audit Comment Regular Expression", type: "text", default: "^CHG[0-9]{6}", show: v => v.reqAudit,
        validate: x => { if (!x) return null; try { new RegExp(x); return null; } catch (e) { return "Expression régulière invalide"; } },
        hint: "Ex. ^CHG[0-9]{6} impose un numéro de change de l'outil de ticketing." },
      { id: "regexTest", label: "Commentaire de test", type: "text", default: "CHG004217 ouverture flux CRM", show: v => v.reqAudit && !!v.regex },
    ],
    build(v) {
      const steps = [{ title: "Paramètres de la rulebase", path: ["Panorama", "Setup", "Management"], window: "Policy Rulebase Settings",
        action: "Cadre Policy Rulebase Settings → ⚙.",
        fields: [["Require Tag on policies", v.reqTag], ["Require description on policies", v.reqDesc], ["Fail commit if policies have no tags or description", v.failCommit],
          ["Require audit comment on policies", v.reqAudit], ["Audit Comment Regular Expression", v.reqAudit && v.regex]],
        note: "Réglable globalement ici, ou indépendamment par template (Device > Setup > Management avec le sélecteur Template) pour les pare-feux." },
        { title: "Consulter l'historique d'une règle", path: ["Policies", "Security", "Pre Rules"], action: "Ouvrir une règle → lien Audit Comment Archive : Audit Comments, Config Logs (between commits), Rule Changes (comparaison de versions).", fields: [] }];
      const cli = [`# Policy Rulebase Settings : réglage documenté en WebUI ; chemin CLI sous « deviceconfig setting management » ${TOVAL}`];
      const notes = [];
      if (v.reqAudit && v.regex) {
        let ok = false; try { ok = new RegExp(v.regex).test(v.regexTest || ""); } catch (e) { }
        notes.push({ type: ok ? "ok" : "bad", title: "Test de l'expression régulière", text: `« ${v.regexTest} » ${ok ? "est accepté" : "serait REFUSÉ"} par ${v.regex}.` });
      }
      notes.push({ type: "or", text: "Sans tag/description saisis, le bouton OK de la règle reste grisé. Combine avec la colonne Rule Usage : une règle Unused documentée se supprime sans risque (désactive-la d'abord)." });
      return { steps, cli, notes };
    },
  });

  /* =====================================================================
     P05 · Log Collector (local ou dédié)
     ===================================================================== */
  register({
    id: "p05-collector",
    module: "P05",
    title: "Log Collector (local ou dédié)",
    icon: "🗄️",
    desc: "Déclarer un Managed Collector : Panorama lui-même (mode Panorama) ou un M-Series/VM dédié en mode Log Collector, avec ses paires de disques.",
    tags: "log collector managed collector dedicated logger mode disks disk pair panorama-server local collector",
    fields: [
      { id: "lcType", label: "Type de collecteur", type: "select", default: "local",
        options: [["local", "Collecteur local (Panorama en mode Panorama)"], ["dedicated", "Log Collector dédié (M-Series / VM en mode Log Collector)"]] },
      { id: "collector", label: "Numéro de série du collecteur", type: "text", required: true, validate: SERIAL, default: "000710012345",
        hint: "Local : n° de série de Panorama (Dashboard > General Information). Dédié : show system info sur le collecteur." },
      { id: "disks", label: "Paires de disques à activer", type: "list", required: true, default: ["A"],
        validate: a => a.every(d => /^[A-H]$/.test(d)) ? (new Set(a).size === a.length ? null : "Disque en double") : "Lettres A à H (une par paire RAID / disque virtuel)" },
      { id: "lcName", label: "Hostname du collecteur", type: "text", required: true, validate: "hostname", default: "LC-Paris-01", show: v => v.lcType === "dedicated", group: "Collecteur dédié" },
      { id: "lcIp", label: "IP de management", type: "ip", required: true, default: "10.1.1.20", show: v => v.lcType === "dedicated" },
      { id: "lcMask", label: "Masque", type: "text", required: true, default: "255.255.255.0", show: v => v.lcType === "dedicated", validate: x => V.ip(x) ? "Masque décimal pointé" : null },
      { id: "lcGw", label: "Passerelle", type: "ip", required: true, default: "10.1.1.1", show: v => v.lcType === "dedicated" },
      { id: "dns1", label: "DNS primaire", type: "ip", default: "10.1.1.53", show: v => v.lcType === "dedicated" },
      { id: "ntp1", label: "NTP primaire", type: "text", validate: "host", default: "0.pool.ntp.org", show: v => v.lcType === "dedicated" },
      { id: "panoIp", label: "IP du Panorama de management", type: "text", required: true, validate: ipOrCidr, default: "10.1.1.10", show: v => v.lcType === "dedicated" },
      { id: "panoIp2", label: "IP du Panorama HA peer (optionnel)", type: "text", validate: x => x ? ipOrCidr(x) : null, show: v => v.lcType === "dedicated" },
      { id: "cg", label: "Collector group de rattachement (pour le push)", type: "text", validate: optName, default: "CG-1", group: "Push",
        hint: "Un collecteur ne reçoit sa configuration qu'une fois membre d'un collector group (module suivant)." },
    ],
    build(v) {
      const sn = v.collector, ded = v.lcType === "dedicated";
      const lc = `set log-collector ${sn}`;
      const steps = [];
      if (ded) steps.push({ title: "Sur le collecteur (console) : passer en mode Log Collector", path: ["CLI console du futur collecteur"],
        action: "Configurer d'abord l'IP de management, noter le n° de série, puis : request system system-mode logger (confirmer → redémarrage). Ensuite : configure → set deviceconfig system panorama-server " + ipOnly(v.panoIp) + (v.panoIp2 ? " ; set deviceconfig system panorama-server-2 " + ipOnly(v.panoIp2) : "") + " → commit.",
        fields: [], warn: "Après le passage en mode Log Collector, l'appliance n'a plus de WebUI : elle se gère uniquement depuis Panorama (et la CLI)." });
      steps.push({ title: "Ajouter le Managed Collector", path: ["Panorama", "Managed Collectors"], tab: "General", window: "Collector",
        action: ded ? "Cliquer sur Add." : "Copier le n° de série de Panorama (Dashboard), puis Add : l'écran se réduit à quelques champs, c'est normal pour le collecteur local.",
        fields: [["Collector S/N", sn], ["Panorama Server IP", ded && ipOnly(v.panoIp)], ["Panorama Server IP 2", ded && v.panoIp2 && ipOnly(v.panoIp2)], ["Hostname", ded && v.lcName],
          ["IP Address", ded && v.lcIp], ["Netmask", ded && v.lcMask], ["Default Gateway", ded && v.lcGw], ["Primary DNS Server", ded && v.dns1], ["Primary NTP Server", ded && v.ntp1]] });
      if (ded) steps.push({ title: "Identifiants d'administration", path: ["Panorama", "Managed Collectors", sn], tab: "Authentication",
        fields: [["Mode", "Password"], ["Password / Confirm", "mot de passe admin du collecteur"]], note: "Champ obligatoire pour un collecteur dédié (avec le S/N et la paire de disques)." });
      steps.push({ title: "Commit puis activer les disques", path: ["Panorama", "Managed Collectors", sn], tab: "Disks",
        action: "Commit > Commit to Panorama (le collecteur apparaît « Out of sync », normal). Rouvrir le collecteur → onglet Disks → Add pour chaque paire.",
        fields: [["Disk Pairs", v.disks]], note: "Faire un nouveau Commit to Panorama après l'ajout des disques, puis le push vers le collector group." });

      const cli = [];
      if (ded) cli.push("# --- Pré-requis sur le collecteur lui-même (console, mode opérationnel puis configure) ---",
        "#   > request system system-mode logger", `#   # set deviceconfig system panorama-server ${ipOnly(v.panoIp)}`, ...(v.panoIp2 ? [`#   # set deviceconfig system panorama-server-2 ${ipOnly(v.panoIp2)}`] : []), "#   # commit",
        "# --- Sur Panorama ---");
      cli.push(`# Managed Collector ${sn} — syntaxe des sous-arbres « deviceconfig » et « disk-settings » ${TOVAL}`);
      if (ded) {
        cli.push(`${lc} deviceconfig system hostname ${q(v.lcName)} ip-address ${v.lcIp} netmask ${v.lcMask} default-gateway ${v.lcGw}`,
          `${lc} deviceconfig system panorama-server ${ipOnly(v.panoIp)}`);
        if (v.panoIp2) cli.push(`${lc} deviceconfig system panorama-server-2 ${ipOnly(v.panoIp2)}`);
        if (v.dns1) cli.push(`${lc} deviceconfig system dns-setting servers primary ${v.dns1}`);
        if (v.ntp1) cli.push(`${lc} deviceconfig system ntp-servers primary-ntp-server ntp-server-address ${v.ntp1}`);
      } else cli.push(`${lc}`);
      v.disks.forEach(d => cli.push(`${lc} disk-settings disk-pair ${d}`));

      const notes = [
        { type: "or", text: "Le collecteur n'est utilisable qu'une fois membre d'un collector group : les pare-feux envoient leurs logs au GROUPE, jamais à un collecteur isolé." },
      ];
      if (!ded) notes.push({ type: "or", text: "Collecteur local : Panorama (VM) doit être en mode Panorama avec un disque de logs ajouté (module « Mode Panorama »). En mode Legacy, cette étape n'existe pas." });
      if (ded) notes.push({ type: "warn", text: "Tous les collecteurs d'un même groupe : même version PAN-OS, même modèle, même nombre et type de disques." });
      const push = v.cg ? [pushCg(v.cg)] : [];
      return { steps, cli, notes, push, verify: [`show log-collector serial-number ${sn}`, "show log-collector-es-cluster health"] };
    },
  });

  /* =====================================================================
     P05 · Collector group (membres, redondance, préférences)
     ===================================================================== */
  const prefLinesV = (txt, v) => {
    const lcs = uniq([v.collector, ...v.lcOthers]);
    for (const l of String(txt || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
      const m = /^(\d+)\s*[:>-]+\s*(.+)$/.exec(l);
      if (!m) return `« ${l} » : format « série-pare-feu : collecteur1, collecteur2 »`;
      const e = SERIAL(m[1]); if (e) return `Pare-feu ${m[1]} : ${e}`;
      for (const c of m[2].split(",").map(s => s.trim())) if (!lcs.includes(c)) return `Collecteur ${c} absent du groupe`;
    }
    return null;
  };

  register({
    id: "p05-cg",
    module: "P05",
    title: "Collector group & redondance",
    icon: "🧺",
    desc: "Regrouper 1 à 16 Log Collectors, activer la redondance des logs, fixer la rétention minimale et la liste de préférence des collecteurs pour chaque pare-feu (Device Log Forwarding).",
    tags: "collector group cg log collector redundancy redondance preference list device log forwarding retention",
    fields: [
      { id: "cg", label: "Nom du collector group", type: "text", required: true, validate: "name", default: "CG-1" },
      { id: "collector", label: "Collecteur principal (n° de série)", type: "text", required: true, validate: SERIAL, default: "000710012345", group: "Membres" },
      { id: "lcOthers", label: "Autres collecteurs du groupe", type: "list", validate: serialList, placeholder: "000710012346",
        hint: "Même modèle, même version et mêmes disques. Latence < 25 ms entre collecteurs (recommandation)." },
      { id: "redund", label: "Enable log redundancy across collectors", type: "checkbox", default: false, show: v => v.lcOthers.length > 0,
        hint: "Chaque log est écrit sur 2 collecteurs : stockage utile divisé par 2 et débit d'ingestion réduit de moitié." },
      { id: "minRet", label: "Minimum Retention Period (jours, optionnel)", type: "number", min: 1, max: 2000, placeholder: "30",
        hint: "Panorama alerte (log système) si la rétention réelle passe sous ce seuil." },
      { id: "prefMode", label: "Préférences de transfert", type: "select", default: "all", group: "Device Log Forwarding",
        options: [["all", "Tous les pare-feux listés → collecteurs dans l'ordre du groupe"], ["custom", "Préférences par pare-feu (avancé)"]] },
      { id: "fwSerial", label: "Pare-feu qui envoie ses logs", type: "text", validate: SERIAL, default: "012801000201", show: v => v.prefMode === "all" },
      { id: "fwOthers", label: "Autres pare-feux", type: "list", validate: serialList, default: ["012801000102"], show: v => v.prefMode === "all" },
      { id: "prefs", label: "Une ligne par pare-feu : série : collecteur1, collecteur2", type: "textarea", wide: true, validate: prefLinesV, show: v => v.prefMode === "custom",
        default: "012801000201 : 000710012345, 000710012346\n012801000102 : 000710012346, 000710012345",
        hint: "Le pare-feu envoie au premier collecteur disponible de sa liste ; le hash du groupe décide ensuite quel collecteur stocke le log." },
    ],
    build(v) {
      const lcs = uniq([v.collector, ...v.lcOthers]);
      const g = `set log-collector-group ${q(v.cg)}`;
      let prefs;
      if (v.prefMode === "custom") prefs = String(v.prefs).split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(l => { const m = /^(\d+)\s*[:>-]+\s*(.+)$/.exec(l); return { fw: m[1], lcs: m[2].split(",").map(s => s.trim()) }; });
      else prefs = uniq([v.fwSerial, ...v.fwOthers]).map(fw => ({ fw, lcs }));
      const redund = v.redund && lcs.length > 1;
      const steps = [
        { title: `Créer le collector group ${v.cg}`, path: ["Panorama", "Collector Groups"], tab: "General", window: "Collector Group", action: "Cliquer sur Add.",
          fields: [["Name", v.cg], ["Minimum Retention Period (days)", v.minRet], ["Collector Group Members (Add)", lcs], ["Enable log redundancy across collectors", redund]],
          note: "Une fois les collecteurs connectés, le champ Log Storage affiche l'espace total et libre de tout le groupe." },
        ...prefs.map((p, i) => ({ title: `Préférence de transfert ${i + 1}`, path: ["Panorama", "Collector Groups", v.cg], tab: "Device Log Forwarding", window: "Log Forwarding Preferences",
          action: "Add → Devices : Modify (cocher le pare-feu) → Collectors : Add dans l'ordre de préférence → OK.", fields: [["Devices", p.fw], ["Collectors (ordre)", p.lcs.join(" → ")]] })),
        { title: "Pousser vers le collector group", path: ["Commit", "Push to Devices"], action: `Après Commit to Panorama : Push to Devices → Edit Selections → onglet Collector Groups → cocher ${v.cg} → OK → Push. Le collecteur passe ensuite « In sync » (Panorama > Managed Collectors).`, fields: [] },
      ];
      const cli = [`# Collector group ${v.cg}`, `${g} logfwd-setting collectors ${members(lcs)}`];
      prefs.forEach(p => cli.push(`${g} logfwd-setting devices ${p.fw} collectors ${members(p.lcs)}`));
      if (redund || v.minRet) cli.push(`# Redondance / rétention — ${TOVAL}`);
      if (redund) cli.push(`${g} general-setting management enable-log-duplication yes`);
      if (v.minRet) cli.push(`${g} general-setting management min-retention-period ${v.minRet}`);
      const notes = [
        { type: "ok", title: `${lcs.length} collecteur(s) · ${prefs.length} pare-feu(x)`, text: redund ? "Redondance active : chaque log existe sur deux collecteurs (perte d'un collecteur sans perte de logs)." : "Sans redondance : la panne d'un collecteur rend ses logs indisponibles (ce n'est pas de la HA)." },
      ];
      if (lcs.length > 16) notes.push({ type: "bad", text: "16 Log Collectors maximum par collector group." });
      if (redund) notes.push({ type: "warn", text: "Redondance = stockage effectif /2 et ingestion /2 : dimensionne avec le module « Dimensionnement du stockage de logs »." });
      if (lcs.length === 1 && v.lcOthers.length === 0) notes.push({ type: "or", text: "Un seul collecteur suffit si : stockage nécessaire < capacité d'un appareil, débit < maximum de la plateforme, et pas de besoin de redondance." });
      notes.push({ type: "or", text: "Côté pare-feu, vérifie la connexion avec « show logging-status » (collecteur connecté, dernier log transféré)." });
      return { steps, cli, notes, push: [pushCg(v.cg)], verify: ["show log-collector-es-cluster health", ...lcs.slice(0, 2).map(s => `show log-collector serial-number ${s}`), ...prefs.slice(0, 2).map(p => `show logging-status device ${p.fw}`)] };
    },
  });

  /* =====================================================================
     P05 · Log forwarding des pare-feux (profil default + server profiles)
     ===================================================================== */
  const LOGTYPES = [["traffic", "Traffic"], ["threat", "Threat"], ["url", "URL Filtering"], ["wildfire", "WildFire Submissions"], ["data", "Data Filtering"],
    ["decryption", "Decryption"], ["tunnel", "Tunnel Inspection"], ["auth", "Authentication"]];
  const filterV = f => {
    if (!f || f === "All Logs") return null;
    let d = 0; for (const c of f) { if (c === "(") d++; if (c === ")") d--; if (d < 0) return "Parenthèse fermante en trop"; }
    return d ? "Parenthèses non équilibrées" : (/\b(eq|neq|in|contains|geq|leq|gt|lt|has|notin)\b/.test(f) ? null : "Opérateur attendu : eq, neq, geq, contains, in…");
  };

  register({
    id: "p05-fwd",
    module: "P05",
    title: "Log forwarding des pare-feux",
    icon: "📤",
    desc: "Profil de Log Forwarding (nommé default → appliqué automatiquement aux nouvelles règles) : envoi vers Panorama par type de log, Threat vers syslog, menaces critiques/hautes par e-mail, server profiles en template.",
    tags: "log forwarding profile default panorama cortex data lake syslog email server profile traffic threat url wildfire match list",
    fields: [
      { id: "loc", label: "Emplacement du profil", type: "select", default: "shared", options: LOCS, hint: "Lab 5 : Shared, pour qu'il soit disponible dans tous les DG." },
      { id: "dg", label: "Device group (portée de push / règles)", type: "text", required: true, validate: "name", default: "Corp-DG" },
      { id: "prof", label: "Nom du profil", type: "text", required: true, validate: "name", default: "default",
        hint: "« default » (en minuscules) est appliqué automatiquement à toute NOUVELLE règle de sécurité." },
      { id: "profDesc", label: "Description", type: "text", default: "Profil standard de log forwarding des règles de sécurité", wide: true },
      { id: "toPano", label: "Types de logs envoyés à Panorama", type: "list", default: ["traffic", "threat", "url", "wildfire"], group: "Vers Panorama / Cortex Data Lake",
        validate: a => a.every(t => LOGTYPES.some(l => l[0] === t)) ? null : "Types : " + LOGTYPES.map(l => l[0]).join(", "),
        hint: "Valeurs : " + LOGTYPES.map(l => l[0]).join(", ") },
      { id: "sysThreat", label: "Envoyer aussi tous les logs Threat au syslog", type: "checkbox", default: true, group: "Syslog & e-mail" },
      { id: "syslogProf", label: "Syslog Server Profile", type: "text", required: true, validate: "name", default: "Syslog_Servers", show: v => v.sysThreat },
      { id: "mailCrit", label: "E-mail pour les menaces critical/high", type: "checkbox", default: true },
      { id: "mailProf", label: "Email Server Profile", type: "text", required: true, validate: "name", default: "Email_Servers", show: v => v.mailCrit },
      { id: "mailFilter", label: "Filtre", type: "text", required: true, default: "(severity eq critical) or (severity eq high)", validate: filterV, show: v => v.mailCrit, wide: true },
      { id: "mkSrv", label: "Créer les server profiles dans un template", type: "checkbox", default: false, group: "Server profiles (Device > Server Profiles, sélecteur Template)",
        hint: "Décoché si déjà créés (ex. Lab 3 dans Region-Americas)." },
      { id: "template", label: "Template", type: "text", required: true, validate: "name", default: "Global-Settings", show: v => v.mkSrv },
      { id: "stack", label: "Template stack à pousser", type: "text", validate: optName, default: "", show: v => v.mkSrv || v.tplSys },
      { id: "syslogIp", label: "Serveur syslog", type: "text", required: true, validate: "host", default: "192.168.50.55", show: v => v.mkSrv && v.sysThreat },
      { id: "syslogTr", label: "Transport", type: "select", default: "UDP", options: [["UDP", "UDP/514"], ["TCP", "TCP/514"], ["SSL", "SSL/6514"]], show: v => v.mkSrv && v.sysThreat },
      { id: "mailFrom", label: "From", type: "text", validate: "email", required: true, default: "chicago-fw@panw.lab", show: v => v.mkSrv && v.mailCrit },
      { id: "mailTo", label: "To", type: "text", validate: "email", required: true, default: "paloalto42@panw.lab", show: v => v.mkSrv && v.mailCrit },
      { id: "mailGw", label: "Email Gateway", type: "text", validate: "host", required: true, default: "192.168.50.150", show: v => v.mkSrv && v.mailCrit },
      { id: "tplSys", label: "Envoyer aussi les logs System et Config des pare-feux à Panorama (Device > Log Settings)", type: "checkbox", default: false, group: "Logs système des pare-feux" },
      { id: "tplSysName", label: "Template pour Device > Log Settings", type: "text", required: true, validate: "name", default: "Global-Settings", show: v => v.tplSys },
      { id: "rules", label: "Règles existantes à rattacher au profil", type: "list", validate: nameList, default: ["Allow-Internet-Access"], group: "Application aux règles existantes",
        hint: "Le profil « default » ne s'applique qu'aux nouvelles règles : les règles existantes doivent être modifiées (onglet Actions)." },
      { id: "rulesRb", label: "Rulebase de ces règles", type: "select", default: "post", options: [["pre", "Pre Rules"], ["post", "Post Rules"]], show: v => v.rules.length > 0 },
    ],
    build(v) {
      const b = base(v);
      const P = `set ${b} log-settings profiles ${q(v.prof)}`;
      const tl = t => (LOGTYPES.find(l => l[0] === t) || [, t])[1];
      const entries = v.toPano.map(t => ({ n: `${tl(t).split(" ")[0]}-to-Panorama${t === "threat" && v.sysThreat ? "-and-Syslog" : ""}`, t, f: "All Logs", pano: true, sys: t === "threat" && v.sysThreat, d: `Envoie tous les logs ${tl(t)} à Panorama${t === "threat" && v.sysThreat ? " et au syslog" : ""}` }));
      if (v.sysThreat && !v.toPano.includes("threat")) entries.push({ n: "Threat-to-Syslog", t: "threat", f: "All Logs", pano: false, sys: true, d: "Envoie tous les logs Threat au syslog" });
      if (v.mailCrit) entries.push({ n: "Threat-critical-and-high-to-mail", t: "threat", f: v.mailFilter, pano: false, mail: true, d: "E-mail pour les menaces critiques et hautes" });
      const tpl = v.mkSrv ? v.template : "";
      const steps = [];
      if (v.mkSrv) {
        if (v.sysThreat) steps.push({ title: `Syslog Server Profile ${v.syslogProf}`, path: ["Device", "Server Profiles", "Syslog"], window: "Syslog Server Profile",
          action: `Sélectionner le template « ${tpl} » dans la liste Template en haut, puis Add.`,
          fields: [["Name", v.syslogProf], ["Location", "Shared"], ["Servers › Name", "Syslog-1"], ["Syslog Server", v.syslogIp], ["Transport", v.syslogTr], ["Port", v.syslogTr === "SSL" ? "6514" : "514"], ["Format", "BSD"], ["Facility", "LOG_USER"]] });
        if (v.mailCrit) steps.push({ title: `Email Server Profile ${v.mailProf}`, path: ["Device", "Server Profiles", "Email"], window: "Email Server Profile", action: "Toujours dans le template, Add.",
          fields: [["Name", v.mailProf], ["Servers › Name", "Mail-1"], ["Email Display Name", "Firewall"], ["From", v.mailFrom], ["To", v.mailTo], ["Email Gateway", v.mailGw]],
          note: "Ne pas cliquer Test Connection depuis le template : le test se fait depuis un pare-feu qui a reçu la configuration." });
      }
      steps.push({ title: `Profil de Log Forwarding « ${v.prof} »`, path: ["Objects", "Log Forwarding"], window: "Log Forwarding Profile",
        action: pickDg(v.dg) + " Puis Add.", fields: [["Name", v.prof], ["Shared", v.loc === "shared"], ["Description", v.profDesc]] });
      entries.forEach(e => steps.push({ title: `Match list : ${e.n}`, path: ["Objects", "Log Forwarding", v.prof], window: "Log Forwarding Profile Match List",
        action: "Dans le profil, Add en bas à gauche.",
        fields: [["Name", e.n], ["Description", e.d], ["Log Type", e.t], ["Filter", e.f], ["Panorama/Cloud Logging", e.pano], ["Syslog (Add)", e.sys && v.syslogProf], ["Email (Add)", e.mail && v.mailProf]] }));
      if (v.tplSys) steps.push({ title: "Logs System / Configuration des pare-feux", path: ["Device", "Log Settings"], action: `Sélectionner le template « ${v.tplSysName} ». Sections System et Configuration → Add.`,
        fields: [["Name", "System-to-Panorama / Config-to-Panorama"], ["Filter", "All Logs"], ["Panorama", true]] });
      if (v.rules.length) steps.push({ title: "Rattacher le profil aux règles existantes", path: ["Policies", "Security", v.rulesRb === "pre" ? "Pre Rules" : "Post Rules"], tab: "Actions",
        action: `${pickDg(v.dg)} Ouvrir chaque règle → onglet Actions → Log Forwarding.`, fields: [["Règles", v.rules], ["Log Forwarding", v.prof]] });

      const cli = [];
      if (v.mkSrv) {
        const ts = `set template ${q(tpl)} config shared log-settings`;
        if (v.sysThreat) cli.push(`${ts} syslog ${q(v.syslogProf)} server Syslog-1 server ${v.syslogIp} transport ${v.syslogTr} port ${v.syslogTr === "SSL" ? 6514 : 514} format BSD facility LOG_USER`);
        if (v.mailCrit) cli.push(`${ts} email ${q(v.mailProf)} server Mail-1 display-name Firewall from ${v.mailFrom} to ${v.mailTo} gateway ${v.mailGw}`);
      }
      cli.push(`${P} description ${q(v.profDesc || v.prof)}`);
      entries.forEach(e => {
        const m = `${P} match-list ${q(e.n)}`;
        cli.push(`${m} log-type ${e.t} filter ${q(e.f)} send-to-panorama ${yn(e.pano)}`, `${m} action-desc ${q(e.d)}`);
        if (e.sys) cli.push(`${m} send-syslog ${q(v.syslogProf)}`);
        if (e.mail) cli.push(`${m} send-email ${q(v.mailProf)}`);
      });
      if (v.tplSys) {
        const ls = `set template ${q(v.tplSysName)} config shared log-settings`;
        cli.push(`${ls} system match-list System-to-Panorama filter "All Logs" send-to-panorama yes`, `${ls} config match-list Config-to-Panorama filter "All Logs" send-to-panorama yes`);
      }
      v.rules.forEach(r => cli.push(`set device-group ${q(v.dg)} ${v.rulesRb}-rulebase security rules ${q(r)} log-setting ${q(v.prof)}`));

      const notes = [
        { type: "or", text: "Panorama/Cloud Logging suffit pour Panorama : chaque pare-feu connaît déjà l'adresse de Panorama (ou de son collector group)." },
        { type: "or", text: "Server profiles = template (Device > Server Profiles) ; profil de Log Forwarding = device group (Objects > Log Forwarding)." },
      ];
      if (v.toPano.includes("traffic")) notes.push({ type: "warn", text: "Les logs Traffic ne sont transférés QUE pour les règles de sécurité qui référencent le profil (onglet Actions). Les autres types de logs n'ont pas cette contrainte d'affectation par règle." });
      if (v.prof !== "default") notes.push({ type: "or", text: "Nom ≠ « default » : le profil devra être choisi manuellement dans chaque règle." });
      if (v.mailCrit && v.mailFilter === "All Logs") notes.push({ type: "bad", text: "E-mail sur tous les logs Threat : risque d'inonder la messagerie. Filtre sur la sévérité." });
      const push = [pushDg(v.dg)];
      if ((v.mkSrv || v.tplSys) && v.stack) push.unshift(pushTs(v.stack));
      if ((v.mkSrv || v.tplSys) && !v.stack) notes.push({ type: "warn", text: "Template modifié : pousse aussi le template stack des pare-feux (renseigne-le pour l'ajouter au push)." });
      return { steps, cli, notes, push };
    },
  });

  /* =====================================================================
     P05 · Panorama → syslog / e-mail (logs de Panorama + Collector Log Forwarding)
     ===================================================================== */
  register({
    id: "p05-syslog",
    module: "P05",
    title: "Transfert Panorama → syslog / e-mail",
    icon: "📡",
    desc: "Server profiles propres à Panorama (Panorama > Server Profiles) et Panorama > Log Settings : logs System vers syslog, commits par e-mail, et option Collector Log Forwarding des logs pare-feux vers un SIEM.",
    tags: "panorama log settings syslog email siem server profile system config commit collector log forwarding",
    fields: [
      { id: "sysProf", label: "Syslog Server Profile Panorama", type: "text", required: true, validate: "name", default: "Panorama-Syslog", group: "Serveur syslog / SIEM" },
      { id: "sysName", label: "Nom du serveur", type: "text", required: true, validate: "name", default: "US-Syslog-1" },
      { id: "sysIp", label: "Adresse", type: "text", required: true, validate: "host", default: "192.168.50.55" },
      { id: "sysTr", label: "Transport", type: "select", default: "UDP", options: [["UDP"], ["TCP"], ["SSL"]] },
      { id: "sysPort", label: "Port", type: "port", required: true, default: "514" },
      { id: "sysFmt", label: "Format", type: "select", default: "BSD", options: [["BSD"], ["IETF"]] },
      { id: "mail", label: "Notifications par e-mail", type: "checkbox", default: true, group: "E-mail" },
      { id: "mailProf", label: "Email Server Profile Panorama", type: "text", required: true, validate: "name", default: "Panorama-Email", show: v => v.mail },
      { id: "mailDisp", label: "Email Display Name", type: "text", default: "Panorama", show: v => v.mail },
      { id: "mailFrom", label: "From", type: "text", validate: "email", required: true, default: "panorama@panw.lab", show: v => v.mail },
      { id: "mailTo", label: "To", type: "text", validate: "email", required: true, default: "paloalto42@panw.lab", show: v => v.mail },
      { id: "mailGw", label: "Email Gateway", type: "text", validate: "host", required: true, default: "192.168.50.150", show: v => v.mail },
      { id: "fwdSys", label: "System → syslog", type: "checkbox", default: true, group: "Panorama > Log Settings" },
      { id: "sysFilter", label: "Filtre System", type: "text", default: "All Logs", validate: filterV, show: v => v.fwdSys },
      { id: "fwdCfg", label: "Configuration → e-mail", type: "checkbox", default: true, show: v => v.mail },
      { id: "cfgFilter", label: "Filtre Configuration", type: "text", default: "(cmd eq commit)", validate: filterV, show: v => v.mail && v.fwdCfg,
        hint: "(cmd eq commit) : un e-mail par commit, pas à chaque modification." },
      { id: "cgFwd", label: "Relayer aussi les logs des pare-feux depuis le collector group (Collector Log Forwarding)", type: "checkbox", default: false, group: "Logs des pare-feux vers le SIEM",
        hint: "Évite de configurer le syslog sur chaque pare-feu : les collecteurs relaient." },
      { id: "cg", label: "Collector group", type: "text", required: true, validate: "name", default: "CG-1", show: v => v.cgFwd },
      { id: "cgTypes", label: "Types relayés", type: "list", default: ["threat", "traffic"], show: v => v.cgFwd,
        validate: a => a.every(t => LOGTYPES.some(l => l[0] === t)) ? null : "Types : " + LOGTYPES.map(l => l[0]).join(", ") },
      { id: "cgFilter", label: "Filtre (Threat)", type: "text", default: "(severity geq high)", validate: filterV, show: v => v.cgFwd && v.cgTypes.includes("threat") },
    ],
    build(v) {
      const ps = "set panorama log-settings";
      const steps = [
        { title: `Syslog Server Profile ${v.sysProf}`, path: ["Panorama", "Server Profiles", "Syslog"], window: "Syslog Server Profile", action: "Cliquer sur Add, puis Add dans l'onglet Servers.",
          fields: [["Name", v.sysProf], ["Servers › Name", v.sysName], ["Syslog Server", v.sysIp], ["Transport", v.sysTr], ["Port", v.sysPort], ["Format", v.sysFmt], ["Facility", "LOG_USER"]] },
      ];
      if (v.mail) steps.push({ title: `Email Server Profile ${v.mailProf}`, path: ["Panorama", "Server Profiles", "Email"], window: "Email Server Profile", action: "Add → Location : Panorama → onglet Servers : Add.",
        fields: [["Name", v.mailProf], ["Servers › Name", "Mail-1"], ["Email Display Name", v.mailDisp], ["From", v.mailFrom], ["To", v.mailTo], ["Email Gateway", v.mailGw]],
        note: "Cliquer Test Connection : un e-mail de test doit arriver avant d'aller plus loin." });
      if (v.fwdSys) steps.push({ title: "System → syslog", path: ["Panorama", "Log Settings"], window: "Log Settings - System", action: "Section System → Add.",
        fields: [["Name", "System-Logs-to-Syslog"], ["Filter", v.sysFilter], ["Description", "Envoie les logs système de Panorama au syslog"], ["Syslog (Add)", v.sysProf]] });
      if (v.mail && v.fwdCfg) steps.push({ title: "Configuration → e-mail", path: ["Panorama", "Log Settings"], window: "Log Settings - Configuration", action: "Section Configuration → Add.",
        fields: [["Name", "Commit-to-Email"], ["Filter", v.cfgFilter], ["Description", "Envoie les commits Panorama par e-mail"], ["Email (Add)", v.mailProf]] });
      if (v.cgFwd) steps.push({ title: "Collector Log Forwarding", path: ["Panorama", "Collector Groups", v.cg], tab: "Collector Log Forwarding",
        action: "Un onglet par type de log : Add → filtre → Syslog : " + v.sysProf + ".",
        fields: v.cgTypes.map(t => [`${(LOGTYPES.find(l => l[0] === t) || [, t])[1]}`, `${t === "threat" ? v.cgFilter || "All Logs" : "All Logs"} → ${v.sysProf}`]) });

      const cli = [`${ps} syslog ${q(v.sysProf)} server ${q(v.sysName)} server ${v.sysIp} transport ${v.sysTr} port ${v.sysPort} format ${v.sysFmt} facility LOG_USER`];
      if (v.mail) cli.push(`${ps} email ${q(v.mailProf)} server Mail-1 display-name ${q(v.mailDisp || "Panorama")} from ${v.mailFrom} to ${v.mailTo} gateway ${v.mailGw}`);
      if (v.fwdSys) cli.push(`${ps} system match-list System-Logs-to-Syslog filter ${q(v.sysFilter || "All Logs")} send-syslog ${q(v.sysProf)}`);
      if (v.mail && v.fwdCfg) cli.push(`${ps} config match-list Commit-to-Email filter ${q(v.cfgFilter)} send-email ${q(v.mailProf)}`);
      if (v.cgFwd) {
        cli.push(`# Collector Log Forwarding — ${TOVAL}`);
        v.cgTypes.forEach(t => cli.push(`set log-collector-group ${q(v.cg)} log-settings ${t} match-list ${t}-to-SIEM filter ${q(t === "threat" ? v.cgFilter || "All Logs" : "All Logs")} send-syslog ${q(v.sysProf)}`));
      }
      const notes = [
        { type: "warn", title: "Server profiles séparés", text: "Panorama n'utilise PAS les server profiles des templates (Device > Server Profiles) : même si les serveurs sont identiques, ils doivent être recréés sous Panorama > Server Profiles." },
        { type: "or", text: "Test : modifie la bannière (Panorama > Setup > Management) et fais un Commit to Panorama : un e-mail « CONFIG ALERT » doit arriver." },
      ];
      if (v.sysTr === "UDP") notes.push({ type: "or", text: "UDP/514 : aucun accusé de réception. Pour un SIEM en production, préfère TCP ou SSL (6514)." });
      if (v.cgFwd) notes.push({ type: "or", text: "Collector Log Forwarding : la charge d'export passe des pare-feux aux collecteurs. Pousse ensuite le collector group." });
      return { steps, cli, notes, push: v.cgFwd ? [pushCg(v.cg)] : [], verify: ["show log system direction equal backward", "show log config direction equal backward"] };
    },
  });

  /* =====================================================================
     P05 · Dimensionnement du stockage de logs (calculateur, noCommit)
     ===================================================================== */
  const PLATFORMS = { "M-200": { pano: 10000, lc: 28000 }, "M-500": { pano: 15000, lc: 30000 }, "M-600": { pano: 25000, lc: 50000 }, "Panorama VM": { pano: 10000, lc: 10000 } };

  register({
    id: "p05-sizing",
    module: "P05",
    title: "Dimensionnement du stockage de logs",
    icon: "📐",
    desc: "Calculateur avant-vente : volume de logs détaillés à partir du débit (LPS) et de la rétention, nombre de collecteurs nécessaires selon la plateforme et la redondance.",
    tags: "sizing dimensionnement lps logs per second retention storage stockage collector capacity calculateur",
    noCommit: true,
    fields: [
      { id: "lps", label: "Débit agrégé (logs par seconde)", type: "number", required: true, min: 1, max: 1000000, default: "1500",
        hint: "Mesure : nb de logs/jour du SIEM ÷ 86 400, scripts device_lps / lc_lps, ou Statistics d'un collecteur existant." },
      { id: "days", label: "Rétention (jours)", type: "number", required: true, min: 1, max: 3650, default: "30" },
      { id: "size", label: "Taille moyenne d'un log (octets)", type: "number", required: true, min: 100, max: 5000, default: "500", hint: "500 octets = valeur de référence Palo Alto Networks." },
      { id: "platform", label: "Plateforme", type: "select", default: "M-600", options: Object.keys(PLATFORMS).map(k => [k]), group: "Collecteurs" },
      { id: "mode", label: "Mode", type: "select", default: "lc", options: [["lc", "Log Collector dédié"], ["pano", "Panorama (collecteur local)"]] },
      { id: "cap", label: "Stockage de logs par collecteur (To)", type: "number", required: true, min: 1, max: 200, default: "16" },
      { id: "redund", label: "Redondance des logs", type: "checkbox", default: false },
    ],
    build(v) {
      const TB = 1099511627776;
      const raw = (+v.lps * 86400 * +v.days * +v.size) / TB;
      const need = raw * (v.redund ? 2 : 1);
      const rate = PLATFORMS[v.platform][v.mode] / (v.redund ? 2 : 1);
      const byRate = Math.ceil(+v.lps / rate), byDisk = Math.ceil(need / +v.cap);
      const n = Math.max(byRate, byDisk, v.redund ? 2 : 1);
      const fmt = x => x.toLocaleString("fr-FR", { maximumFractionDigits: 2 });
      const steps = [
        { title: "Formule (cours EDU-220)", path: ["Calcul"], action: "[(LPS × 86 400 s) × jours] × taille moyenne ÷ 1 099 511 627 776 octets/To",
          fields: [["Calcul", `[(${v.lps} × 86 400) × ${v.days}] × ${v.size} ÷ 1 099 511 627 776`], ["Logs détaillés (Traffic/Threat)", fmt(raw) + " To"], ["Avec redondance", v.redund ? fmt(need) + " To" : ""]] },
        { title: "Nombre de collecteurs", path: ["Calcul"], fields: [["Plateforme / mode", `${v.platform} — ${v.mode === "lc" ? "Log Collector" : "Panorama"}`], ["Ingestion max par collecteur", fmt(rate) + " LPS" + (v.redund ? " (÷2 redondance)" : "")],
          ["Collecteurs pour le débit", byRate], ["Collecteurs pour le stockage", byDisk], ["Recommandation", `${n} collecteur(s) dans le collector group`]] },
        { title: "Mesurer le débit réel", path: ["Panorama", "Managed Collectors"], action: "Lien Statistics de chaque collecteur : disques, CPU, LPS moyen et plus ancien log conservé.", fields: [] },
      ];
      const notes = [
        { type: "ok", title: `≈ ${fmt(need)} To · ${n} collecteur(s)`, text: `${v.lps} LPS pendant ${v.days} jours${v.redund ? ", logs dupliqués" : ""}.` },
        { type: "or", text: "Chiffres d'ingestion = valeurs du cours EDU-220 11.1 (M-200 28k, M-500 30k, M-600 50k LPS en mode Log Collector). Vérifie le Panorama Sizing and Design Guide et le Cortex sizing calculator à jour." },
        { type: "or", text: "Mesure sur plusieurs jours, jours ouvrés ET week-end : l'écart de débit est souvent important. Quand le disque est plein, les logs les plus anciens sont écrasés." },
      ];
      if (n > 16) notes.push({ type: "bad", text: "Plus de 16 collecteurs : répartir sur plusieurs collector groups, ou envisager Strata Logging Service (Cortex Data Lake)." });
      const cliRaw = ["# --- Mesure du débit de logs (mode opérationnel) ---", "debug log-receiver statistics", "show system logdb-quota", "show log-collector-es-cluster health"];
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P06 · Générateur de requêtes de logs (noCommit)
     ===================================================================== */
  const LOGGUI = { traffic: "Traffic", threat: "Threat", url: "URL Filtering", wildfire: "WildFire Submissions", data: "Data Filtering", decryption: "Decryption", auth: "Authentication", system: "System", config: "Configuration" };
  const isT = (...t) => v => v.preset === "custom" && t.includes(v.logType);
  const NET = ["traffic", "threat", "url", "wildfire", "data", "decryption", "auth"];
  const tsV = s => !s ? null : (/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/.test(s) ? null : "Format AAAA/MM/JJ HH:MM:SS (ex. 2026/10/21 13:15:00)");
  const pad = n => String(n).padStart(2, "0");
  const ts = d => `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:00`;
  const qv = s => /^[A-Za-z0-9._\-\/:]+$/.test(s) ? s : `'${String(s).replace(/'/g, "")}'`;
  const PRESETS = {
    "url-gambling-weapons": { label: "URL : sites gambling OU weapons (Lab 6)", logType: "url", urlCats: ["gambling", "weapons"] },
    "traffic-dropbox": { label: "Traffic : utilisateurs de Dropbox (Lab 6)", logType: "traffic", apps: ["dropbox-base"] },
    "traffic-not-allowed": { label: "Traffic : tout ce qui n'est pas autorisé", logType: "traffic", action: "allow", actionNeg: true },
    "url-blocked": { label: "URL : requêtes bloquées par le profil", logType: "url", action: "block-url" },
    "traffic-denied-15": { label: "Traffic : refusé dans les 15 dernières minutes (Lab 6)", logType: "traffic", action: "allow", actionNeg: true, timeFromRel: 15 },
    "threat-crit-high": { label: "Threat : sévérité high ou critical", logType: "threat", sev: "high", sevOp: "geq" },
    "user-allowed": { label: "Traffic : un utilisateur autorisé par un pare-feu depuis une heure (MOD-06)", logType: "traffic", srcUser: ["chicago\\bbart"], deviceName: "chicago-fw", action: "allow", timeFromRel: 60 },
    "config-commit": { label: "Configuration : commits", logType: "config", cmd: "commit" },
    "system-high": { label: "System : événements high/critical", logType: "system", sev: "high", sevOp: "geq" },
  };

  function buildQuery(c) {
    const parts = [], fb = [], cli = [];
    const add = (attr, op, vals, label, cliKey) => {
      vals = [].concat(vals).filter(x => x !== "" && x != null);
      if (!vals.length) return;
      const one = vals.map(x => `( ${attr} ${op} ${qv(x)} )`);
      parts.push(one.length > 1 ? `( ${one.join(" or ")} )` : one[0]);
      vals.forEach((x, i) => fb.push([i ? "or" : (parts.length > 1 ? c.conn : "—"), label, op, x]));
      if (cliKey && vals.length === 1) cli.push(`${cliKey} ${vals[0]}`);
    };
    add("addr.src", "in", c.srcIp, "Source Address", "src in");
    add("addr.dst", "in", c.dstIp, "Destination Address", "dst in");
    add("user.src", "eq", c.srcUser, "Source User", "srcuser equal");
    add("zone.src", "eq", c.zoneSrc, "Source Zone", "from equal");
    add("zone.dst", "eq", c.zoneDst, "Destination Zone", "to equal");
    add("port.dst", "eq", c.dport, "Destination Port", "dport equal");
    add("app", "eq", c.apps, "Application", "app equal");
    add("rule", "eq", c.rule, "Rule", "rule equal");
    if (c.action) add("action", c.actionNeg ? "neq" : "eq", c.action, "Action", c.actionNeg ? null : "action equal");
    if (c.sev) add("severity", c.sevOp || "eq", c.sev, "Severity", c.sevOp === "eq" || !c.sevOp ? "severity equal" : null);
    add("url_category_list", "contains", c.urlCats, "URL Category List");
    add("url", "contains", c.urlContains, "URL");
    add("name-of-threatid", "contains", c.threatName, "Threat ID/Name");
    add("subtype", "eq", c.subtype, "Subtype", "subtype equal");
    add("cmd", "eq", c.cmd, "Command");
    add("admin", "eq", c.admin, "Administrator");
    add("description", "contains", c.descContains, "Description");
    add("device_name", "eq", c.deviceName, "Device Name");
    add("serial", "eq", c.serial, "Serial Number");
    add("time_generated", "geq", c.timeFrom, "Time Generated", null);
    add("time_generated", "leq", c.timeTo, "Time Generated", null);
    return { filter: parts.join(` ${c.conn} `), fb, cli, n: parts.length };
  }

  register({
    id: "p06-query",
    module: "P06",
    title: "Générateur de requêtes de logs",
    icon: "🔎",
    desc: "Construire un filtre de log Panorama (syntaxe du Filter Builder) à partir de critères ou d'un cas d'usage du Lab 6, avec l'équivalent CLI et API XML, et la procédure d'enregistrement / export CSV.",
    tags: "logs query requête filtre filter builder monitor traffic threat url system config export csv saved filter",
    noCommit: true,
    fields: [
      { id: "preset", label: "Cas d'usage", type: "select", default: "custom",
        options: [["custom", "Personnalisé (critères ci-dessous)"], ...Object.entries(PRESETS).map(([k, p]) => [k, p.label])] },
      { id: "logType", label: "Log", type: "select", default: "traffic", options: Object.entries(LOGGUI), show: v => v.preset === "custom" },
      { id: "dg", label: "Device Group affiché", type: "text", default: "Corp-DG", hint: "Liste déroulante Device Group du Monitor (« All » = tous). Un DG parent montre les logs de tous ses descendants." },
      { id: "conn", label: "Combiner les critères avec", type: "select", default: "and", options: [["and", "and (tous les critères)"], ["or", "or (au moins un)"]], show: v => v.preset === "custom",
        hint: "Plusieurs valeurs d'un MÊME critère sont toujours combinées en or (un champ ne peut pas valoir deux choses à la fois)." },
      { id: "srcIp", label: "IP source (in)", type: "list", validate: "ipcidr", show: isT(...NET), group: "Réseau", placeholder: "10.4.5.101, 192.168.1.0/24" },
      { id: "dstIp", label: "IP destination (in)", type: "list", validate: "ipcidr", show: isT(...NET) },
      { id: "zoneSrc", label: "Zone source", type: "list", show: isT(...NET) },
      { id: "zoneDst", label: "Zone destination", type: "list", show: isT(...NET) },
      { id: "dport", label: "Port destination", type: "list", validate: "port", show: isT(...NET) },
      { id: "srcUser", label: "Utilisateur source (domaine\\user)", type: "list", show: isT(...NET), group: "Utilisateur & application", placeholder: "chicago\\bbart" },
      { id: "apps", label: "Application(s)", type: "list", default: ["web-browsing", "ssl"], show: isT(...NET), hint: "Sensible à la casse : dropbox-base, web-browsing, ssl…" },
      { id: "rule", label: "Règle de sécurité", type: "text", show: isT(...NET) },
      { id: "action", label: "Action", type: "select", default: "", show: isT("traffic", "threat", "url", "wildfire", "data", "decryption"), group: "Action & sévérité",
        options: [["", "(toutes)"], ["allow"], ["deny"], ["drop"], ["reset-both"], ["reset-client"], ["reset-server"], ["alert"], ["block-url"], ["continue"], ["override"], ["sinkhole"]] },
      { id: "actionNeg", label: "Inverser (neq : tout SAUF cette action)", type: "checkbox", default: false, show: v => isT("traffic", "threat", "url", "wildfire", "data", "decryption")(v) && !!v.action },
      { id: "sev", label: "Sévérité", type: "select", default: "", show: isT("threat", "system", "wildfire"), options: [["", "(toutes)"], ["critical"], ["high"], ["medium"], ["low"], ["informational"]] },
      { id: "sevOp", label: "Opérateur", type: "select", default: "geq", show: v => isT("threat", "system", "wildfire")(v) && !!v.sev, options: [["eq", "égale"], ["geq", "supérieure ou égale"]] },
      { id: "subtype", label: "Sous-type", type: "select", default: "", show: isT("threat"), options: [["", "(tous)"], ["vulnerability"], ["spyware"], ["virus"], ["wildfire-virus"], ["file"], ["scan"], ["flood"]] },
      { id: "threatName", label: "Nom de menace contient", type: "text", show: isT("threat") },
      { id: "urlCats", label: "Catégories URL (URL Category List contains)", type: "list", validate: catList, show: isT("url"), group: "URL", placeholder: "gambling, weapons" },
      { id: "urlContains", label: "URL contient", type: "text", show: isT("url") },
      { id: "cmd", label: "Commande", type: "select", default: "", show: isT("config"), group: "Configuration / System", options: [["", "(toutes)"], ["set"], ["edit"], ["delete"], ["commit"], ["move"], ["rename"], ["clone"]] },
      { id: "admin", label: "Administrateur", type: "text", show: isT("config", "system") },
      { id: "descContains", label: "Description contient", type: "text", show: isT("system") },
      { id: "deviceName", label: "Nom du pare-feu (Device Name)", type: "text", show: v => v.preset === "custom", group: "Pare-feu & période" },
      { id: "timeFrom", label: "Depuis (AAAA/MM/JJ HH:MM:SS)", type: "text", validate: tsV, show: v => v.preset === "custom", placeholder: "2026/10/21 02:00:00" },
      { id: "timeTo", label: "Jusqu'à (optionnel)", type: "text", validate: tsV, show: v => v.preset === "custom" },
      { id: "saveName", label: "Nom du filtre enregistré (optionnel)", type: "text", default: "", group: "Enregistrement & export", placeholder: "URL is gambling or weapons" },
      { id: "csv", label: "Exporter le résultat en CSV", type: "checkbox", default: false },
    ],
    build(v) {
      let c;
      if (v.preset !== "custom") {
        const p = PRESETS[v.preset];
        c = Object.assign({ conn: "and" }, p);
        if (p.timeFromRel) c.timeFrom = ts(new Date(Date.now() - p.timeFromRel * 60000));
      } else {
        c = Object.assign({}, v, { rule: v.rule ? [v.rule] : [], urlContains: v.urlContains ? [v.urlContains] : [], threatName: v.threatName ? [v.threatName] : [],
          admin: v.admin ? [v.admin] : [], descContains: v.descContains ? [v.descContains] : [], deviceName: v.deviceName ? [v.deviceName] : [] });
        const keep = { srcIp: NET, dstIp: NET, zoneSrc: NET, zoneDst: NET, dport: NET, srcUser: NET, apps: NET, rule: NET, action: ["traffic", "threat", "url", "wildfire", "data", "decryption"],
          sev: ["threat", "system", "wildfire"], subtype: ["threat"], threatName: ["threat"], urlCats: ["url"], urlContains: ["url"], cmd: ["config"], admin: ["config", "system"], descContains: ["system"] };
        Object.entries(keep).forEach(([k, types]) => { if (!types.includes(v.logType)) c[k] = Array.isArray(c[k]) ? [] : ""; });
      }
      const lt = c.logType, gui = LOGGUI[lt];
      const r = buildQuery(c);
      const filter = r.filter || "";
      const steps = [
        { title: `Ouvrir le log ${gui}`, path: ["Monitor", "Logs", gui], action: `Liste Device Group en haut : « ${v.dg || "All"} ». Cliquer Clear Filter (✕) pour repartir de zéro.`, fields: [] },
        { title: filter ? "Saisir le filtre et l'appliquer" : "Aucun critère : tous les logs", path: ["Monitor", "Logs", gui], window: "Filtre",
          action: filter ? "Coller le filtre dans le champ au-dessus du tableau, puis Apply Filter (flèche →)." : "Ajoute au moins un critère pour filtrer.",
          fields: [["Filtre", filter]], note: "Astuce : cliquer un lien dans le tableau (IP, application, utilisateur…) génère automatiquement la syntaxe ; plusieurs clics sont combinés en « and »." },
      ];
      if (r.fb.length) steps.push({ title: "Équivalent Filter Builder", path: ["Monitor", "Logs", gui, "Add Filter (+)"], window: "Add Log Filter",
        action: "Pour chaque ligne : Connector → Attribute → Operator → Value → Add ; puis Apply. (Valeurs sensibles à la casse.)",
        fields: r.fb.map(([cn, a, o, val], i) => [`${i + 1}. ${cn} · ${a} · ${o}`, val]) });
      if (v.saveName) steps.push({ title: "Enregistrer le filtre", path: ["Monitor", "Logs", gui, "Save Filter (💾)"], fields: [["Name", v.saveName]], note: "Le rappeler plus tard avec Load Filter, puis Apply Filter." });
      if (v.csv) steps.push({ title: "Exporter en CSV", path: ["Monitor", "Logs", gui, "Export to CSV"], action: "Après Apply Filter : Export to CSV → lien Download file → ouvrir dans un tableur.",
        fields: [], note: "Toutes les colonnes du log sont exportées, même celles masquées à l'écran. Nombre de lignes plafonné (Max Rows in CSV Export, module suivant)." });
      steps.push({ title: "Personnaliser les colonnes (optionnel)", path: ["Monitor", "Logs", gui], action: "Flèche d'un en-tête → Columns pour afficher/masquer ; glisser-déposer un en-tête pour le déplacer (ex. Device Name à gauche). La vue est conservée par Panorama.", fields: [] });

      const apiType = lt;
      const cliRaw = [`# Filtre ${gui} :`, filter || "# (aucun critère)", ""];
      if (["traffic", "threat", "url", "system", "config"].includes(lt)) {
        cliRaw.push(`# CLI Panorama (mode opérationnel) — équivalent approximatif, opérateurs ${TOVAL}`,
          `show log ${lt} direction equal backward${r.cli.length ? " " + r.cli.join(" ") : ""}`, "");
      }
      cliRaw.push("# API XML (lance un job ; récupérer ensuite le résultat avec type=log&action=get&job-id=<id>)",
        `curl -k -G "https://<panorama>/api/" --data-urlencode "type=log" --data-urlencode "log-type=${apiType}" --data-urlencode "query=${filter.replace(/"/g, '\\"')}" --data-urlencode "nlogs=100" --data-urlencode "key=<API-KEY>"`);

      const notes = [{ type: filter ? "ok" : "warn", title: filter ? `Filtre ${gui} (${r.n} critère${r.n > 1 ? "s" : ""})` : "Aucun critère", html: filter ? preBlock(filter) : PAN.esc("Le log entier sera affiché.") }];
      if (c.conn === "and" && [c.srcUser, c.apps, c.srcIp].some(a => Array.isArray(a) && a.length > 1)) notes.push({ type: "or", text: "Valeurs multiples d'un même champ regroupées en « or » : ( user eq A ) and ( user eq B ) ne renverrait jamais rien." });
      if (lt === "url" && (c.urlCats || []).length) notes.push({ type: "or", text: "url_category_list contient TOUTES les catégories d'une URL ; la colonne Category n'affiche que la principale." });
      if (c.timeFrom) notes.push({ type: "or", text: `Période calculée depuis ${c.timeFrom} (heure de Panorama — vérifie l'heure dans Dashboard > General Information).` });
      notes.push({ type: "or", text: "Les logs ne remontent dans Panorama que si les pare-feux les transfèrent (profil de Log Forwarding sur les règles)." });
      return { steps, cli: cliRaw, cliRaw, notes };
    },
  });

  /* =====================================================================
     P06 · Paramètres d'export / rapports (Max Rows CSV)
     ===================================================================== */
  register({
    id: "p06-export",
    module: "P06",
    title: "Export CSV & limites d'affichage",
    icon: "📥",
    desc: "Relever le nombre maximal de lignes des exports CSV et des rapports PDF sur Panorama (et, via template, sur les pare-feux).",
    tags: "export csv max rows pdf report logging and reporting settings",
    fields: [
      { id: "csvRows", label: "Max Rows in CSV Export", type: "number", required: true, min: 1, max: 1048576, default: "65535",
        hint: "Sans filtre, l'export contient les entrées les plus récentes jusqu'à ce plafond." },
      { id: "pdfRows", label: "Max Rows in User Activity / PDF Report", type: "number", min: 1, max: 1048576, default: "5000" },
      { id: "tpl", label: "Appliquer aussi aux pare-feux via un template", type: "checkbox", default: false, group: "Pare-feux" },
      { id: "template", label: "Template", type: "text", required: true, validate: "name", default: "Global-Settings", show: v => v.tpl },
      { id: "stack", label: "Template stack à pousser", type: "text", validate: optName, default: "", show: v => v.tpl },
    ],
    build(v) {
      const steps = [{ title: "Logging and Reporting Settings de Panorama", path: ["Panorama", "Setup", "Management"], tab: "Log Export and Reporting", window: "Logging and Reporting Settings",
        action: "Cadre Logging and Reporting Settings → ⚙ → onglet Log Export and Reporting.", fields: [["Max Rows in CSV Export", v.csvRows], ["Max Rows in User Activity Report", v.pdfRows]] }];
      const m = "deviceconfig setting management";
      const cli = [`set ${m} max-rows-in-csv-export ${v.csvRows}`, v.pdfRows && `set ${m} max-rows-in-pdf-report ${v.pdfRows}`].filter(Boolean);
      if (v.tpl) {
        steps.push({ title: "Même réglage pour les pare-feux", path: ["Device", "Setup", "Management"], tab: "Log Export and Reporting", action: `Sélectionner le template « ${v.template} » en haut.`, fields: [["Max Rows in CSV Export", v.csvRows]] });
        cli.push(`set template ${q(v.template)} config devices localhost.localdomain ${m} max-rows-in-csv-export ${v.csvRows}`);
      }
      const notes = [{ type: "or", text: "Un export volumineux charge le management plane : filtre d'abord (module « Générateur de requêtes »), exporte ensuite." }];
      if (+v.csvRows > 200000) notes.push({ type: "warn", text: "Au-delà de quelques centaines de milliers de lignes, privilégie l'API XML ou un SIEM (Collector Log Forwarding)." });
      return { steps, cli, notes, push: v.tpl && v.stack ? [pushTs(v.stack)] : [] };
    },
  });

  /* =====================================================================
     P06 · Des logs à l'action (Lab 6 : bloquer une app / des catégories)
     ===================================================================== */
  register({
    id: "p06-investigate",
    module: "P06",
    title: "Des logs à la règle (investigation)",
    icon: "🕵️",
    desc: "Démarche du Lab 6 : repérer un usage non autorisé dans les logs, l'exporter pour le management, le bloquer depuis Panorama (pre-rule ou profil URL) puis vérifier le blocage dans les logs.",
    tags: "investigation logs dropbox block application url category corp-url pre-rule verify lab 6",
    fields: [
      { id: "case", label: "Cas", type: "select", default: "app", options: [["app", "Application non autorisée → règle de blocage"], ["url", "Catégories web à risque → profil URL Filtering"]] },
      { id: "dg", label: "Device group", type: "text", required: true, validate: "name", default: "HQ-DG" },
      { id: "logApp", label: "Application vue dans les logs", type: "text", required: true, default: "dropbox-base", show: v => v.case === "app", group: "Application" },
      { id: "blockApps", label: "Applications à bloquer", type: "list", required: true, default: ["dropbox"], show: v => v.case === "app",
        hint: "Bloquer l'application « parente » (dropbox) couvre ses fonctions (dropbox-base, dropbox-uploading…)." },
      { id: "ruleName", label: "Nom de la pre-rule", type: "text", required: true, validate: "name", default: "Block_Unauthorized_File_Storage_Apps", show: v => v.case === "app" },
      { id: "srcZ", label: "Zone source", type: "list", required: true, validate: nameList, default: ["Users_Net"], show: v => v.case === "app" },
      { id: "dstZ", label: "Zone destination", type: "list", required: true, validate: nameList, default: ["Internet"], show: v => v.case === "app" },
      { id: "logSet", label: "Log Forwarding", type: "text", validate: optName, default: "default", show: v => v.case === "app" },
      { id: "urlProf", label: "Profil URL Filtering à modifier", type: "text", required: true, validate: "name", default: "Corp-URL", show: v => v.case === "url", group: "URL" },
      { id: "cats", label: "Catégories à passer en block", type: "list", required: true, validate: catList, default: URL_BLOCK_LAB6, show: v => v.case === "url" },
      { id: "profDg", label: "DG où le profil est défini", type: "text", required: true, validate: "name", default: "Corp-DG", show: v => v.case === "url",
        hint: "Le profil se modifie dans le DG qui le contient (ancêtre), pas dans le descendant qui en hérite." },
    ],
    build(v) {
      const app = v.case === "app";
      const detect = app ? `( app eq ${v.logApp} )` : `( ${v.cats.slice(0, 3).map(c => `url_category_list contains ${c}`).join(" ) or ( ")} )`;
      const verifyF = app ? `( action neq allow ) and ( app eq ${v.logApp} )` : "( action eq block-url )";
      const pushDgName = app ? v.dg : v.profDg;
      const steps = [
        { title: "1 · Repérer l'usage dans les logs", path: ["Monitor", "Logs", app ? "Traffic" : "URL Filtering"], action: `Device Group : ${app ? v.dg : "Corp-DG / All"}. Appliquer le filtre ci-dessous.`, fields: [["Filtre", detect]] },
        { title: "2 · Exporter la liste pour le management", path: ["Monitor", "Logs", app ? "Traffic" : "URL Filtering", "Export to CSV"], action: "Export to CSV → Download file. La colonne Source User identifie les utilisateurs concernés.", fields: [] },
      ];
      const cli = [];
      if (app) {
        const r = `set device-group ${q(v.dg)} pre-rulebase security rules ${q(v.ruleName)}`;
        steps.push({ title: "3 · Bloquer par une Pre Rule", path: ["Policies", "Security", "Pre Rules"], window: "Security Policy Rule",
          action: pickDg(v.dg) + " Add. En Pre Rule, aucun admin local ne pourra placer d'exception au-dessus.",
          fields: [["Name", v.ruleName], ["Description", "Bloque les applications de stockage non autorisées"], ["Source Zone", v.srcZ], ["Destination Zone", v.dstZ], ["Application", v.blockApps], ["Service", "any"], ["Action", "Deny"], ["Log Forwarding", v.logSet]] });
        cli.push(`${r} from ${members(v.srcZ)} to ${members(v.dstZ)} source any destination any source-user any category any application ${members(v.blockApps)} service any action deny`,
          `${r} description "Bloque les applications de stockage non autorisees"`, `${r} log-end yes`);
        if (v.logSet) cli.push(`${r} log-setting ${q(v.logSet)}`);
      } else {
        steps.push({ title: "3 · Bloquer les catégories", path: ["Objects", "Security Profiles", "URL Filtering"], window: "URL Filtering Profile",
          action: pickDg(v.profDg) + ` Ouvrir ${v.urlProf} → colonne Site Access : alert → block pour chaque catégorie (trier la colonne pour les retrouver).`, fields: [["Catégories en block", v.cats]] });
        cli.push(`set device-group ${q(v.profDg)} profiles url-filtering ${q(v.urlProf)} block ${members(v.cats)}`,
          `# Retirer ces catégories de la liste « alert » si elles y figurent : delete ... alert <catégorie>`);
      }
      steps.push({ title: "4 · Vérifier le blocage", path: ["Monitor", "Logs", app ? "Traffic" : "URL Filtering"], action: "Après le push et quelques minutes de trafic : Device Group = All, appliquer le filtre de vérification.", fields: [["Filtre", verifyF]] });
      const notes = [
        { type: "or", text: "Démarche : observer (filtre) → documenter (export CSV) → décider avec le management → appliquer (Panorama) → vérifier (logs)." },
        { type: "or", text: app ? "Avec action deny, la session apparaît dans le Traffic log avec action deny/reset et la règle « " + v.ruleName + " »." : "Les requêtes bloquées apparaissent dans le log URL Filtering avec l'action block-url ; la page de blocage s'affiche côté utilisateur." },
      ];
      return { steps, cli, notes, push: [pushDg(pushDgName)], verify: ["show jobs all"] };
    },
  });
})();
