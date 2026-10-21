/* PANW Config Builder — Panorama 11.1 : parcours guidés (use cases clients).
   Chaque parcours enchaîne des modules Panorama (IDs du contrat) ; les champs partagés
   (panoIp, fwSerial, template, stack, dg, cg…) sont repris automatiquement d'un module à l'autre.
   Lien : panorama-configurateur.html#parcours=<id> */
(function () {
  const S = [
    {
      id: "pano-zero", icon: "🚀", level: "Débutant", duration: "≈ 60 min",
      title: "Nouveau Panorama de zéro",
      desc: "Mise en service complète : management, licences et mises à jour, mode, premier template et template stack, device group, puis rattachement du premier pare-feu.",
      tags: ["mise en service", "initial", "greenfield"],
      steps: ["p01-mgmt", "p01-licence", "p01-mode", "p03-template", "p03-device", "p03-stack", "p04-dg", "p02-add-fw"],
    },
    {
      id: "pano-onboard", icon: "🔌", level: "Débutant", duration: "≈ 25 min",
      title: "Onboarder un pare-feu",
      desc: "Clé d'enregistrement, ajout du numéro de série, configuration côté pare-feu, rattachement au template stack et au device group, envoi des logs vers Panorama.",
      tags: ["ajout", "auth key", "managed device"],
      steps: ["p02-add-fw", "p03-stack", "p04-dg", "p05-fwd", "p02-deploy"],
    },
    {
      id: "pano-migrate", icon: "📦", level: "Intermédiaire", duration: "≈ 45 min",
      title: "Migrer un pare-feu existant sous Panorama",
      desc: "Reprendre la configuration d'un pare-feu en production : import en template + device group, contrôle des objets/règles importés, puis push sans coupure.",
      tags: ["migration", "import", "brownfield"],
      steps: ["p02-add-fw", "p02-migrate", "p03-stack", "p04-dg", "p04-objects", "p04-policy"],
    },
    {
      id: "pano-multisite", icon: "🌍", level: "Intermédiaire", duration: "≈ 50 min",
      title: "Multi-sites : templates + variables + hiérarchie de DG",
      desc: "Un template commun + un template par site, des variables $ pour les valeurs propres à chaque site, une hiérarchie de device groups parent/enfant et des règles pre/post.",
      tags: ["multi-sites", "variables", "hiérarchie", "héritage"],
      steps: ["p03-template", "p03-variables", "p03-stack", "p04-dg", "p04-objects", "p04-policy"],
    },
    {
      id: "pano-logs", icon: "📡", level: "Intermédiaire", duration: "≈ 45 min",
      title: "Logs centralisés & SIEM",
      desc: "Log collector et collector group, log forwarding des pare-feux vers Panorama, transfert vers syslog/SIEM, requêtes de logs et rapports planifiés.",
      tags: ["logs", "log collector", "syslog", "SIEM", "rapports"],
      steps: ["p01-mode", "p05-collector", "p05-cg", "p05-fwd", "p05-syslog", "p06-query", "p08-report"],
    },
    {
      id: "pano-mssp", icon: "🏢", level: "Avancé", duration: "≈ 35 min",
      title: "MSSP : délégation par access domains",
      desc: "Rôles d'administration Panorama, access domains limités à certains device groups / templates, comptes administrateurs par client ou par équipe.",
      tags: ["MSSP", "RBAC", "access domain", "administrateurs"],
      steps: ["p04-dg", "p03-template", "p07-roles", "p07-access-domain", "p07-admin"],
    },
    {
      id: "pano-ha", icon: "🛟", level: "Avancé", duration: "≈ 40 min",
      title: "Haute disponibilité & sauvegarde",
      desc: "Paire Panorama HA active/passive (priorités, peer, synchronisation) et export planifié des sauvegardes de configuration vers un serveur SCP/FTP.",
      tags: ["HA", "backup", "export", "PRA"],
      steps: ["p01-mgmt", "p10-ha", "p10-backup"],
    },
    {
      id: "pano-updates", icon: "🔄", level: "Débutant", duration: "≈ 20 min",
      title: "Mises à jour centralisées",
      desc: "Mises à jour dynamiques et logicielles de Panorama, puis déploiement planifié des contenus (Apps & Threats, antivirus, WildFire), licences et PAN-OS vers les pare-feux.",
      tags: ["updates", "contenu", "logiciel", "planification"],
      steps: ["p01-licence", "p02-deploy"],
    },
    {
      id: "pano-troubleshoot", icon: "🩺", level: "Intermédiaire", duration: "≈ 20 min",
      title: "Dépannage",
      desc: "Pare-feu déconnecté, commit/push en échec, logs absents : commandes de diagnostic Panorama et pare-feu, puis requêtes de logs ciblées.",
      tags: ["troubleshooting", "connectivité", "push", "logs"],
      steps: ["p09-troubleshoot", "p06-query"],
    },
  ];
  // exposé pour les pages d'accueil (affichage même si le moteur ne gère pas encore les parcours)
  window.PAN = window.PAN || {};
  PAN.panoramaScenarios = S;
  const C = PAN.cfg;
  if (!C || typeof C.scenario !== "function") {
    if (typeof console !== "undefined") console.warn("PAN.cfg.scenario indisponible : parcours Panorama non déclarés");
    return;
  }
  S.forEach(s => { try { C.scenario(s); } catch (e) { console.warn("Parcours Panorama ignoré :", s.id, e); } });
})();
