/* Parcours guidés PAN-OS 11.0 (use cases clients) — enchaînement de modules existants.
   PAN.cfg.scenario({ id, title, icon, desc, steps:[moduleIds], tags?, level?, duration?, moduleValues? })
   Lien direct : pages/configurateur.html#parcours=<id> */
(function () {
  const { scenario } = PAN.cfg;

  scenario({
    id: "nouveau-pare-feu",
    title: "Nouveau pare-feu en 30 min",
    icon: "🚀",
    level: "Débutant",
    duration: "30 min",
    desc: "De la sortie du carton à un pare-feu opérationnel : identité, management, mises à jour, zones, interfaces, routage, NAT sortant, première règle et sauvegarde.",
    tags: "installation mise en service initial day0 baseline",
    steps: ["m02-general", "m02-mgmt-interface", "m02-admin-password", "m02-dynamic-updates", "m05-zone", "m05-l3-interface",
      "m05-virtual-router", "m07-snat-dipp", "m06-security-rule", "m03-save-snapshot"],
  });

  scenario({
    id: "publier-serveur-web",
    title: "Publier un serveur web (DMZ)",
    icon: "🌐",
    level: "Intermédiaire",
    duration: "20 min",
    desc: "Exposer un serveur HTTPS hébergé en DMZ : zone et interface DMZ, objets, NAT de destination, U-turn pour les utilisateurs internes, règle entrante protégée par un groupe de profils.",
    tags: "dmz dnat publication serveur web https port forwarding",
    steps: ["m05-zone", "m05-l3-interface", "m06-address-objects", "m09-profile-group", "m07-dnat", "m07-uturn", "m06-security-rule"],
    moduleValues: {
      "m05-zone": { name: "DMZ", ifs: ["ethernet1/3"] },
      "m05-l3-interface": { iface: "ethernet1/3", comment: "DMZ", zone: "DMZ", ips: ["172.16.1.1/24"] },
      "m06-security-rule": { name: "Allow-Web-DMZ", from: ["Untrust"], src: ["any"], to: ["DMZ"], dst: ["172.16.1.10"], app: ["web-browsing", "ssl"] },
    },
  });

  scenario({
    id: "securiser-internet",
    title: "Sécuriser l'accès Internet (profils, URL, décryptage)",
    icon: "🛡️",
    level: "Intermédiaire",
    duration: "45 min",
    desc: "Bonnes pratiques de sortie Internet : antivirus, anti-spyware (sinkhole DNS), vulnérabilités, blocage de fichiers, WildFire, filtrage URL, décryptage SSL avec exclusions, puis règle utilisateurs → Internet.",
    tags: "profils security profile url filtering decryption ssl wildfire best practice",
    steps: ["m09-antivirus", "m09-anti-spyware", "m09-vulnerability", "m09-file-blocking", "m11-wildfire-profile", "m10-url-profile",
      "m09-profile-group", "m13-certificates", "m13-decryption-profile", "m13-decryption-policy", "m13-decryption-exclusion", "m06-security-rule"],
  });

  scenario({
    id: "vpn-site-a-site",
    title: "VPN IPsec site-à-site",
    icon: "🔐",
    level: "Intermédiaire",
    duration: "25 min",
    desc: "Relier deux sites : sauvegarde préalable, puis tunnel route-based complet (zone VPN, interface tunnel, profils IKE/IPsec, IKE gateway, routes) et règle complémentaire si besoin.",
    tags: "vpn ipsec ike tunnel site to site s2s",
    steps: ["m03-save-snapshot", "sup-ipsec-s2s", "m06-security-rule"],
    moduleValues: {
      "m06-security-rule": { name: "LAN-to-VPN", from: ["Trust"], to: ["VPN"], src: ["192.168.1.0/24"], dst: ["10.20.0.0/16"], app: ["any"] },
    },
  });

  scenario({
    id: "ha-actif-passif",
    title: "Haute disponibilité actif/passif",
    icon: "♻️",
    level: "Avancé",
    duration: "40 min",
    desc: "Sauvegarder, aligner les versions de contenu puis monter une paire HA actif/passif : liens HA1/HA2, priorités, préemption, link & path monitoring.",
    tags: "ha high availability cluster active passive redondance",
    steps: ["m03-save-snapshot", "m02-dynamic-updates", "sup-ha-active-passive", "m03-commit-options"],
  });

  scenario({
    id: "durcir-management",
    title: "Durcir le management",
    icon: "🔒",
    level: "Intermédiaire",
    duration: "30 min",
    desc: "Réduire la surface d'attaque de l'administration : mot de passe admin, complexité, rôles et comptes nominatifs, authentification centralisée, interface de management restreinte, service routes et journalisation syslog.",
    tags: "hardening durcissement admin management securite best practice",
    steps: ["m02-admin-password", "m04-password-complexity", "m04-admin-role", "m04-auth-profile", "m04-local-admin",
      "m02-mgmt-interface", "m05-mgmt-profile", "sup-service-route", "m14-syslog"],
  });

  scenario({
    id: "user-id",
    title: "Règles par utilisateur (User-ID)",
    icon: "👥",
    level: "Avancé",
    duration: "35 min",
    desc: "Identifier les utilisateurs Active Directory : group mapping LDAP, surveillance des contrôleurs de domaine, activation User-ID sur la zone, puis règles basées sur les groupes.",
    tags: "user-id ldap active directory groupes identification",
    steps: ["m12-ldap-group-mapping", "m12-server-monitoring", "m12-enable-zone", "m12-user-rule"],
  });

  scenario({
    id: "protections-attaques",
    title: "Protéger contre les attaques (zone & DoS)",
    icon: "🧯",
    level: "Avancé",
    duration: "20 min",
    desc: "Zone Protection (floods, reconnaissance, paquets malformés) sur la zone Internet, politique DoS pour les serveurs exposés, alertes e-mail et transfert syslog des menaces.",
    tags: "zone protection dos flood syn attaque alertes",
    steps: ["sup-zone-protection", "sup-dos-protection", "m14-email-alerts", "m14-syslog"],
  });
})();
