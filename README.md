# 🛡️ PANW Config Builder — configurateur Palo Alto Networks (PAN-OS 11.0 · Panorama 11.1)

Outil web pour configurer un environnement Palo Alto Networks chez n'importe quel client : **tu saisis tes informations, l'outil les valide et génère la configuration**, au choix :

- 🖱️ **Mode GUI** : le pas-à-pas WebUI, étape par étape (chemin de menu, onglet, valeurs à saisir), chaque étape cochable « Fait ».
- ⌨️ **Mode CLI** : les commandes `set` prêtes à coller en SSH, avec `commit`, le push Panorama et les commandes de vérification.

🌐 **En ligne : https://dinecherd.github.io/panw/**
⬇ **Version locale (hors ligne) : [télécharger le site (.zip)](https://github.com/dinecherd/panw/archive/refs/heads/main.zip)** — dézippe puis ouvre `index.html`, aucun serveur ni installation (HTML/CSS/JS pur).

## Deux produits

| | 🛡️ **PAN-OS 11.0** (pare-feu NGFW) | 🛰️ **Panorama 11.1** (gestion centralisée) |
|---|---|---|
| Page | `pages/pan-os.html` | `pages/panorama.html` |
| Configurateur | `pages/configurateur.html` | `pages/panorama-configurateur.html` |
| Contenu | 68 modules + parcours guidés | Mise en service, ajout de pare-feux, templates & stacks, device groups, logs, admins, rapports, dépannage, HA, Zero Touch Provisioning (ZTP) |
| Spécificités | Assistants NAT & Règle | Commit to Panorama, Push to Devices, CLI côté pare-feu |

### PAN-OS — modules

| Catégorie | Exemples |
|---|---|
| **Déploiement standard client** | Config de base complète en un formulaire : système, management, WAN/LAN/DMZ, routage, NAT, publication serveur, règles, profils, mises à jour |
| Système & management | Hostname/DNS/NTP, interface de management, mises à jour dynamiques, sécurisation admin |
| Sauvegarde & config | Snapshots, export, restauration, commit partiel |
| Comptes administrateurs | Admin roles, comptes locaux, complexité MDP, LDAP/RADIUS/TACACS+ |
| Interfaces, zones & routage | Zones, interfaces L3, sous-interfaces VLAN, Mgmt profile, virtual router, DHCP, vwire, L2, tap |
| Règles de sécurité & NAT | Objets, tags, règle de sécurité, SNAT DIPP / pool, static 1:1, DNAT, U-turn |
| App-ID, profils, URL | Filtres/groupes d'apps, AV, Anti-Spyware (sinkhole), Vulnérabilités, File Blocking, URL, EDL |
| WildFire, User-ID, Décryptage | Profils WildFire, LDAP/group mapping, server monitoring, auth portal, certificats, SSL forward proxy |
| Logs | Syslog, alertes e-mail, SNMP, rapports, générateur de filtres de logs |
| VPN, HA & protections | IPsec site-à-site, GlobalProtect, HA actif/passif, Zone Protection, DoS, service routes |

### PAN-OS — parcours guidés

Nouveau pare-feu en 30 min · Publier un serveur web (DMZ) · Sécuriser l'accès Internet (profils, URL, décryptage) · VPN IPsec site-à-site · HA actif/passif · Durcir le management · Règles par utilisateur (User-ID) · Protéger contre les attaques.

Plus deux assistants visuels : **Assistant NAT** (flux animé avant/après NAT) et **Assistant Règle** (score bonnes pratiques, rulebase, test de flux).

## Fonctionnalités du configurateur

- **Parcours guidés** : stepper, progression, valeurs reprises automatiquement d'une étape à l'autre (hostname, IP, zones…), export de la **CLI complète** du parcours et **rapport imprimable / PDF**.
- **Projet client** : nom du client, sauvegarde automatique dans le navigateur, **export / import JSON**, état « Fait » des étapes conservé. Les mots de passe ne sont jamais enregistrés.
- **Validation en direct**, barre de progression des champs, « Charger un exemple », « Réinitialiser », copie en un clic (CLI ou valeur d'un champ GUI).
- **Lien de partage** : l'URL contient les valeurs saisies (`configurateur.html#<module>&v=…`).
- **Raccourcis** : `/` recherche, `⌘K` / `Ctrl K` palette de commandes, `Ctrl/⌘ + Entrée` générer.
- Liens directs : `configurateur.html#<moduleId>` et `configurateur.html#parcours=<parcoursId>`.

## Ajouter un module ou un parcours

Chaque module est une définition déclarative (`PAN.cfg.register({...})`) dans `assets/js/modules/` (PAN-OS) ou `assets/js/panorama/` (Panorama) ; un parcours se déclare avec `PAN.cfg.scenario({...})`. Voir l'en-tête de `assets/js/engine.js` (API complète : `category`, `push`, `fwCli`, `scenario`…).

## ⚠️ Avertissement

Outil non officiel. Relis toujours la configuration générée et teste-la avant toute mise en production. Certaines syntaxes CLI avancées (GlobalProtect, HA, User-ID agent, push Panorama…) sont à valider sur ta version : en cas de refus, utilise `?` dans la CLI ou le mode GUI.

---
Conçu par **Dinèche RADJOU**
