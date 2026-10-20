# 🛡️ PAN Config Builder — configurateur Palo Alto (PAN-OS 11.0)

Outil web pour configurer un pare-feu Palo Alto Networks chez n'importe quel client : **tu saisis tes informations, l'outil les valide et génère la configuration**, au choix :

- 🖱️ **Mode GUI** : le pas-à-pas WebUI, étape par étape (chemin de menu, onglet, valeurs à saisir), chaque étape cochable « Fait ».
- ⌨️ **Mode CLI** : les commandes `set` prêtes à coller en SSH, avec `commit` et les commandes de vérification.

## Contenu (68 modules)

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

Plus deux assistants visuels : **Assistant NAT** (flux animé avant/après NAT) et **Assistant Règle** (score bonnes pratiques, rulebase, test de flux).

## Utilisation

- **En ligne** : via GitHub Pages.
- **En local** : télécharge le dépôt et ouvre `index.html` — aucun serveur ni installation (HTML/CSS/JS pur).

## Ajouter un module

Chaque module est une simple définition déclarative (`PAN.cfg.register({...})`) dans `assets/js/modules/`. Voir l'en-tête de `assets/js/engine.js`.

## ⚠️ Avertissement

Outil non officiel. Relis toujours la configuration générée et teste-la avant toute mise en production. Certaines syntaxes CLI avancées (GlobalProtect, HA, User-ID agent…) sont à valider sur ta version de PAN-OS : en cas de refus, utilise `?` dans la CLI ou le mode GUI.

---
Conçu par **Dinèche RADJOU**
