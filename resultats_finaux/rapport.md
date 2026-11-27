# Rapport de recommandations

Généré le 2026-11-27 par la chaîne d'agents, à partir du trafic de CICIDS2017 du 2017-07-06. Ce rapport a été produit avec l'aide d'une IA générative.

## Résumé

14 actifs analysés : 2 critique, 1 élevé, 8 moyen, 2 faible, 1 inconnu.

**Incident en cours sur 192.168.10.8 :** Compromission probable : elle a balayé 11 autres machines du réseau et des outils d'attaque passent dans son trafic (Nmap). La machine doit être isolée immédiatement.

## Classement des risques

| Rang | Actif | Rôle | Score | Niveau | Raison principale |
| --- | --- | --- | --- | --- | --- |
| 1 | 192.168.10.3 | Contrôleur de domaine | 68.6 | Critique | Pire faille : CVE-2017-8543 (Windows Server 2016), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 2 | 192.168.10.8 | Poste de travail | 27.4 | Critique | Compromission probable : elle a balayé 11 autres machines du réseau et des outils d'attaque passent dans son trafic (Nmap). |
| 3 | 192.168.10.50 | Serveur web | 35.6 | Élevé | Pire faille : CVE-2016-8740 (Apache 2.4.18), CVSS 7.5, EPSS 0.7907, exploitable depuis Internet. |
| 4 | 192.168.10.9 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-1776 (Windows 7 SP1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 5 | 192.168.10.5 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-1776 (Windows 8.1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 6 | 192.168.10.14 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2015-0311 (Windows 10), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 7 | 192.168.10.15 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2015-0311 (Windows 10), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 8 | 192.168.10.51 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-6271 (Ubuntu 12.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 9 | 192.168.10.19 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-6271 (Ubuntu 14.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 10 | 192.168.10.17 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-6271 (Ubuntu 14.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 11 | 192.168.10.12 | Poste de travail | 17.0 | Moyen | Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne. |
| 12 | 192.168.10.25 | Poste de travail | 13.7 | Faible | Pire faille : CVE-2014-6271 (Mac OS X 10.5.8), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 13 | 192.168.10.16 | Poste de travail | 11.3 | Faible | Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne. |
| 14 | 192.168.10.1 | Équipement réseau (pare-feu, routeur) | 0.0 | Inconnu | Aucun logiciel connu : impossible d'évaluer ses failles. Compléter l'inventaire. |

## Actions immédiates, toutes machines confondues

- **192.168.10.3** (Contrôleur de domaine) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143. Bulletins de sécurité correspondants : MS16-129, MS16-132, MS17-010, MSRC CVE-2017-0143, MSRC CVE-2017-8543.
- **192.168.10.8** (Poste de travail) : Isoler la machine du réseau, conserver ses journaux pour l'analyse, la réinstaller, puis changer les mots de passe des comptes utilisés dessus.
- **192.168.10.8** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792. Bulletins de sécurité correspondants : MS10-002, MS11-087, MS12-034, MS12-039, MS12-043, MS13-008, MS14-021.
- **192.168.10.50** (Serveur web) : Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.
- **192.168.10.9** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889. Bulletins de sécurité correspondants : MS11-087, MS12-034, MS12-039, MS12-043, MS14-021, MS15-034, MSRC CVE-2017-8543.
- **192.168.10.5** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543. Bulletins de sécurité correspondants : MS14-021, MS15-034, MSRC CVE-2017-8543.
- **192.168.10.14** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-0311, CVE-2015-0313, CVE-2017-8543, CVE-2015-2426, CVE-2015-2502. Bulletins de sécurité correspondants : MS15-078, MS15-093, MSRC CVE-2017-8543.
- **192.168.10.15** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-0311, CVE-2015-0313, CVE-2017-8543, CVE-2015-2426, CVE-2015-2502. Bulletins de sécurité correspondants : MS15-078, MS15-093, MSRC CVE-2017-8543.
- **192.168.10.51** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-0160, CVE-2014-3153. Bulletins de sécurité correspondants : USN-2165-1, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1.
- **192.168.10.19** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.17** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.12** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.25** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-4404, CVE-2015-1130. Bulletins de sécurité correspondants : DSA-3032, DSA-3035, USN-2362-1, USN-2363-1, USN-2363-2.
- **192.168.10.16** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

## Correctifs prioritaires

Bulletins des éditeurs qui corrigent des failles déjà exploitées (CISA KEV). Les bulletins équivalents (mêmes failles, mêmes machines, par exemple un bulletin Ubuntu par version) sont regroupés. Classés par nombre de machines protégées, puis rançongiciels d'abord, puis nombre de failles corrigées.

| Bulletins | Machines | Failles KEV corrigées | Rançongiciel | Adresses |
| --- | --- | --- | --- | --- |
| [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) | 6 | 6 (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145 ...) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.3, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-135](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135) | 6 | 1 (CVE-2016-7255) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.3, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [Mises à jour cumulatives Microsoft (guide MSRC)](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0001) | 6 | 5 (CVE-2017-0001, CVE-2017-0005, CVE-2017-0022 ...) |  | 192.168.10.14, 192.168.10.15, 192.168.10.3, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-132](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-132) | 6 | 1 (CVE-2016-7256) |  | 192.168.10.14, 192.168.10.15, 192.168.10.3, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [USN-3104-1](http://www.ubuntu.com/usn/USN-3104-1), [USN-3104-2](http://www.ubuntu.com/usn/USN-3104-2), [USN-3105-1](http://www.ubuntu.com/usn/USN-3105-1), [USN-3105-2](http://www.ubuntu.com/usn/USN-3105-2) | 6 | 1 (CVE-2016-5195) |  | 192.168.10.12, 192.168.10.16, 192.168.10.17, 192.168.10.19, 192.168.10.50, 192.168.10.51 |
| [Mises à jour cumulatives Microsoft (guide MSRC)](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0210) | 5 | 7 (CVE-2017-0210, CVE-2017-0213, CVE-2017-0222 ...) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.3, 192.168.10.5, 192.168.10.9 |
| [MS16-039](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-039) | 5 | 2 (CVE-2016-0165, CVE-2016-0167) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS15-097](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-097) | 5 | 1 (CVE-2015-2546) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-032](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) | 5 | 1 (CVE-2016-0099) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-051](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-051), [MS16-053](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-053) | 5 | 1 (CVE-2016-0189) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-098](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-098) | 5 | 1 (CVE-2016-3309) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-104](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104), [MS16-105](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105) | 5 | 1 (CVE-2016-3351) | oui | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS13-098](http://blogs.technet.com/b/srd/archive/2013/12/10/ms13-098-update-to-enhance-the-security-of-authenticode.aspx) | 5 | 1 (CVE-2013-3900) |  | 192.168.10.14, 192.168.10.15, 192.168.10.3, 192.168.10.5, 192.168.10.9 |
| [MS15-078](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-078) | 5 | 1 (CVE-2015-2426) |  | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS15-085](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-085) | 5 | 1 (CVE-2015-1769) |  | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |

*Et 53 autres groupes de bulletins, détaillés dans le tableau de bord.*

## Plan d'action par actif

### 192.168.10.3 : Contrôleur de domaine (Critique, score 68.6)

Le contrôleur de domaine Windows Server 2016 présente plusieurs failles critiques déjà exploitées (KEV) et expose des services internes sensibles.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143. Bulletins de sécurité correspondants : MS16-129, MS16-132, MS17-010, MSRC CVE-2017-0143, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité correspondant aux bulletins MS16-129, MS16-132, MS17-010, MSRC CVE-2017-8543 et MSRC CVE-2017-0143 afin de corriger les CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256 et CVE-2017-0143. *Ces vulnérabilités sont répertoriées dans le catalogue CISA KEV et ont été exploitées en interne. Leur correction élimine la porte d’entrée principale.*

*Priorité court terme*

- Segmenter le réseau en isolant le contrôleur de domaine sur un VLAN dédié et restreindre les flux réseau vers les ports 135, 389, 445, 3268 uniquement aux systèmes autorisés. *Réduire la surface d’attaque interne limite la capacité d’un attaquant à exploiter les failles depuis d’autres machines du réseau.*
- Activer l’authentification forte (MFA) pour tous les comptes administratifs du domaine et désactiver les comptes inutilisés ou à privilèges excessifs. *Même si une faille est exploitée, la MFA empêche l’escalade de privilèges vers le contrôleur de domaine.*

*Priorité moyen terme*

- Mettre en place une solution de sauvegarde quotidienne hors site des données d’annuaire et tester régulièrement la restauration. *En cas de compromission, des sauvegardes fiables permettent de restaurer rapidement les informations d’identité et les politiques de sécurité.*
- Déployer une surveillance renforcée : activer la journalisation détaillée (Event Forwarding, Sysmon), surveiller les connexions SMB et les tentatives d’accès aux services LDAP, et alerter sur tout comportement anormal. *Une visibilité accrue permet de détecter rapidement une exploitation éventuelle des vulnérabilités restantes ou de nouvelles tentatives d’intrusion.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.8 : Poste de travail (Critique, score 27.4)

Machine Windows Vista SP2 compromise, exploitable via plusieurs vulnérabilités KEV, a déjà balayé le réseau.

**Constats établis par les règles**

- (immédiate) Isoler la machine du réseau, conserver ses journaux pour l'analyse, la réinstaller, puis changer les mots de passe des comptes utilisés dessus.
- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792. Bulletins de sécurité correspondants : MS10-002, MS11-087, MS12-034, MS12-039, MS12-043, MS13-008, MS14-021.
- (court terme) Remplacer Windows Vista SP2 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Isoler la machine du réseau, conserver les journaux et les artefacts pour l’analyse, puis réinstaller le système d’exploitation et changer les mots de passe de tous les comptes locaux. *Compromission avérée : la machine a balayé 11 autres postes et du trafic d’outils d’attaque a été observé.*
- Appliquer les correctifs de sécurité correspondant aux vulnérabilités KEV : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792 via les bulletins MS14-021, MS10-002, MS11-087, MS12-034, MS12-039, MS12-043, MS13-008, ainsi que les bulletins disponibles listés (MS17-010, MS14-058, MS14-064, MS16-039, MS09-025, MS10-046, MS10-090). *Ces failles sont répertoriées dans le catalogue CISA KEV ; leur exploitation a été confirmée.*

*Priorité court terme*

- Remplacer Windows Vista SP2 par un système d’exploitation maintenu (ex. Windows 10/11) et mettre à jour les navigateurs et Java vers des versions supportées. *Fin de support de Vista le 11‑04‑2017 ; aucune mise à jour de sécurité n’est disponible depuis, laissant la machine exposée aux nouvelles vulnérabilités.*
- Renforcer l’authentification locale : activer l’authentification multifacteur ou des mots de passe forts, désactiver ou supprimer les comptes inutilisés. *Réduire le risque d’accès non autorisé après la réinstallation du poste.*

*Priorité moyen terme*

- Segmenter le réseau en plaçant les postes de travail sur un VLAN isolé, déployer un IDS/IPS pour surveiller le trafic interne et mettre en place des sauvegardes chiffrées et régulières des données utilisateurs. *Limiter la propagation d’éventuelles infections futures et garantir la disponibilité des données en cas d’incident.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.50 : Serveur web (Élevé, score 35.6)

Le serveur web Ubuntu 16.04 expose les ports 21, 22, 80 et 443 à Internet et présente plusieurs vulnérabilités critiques (CVE-2016-8740, CVE-2016-5387, CVE-2016-6515, CVE-2016-4971) non corrigées.

**Constats établis par les règles**

- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-8740, CVE-2016-5387, CVE-2016-6515, CVE-2016-4971. Bulletins de sécurité correspondants : USN-3012-1, USN-3038-1.
- (immédiate) Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.

**Plan d'action détaillé**

*Priorité immédiate*

- Restreindre l'accès Internet aux services FTP (21) et SSH (22) en les bloquant au pare‑feu ou en les limitant à un VPN ou à des adresses IP autorisées. *Ces services d'administration sont exposés à Internet, ce qui les rend vulnérables aux attaques par force brute et aux exploits connus.*
- Appliquer les correctifs de sécurité disponibles USN-3104-1, USN-3104-2, USN-3105-1 et USN-3105-2. *Ces bulletins corrigent les failles déjà exploitées dans le catalogue KEV et renforcent la posture de la machine.*

*Priorité court terme*

- Installer les correctifs USN-3012-1 (pour CVE-2016-4971) et USN-3038-1 (pour CVE-2016-5387) afin de corriger les vulnérabilités graves du serveur Apache. *Ces deux CVE ont un score CVSS ≥ 8 et sont exploitables depuis Internet.*
- Mettre à jour Apache vers une version supérieure à 2.4.23 (ex. 2.4.24 ou plus) et OpenSSH vers 7.3 ou supérieure. *Les versions actuelles contiennent les CVE-2016-8740, CVE-2016-6515 et CVE-2016-6210, toutes exploitables depuis Internet.*

*Priorité moyen terme*

- Renforcer l'authentification SSH en désactivant l'authentification par mot de passe et en imposant l'usage de clés publiques, puis surveiller les tentatives de connexion avec un système de détection d'intrusion. *Réduit le risque d'énumération d'utilisateurs (CVE-2016-6210) et de déni de service par mots de passe longs (CVE-2016-6515).*

*Plan rédigé par : règles + LLM.*

### 192.168.10.9 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Windows 7 SP1 possède plusieurs vulnérabilités KEV très critiques exploitées depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889. Bulletins de sécurité correspondants : MS11-087, MS12-034, MS12-039, MS12-043, MS14-021, MS15-034, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité correspondant aux CVE‑2014‑1776, CVE‑2015‑1635, CVE‑2017‑8543, CVE‑2011‑3402 et CVE‑2012‑1889 via les bulletins MS14‑021, MS15‑034, MSRC CVE‑2017‑8543, MS11‑087, MS12‑034, MS12‑039 et MS12‑043. Installer également les correctifs listés dans MS17‑010, MS14‑058, MS14‑064, MS15‑065, MS16‑039 et MS12‑024 qui couvrent d’autres vulnérabilités KEV. *Ces failles sont confirmées exploitées dans le monde (KEV) et sont exploitables depuis le réseau interne. Les correctifs éliminent le risque d’exécution de code ou de déni de service.*
- Activer l’authentification forte (MFA) pour les connexions locales et à distance (RDP, VPN) et désactiver les comptes inutilisés. *Réduit la probabilité qu’un attaquant exploite une faille pour obtenir des privilèges en limitant l’accès aux identifiants valides.*

*Priorité court terme*

- Segmenter le poste de travail sur un VLAN dédié, restreindre les communications entrantes aux services strictement nécessaires et bloquer tout trafic non autorisé depuis le réseau interne. *Limite la surface d’attaque et empêche la propagation d’une compromission éventuelle vers d’autres systèmes.*

*Priorité moyen terme*

- Planifier la migration vers un système d’exploitation supporté (ex. Windows 10) avant la fin de support de Windows 7 le 14 janvier 2020, puis mettre à jour Firefox et Java vers leurs versions récentes. *Un OS non‑supporté ne reçoit plus de correctifs, augmentant le risque de nouvelles vulnérabilités. Les navigateurs et Java à jour réduisent les vecteurs d’exploitation web.*
- Mettre en place des sauvegardes quotidiennes des documents utilisateurs et activer une solution EDR (Endpoint Detection and Response) avec journalisation centralisée et alertes sur comportements suspects. *Assure la récupération des données en cas d’incident et permet de détecter rapidement une exploitation éventuelle des vulnérabilités résiduelles.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.5 : Poste de travail (Moyen, score 27.4)

Le poste de travail Windows 8.1 présente plusieurs vulnérabilités KEV très critiques exploitées depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543. Bulletins de sécurité correspondants : MS14-021, MS15-034, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité correspondant aux CVE exploitées : appliquer les bulletins MS14-021, MS15-034 et MSRC CVE-2017-8543, ainsi que les bulletins listés dans correctifs_disponibles_pour_failles_kev (MS17-010, MS14-058, MS14-064, MS15-065, MS16-039, MS13-080, MS13-090, MS13-098). *Ces vulnérabilités sont confirmées dans le catalogue CISA KEV et permettent une exécution de code ou un déni de service depuis le réseau interne.*
- Mettre à jour ou remplacer les logiciels obsolètes : installer la dernière version supportée de Firefox et de Java, ou les désinstaller si non nécessaires. *Firefox 54 et Java 8u121 ne reçoivent plus de correctifs de sécurité, exposant le poste à des vulnérabilités non répertoriées dans la fiche.*

*Priorité court terme*

- Segmenter le réseau interne : placer le poste de travail dans un VLAN isolé et restreindre les flux entrants depuis les autres segments via des règles de pare‑feu. *Réduire la surface d’attaque interne limite la possibilité d’exploiter les vulnérabilités depuis d’autres machines du réseau.*
- Activer l’authentification forte (MFA) pour les accès locaux et distants, et appliquer une politique de mots de passe complexes. *Même si une vulnérabilité est exploitée, l’accès non autorisé sera bloqué sans second facteur d’authentification.*

*Priorité moyen terme*

- Déployer une solution de détection et de réponse sur les points d’extrémité (EDR) et mettre en place une surveillance continue des processus et des connexions réseau. *Permet de détecter rapidement toute tentative d’exploitation des vulnérabilités connues ou de nouvelles attaques.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.14 : Poste de travail (Moyen, score 27.4)

Poste de travail Windows 10 avec plusieurs vulnérabilités critiques (CVE-2015-0311, CVE-2015-0313, CVE-2017-8543, CVE-2015-2426, CVE-2015-2502) déjà exploitées dans le monde, aucune mise à jour appliquée.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-0311, CVE-2015-0313, CVE-2017-8543, CVE-2015-2426, CVE-2015-2502. Bulletins de sécurité correspondants : MS15-078, MS15-093, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité correspondant aux CVE exploitées : installer les bulletins MS15-078, MS15-093 et MSRC CVE-2017-8543, ainsi que les autres correctifs listés (MS17-010, MS16-039, MS16-129, MS13-098, MS15-085, MS15-097). *Ces vulnérabilités sont répertoriées dans le catalogue CISA KEV, leur exploitation est prouvée. Les correctifs disponibles éliminent la faille.*
- Désinstaller ou désactiver complètement Adobe Flash Player sur la machine. *Toutes les CVE listées concernent des vulnérabilités de Flash. Supprimer le composant élimine la surface d'attaque.*

*Priorité court terme*

- Mettre en place une authentification forte (MFA) pour les connexions locales et les accès distants au poste de travail. *Réduit le risque d’accès non autorisé même si une vulnérabilité est exploitée.*
- Segmenter le réseau interne : placer le poste de travail dans un VLAN isolé et restreindre les communications vers les serveurs critiques. *Limite la capacité d’un attaquant à se déplacer latéralement depuis le poste compromis.*

*Priorité moyen terme*

- Instaurer des sauvegardes quotidiennes chiffrées des données utilisateur, stockées hors ligne ou dans un cloud sécurisé. *Assure la disponibilité des courriels, documents et historiques en cas d’incident.*
- Déployer une solution EDR et activer la journalisation détaillée (PowerShell, logs d’applications) pour détecter toute tentative d’exploitation des vulnérabilités connues. *Permet une détection précoce et une réponse rapide aux attaques ciblant les failles identifiées.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.15 : Poste de travail (Moyen, score 27.4)

Le poste de travail Windows 10 expose des failles critiques déjà exploitées (CVE‑2015‑0311, CVE‑2015‑0313, CVE‑2017‑8543, CVE‑2015‑2426, CVE‑2015‑2502) et utilise un navigateur obsolète.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-0311, CVE-2015-0313, CVE-2017-8543, CVE-2015-2426, CVE-2015-2502. Bulletins de sécurité correspondants : MS15-078, MS15-093, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité correspondant aux CVE exploitées : installer les bulletins MS15‑078, MS15‑093 et MSRC CVE‑2017‑8543, ainsi que tout correctif disponible dans les bulletins listés (MS17‑010, MS16‑039, MS16‑129, MS13‑098, MS15‑085, MS15‑097). *Ces vulnérabilités sont répertoriées dans le catalogue CISA KEV, leur exploitation est prouvée. Le correctif supprime la possibilité d’exécution de code à distance depuis le réseau interne.*
- Désinstaller ou désactiver Adobe Flash Player et tous les plugins associés. *Les CVE les plus critiques (CVE‑2015‑0311, CVE‑2015‑0313) concernent Flash. Leur suppression élimine la surface d’attaque sans attendre les mises à jour du système.*

*Priorité court terme*

- Activer le pare‑feu local et placer le poste de travail dans un VLAN segmenté, limitant les communications entrantes aux services strictement nécessaires. *Les failles sont exploitables depuis le réseau interne. La segmentation réduit la portée d’une éventuelle compromission et empêche les mouvements latéraux.*
- Mettre à jour Firefox vers la version la plus récente et supprimer les extensions obsolètes. *Un navigateur désuet augmente le risque d’exploitation via le web. La version actuelle (54.0) ne reçoit plus de correctifs.*

*Priorité moyen terme*

- Déployer une authentification forte (MFA) pour les comptes utilisateurs, instaurer des sauvegardes quotidiennes chiffrées et installer une solution EDR pour la détection d’activités suspectes. *En cas de compromission résiduelle, MFA limite l’escalade, les sauvegardes assurent la continuité et l’EDR permet de détecter rapidement toute exploitation non corrigée.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.51 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Ubuntu 12.04 et Firefox 31.0 présente plusieurs failles critiques déjà exploitées (KEV) et n'est plus maintenu depuis le 28‑04‑2017.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-0160, CVE-2014-3153. Bulletins de sécurité correspondants : USN-2165-1, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1.
- (court terme) Remplacer Ubuntu 12.04 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles (USN‑2165‑1, USN‑2237‑1, USN‑2240‑1, USN‑2362‑1, USN‑2363‑1, USN‑2363‑2, USN‑2707‑1) pour corriger les CVE‑2014‑6271, CVE‑2014‑7169, CVE‑2015‑4495, CVE‑2014‑0160 et CVE‑2014‑3153. *Ces vulnérabilités sont répertoriées dans le catalogue CISA KEV et leur exploitation a été observée. Les correctifs éliminent les vecteurs d'attaque connus.*
- Isoler la machine du réseau interne en la plaçant dans un VLAN de quarantaine et bloquer tout trafic entrant non essentiel. *Les failles Bash (CVE‑2014‑6271, CVE‑2014‑7169) sont exploitables depuis le réseau interne. L’isolation limite la surface d’attaque pendant la mise à jour.*

*Priorité court terme*

- Migrer le poste de travail vers une version d'Ubuntu toujours maintenue (ex. 20.04 LTS) et réinstaller les applications nécessaires. *Ubuntu 12.04 a atteint sa fin de support le 28‑04‑2017, aucune mise à jour de sécurité n’est plus fournie. Une version supportée recevra les correctifs futurs.*
- Mettre à jour Firefox vers la dernière version prise en charge par l’organisation. *Firefox 31.0 contient la vulnérabilité CVE‑2015‑4495 qui permet de contourner la Same‑Origin Policy. Une version à jour corrige ce problème.*

*Priorité moyen terme*

- Renforcer la configuration du système : désactiver l’interprétation des variables d’environnement par Bash (désactiver ForceCommand), activer AppArmor/SELinux en mode enforcing, et mettre en place une surveillance des logs SSH et des appels système liés à Bash. *Même après correctif, réduire la surface d’attaque en limitant les vecteurs d’exploitation Bash et en détectant rapidement toute tentative d’abus.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.19 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Ubuntu 14.04 et Firefox 31.0 possède plusieurs failles critiques déjà exploitées (KEV) et reste exposé depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles via les bulletins USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2, USN-2237-1 et USN-2240-1. *Ces bulletins corrigent les CVE déjà exploités (KEV) et réduisent immédiatement le risque d'attaque.*

*Priorité court terme*

- Mettre à jour le système d'exploitation vers une version Ubuntu LTS prise en charge et installer la dernière version de Firefox. *Une version plus récente intègre les correctifs des vulnérabilités listées et élimine les failles liées à Bash, au noyau Linux et au lecteur PDF de Firefox.*

*Priorité moyen terme*

- Renforcer la segmentation du réseau interne en isolant les postes de travail du reste du réseau et en limitant les communications inutiles. *Réduire la surface d'attaque interne empêche l'exploitation des failles qui nécessitent un accès depuis le réseau interne.*
- Déployer une surveillance continue (IDS/IPS, journalisation centralisée) et mettre en place des sauvegardes quotidiennes chiffrées des données utilisateurs. *Détecter rapidement toute tentative d'exploitation et garantir la récupération des données en cas d'incident.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.17 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Ubuntu 14.04 et Firefox 31.0 présente plusieurs failles déjà exploitées (KEV) dont les correctifs existent mais ne sont pas appliqués.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les mises à jour de sécurité correspondant aux bulletins USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1 et USN-3105-2. *Ces correctifs corrigent les CVE déjà exploités (KEV) et réduisent immédiatement le risque d’escalade ou d’exécution de code.*
- Mettre à jour le navigateur Firefox vers une version prise en charge. *La version 31.0 contient la faille CVE-2015-4495 qui permet de contourner la Same Origin Policy.*

*Priorité court terme*

- Migrer le système d’exploitation vers une version Ubuntu LTS supportée (ex. 20.04). *Ubuntu 14.04 approche de sa fin de support (30‑04‑2019) et ne recevra plus de correctifs après cette date, augmentant le risque à long terme.*
- Durcir la configuration Bash/SSH : désactiver ForceCommand, nettoyer les variables d’environnement avant l’appel de Bash, et limiter les accès SSH aux comptes nécessaires. *Les failles CVE-2014-6271 et CVE-2014-7169 exploitent des chaînes d’environnement Bash, souvent via ForceCommand.*

*Priorité moyen terme*

- Segmenter le poste de travail sur un VLAN dédié et activer le pare‑feu local (ufw) pour bloquer tout trafic entrant non essentiel. *Réduire la surface d’attaque interne limite l’exploitation des vulnérabilités nécessitant un accès réseau.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.12 : Poste de travail (Moyen, score 17.0)

Poste de travail sous Ubuntu 16.04 avec plusieurs vulnérabilités graves, dont une déjà exploitée (Dirty COW). Le risque est moyen mais nécessite des correctifs rapides.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. Bulletins de sécurité correspondants : USN-3012-1, USN-4246-1, USN-4292-1.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité pour la vulnérabilité Dirty COW (CVE-2016-5195) en installant les bulletins USN-3104-1, USN-3104-2, USN-3105-1 et USN-3105-2. *Cette faille est répertoriée dans le catalogue CISA KEV, preuve d'exploitation réelle. La mise à jour élimine le risque d'élévation de privilèges locale.*
- Corriger les autres vulnérabilités critiques (CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843) en appliquant les bulletins USN-3012-1, USN-4246-1 et USN-4292-1. *Ces failles ont un score CVSS ≥ 7 et sont exploitables depuis le réseau interne. Les correctifs réduisent la surface d'attaque.*

*Priorité court terme*

- Activer et configurer le pare‑feu local (ufw ou iptables) pour bloquer tout trafic entrant non nécessaire depuis le réseau interne, limitant ainsi les vecteurs d’exploitation des failles réseau. *Les vulnérabilités CVE‑2016‑4971, CVE‑2016‑7117, CVE‑2016‑9841 et CVE‑2016‑9843 sont exploitées depuis le réseau interne. Un filtrage strict réduit l’exposition.*
- Renforcer la politique d’authentification en imposant une authentification forte (ex. mot de passe complexe + 2FA) pour les comptes locaux et les accès à distance. *Limiter les accès locaux diminue la probabilité d’exploitation de la vulnérabilité locale Dirty COW (CVE‑2016‑5195).*

*Priorité moyen terme*

- Mettre en place une surveillance continue des journaux système et des alertes de détection d’anomalies (ex. auditd, syslog centralisé) pour repérer d’éventuelles tentatives d’exploitation. *Une visibilité accrue permet de réagir rapidement en cas d’activité suspecte liée aux vulnérabilités connues.*
- Planifier des sauvegardes régulières et chiffrées des données utilisateur et des configurations système, stockées hors site ou sur un support isolé. *En cas d’exploitation réussie, les sauvegardes garantissent la continuité d’activité et la récupération des données.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.25 : Poste de travail (Faible, score 13.7)

Niveau de risque Faible (score 13.7). Pire faille : CVE-2014-6271 (Mac OS X 10.5.8), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-4404, CVE-2015-1130. Bulletins de sécurité correspondants : DSA-3032, DSA-3035, USN-2362-1, USN-2363-1, USN-2363-2. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2010-1119. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.16 : Poste de travail (Faible, score 11.3)

Niveau de risque Faible (score 11.3). Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. Bulletins de sécurité correspondants : USN-3012-1, USN-4246-1, USN-4292-1. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.1 : Équipement réseau (pare-feu, routeur) (Inconnu, score 0.0)

Équipement réseau (pare-feu/routeur) avec service DNS ouvert, aucune information d'inventaire disponible, aucune faille identifiée.

**Constats établis par les règles**

- (court terme) Compléter l'inventaire : système, logiciels et versions installés.

**Plan d'action détaillé**

*Priorité immédiate*

- Restreindre l'accès au port DNS (53) aux seules adresses IP internes autorisées. *Limiter l'exposition du service DNS empêche les requêtes non autorisées depuis le réseau interne ou externe.*
- Activer la journalisation détaillée des requêtes DNS et des connexions au dispositif. *Permet de détecter rapidement des comportements anormaux et de disposer d'éléments d'investigation.*

*Priorité court terme*

- Compléter l'inventaire du dispositif : identifier le système d'exploitation, les logiciels/firmwares et leurs versions. *Sans inventaire, impossible d'évaluer les vulnérabilités et d'appliquer les correctifs nécessaires.*
- Planifier l'application des mises à jour ou correctifs du firmware dès que l'inventaire sera connu. *Les correctifs corrigent les failles déjà exploitées (KEV) et réduisent le risque d'attaque.*

*Priorité moyen terme*

- Segmenter le réseau en isolant le dispositif DNS sur un VLAN dédié avec des contrôles d'accès stricts. *La segmentation limite la propagation d'une éventuelle compromission et renforce la défense en profondeur.*
- Mettre en place des sauvegardes régulières et sécurisées de la configuration du pare-feu/routeur. *Assure une restauration rapide en cas de perte ou de corruption de la configuration.*

*Plan rédigé par : règles + LLM.*

## Inventaire et observations

- Machines sans logiciel connu : 192.168.10.1.
- Balayages de ports observés : 12, depuis 172.16.0.1, 192.168.10.8.
