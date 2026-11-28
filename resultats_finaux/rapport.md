# Rapport de recommandations

Généré le 2026-11-28 par la chaîne d'agents, à partir du trafic de CICIDS2017 du 2017-07-06. Ce rapport a été produit avec l'aide d'une IA générative.

## Résumé

14 actifs analysés. Par niveau de risque : Critique 2, Élevé 1, Moyen 8, Faible 2, Inconnu 1.

**Incident en cours sur 192.168.10.8 :** Compromission probable : elle a balayé 11 autres machines du réseau et des outils d'attaque passent dans son trafic (Nmap). La machine doit être isolée immédiatement.

## Classement des risques

| Rang | Actif | Rôle | Score | Niveau | Raison principale |
| --- | --- | --- | --- | --- | --- |
| 1 | 192.168.10.3 | Contrôleur de domaine | 68.6 | Critique | Pire faille : CVE-2017-8543 (Windows Server 2016), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 2 | 192.168.10.8 | Poste de travail | 27.4 | Critique | Compromission probable : elle a balayé 11 autres machines du réseau et des outils d'attaque passent dans son trafic (Nmap). |
| 3 | 192.168.10.50 | Serveur web | 35.6 | Élevé | Pire faille : CVE-2016-8740 (Apache 2.4.18), CVSS 7.5, EPSS 0.7907, exploitable depuis Internet. |
| 4 | 192.168.10.9 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-1776 (Windows 7 SP1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 5 | 192.168.10.5 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-1776 (Windows 8.1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 6 | 192.168.10.14 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2017-8543 (Windows 10), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 7 | 192.168.10.15 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2017-8543 (Windows 10), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
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
- **192.168.10.50** (Serveur web) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.50** (Serveur web) : Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.
- **192.168.10.9** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889. Bulletins de sécurité correspondants : MS11-087, MS12-034, MS12-039, MS12-043, MS14-021, MS15-034, MSRC CVE-2017-8543.
- **192.168.10.5** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543. Bulletins de sécurité correspondants : MS14-021, MS15-034, MSRC CVE-2017-8543.
- **192.168.10.14** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256. Bulletins de sécurité correspondants : MS15-093, MS16-129, MS16-132, MSRC CVE-2017-8543.
- **192.168.10.15** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256. Bulletins de sécurité correspondants : MS15-093, MS16-129, MS16-132, MSRC CVE-2017-8543.
- **192.168.10.51** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-0160, CVE-2014-3153. Bulletins de sécurité correspondants : USN-2165-1, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1.
- **192.168.10.19** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.17** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.12** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.25** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-4404, CVE-2015-1130. Bulletins de sécurité correspondants : Apple HT204659, Apple HT6441, Apple HT6442, Apple HT6495, Apple HT6535.
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
| [MS15-085](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-085) | 5 | 1 (CVE-2015-1769) |  | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS15-093](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-093) | 5 | 1 (CVE-2015-2502) |  | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |
| [MS16-037](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-037) | 5 | 1 (CVE-2016-0162) |  | 192.168.10.14, 192.168.10.15, 192.168.10.5, 192.168.10.8, 192.168.10.9 |

*Et 55 autres groupes de bulletins, détaillés dans le tableau de bord.*

## Plan d'action par actif

### 192.168.10.3 : Contrôleur de domaine (Critique, score 68.6)

Le contrôleur de domaine Windows Server 2016 présente plusieurs failles critiques déjà exploitées (KEV) et reste exposé depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143. Bulletins de sécurité correspondants : MS16-129, MS16-132, MS17-010, MSRC CVE-2017-0143, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles (MS16-129, MS16-132, MS17-010, MSRC CVE-2017-8543) pour corriger les vulnérabilités CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256 et CVE-2017-0143. *Ces failles sont répertoriées dans le catalogue KEV et leur exploitation a été confirmée. Leur correction élimine la possibilité d'attaque depuis le réseau interne.*

*Priorité court terme*

- Désactiver SMBv1 et restreindre les ports critiques (445, 135, 389, 3268) aux seules machines autorisées via des règles de pare‑feu internes. *SMBv1 est la cible de la vulnérabilité CVE-2017-0143. Limiter l’accès réseau réduit la surface d’attaque pour les failles restantes.*
- Mettre en place une authentification forte (ex. MFA) pour les comptes administratifs du domaine et appliquer la politique de mot de passe robuste. *Le contrôleur de domaine détient les mots de passe hachés et les politiques de sécurité ; renforcer l’authentification empêche la compromission même si une faille est exploitée.*

*Priorité moyen terme*

- Segmenter le réseau en isolant le contrôleur de domaine sur un VLAN dédié avec des contrôles d’accès stricts. *La plupart des failles sont exploitables depuis le réseau interne. La segmentation limite la propagation d’une éventuelle compromission.*
- Déployer une solution de surveillance et de journalisation centralisée (SIEM) pour détecter les tentatives d’exploitation sur les ports exposés et les services critiques. *Une visibilité en temps réel permet d’identifier rapidement les activités suspectes liées aux vulnérabilités connues.*
- Établir des sauvegardes quotidiennes chiffrées du contrôleur de domaine et tester régulièrement la restauration. *En cas de compromission, des sauvegardes fiables assurent la continuité de l’annuaire et la récupération des données d’identité.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.8 : Poste de travail (Critique, score 27.4)

La machine Windows Vista SP2 montre des signes de compromission et possède plusieurs failles exploitées dans le monde, dont la plus critique CVE-2014-1776.

**Constats établis par les règles**

- (immédiate) Isoler la machine du réseau, conserver ses journaux pour l'analyse, la réinstaller, puis changer les mots de passe des comptes utilisés dessus.
- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792. Bulletins de sécurité correspondants : MS10-002, MS11-087, MS12-034, MS12-039, MS12-043, MS13-008, MS14-021.
- (court terme) Remplacer Windows Vista SP2 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Isoler la station du réseau, sauvegarder les journaux pour analyse, réinstaller le système d’exploitation et changer tous les mots de passe des comptes locaux. *Des outils d’attaque ont été détectés dans le trafic et la machine a probablement compromis d’autres postes.*
- Appliquer les correctifs de sécurité qui corrigent les vulnérabilités déjà exploitées : installer les bulletins MS14-021, MS10-002, MS11-087, MS12-034, MS12-039, MS12-043, MS13-008 ainsi que les correctifs disponibles listés (MS10-002, MS10-046, MS10-090, MS14-058, MS14-064, MS16-039, MS17-010, MS09-025). *Ces correctifs couvrent les CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889 et CVE-2012-4792, qui sont connues comme exploitées dans le monde.*

*Priorité court terme*

- Remplacer Windows Vista SP2 par une version maintenue du système d’exploitation. *Le support de Vista a pris fin le 11 avril 2017, aucune mise à jour ne sera plus fournie, ce qui laisse la machine exposée aux nouvelles vulnérabilités.*

*Priorité moyen terme*

- Mettre à jour ou désinstaller les navigateurs et les runtimes obsolètes (Firefox 52.0, Java 8 u131) et désactiver l’exécution de Java dans le navigateur. *Ces composants sont anciens, ne reçoivent plus de correctifs récents et peuvent être exploités via le web.*
- Renforcer la sécurité d’accès : implémenter une authentification forte pour les comptes locaux et segmenter le réseau afin de limiter les communications internes vers les postes critiques. *Réduire la surface d’attaque interne limite la propagation d’éventuelles compromissions futures.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.50 : Serveur web (Élevé, score 35.6)

Le serveur web expose plusieurs services Internet et présente des failles graves sur Apache, OpenSSH et le système d'exploitation, dont certaines sont déjà exploitées ailleurs.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-8740, CVE-2016-5387, CVE-2016-6515, CVE-2016-4971. Bulletins de sécurité correspondants : USN-3012-1, USN-3038-1.
- (immédiate) Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent la faille CVE-2016-5195 en suivant les bulletins USN-3104-1, USN-3104-2, USN-3105-1 et USN-3105-2. *Cette faille figure dans le catalogue KEV, son exploitation réelle est prouvée ailleurs.*
- Restreindre l'accès depuis Internet aux services FTP (port 21) et SSH (port 22) en les limitant à un VPN ou à une liste d'adresses IP autorisées. *Ces services d'administration sont exposés à Internet, ce qui les rend vulnérables aux attaques par force brute.*

*Priorité court terme*

- Mettre à jour Apache 2.4.18 afin de corriger les failles CVE-2016-8740 et CVE-2016-5387, en appliquant les correctifs indiqués dans les bulletins USN-3038-1 et USN-3012-1. *Ces vulnérabilités graves permettent un déni de service et une redirection de trafic HTTP.*
- Mettre à jour OpenSSH 7.2p2 pour corriger les failles CVE-2016-6515 et CVE-2016-6210. *Ces vulnérabilités peuvent entraîner un déni de service et l'énumération d'utilisateurs.*

*Priorité moyen terme*

- Passer à une authentification forte (clé publique) pour SSH, désactiver l'authentification par mot de passe et activer une journalisation détaillée avec alertes sur les tentatives d'accès. *Renforcer la sécurité d'accès réduit le risque d'attaque par force brute et améliore la détection d'activités suspectes.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.9 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Windows 7 SP1 possède plusieurs failles critiques déjà exploitées (KEV) et utilise des navigateurs et Java non à jour.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889. Bulletins de sécurité correspondants : MS11-087, MS12-034, MS12-039, MS12-043, MS14-021, MS15-034, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité correspondant aux CVE‑2014‑1776, CVE‑2015‑1635, CVE‑2017‑8543, CVE‑2011‑3402 et CVE‑2012‑1889 via les bulletins MS14‑021, MS15‑034, MSRC CVE‑2017‑8543, MS11‑087, MS12‑034, MS12‑039 et MS12‑043. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et ont déjà fait l'objet d'exploits confirmés.*
- Activer le pare‑feu local et restreindre les connexions entrantes depuis le réseau interne aux services strictement nécessaires. *Toutes les failles critiques sont exploitables depuis le réseau interne ; le filtrage limite la surface d’attaque.*

*Priorité court terme*

- Mettre à jour Firefox vers la dernière version maintenue et installer les dernières mises à jour de Java 8. *Des versions anciennes du navigateur et de Java augmentent le risque de compromission via des vecteurs client‑side.*
- Déployer une authentification forte (MFA) pour les comptes locaux et les accès aux ressources critiques, et appliquer une politique de mots de passe robustes. *Renforcer la protection des comptes réduit l’impact d’une éventuelle compromission de la machine.*

*Priorité moyen terme*

- Planifier la migration du poste de travail vers un système d’exploitation supporté (ex. Windows 10) avant la fin du support de Windows 7 en 2020. *Un OS supporté reçoit régulièrement des correctifs, ce qui diminue la probabilité d’exploitation de vulnérabilités non corrigées.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.5 : Poste de travail (Moyen, score 27.4)

Poste de travail Windows 8.1 avec plusieurs vulnérabilités déjà exploitées (KEV) et un risque moyen.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543. Bulletins de sécurité correspondants : MS14-021, MS15-034, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles pour les CVE‑2014‑1776, CVE‑2015‑0311, CVE‑2015‑0313, CVE‑2015‑1635 et CVE‑2017‑8543 en suivant les bulletins MS14‑021, MS15‑034 et MSRC CVE‑2017‑8543, ainsi que les bulletins listés comme correctifs disponibles (MS17‑010, MS14‑058, MS14‑064, MS15‑065, MS16‑039, MS13‑080, MS13‑090, MS13‑098). *Ces failles sont répertoriées dans le catalogue KEV et leur exploitation a été observée. Les correctifs éliminent les vulnérabilités critiques.*

*Priorité court terme*

- Activer le pare‑feu Windows et le configurer pour bloquer tout trafic entrant non nécessaire depuis le réseau interne, en autorisant uniquement les ports requis par les applications légitimes. *Réduire la surface d’attaque et empêcher l’exploitation des vulnérabilités depuis le réseau interne.*
- Mettre en place une authentification forte (ex. mot de passe complexe + MFA) pour les connexions locales et les accès distants au poste de travail. *Limite le risque de compromission d’identifiants qui pourrait faciliter l’exploitation des failles existantes.*

*Priorité moyen terme*

- Isoler le poste de travail sur un VLAN dédié ou segmenté, séparé des serveurs critiques et des autres postes, avec des contrôles d’accès stricts. *Empêche la propagation latérale d’une éventuelle infection vers des systèmes plus sensibles.*
- Instaurer des sauvegardes quotidiennes des documents utilisateurs et des courriels, stockées hors ligne ou sur un serveur de sauvegarde dédié, et tester régulièrement les restaurations. *Assure la disponibilité des données en cas de compromission ou de perte suite à une exploitation.*
- Déployer une solution de détection et de réponse sur les points d’extrémité (EDR) ou un système de surveillance du trafic réseau pour identifier rapidement toute tentative d’exploitation des vulnérabilités connues. *Permet une détection précoce et une réponse rapide aux attaques ciblant les failles présentes.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.14 : Poste de travail (Moyen, score 27.4)

Le poste de travail Windows 10 possède plusieurs vulnérabilités critiques déjà exploitées (KEV) et expose des données utilisateur sensibles.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256. Bulletins de sécurité correspondants : MS15-093, MS16-129, MS16-132, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité correspondant aux vulnérabilités exploitées : installer les mises à jour des bulletins MSRC CVE‑2017‑8543, MS15‑093, MS16‑129 et MS16‑132. *Ces failles sont répertoriées dans le catalogue KEV et leur exploitation a été observée. Leur correction élimine le vecteur d’attaque depuis le réseau interne.*

*Priorité court terme*

- Activer l’authentification forte (MFA) pour les comptes locaux et les services d’accès à distance. *Renforce la résistance aux tentatives d’accès non autorisé même si une vulnérabilité était exploitée.*
- Segmenter le poste de travail du reste du réseau interne en le plaçant dans un VLAN dédié avec des règles de pare‑feu limitant les communications entrantes uniquement aux services nécessaires. *Réduit la surface d’exposition aux attaques provenant du réseau interne où les vulnérabilités sont exploitables.*

*Priorité moyen terme*

- Déployer une solution de détection et de réponse sur les points de terminaison (EDR) et configurer la journalisation des événements de sécurité pour alerter sur toute tentative d’exploitation des CVE connues. *Permet une détection précoce d’activités suspectes et une réponse rapide en cas d’incident.*
- Mettre en place des sauvegardes quotidiennes chiffrées des données utilisateur (courriels, documents, historiques) et tester régulièrement la restauration. *Assure la disponibilité des données en cas de compromission ou de perte suite à une exploitation.*
- Mettre à jour le navigateur Firefox vers la dernière version maintenue et désactiver les fonctionnalités non nécessaires (JavaScript, plugins) pour limiter les vecteurs d’attaque web. *Réduit le risque d’exploitation de vulnérabilités liées au navigateur, même si aucune CVE spécifique n’est mentionnée dans la fiche.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.15 : Poste de travail (Moyen, score 27.4)

Poste de travail Windows 10 avec Firefox 54, contenant plusieurs vulnérabilités critiques déjà exploitées (CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256) et exploitables depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256. Bulletins de sécurité correspondants : MS15-093, MS16-129, MS16-132, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité disponibles pour toutes les vulnérabilités répertoriées, en appliquant les bulletins MS15-093, MS16-129, MS16-132 et le correctif MSRC correspondant à CVE-2017-8543. *Ces failles sont présentes dans le catalogue KEV et leur exploitation a été confirmée. Leur correction élimine le vecteur d'attaque le plus critique.*
- Activer le pare-feu local et restreindre les communications entrantes au strict nécessaire, en bloquant tout trafic non autorisé depuis le réseau interne vers le poste. *Les vulnérabilités sont exploitables depuis le réseau interne ; limiter les flux réduit la surface d'attaque.*

*Priorité court terme*

- Mettre en place une authentification forte (MFA) pour les comptes utilisateurs locaux et les services d’accès distant. *Renforcer la protection des identifiants empêche la compromission même si une faille est exploitée.*

*Priorité moyen terme*

- Déployer une solution de sauvegarde automatisée et régulièrement testée des documents bureautiques et des courriels. *En cas d’infection ou de perte de données, des sauvegardes récentes permettent une restauration rapide et limitent l’impact.*
- Installer un agent de détection d’intrusion ou de surveillance des processus et des connexions réseau sur le poste, avec alertes en temps réel. *Une visibilité accrue permet de détecter rapidement toute tentative d’exploitation des vulnérabilités restantes.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.51 : Poste de travail (Moyen, score 27.4)

La machine exécute Ubuntu 12.04 et Firefox 31.0 ; plusieurs failles critiques déjà exploitées (Bash, OpenSSL, Firefox PDF) sont présentes.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-0160, CVE-2014-3153. Bulletins de sécurité correspondants : USN-2165-1, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1.
- (court terme) Remplacer Ubuntu 12.04 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles pour les failles connues (USN‑2165‑1, USN‑2237‑1, USN‑2240‑1, USN‑2362‑1, USN‑2363‑1, USN‑2363‑2, USN‑2707‑1). *Ces correctifs corrigent les vulnérabilités déjà exploitées par des attaquants et réduisent immédiatement le risque.*
- Mettre à jour Bash ou désactiver les fonctions dangereuses (ex. désactiver le traitement des variables d’environnement non fiables) afin de neutraliser les vecteurs d’exploitation de CVE‑2014‑6271 et CVE‑2014‑7169. *Ces vulnérabilités permettent l’exécution de code à distance via des variables d’environnement ; les corriger ou les désactiver empêche leur exploitation.*

*Priorité court terme*

- Remplacer Ubuntu 12.04 par une version d’Ubuntu maintenue et à jour. *Le support d’Ubuntu 12.04 s’est terminé le 28 avril 2017 ; aucune mise à jour ne sera fournie après cette date, laissant la machine exposée aux nouvelles vulnérabilités.*

*Priorité moyen terme*

- Segmenter le réseau interne et restreindre les communications vers le poste de travail à l’aide de VLAN ou d’ACL, en limitant l’accès uniquement aux services légitimes. *Les failles sont exploitables depuis le réseau interne ; la segmentation réduit la surface d’attaque et empêche la propagation d’un compromis.*
- Déployer une surveillance continue des journaux système et des alertes sur les comportements suspects liés à Bash et au lecteur PDF de Firefox, et mettre en place des sauvegardes régulières des données utilisateur. *Une détection précoce permet d’intervenir rapidement en cas d’exploitation ; les sauvegardes assurent la continuité des activités en cas de compromission.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.19 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Ubuntu 14.04 et Firefox 31.0 présente plusieurs failles déjà exploitées (KEV) accessibles depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles pour les vulnérabilités observées (CVE‑2014‑6271, CVE‑2014‑7169, CVE‑2015‑4495, CVE‑2014‑3153, CVE‑2016‑5195) en installant les bulletins USN‑2362‑1, USN‑2363‑1, USN‑2363‑2, USN‑2707‑1, USN‑2237‑1, USN‑2240‑1, USN‑3104‑1, USN‑3104‑2, USN‑3105‑1, USN‑3105‑2. *Ces failles sont répertoriées dans le catalogue CISA KEV et ont été exploitées. Leur correction élimine le vecteur d’attaque connu.*

*Priorité court terme*

- Restreindre l’accès réseau au poste de travail : bloquer les connexions entrantes non nécessaires, désactiver les fonctions SSH ForceCommand et limiter les services exposés au réseau interne. *Les vulnérabilités Bash (CVE‑2014‑6271, CVE‑2014‑7169) sont exploitables depuis le réseau interne via des variables d’environnement manipulées.*
- Durcir la configuration de Bash : désactiver le traitement des variables d’environnement dangereuses (e.g., env_reset), appliquer les recommandations de sécurité du projet Bash et supprimer les scripts inutiles. *Réduire la surface d’attaque liée aux fonctions de traitement des chaînes de caractères dans Bash limite les possibilités d’exploitation même si un vecteur réseau persiste.*

*Priorité moyen terme*

- Planifier la migration vers une version d’Ubuntu maintenue avant la fin du support (30 avril 2019) afin de bénéficier de correctifs futurs et d’un cycle de mise à jour plus rapide. *Le système actuel accumule plusieurs vulnérabilités critiques ; une version maintenue simplifiera la gestion des correctifs à long terme.*
- Mettre en place une procédure de sauvegarde quotidienne des fichiers utilisateurs et des documents internes, avec vérification périodique de la restauration. *En cas d’exploitation réussie, les sauvegardes permettent de restaurer rapidement les données critiques et de limiter l’impact opérationnel.*
- Déployer un système de détection d’intrusion hôte (HIDS) et activer la journalisation détaillée des activités système et réseau, en alertant le SOC en cas d’anomalies liées aux CVE connues. *Une surveillance continue permet de détecter rapidement toute tentative d’exploitation des vulnérabilités restantes ou de nouvelles attaques.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.17 : Poste de travail (Moyen, score 27.4)

Poste de travail sous Ubuntu 14.04 et Firefox 31.0, contenant plusieurs vulnérabilités critiques déjà exploitées (Bash, kernel Linux, lecteur PDF de Firefox).

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer tous les correctifs de sécurité disponibles pour les vulnérabilités identifiées. *Les correctifs corrigent les failles déjà exploitées (KEV) et réduisent immédiatement le risque d'attaque.*

*Priorité court terme*

- Segmenter le réseau interne et appliquer des règles de pare‑feu pour limiter les communications vers le poste de travail uniquement aux services nécessaires. *Les vulnérabilités Bash (CVE‑2014‑6271, CVE‑2014‑7169) sont exploitables depuis le réseau interne ; la segmentation réduit la surface d’exposition.*
- Mettre à niveau le système d’exploitation vers une version Ubuntu maintenue et mettre à jour Firefox vers une version récente. *Une version maintenue reçoit régulièrement des correctifs de sécurité ; la mise à jour du navigateur élimine la vulnérabilité PDF (CVE‑2015‑4495).*

*Priorité moyen terme*

- Renforcer l’authentification en activant l’authentification à facteurs multiples pour tout accès distant (SSH) et appliquer des politiques de mots de passe forts. *Réduit le risque d’accès non autorisé qui pourrait être combiné avec les vulnérabilités locales.*
- Déployer une solution de détection et de réponse sur les points de terminaison (EDR) et centraliser la journalisation des événements système. *Permet de détecter rapidement toute tentative d’exploitation des vulnérabilités résiduelles et d’y répondre.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.12 : Poste de travail (Moyen, score 17.0)

Le poste de travail sous Ubuntu 16.04 présente plusieurs failles critiques, dont une déjà exploitée (Dirty COW) et d'autres exploitables depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. Bulletins de sécurité correspondants : USN-3012-1, USN-4246-1, USN-4292-1.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles pour la faille déjà exploitée (CVE-2016-5195) en installant les bulletins USN-3104-1, USN-3104-2, USN-3105-1 et USN-3105-2. *Cette vulnérabilité est répertoriée dans le catalogue KEV et a été exploitée en pratique. Corriger immédiatement réduit le risque d'élévation de privilèges locale.*

*Priorité court terme*

- Installer les correctifs pour les autres failles graves (CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843) en appliquant les bulletins USN-3012-1, USN-4246-1 et USN-4292-1. *Ces vulnérabilités ont un score CVSS élevé et sont exploitables depuis le réseau interne. Les corriger limite les vecteurs d'attaque externes et internes.*

*Priorité moyen terme*

- Renforcer la segmentation du réseau interne en plaçant les postes de travail sur un VLAN séparé et en limitant les communications vers les serveurs critiques. *La plupart des failles sont exploitables depuis le réseau interne. Une segmentation réduit la portée d'une compromission éventuelle.*
- Mettre en place une surveillance continue des journaux système et réseau, avec alertes sur les tentatives d'accès aux services vulnérables et sur les comportements anormaux. *Détecter rapidement une exploitation ou une tentative d'exploitation permet une réponse immédiate et limite les dommages.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.25 : Poste de travail (Faible, score 13.7)

Niveau de risque Faible (score 13.7). Pire faille : CVE-2014-6271 (Mac OS X 10.5.8), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-4404, CVE-2015-1130. Bulletins de sécurité correspondants : Apple HT204659, Apple HT6441, Apple HT6442, Apple HT6495, Apple HT6535. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2010-1119. Bulletins de sécurité correspondants : Apple HT4196, Apple HT4220, Apple HT4225. *Failles graves, sans exploitation prouvée à ce jour.*
- Remplacer Mac OS X 10.5.8 par une version maintenue. *Plus aucun correctif de sécurité depuis le 2011-06 : les failles découvertes après cette date ne seront jamais corrigées.*

*Plan rédigé par : règles.*

### 192.168.10.16 : Poste de travail (Faible, score 11.3)

Niveau de risque Faible (score 11.3). Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. Bulletins de sécurité correspondants : USN-3012-1, USN-4246-1, USN-4292-1. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.1 : Équipement réseau (pare-feu, routeur) (Inconnu, score 0.0)

Le dispositif réseau ne possède aucun logiciel identifié, ce qui empêche d'évaluer ses vulnérabilités. Un inventaire complet et des mesures de durcissement sont nécessaires.

**Constats établis par les règles**

- (court terme) Compléter l'inventaire : système, logiciels et versions installés.

**Plan d'action détaillé**

*Priorité immédiate*

- Activer la journalisation détaillée du pare‑feu et du service DNS, puis centraliser les logs dans un serveur sécurisé. *Des logs complets permettent de détecter rapidement toute activité suspecte ou tentative d’exploitation.*
- Restreindre l’accès au service DNS aux seules adresses IP internes autorisées via des listes de contrôle d’accès (ACL). *Limiter l’accès empêche les requêtes non autorisées depuis l’extérieur et réduit la surface d’attaque.*

*Priorité court terme*

- Compléter l’inventaire du système, des logiciels installés et de leurs versions. *Sans inventaire, il est impossible d’identifier les failles potentielles et d’appliquer les correctifs appropriés.*

*Priorité moyen terme*

- Mettre en place une segmentation réseau pour isoler le dispositif DNS du reste de l’infrastructure. *La segmentation limite l’impact d’une éventuelle compromission du service DNS sur les autres systèmes.*
- Établir des sauvegardes régulières de la configuration du pare‑feu/routeur et tester les procédures de restauration. *Des sauvegardes fiables assurent une reprise rapide en cas de perte ou de corruption de la configuration.*

*Plan rédigé par : règles + LLM.*

## Inventaire et observations

- Machines sans logiciel connu : 192.168.10.1.
- Balayages de ports observés : 12, depuis 172.16.0.1, 192.168.10.8.
