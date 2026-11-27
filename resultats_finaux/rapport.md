# Rapport de recommandations

Généré le 2026-11-27 par la chaîne d'agents, à partir du trafic de CICIDS2017 du 2017-07-06. Ce rapport a été produit avec l'aide d'une IA générative.

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
- **192.168.10.51** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-0160, CVE-2014-3153. Bulletins de sécurité correspondants : Apple HT6495, Apple HT6535, USN-2165-1, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1.
- **192.168.10.19** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : Apple HT6495, Apple HT6535, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- **192.168.10.17** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : Apple HT6495, Apple HT6535, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
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

Le contrôleur de domaine Windows Server 2016 présente plusieurs failles critiques déjà exploitées (KEV) et expose des services internes sensibles.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143. Bulletins de sécurité correspondants : MS16-129, MS16-132, MS17-010, MSRC CVE-2017-0143, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité correspondant aux bulletins MS16-129, MS16-132, MS17-010 et MSRC CVE-2017-8543. *Ces correctifs corrigent les vulnérabilités déjà exploitées par des attaquants et réduisent le risque d’escalade depuis le réseau interne.*
- Restreindre le trafic réseau vers le contrôleur de domaine en ne laissant passer que les ports nécessaires (53, 88, 135, 389, 445, 3268) depuis les sous‑réseaux autorisés. *Les failles sont exploitables depuis le réseau interne ; limiter l’accès diminue la surface d’attaque.*

*Priorité court terme*

- Activer l’authentification forte (MFA) pour tous les comptes administratifs et désactiver les comptes inutilisés ou inactifs. *Renforcer la protection des identités stockées sur le serveur contre le vol de mots de passe hachés.*
- Mettre en place une journalisation détaillée et une alerte en temps réel sur les connexions SMB, LDAP et Kerberos. *Détecter rapidement toute tentative d’exploitation des services exposés.*

*Priorité moyen terme*

- Établir des sauvegardes complètes et hors ligne de l’annuaire Active Directory, avec des tests de restauration périodiques. *Assurer la continuité de l’activité et la récupération des données d’identité en cas de compromission.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.8 : Poste de travail (Critique, score 27.4)

La machine Windows Vista SP2 montre des signes de compromission et possède plusieurs failles critiques déjà exploitées dans le monde.

**Constats établis par les règles**

- (immédiate) Isoler la machine du réseau, conserver ses journaux pour l'analyse, la réinstaller, puis changer les mots de passe des comptes utilisés dessus.
- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792. Bulletins de sécurité correspondants : MS10-002, MS11-087, MS12-034, MS12-039, MS12-043, MS13-008, MS14-021.
- (court terme) Remplacer Windows Vista SP2 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Isoler la machine du réseau, conserver les journaux pour l'analyse, la réinstaller complètement puis changer les mots de passe des comptes locaux. *Compromission probable détectée : balayage de 11 machines et présence d'outils d'attaque dans le trafic.*
- Appliquer les correctifs de sécurité qui corrigent les failles exploitées (CVE‑2014‑1776, CVE‑2010‑0249, CVE‑2011‑3402, CVE‑2012‑1889, CVE‑2012‑4792) en suivant les bulletins MS10‑002, MS11‑087, MS12‑034, MS12‑039, MS12‑043, MS13‑008, MS14‑021. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et ont été exploitées en pratique.*
- Installer les correctifs disponibles listés dans les bulletins de sécurité (MS10‑002, MS11‑087, MS12‑034, MS12‑039, MS12‑043, MS13‑008, MS14‑021) afin de couvrir l’ensemble des failles connues. *Les correctifs disponibles corrigent les vulnérabilités déjà exploitées et réduisent le risque d’une nouvelle compromission.*

*Priorité court terme*

- Remplacer Windows Vista SP2 par une version maintenue du système d’exploitation. *Le support de Windows Vista SP2 a pris fin le 11 avril 2017, aucune mise à jour de sécurité n’est plus fournie depuis cette date.*

*Priorité moyen terme*

- Mettre en place une authentification forte pour les comptes locaux, segmenter le réseau interne pour limiter l’accès depuis les postes de travail, déployer une surveillance du trafic et instaurer des sauvegardes régulières des données utilisateurs. *Ces mesures renforcent la défense en profondeur et limitent l’impact d’éventuelles futures compromissions.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.50 : Serveur web (Élevé, score 35.6)

Le serveur web Ubuntu 16.04 expose Apache, SSH et FTP à Internet et présente plusieurs failles graves, dont une déjà exploitée dans le catalogue KEV.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-8740, CVE-2016-5387, CVE-2016-6515, CVE-2016-4971. Bulletins de sécurité correspondants : Apple HT208221, USN-3012-1, USN-3038-1.
- (immédiate) Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles (USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2) pour corriger la faille CVE-2016-5195. *Cette vulnérabilité est répertoriée dans le catalogue KEV, son exploitation réelle est prouvée.*
- Restreindre l’accès Internet aux services FTP (port 21) et SSH (port 22) en les limitant à un VPN ou à une liste d’adresses autorisées. *Ces services d’administration sont exposés à Internet, ce qui les rend vulnérables aux attaques par force brute.*

*Priorité court terme*

- Mettre à jour Apache vers une version qui corrige les vulnérabilités CVE-2016-8740 et CVE-2016-5387, ou désactiver le module HTTP/2 et retirer les protocoles h2/h2c de la configuration. *Ces failles graves permettent un déni de service ou une redirection du trafic HTTP vers des destinations arbitraires.*
- Mettre à jour OpenSSH vers une version corrigée ou renforcer la configuration : désactiver l’authentification par mot de passe, imposer l’usage de clés SSH, et limiter la longueur des mots de passe. *Les vulnérabilités CVE-2016-6210 et CVE-2016-6515 permettent l’énumération d’utilisateurs et un déni de service par consommation CPU.*

*Priorité moyen terme*

- Instaurer des sauvegardes quotidiennes des pages web et des logs, et déployer une surveillance des connexions HTTP/2 et des tentatives de connexion SSH. *Une sauvegarde régulière assure la restauration rapide en cas d’incident, et la surveillance permet de détecter rapidement toute tentative d’exploitation.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.9 : Poste de travail (Moyen, score 27.4)

Le poste de travail Windows 7 SP1 possède plusieurs vulnérabilités critiques déjà exploitées (KEV) et n’est pas à jour.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889. Bulletins de sécurité correspondants : MS11-087, MS12-034, MS12-039, MS12-043, MS14-021, MS15-034, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité correspondant aux CVE‑2014‑1776, CVE‑2015‑1635, CVE‑2017‑8543, CVE‑2011‑3402 et CVE‑2012‑1889 en appliquant les bulletins MS14‑021, MS15‑034, MSRC CVE‑2017‑8543, MS11‑087, MS12‑034, MS12‑039 et MS12‑043, ainsi que les correctifs disponibles listés (MS17‑010, MS14‑058, MS14‑064, MS15‑065, MS16‑039, MS11‑087, MS12‑024, MS12‑034). *Ces failles sont répertoriées dans le catalogue KEV ; leur exploitation a été observée. Les correctifs éliminent la vulnérabilité.*

*Priorité court terme*

- Activer l’authentification forte (MFA) pour les comptes locaux et les accès aux services réseau depuis ce poste. *Réduit le risque de compromission d’identifiants, surtout si une vulnérabilité était exploitée.*
- Isoler le poste sur un VLAN dédié et restreindre les flux réseau entrants depuis le réseau interne aux seuls services nécessaires. *Limite la surface d’attaque et empêche un attaquant interne d’exploiter les failles depuis le réseau.*

*Priorité moyen terme*

- Déployer une solution de détection et de réponse sur les points d’extrémité (EDR) et configurer une surveillance continue des tentatives d’exploitation des services Internet Explorer, HTTP.sys et du moteur de rendu de police. *Permet de détecter rapidement toute tentative d’exploitation des vulnérabilités connues.*
- Mettre en place des sauvegardes régulières et hors ligne des documents utilisateurs, courriels et données de travail stockées sur le poste. *Assure la disponibilité des données en cas d’incident ou de compromission du système.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.5 : Poste de travail (Moyen, score 27.4)

Poste de travail sous Windows 8.1 contenant plusieurs vulnérabilités très critiques déjà exploitées (KEV) et exposées depuis le réseau interne, ce qui place la machine à risque moyen.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543. Bulletins de sécurité correspondants : MS14-021, MS15-034, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité correspondant aux CVE‑2014‑1776, CVE‑2015‑0311, CVE‑2015‑0313, CVE‑2015‑1635 et CVE‑2017‑8543 en appliquant les bulletins MS14‑021, MS15‑034 et MSRC CVE‑2017‑8543. *Ces failles sont répertoriées dans le catalogue KEV et leur exploitation a été observée. Leur correction élimine la vulnérabilité la plus dangereuse.*
- Appliquer l’ensemble des correctifs de sécurité disponibles listés (MS17‑010, MS14‑058, MS14‑064, MS15‑065, MS16‑039, MS13‑080, MS13‑090, MS13‑098). *Ces bulletins corrigent d’autres vulnérabilités déjà exploitées dans le monde et renforcent la posture de la machine.*

*Priorité court terme*

- Activer et configurer le pare‑feu Windows pour bloquer tout trafic entrant non nécessaire depuis le réseau interne. *Les vulnérabilités sont exploitables depuis le réseau interne ; limiter les ports ouverts réduit la surface d’attaque.*
- Déployer une solution de protection des points de terminaison avec détection comportementale et activer les mises à jour automatiques pour le système d’exploitation, le navigateur Firefox et Java. *Une protection en temps réel détecte les tentatives d’exploitation et les mises à jour régulières préviennent l’apparition de nouvelles failles.*

*Priorité moyen terme*

- Mettre en place une authentification forte (ex. MFA) pour les sessions locales et les accès distants, et appliquer la politique de mots de passe robustes. *Renforcer l’authentification limite les mouvements latéraux après une éventuelle compromission.*
- Instaurer des sauvegardes quotidiennes des documents utilisateurs et des courriels, stockées hors ligne et testées régulièrement. *En cas d’incident, les sauvegardes permettent de restaurer rapidement les données critiques.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.14 : Poste de travail (Moyen, score 27.4)

Le poste de travail Windows 10 expose plusieurs failles déjà exploitées (CVE‑2017‑8543, CVE‑2015‑2502, CVE‑2016‑7200, CVE‑2016‑7201, CVE‑2016‑7256) accessibles depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256. Bulletins de sécurité correspondants : MS15-093, MS16-129, MS16-132, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité correspondant aux failles exploitées : appliquer les bulletins MS15‑093, MS16‑129, MS16‑132 et le correctif MSRC CVE‑2017‑8543. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et leur exploitation a été observée. Les correctifs éliminent la possibilité d’exploitation.*

*Priorité court terme*

- Activer le pare‑feu Windows et restreindre les connexions entrantes depuis le réseau interne aux services strictement nécessaires. *Toutes les failles listées sont exploitables depuis le réseau interne ; limiter les ports ouverts réduit la surface d’attaque.*
- Mettre en place une authentification forte (MFA) pour les comptes locaux et les accès distants au poste de travail. *Renforcer la vérification d’identité limite les risques de compromission par vol de mots de passe ou exploitation de vulnérabilités côté client.*

*Priorité moyen terme*

- Déployer une solution de détection et de réponse sur les points d’extrémité (EDR) et activer la journalisation détaillée des processus et des connexions réseau. *Une visibilité continue permet de détecter rapidement toute tentative d’exploitation des vulnérabilités connues et d’y répondre.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.15 : Poste de travail (Moyen, score 27.4)

Le poste de travail Windows 10 expose plusieurs vulnérabilités critiques déjà exploitées (CVE‑2017‑8543, CVE‑2015‑2502, etc.) et présente un risque moyen.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2015-2502, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256. Bulletins de sécurité correspondants : MS15-093, MS16-129, MS16-132, MSRC CVE-2017-8543.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité correspondant aux vulnérabilités exploitées : appliquer les bulletins MSRC CVE‑2017‑8543, MS15‑093, MS16‑129, MS16‑132 et les autres correctifs disponibles. *Ces failles sont répertoriées dans le catalogue KEV et leur exploitation a été confirmée. Leur correction élimine la possibilité d’exploitation depuis le réseau interne.*
- Activer l’authentification forte (MFA) pour tous les comptes utilisateurs du poste de travail. *Renforce la protection des identifiants même si une vulnérabilité était exploitée, limitant l’accès non autorisé.*

*Priorité court terme*

- Isoler le poste de travail du reste du réseau interne via segmentation VLAN ou règles de pare‑feu, en limitant les communications entrantes non nécessaires. *Réduit la surface d’attaque et empêche un attaquant qui aurait compromis un autre système d’atteindre directement ce poste.*

*Priorité moyen terme*

- Déployer une solution EDR ou un système de détection d’intrusion capable de surveiller les tentatives d’exploitation des CVE critiques. *Permet de détecter rapidement toute tentative d’exploitation des vulnérabilités connues et d’intervenir avant compromission.*
- Mettre en place des sauvegardes régulières et hors ligne des documents bureautiques et courriels, avec des tests de restauration périodiques. *Assure la disponibilité des données en cas d’incident ou de compromission du poste.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.51 : Poste de travail (Moyen, score 27.4)

Le poste de travail exécute Ubuntu 12.04 et Firefox 31.0, avec plusieurs failles critiques déjà exploitées (KEV) et dont le support d'Ubuntu a pris fin le 28‑04‑2017.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-0160, CVE-2014-3153. Bulletins de sécurité correspondants : Apple HT6495, Apple HT6535, USN-2165-1, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1.
- (court terme) Remplacer Ubuntu 12.04 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles (Apple HT6495, Apple HT6535, USN‑2165‑1, USN‑2237‑1, USN‑2240‑1, USN‑2362‑1, USN‑2363‑1, USN‑2363‑2, USN‑2707‑1) afin de corriger les CVE‑2014‑6271, CVE‑2014‑7169, CVE‑2015‑4495, CVE‑2014‑0160 et CVE‑2014‑3153. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et leur exploitation a été observée. Les correctifs éliminent les vecteurs d'attaque connus.*

*Priorité court terme*

- Remplacer Ubuntu 12.04 par une version maintenue du système d'exploitation. *Le support d'Ubuntu 12.04 s'est terminé le 28‑04‑2017, aucune mise à jour de sécurité n'est plus fournie, ce qui laisse la machine exposée aux nouvelles vulnérabilités.*

*Priorité moyen terme*

- Durcir la configuration du shell Bash en désactivant les fonctions d'importation d'environnement non nécessaires et en limitant l'usage de ForceCommand dans OpenSSH. *CVE‑2014‑6271 et CVE‑2014‑7169 exploitent la façon dont Bash traite les variables d'environnement. Restreindre ces mécanismes réduit le risque d'exécution de code via des variables manipulées.*
- Segmenter le réseau interne en isolant les postes de travail des services critiques et mettre en place une surveillance du trafic interne pour détecter les tentatives d'exploitation de Bash et de Firefox. *Les failles sont exploitables depuis le réseau interne. La segmentation limite la portée d'une compromission et la surveillance permet de repérer rapidement des comportements suspects.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.19 : Poste de travail (Moyen, score 27.4)

Le poste de travail sous Ubuntu 14.04 et Firefox 31.0 présente plusieurs failles déjà exploitées (CVE‑2014‑6271, CVE‑2014‑7169, CVE‑2015‑4495, CVE‑2014‑3153, CVE‑2016‑5195) accessibles depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : Apple HT6495, Apple HT6535, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité disponibles pour les failles identifiées en appliquant les bulletins de sécurité correspondants. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et leur exploitation a été confirmée. Les correctifs éliminent les vecteurs d’attaque connus.*

*Priorité court terme*

- Restreindre l’accès réseau au poste de travail en activant le pare‑feu local et en limitant les communications aux services strictement nécessaires. *Les failles peuvent être exploitées depuis le réseau interne ; réduire la surface d’exposition diminue le risque d’exploitation.*
- Durcir la configuration de Bash et du serveur SSH : désactiver les options dangereuses (ex. ForceCommand), nettoyer les variables d’environnement et appliquer les profils AppArmor recommandés. *CVE‑2014‑6271 et CVE‑2014‑7169 exploitent la manipulation d’environnements Bash. Une configuration stricte empêche ces vecteurs.*

*Priorité moyen terme*

- Planifier la migration vers une version d’Ubuntu maintenue avant la fin du support prévue en 2019‑04‑30. *Une version maintenue recevra des correctifs futurs, garantissant une protection continue contre de nouvelles vulnérabilités.*
- Mettre en place des sauvegardes quotidiennes chiffrées des données utilisateurs et configurer une surveillance continue des journaux (IDS/IPS, alertes de connexion anormale). *En cas d’exploitation, les sauvegardes permettent une restauration rapide et la surveillance aide à détecter rapidement toute activité suspecte.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.17 : Poste de travail (Moyen, score 27.4)

Poste de travail sous Ubuntu 14.04 et Firefox 31.0, contenant plusieurs vulnérabilités KEV exploitées depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2015-4495, CVE-2014-3153, CVE-2016-5195. Bulletins de sécurité correspondants : Apple HT6495, Apple HT6535, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les correctifs de sécurité disponibles (Apple HT6495, Apple HT6535, USN-2237-1, USN-2240-1, USN-2362-1, USN-2363-1, USN-2363-2, USN-2707-1, USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2) afin de corriger les vulnérabilités exploitées. *Ces correctifs éliminent les failles déjà observées dans le catalogue KEV, réduisant le risque d'exécution de code ou d'élévation de privilèges.*

*Priorité court terme*

- Mettre à jour le navigateur Firefox vers une version maintenue qui corrige la vulnérabilité du lecteur PDF (CVE-2015-4495). *Cette mise à jour empêche le contournement de la Same Origin Policy et la lecture de fichiers arbitraires depuis le navigateur.*
- Planifier la migration du système d'exploitation vers une version d'Ubuntu toujours maintenue (ex. 16.04 LTS ou supérieure). *Ubuntu 14.04 approche de sa fin de support (30 avril 2019). Une version maintenue recevra des correctifs de sécurité continus.*

*Priorité moyen terme*

- Segmenter le réseau interne et restreindre les flux vers le poste de travail à l'aide de règles de pare‑feu, limitant ainsi l'accès depuis d'autres machines. *Les vulnérabilités Bash sont exploitables depuis le réseau interne ; la segmentation réduit la surface d'attaque.*
- Renforcer l'authentification locale et distante (exigence de mots de passe forts, utilisation de clés SSH protégées par phrase de passe, mise en place de MFA pour les comptes administratifs). *Une authentification robuste limite les possibilités d'accès non autorisé, notamment pour les failles nécessitant un accès local.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.12 : Poste de travail (Moyen, score 17.0)

Le poste de travail sous Ubuntu 16.04 présente plusieurs vulnérabilités graves, dont une déjà exploitée (Dirty COW) et d’autres exploitables depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. Bulletins de sécurité correspondants : USN-3104-1, USN-3104-2, USN-3105-1, USN-3105-2.
- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. Bulletins de sécurité correspondants : Apple HT208112, Apple HT208113, Apple HT208115, Apple HT208144, USN-3012-1.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité qui corrigent la vulnérabilité Dirty COW (CVE-2016-5195) en appliquant les bulletins USN-3104-1, USN-3104-2, USN-3105-1 et USN-3105-2. *Cette faille est répertoriée dans le catalogue KEV et a déjà été exploitée dans le monde. La corriger immédiatement empêche une élévation de privilèges locale.*
- Mettre à jour les paquets affectés par les vulnérabilités CVE-2016-4971, CVE-2016-7117, CVE-2016-9841 et CVE-2016-9843 en appliquant les bulletins USN-3012-1 et les bulletins Apple HT208112, HT208113, HT208115, HT208144. *Ces failles ont un score CVSS ≥ 7 et sont exploitables depuis le réseau interne. Les correctifs disponibles réduisent le risque d’exécution de code ou d’impact non spécifié.*

*Priorité court terme*

- Segmenter le réseau interne afin d’isoler le poste de travail des autres machines et limiter l’accès au réseau interne uniquement aux services nécessaires. *La plupart des vulnérabilités observées sont exploitables depuis le réseau interne. Une segmentation réduit la surface d’attaque.*

*Priorité moyen terme*

- Renforcer l’authentification locale : activer le verrouillage automatique, exiger des mots de passe forts et, si possible, ajouter une authentification à deux facteurs pour les accès sudo. *Une élévation de privilèges locale (Dirty COW) nécessite déjà un accès à la machine ; renforcer l’authentification limite la possibilité d’obtenir cet accès.*
- Mettre en place des sauvegardes régulières des données utilisateur et vérifier périodiquement la restauration. *En cas d’exploitation réussie, des sauvegardes récentes permettent de restaurer les données sans perte majeure.*

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

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. Bulletins de sécurité correspondants : Apple HT208112, Apple HT208113, Apple HT208115, Apple HT208144, USN-3012-1. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.1 : Équipement réseau (pare-feu, routeur) (Inconnu, score 0.0)

Le pare-feu/routeur interne possède uniquement le port DNS ouvert, mais aucune information sur les logiciels installés, ce qui empêche d'évaluer les vulnérabilités.

**Constats établis par les règles**

- (court terme) Compléter l'inventaire : système, logiciels et versions installés.

**Plan d'action détaillé**

*Priorité immédiate*

- Compléter l'inventaire du système, des logiciels et de leurs versions. *Sans inventaire, il est impossible de savoir quelles failles peuvent affecter la machine.*
- Activer la journalisation détaillée du trafic DNS et des accès d'administration, puis centraliser les logs dans un serveur de SIEM. *Permet de détecter rapidement des comportements anormaux ou des tentatives d'exploitation.*

*Priorité court terme*

- Restreindre l'accès à l'interface de gestion du pare-feu aux adresses IP internes autorisées et exiger une authentification forte (MFA). *Réduit le risque d'accès non autorisé depuis le réseau ou Internet.*

*Priorité moyen terme*

- Segmenter le réseau en isolant le service DNS du reste de l'infrastructure à l'aide de VLANs ou de listes de contrôle d'accès. *Limite la portée d'une éventuelle compromission du service DNS.*

*Plan rédigé par : règles + LLM.*

## Inventaire et observations

- Machines sans logiciel connu : 192.168.10.1.
- Balayages de ports observés : 12, depuis 172.16.0.1, 192.168.10.8.
