# Rapport de recommandations

Généré le 2026-11-26 par la chaîne d'agents, à partir du trafic de CICIDS2017 du 2017-07-06. Ce rapport a été produit avec l'aide d'une IA générative.

## Résumé

14 actifs analysés : 2 critique, 1 élevé, 3 moyen, 6 faible, 2 inconnu.

**Incident en cours :** 192.168.10.8 balaie le réseau interne et est probablement compromise. Elle doit être isolée immédiatement.

## Classement des risques

| Rang | Actif | Rôle | Score | Niveau | Raison principale |
| --- | --- | --- | --- | --- | --- |
| 1 | 192.168.10.3 | Contrôleur de domaine | 68.6 | Critique | Pire faille : CVE-2017-8543 (Windows Server 2016), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 2 | 192.168.10.8 | Poste de travail | 27.4 | Critique | Compromission probable : cette machine a balayé 11 autres machines du réseau. |
| 3 | 192.168.10.50 | Serveur web | 47.4 | Élevé | Pire faille : CVE-2016-8740 (Apache 2.4.18), CVSS 7.5, EPSS 0.7907, exploitable depuis Internet. |
| 4 | 192.168.10.19 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-6271 (Ubuntu 14.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 5 | 192.168.10.17 | Poste de travail | 27.4 | Moyen | Pire faille : CVE-2014-6271 (Ubuntu 14.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 6 | 192.168.10.15 | Poste de travail | 24.6 | Moyen | Pire faille : CVE-2015-2426 (Windows 10), CVSS 8.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 7 | 192.168.10.9 | Poste de travail | 13.7 | Faible | Pire faille : CVE-2014-1776 (Windows 7 SP1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 8 | 192.168.10.5 | Poste de travail | 13.7 | Faible | Pire faille : CVE-2014-1776 (Windows 8.1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 9 | 192.168.10.51 | Poste de travail | 13.7 | Faible | Pire faille : CVE-2014-6271 (Ubuntu 12.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 10 | 192.168.10.14 | Poste de travail | 12.3 | Faible | Pire faille : CVE-2015-2426 (Windows 10), CVSS 8.8, exploitation prouvée (KEV), exploitable depuis le réseau interne. |
| 11 | 192.168.10.16 | Poste de travail | 5.7 | Faible | Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne. |
| 12 | 192.168.10.12 | Poste de travail | 5.7 | Faible | Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne. |
| 13 | 192.168.10.1 | Équipement réseau (pare-feu, routeur) | 0.0 | Inconnu | Aucun logiciel connu : impossible d'évaluer ses failles. Compléter l'inventaire. |
| 14 | 192.168.10.25 | Poste de travail | 0.0 | Inconnu | Aucun logiciel connu : impossible d'évaluer ses failles. Compléter l'inventaire. |

## Actions immédiates, toutes machines confondues

- **192.168.10.3** (Contrôleur de domaine) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143.
- **192.168.10.8** (Poste de travail) : Isoler la machine du réseau, conserver ses journaux pour l'analyse, la réinstaller, puis changer les mots de passe des comptes utilisés dessus.
- **192.168.10.8** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792.
- **192.168.10.50** (Serveur web) : Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.
- **192.168.10.19** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-3153, CVE-2016-5195, CVE-2014-0196.
- **192.168.10.17** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-3153, CVE-2016-5195, CVE-2014-0196.
- **192.168.10.15** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-2426, CVE-2015-1769.
- **192.168.10.9** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889.
- **192.168.10.5** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543.
- **192.168.10.51** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-0160, CVE-2014-3153, CVE-2016-5195.
- **192.168.10.14** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-2426, CVE-2015-1769.
- **192.168.10.16** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195.
- **192.168.10.12** (Poste de travail) : Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195.

## Plan d'action par actif

### 192.168.10.3 : Contrôleur de domaine (Critique, score 68.6)

Contrôleur de domaine Windows Server 2016 avec plusieurs vulnérabilités critiques exploitées en interne, risque élevé.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées : CVE-2017-8543, CVE-2016-7200, CVE-2016-7201, CVE-2016-7256, CVE-2017-0143. *Ces vulnérabilités sont répertoriées dans le catalogue KEV de CISA, leur exploitation est prouvée. La mise à jour élimine le vecteur d'attaque le plus dangereux.*
- Désactiver le protocole SMBv1 et désactiver les partages non nécessaires sur le serveur. *SMBv1 est la cible de CVE-2017-0143 et d’autres attaques. Le désactiver réduit immédiatement la surface d’attaque.*

*Priorité court terme*

- Mettre en place une authentification forte (MFA) pour tous les comptes administratifs du domaine. *Même si une faille est exploitée, la MFA empêche l’escalade de privilèges et protège les comptes critiques.*
- Segmenter le réseau en isolant le contrôleur de domaine du reste du réseau interne et limiter les ports exposés (53, 88, 135, 389, 445, 3268) aux flux strictement nécessaires. *Réduire la portée d’un attaquant qui aurait compromis un autre système interne. La segmentation empêche la propagation latérale.*

*Priorité moyen terme*

- Déployer une solution de sauvegarde quotidienne hors site et tester régulièrement la restauration des données d’annuaire. *En cas de compromission ou de ransomware, des sauvegardes fiables permettent de restaurer rapidement le contrôleur de domaine et de limiter l’impact.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.8 : Poste de travail (Critique, score 27.4)

Poste de travail sous Windows Vista SP2, compromis et ayant balayé 11 machines. De multiples vulnérabilités critiques (CVE-2014-1776, CVE-2010-0249, etc.) sont exploitées depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Isoler la machine du réseau, conserver ses journaux pour l'analyse, la réinstaller, puis changer les mots de passe des comptes utilisés dessus.
- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792.
- (court terme) Remplacer Windows Vista SP2 par une version maintenue.

**Plan d'action détaillé**

*Priorité immédiate*

- Isoler la machine du réseau, conserver ses journaux pour l'analyse, réinstaller le système et changer les mots de passe des comptes utilisés. *Compromission avérée ; la machine a déjà infecté d’autres postes.*
- Appliquer les correctifs de sécurité pour les vulnérabilités exploitées : CVE-2014-1776, CVE-2010-0249, CVE-2011-3402, CVE-2012-1889, CVE-2012-4792. *Ces failles sont répertoriées dans le catalogue KEV et leur exploitation est prouvée.*

*Priorité court terme*

- Remplacer Windows Vista SP2 par un système d’exploitation maintenu et supporté. *Aucun correctif n’est publié depuis 2017 ; les nouvelles vulnérabilités resteront non corrigées.*
- Mettre en place une authentification forte (MFA) pour les comptes locaux et les accès réseau. *Réduit le risque de vol de mots de passe et de réutilisation après la compromission.*

*Priorité moyen terme*

- Segmenter le réseau en VLAN isolant les postes de travail anciens et limiter le trafic vers les serveurs critiques. *Empêche la propagation d’une infection et restreint l’accès aux ressources sensibles.*
- Déployer une solution EDR/antivirus moderne et configurer la collecte centralisée des logs pour une surveillance continue. *Permet de détecter rapidement toute activité suspecte et d’intervenir avant une escalade.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.50 : Serveur web (Élevé, score 47.4)

Serveur web exposé avec Apache 2.4.18 et OpenSSH 7.2p2, contenant plusieurs vulnérabilités critiques et des services d'administration ouverts sur Internet.

**Constats établis par les règles**

- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-8740, CVE-2016-5387, CVE-2016-6515, CVE-2016-4971.
- (immédiate) Fermer l'accès depuis Internet à FTP (21), SSH (22), ou le limiter à un VPN ou à une liste d'adresses autorisées.

**Plan d'action détaillé**

*Priorité immédiate*

- Bloquer l'accès Internet aux ports FTP (21) et SSH (22) ou les restreindre à un VPN / liste d'adresses autorisées. *Ces services d'administration sont accessibles depuis Internet, ce qui les rend vulnérables aux attaques par force brute et aux exploits connus.*
- Mettre à jour Apache vers une version corrigée ou désactiver le module mod_http2 et limiter la taille des en‑têtes HTTP. *Corrige les vulnérabilités critiques CVE-2016-8740 et CVE-2016-5387 qui permettent l'exécution de code à distance ou le contournement de la sécurité.*

*Priorité court terme*

- Mettre à jour OpenSSH vers une version post‑7.3 et désactiver les algorithmes de hachage faibles. *Élimine les failles CVE-2016-6210 et CVE-2016-6515 qui permettent l'énumération d'utilisateurs et un déni de service par dépassement de longueur de mot de passe.*
- Désactiver ou restreindre l'utilisation de la variable d'environnement HTTP_PROXY dans les scripts CGI et les applications web. *Réduit le risque d'exploitation de CVE-2016-5387 qui expose le serveur à des attaques de type proxy injection.*

*Priorité moyen terme*

- Mettre en place des sauvegardes quotidiennes chiffrées hors site et un système de surveillance des logs avec alertes en temps réel. *Assure la continuité d'activité en cas d'incident et permet de détecter rapidement toute activité suspecte.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.19 : Poste de travail (Moyen, score 27.4)

Poste de travail sous Ubuntu 14.04, exposé à plusieurs failles critiques dont Bash (CVE-2014-6271, CVE-2014-7169) exploitables depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-3153, CVE-2016-5195, CVE-2014-0196.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées : CVE-2014-6271, CVE-2014-7169, CVE-2014-3153, CVE-2016-5195, CVE-2014-0196. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et leur exploitation est prouvée. La mise à jour élimine le vecteur d'attaque le plus critique.*

*Priorité court terme*

- Activer l’authentification forte (MFA) pour les sessions locales et les accès distants (SSH). *Même si un attaquant exploite une faille, il devra encore franchir une seconde barrière d’authentification, réduisant le risque de compromission.*
- Isoler le poste de travail dans un VLAN dédié et appliquer des règles de pare‑feu limitant les communications vers les services internes uniquement nécessaires. *La vulnérabilité Bash est exploitable depuis le réseau interne ; la segmentation empêche la propagation latérale vers d’autres systèmes.*

*Priorité moyen terme*

- Déployer une solution de journalisation centralisée et activer l’audit des appels Bash et des modifications de fichiers système. *Détecter rapidement toute exploitation de Bash ou d’autres vulnérabilités locales permet une réponse immédiate.*
- Mettre en place des sauvegardes quotidiennes chiffrées des documents utilisateurs et des courriels, stockées hors site. *En cas d’exploitation réussie menant à perte ou corruption de données, les sauvegardes garantissent la continuité de l’activité.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.17 : Poste de travail (Moyen, score 27.4)

Poste de travail sous Ubuntu 14.04, exposé à plusieurs vulnérabilités critiques dont la faille Bash (CVE-2014-6271) exploitable depuis le réseau interne.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-3153, CVE-2016-5195, CVE-2014-0196.

**Plan d'action détaillé**

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées : CVE-2014-6271, CVE-2014-7169, CVE-2014-3153, CVE-2016-5195, CVE-2014-0196. *Ces vulnérabilités sont répertoriées dans le catalogue KEV et leur exploitation est prouvée.*
- Planifier et réaliser la migration vers une version d'Ubuntu supportée (ex. 20.04 LTS) afin de bénéficier de correctifs continus. *Ubuntu 14.04 est en fin de vie, aucune mise à jour officielle n'est disponible, ce qui laisse la machine vulnérable.*

*Priorité court terme*

- Mettre en place une authentification forte (MFA) pour les accès locaux et distants au poste de travail. *Réduit le risque d'escalade de privilèges même si un attaquant exploite une vulnérabilité locale.*
- Segmenter le poste de travail sur un VLAN dédié et appliquer des règles de pare‑feu limitant les communications internes uniquement aux services nécessaires. *Limite la portée d'une exploitation depuis le réseau interne, notamment pour les vulnérabilités Bash.*

*Priorité moyen terme*

- Déployer un système de détection d’intrusion hôte (HIDS) et activer la surveillance d’intégrité des fichiers critiques (auditd) pour détecter toute tentative d’exploitation des failles Bash. *Permet une détection précoce d’activités suspectes liées aux CVE-2014-6271 et CVE-2014-7169.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.15 : Poste de travail (Moyen, score 24.6)

Poste Windows 10 avec plusieurs vulnérabilités critiques, dont deux déjà exploitées en interne, ce qui le place à risque moyen.

**Constats établis par les règles**

- (immédiate) Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-2426, CVE-2015-1769.
- (court terme) Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-3236, CVE-2015-2455, CVE-2015-2456.

**Plan d'action détaillé**

*Priorité immédiate*

- Installer les correctifs de sécurité pour CVE-2015-2426 et CVE-2015-1769. *Ces failles sont répertoriées dans le catalogue KEV et ont déjà été exploitées.*
- Activer Windows Defender Exploit Guard et désactiver les services non nécessaires. *Renforce la protection du système contre les attaques de type mémoire et réduit la surface d’attaque.*

*Priorité court terme*

- Appliquer les correctifs pour les vulnérabilités CVE-2016-3236, CVE-2015-2455 et CVE-2015-2456. *Ces failles ont un score CVSS ≥ 7 et sont exploitables depuis le réseau interne.*
- Isoler le poste sur un VLAN dédié et restreindre le trafic réseau entrant via le pare‑feu Windows. *Limite la propagation d’une éventuelle compromission et empêche les attaques depuis le réseau interne.*

*Priorité moyen terme*

- Déployer l’authentification multifacteur pour les connexions locales et les services critiques. *Réduit le risque d’accès non autorisé même si les identifiants sont compromis.*
- Mettre en place des sauvegardes quotidiennes chiffrées et tester la restauration, ainsi qu’une solution EDR pour la surveillance continue. *Assure la disponibilité des données et détecte rapidement toute activité suspecte.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.9 : Poste de travail (Faible, score 13.7)

Niveau de risque Faible (score 13.7). Pire faille : CVE-2014-1776 (Windows 7 SP1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-1635, CVE-2017-8543, CVE-2011-3402, CVE-2012-1889. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Plan rédigé par : règles.*

### 192.168.10.5 : Poste de travail (Faible, score 13.7)

Niveau de risque Faible (score 13.7). Pire faille : CVE-2014-1776 (Windows 8.1), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-1776, CVE-2015-0311, CVE-2015-0313, CVE-2015-1635, CVE-2017-8543. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Plan rédigé par : règles.*

### 192.168.10.51 : Poste de travail (Faible, score 13.7)

Niveau de risque Faible (score 13.7). Pire faille : CVE-2014-6271 (Ubuntu 12.04), CVSS 9.8, exploitation prouvée (KEV), exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2014-6271, CVE-2014-7169, CVE-2014-0160, CVE-2014-3153, CVE-2016-5195. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Remplacer Ubuntu 12.04 par une version maintenue. *Plus aucun correctif de sécurité depuis le 2017-04-28 : les failles découvertes après cette date ne seront jamais corrigées.*

*Plan rédigé par : règles.*

### 192.168.10.14 : Poste de travail (Faible, score 12.3)

Niveau de risque Faible (score 12.3). Pire faille : CVE-2015-2426 (Windows 10), CVSS 8.8, exploitation prouvée (KEV), exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2015-2426, CVE-2015-1769. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-3236, CVE-2015-2455, CVE-2015-2456. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.16 : Poste de travail (Faible, score 5.7)

Niveau de risque Faible (score 5.7). Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.12 : Poste de travail (Faible, score 5.7)

Niveau de risque Faible (score 5.7). Pire faille : CVE-2016-4971 (Ubuntu 16.04), CVSS 8.8, EPSS 0.4606, exploitable depuis le réseau interne.

*Priorité immédiate*

- Appliquer les mises à jour de sécurité qui corrigent les failles déjà exploitées par des attaquants : CVE-2016-5195. *Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.*

*Priorité court terme*

- Corriger les autres failles graves (CVSS 7 ou plus) : CVE-2016-4971, CVE-2016-7117, CVE-2016-9841, CVE-2016-9843. *Failles graves, sans exploitation prouvée à ce jour.*

*Plan rédigé par : règles.*

### 192.168.10.1 : Équipement réseau (pare-feu, routeur) (Inconnu, score 0.0)

Le pare-feu/routeur expose uniquement le service DNS interne et son inventaire logiciel est inconnu, ce qui empêche d’évaluer les vulnérabilités.

**Constats établis par les règles**

- (court terme) Compléter l'inventaire : système, logiciels et versions installés.

**Plan d'action détaillé**

*Priorité immédiate*

- Compléter l’inventaire du dispositif : identifier le système d’exploitation, les logiciels et leurs versions. *Sans inventaire, aucune analyse de vulnérabilité ne peut être réalisée.*
- Mettre en place une authentification forte (MFA) pour tout accès administratif au pare-feu/routeur. *Réduit le risque d’accès non autorisé via des identifiants compromis.*

*Priorité court terme*

- Segmenter le réseau en isolant le service DNS interne du reste du réseau et limiter son accès aux seules machines autorisées. *Empêche la propagation d’éventuelles compromissions et limite la visibilité des informations de topologie.*
- Configurer la journalisation et la surveillance du trafic DNS (alertes sur requêtes inhabituelles, volumes anormaux). *Permet de détecter rapidement des activités suspectes ou des tentatives d’exfiltration.*

*Priorité moyen terme*

- Sauvegarder régulièrement la configuration du pare-feu/routeur et stocker les sauvegardes hors site. *Assure une restauration rapide en cas de perte ou de compromission de la configuration.*
- Appliquer les bonnes pratiques de durcissement du système (désactiver les services inutiles, restreindre les accès, mettre à jour le firmware dès qu’il est disponible). *Réduit la surface d’attaque même en l’absence de vulnérabilités connues.*

*Plan rédigé par : règles + LLM.*

### 192.168.10.25 : Poste de travail (Inconnu, score 0.0)

Le poste de travail ne possède pas d'inventaire logiciel, ce qui empêche d'évaluer ses vulnérabilités.

**Constats établis par les règles**

- (court terme) Compléter l'inventaire : système, logiciels et versions installés.

**Plan d'action détaillé**

*Priorité immédiate*

- Lancer un audit complet du système pour recenser le système d'exploitation, les logiciels installés et leurs versions. *Sans inventaire, aucune vulnérabilité ne peut être identifiée ni corrigée.*

*Priorité court terme*

- Mettre en place une authentification forte (MFA) pour les accès locaux et aux services critiques. *Réduit le risque d'accès non autorisé même si des failles apparaissent plus tard.*
- Appliquer les bonnes pratiques de durcissement du système d'exploitation : désactiver les services inutiles, appliquer les politiques de mots de passe, configurer les mises à jour automatiques. *Limite la surface d'attaque et assure que les correctifs sont appliqués rapidement.*

*Priorité moyen terme*

- Déployer une solution de sauvegarde quotidienne des documents bureautiques et des courriels, avec stockage hors site. *Permet de récupérer les données en cas de perte, ransomware ou compromission.*
- Installer un agent de détection et de réponse sur le poste (EDR) et configurer la journalisation centralisée. *Facilite la détection précoce d’activités suspectes et la réponse aux incidents.*

*Plan rédigé par : règles + LLM.*

## Inventaire et observations

- Machines sans logiciel connu : 192.168.10.1, 192.168.10.25.
- Balayages de ports observés : 12, depuis 172.16.0.1, 192.168.10.8.
