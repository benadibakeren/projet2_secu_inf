# Projet 2 : découverte des actifs et gestion des vulnérabilités

Cours 8INF857 Sécurité informatique, UQAC, automne 2026.
Équipe : Keren BENADIBA, Luc LENNE, Matthieu ZOZOR. Enseignant : Fehmi Jaafar.

Une chaîne de cinq agents part du trafic réseau de CICIDS2017 (jeudi 6 juillet 2017) pour
découvrir les machines, les classer, trouver leurs failles, mesurer le risque et proposer un
plan d'action. Principe : **le code établit les faits, le LLM juge et rédige, et il est vérifié.**

## Résultats du lancement final

Dossier `resultats_finaux/` (journaux `lancement_final.txt` et `lancement_agent5.txt`, rapport `rapport.md`).

- 14 machines internes découvertes sur 14, 13 bien classées
- 12 balayages de ports détectés, venant de 192.168.10.8 (poste infecté) et 172.16.0.1
- Zeek : 12 comptes utilisateurs, Nmap dans le trafic de 192.168.10.8, un Mac OS X 10.5.8
- Serveur web 192.168.10.50 (seule machine attaquée selon les étiquettes) classé 3e sur 14
- 192.168.10.8 repérée comme compromise, aucune fausse alerte
- Premier correctif à déployer : MS17-010 (EternalBlue), sur les 6 machines Windows

## Structure

```
projet2/
├── main.py                    lance les agents dans l'ordre
├── config.py                  tous les réglages (réseau, seuils, NVD, risque, LLM)
├── dashboard.py               tableau de bord Streamlit (7 onglets)
├── requirements.txt
├── .streamlit/config.toml     thème du tableau de bord
├── agents/
│   ├── decouverte.py          agent 1 : machines, services, graphe, balayages, comptes (CSV + Zeek)
│   ├── classification.py      agent 2 : rôle par règles, criticité et justification par LLM
│   ├── vulnerabilites.py      agent 3 : CVE (API NVD 2.0), CISA KEV, bulletins des éditeurs
│   ├── risque.py              agent 4 : score de risque (CVSS, KEV, EPSS, accessibilité)
│   └── remediation.py         agent 5 : constats par règles, plan par LLM, rapport.md
├── outils/
│   ├── evaluer.py             compare le classement à la vérité terrain
│   ├── voir_actif.py          affiche la fiche complète d'une machine
│   └── creer_exemple.py       crée de petites données de test
├── data/
│   ├── inventaire_declare.json  inventaire "officiel" (systèmes et logiciels déclarés)
│   ├── csv/                   CSV GeneratedLabelledFlows (non versionnés)
│   ├── zeek/                  journaux Zeek (non versionnés)
│   └── exemple/               données de test générées
├── cache/                     réponses NVD, KEV et EPSS gardées en cache (non versionné)
├── output/                    résultats du dernier lancement (non versionné)
└── resultats_finaux/          copie du lancement final (versionnée)
```

Chaque agent lit le fichier du précédent et écrit le sien dans `output/`.

| Agent | Lit | Écrit | Technique |
| --- | --- | --- | --- |
| 1. Découverte | CSV, journaux Zeek | `inventaire.json`, `dependances.graphml`, `dependances.csv`, `balayages.json`, `comptes.json`, `verite_terrain.json` | pandas, networkx |
| 2. Classification | `inventaire.json` | `actifs_classes.json` | règles + LLM |
| 3. Vulnérabilités | `actifs_classes.json`, `data/inventaire_declare.json` | `vulnerabilites.json`, `ecarts_inventaire.json` | API NVD, CISA KEV |
| 4. Risque | `vulnerabilites.json` | `risques.json` | formule, EPSS |
| 5. Remédiation | `risques.json` | `remediation.json`, `rapport.md` | règles + LLM |

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Deux clés gratuites, à mettre dans les **secrets GitHub Codespaces** :

| Variable | Service | Rôle |
| --- | --- | --- |
| `GROQ_API_KEY` | https://console.groq.com | LLM des agents 2 et 5 (modèle `openai/gpt-oss-120b`) |
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key | requêtes NVD plus rapides (facultative) |

## Données

1. **CSV (source principale).** Sur la page CICIDS2017 de l'UNB, prendre l'archive
   **GeneratedLabelledFlows** (aussi appelée TrafficLabelling), pas MachineLearningCVE qui n'a pas
   les adresses IP. Mettre les deux fichiers du jeudi dans `data/csv/`.
2. **Zeek (logiciels, comptes, outils d'attaque).** La capture du jeudi fait 8,3 Go. Le serveur
   officiel n'étant pas accessible, nous avons utilisé une copie publique sur Hugging Face.
   Elle est lue au fil du téléchargement, sans être enregistrée :
   ```bash
   cd data/zeek
   curl -L https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/Thursday-WorkingHours.pcap \
     | docker run -i --rm -v "$PWD:/data" -w /data zeek/zeek zeek -C -r - local
   ```
   - `-C` ignore les erreurs de checksum (fréquentes dans CICIDS2017)
   - `local` active les scripts qui produisent `software.log`
   - journaux utilisés : `software.log`, `kerberos.log`, `ntlm.log`

Sans Zeek, la chaîne fonctionne avec les CSV seuls, mais sans versions observées ni comptes.

## Lancement

```bash
python -u main.py 2>&1 | tee lancement.txt     # les 5 agents
python -u outils/evaluer.py                     # évaluation par la vérité terrain
streamlit run dashboard.py                      # tableau de bord sur output/
```

Options de `main.py` :

| Option | Effet |
| --- | --- |
| `--depuis N` | relance à partir de l'agent N (les fichiers des agents précédents doivent exister) |
| `--sans-llm` | agents 2 et 5 sans LLM, règles seules |
| `--csv`, `--zeek`, `--sortie` | autres dossiers d'entrée ou de sortie |

Le `-u` affiche les messages au fur et à mesure (sinon `tee` les retient jusqu'à la fin).

Pour figer un lancement et le montrer :

```bash
rm -rf resultats_finaux && cp -r output resultats_finaux
streamlit run dashboard.py -- resultats_finaux
```

Outils : `python outils/voir_actif.py 192.168.10.50` affiche la fiche d'une machine ;
`python outils/creer_exemple.py` puis `python main.py --zeek data/exemple --sortie output/exemple`
fait tourner la chaîne sur de petites données de test.

## Choix importants

- **Balayages** : plus de 100 ports différents d'une source vers une destination. Le trafic normal
  en touche au plus 49, les balayages plus de 900. Répondre à un scanner n'est pas scanner.
- **Services** : ports 1 à 32767 seulement ; flux remis dans le bon sens quand le port source est
  inférieur à 1024 ; un service a au moins 2 clients, sauf s'il est utilisé depuis Internet ou
  reçoit plus de 500 connexions.
- **Rôle** décidé par des règles ; le LLM donne la criticité (1 à 5), les données probables et une
  justification, et peut signaler un désaccord sans changer le rôle.
- **CVE** : seulement celles publiées avant le 6 juillet 2017 ; pour Windows 10 et Server 2016,
  celles publiées avant la sortie du système sont écartées ; pour Ubuntu, seulement les paquets de
  base ; seuls les bulletins de l'éditeur du système sont gardés (MS, USN, Apple).
- **Risque** : `menace = CVSS/10 × probabilité × accessibilité`, avec probabilité 1 si KEV sinon
  EPSS, accessibilité 1 (Internet), 0,7 (réseau interne) ou 0,4 (local) ;
  `risque = 100 × criticité/5 × pire menace`. Critique ≥ 50, Élevé ≥ 30, Moyen ≥ 15.
  Une machine qui balaie le réseau ou transporte des outils d'attaque est Critique d'office.
- **LLM** : chaque CVE et chaque bulletin cité est vérifié ; les constats des règles restent
  affichés ; si Groq refuse (quota gratuit), l'agent attend le délai indiqué puis garde le plan
  des règles si le quota du jour est épuisé.

## Vérité terrain

L'agent 1 écrit les étiquettes d'attaque dans `output/verite_terrain.json`. **Aucun agent ne lit
ce fichier** : seul `outils/evaluer.py` l'utilise, pour vérifier le classement final.

Topologie publiée de CICIDS2017 :

| IP | Machine |
| --- | --- |
| 192.168.10.1 | Pare-feu |
| 192.168.10.3 | Windows Server 2016 (contrôleur de domaine, DNS) |
| 192.168.10.50 | Serveur web Ubuntu 16.04 |
| 192.168.10.51 | Serveur Ubuntu 12.04 |
| 192.168.10.5, .8, .9, .14, .15 | Postes Windows (8.1, Vista, 7, 10, 10) |
| 192.168.10.12, .16, .17, .19 | Postes Ubuntu |
| 192.168.10.25 | Mac |

## Limites connues

- Niveau de mise à jour des machines inconnu : les nombres de CVE sont des maximums.
- Seuils réglés sur un seul jour de données.
- Versions vues par Zeek : celles que les logiciels annoncent, donc falsifiables.
- Le LLM varie un peu d'un lancement à l'autre et peut encore se tromper : le rapport doit être relu.
- EPSS donne la probabilité d'aujourd'hui, pas celle de 2017.

## Utilisation de l'IA

Ce projet a été réalisé avec l'aide d'une IA générative, niveau « production partagée »
(déclaré dans le rapport). Les agents 2 et 5 utilisent aussi un LLM pendant leur exécution ; ses sorties sont encadrées par des règles et vérifiées.