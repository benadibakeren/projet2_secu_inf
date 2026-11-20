# Projet 2 : découverte des actifs et gestion des vulnérabilités

Cours 8INF857, UQAC. Jeu de données : CICIDS2017.

## Structure

```
projet2/
├── main.py                 lance les agents dans l'ordre
├── config.py               réglages communs (réseau interne, chemins, ports)
├── requirements.txt
├── agents/
│   ├── decouverte.py       agent 1 (fait)
│   ├── classification.py   agent 2 (à faire, LLM)
│   ├── vulnerabilites.py   agent 3 (à faire, NVD + KEV)
│   ├── risque.py           agent 4 (à faire)
│   └── remediation.py      agent 5 (à faire, LLM)
├── outils/
│   └── creer_exemple.py    crée de petites données de test
├── data/
│   ├── zeek/               mettre ici conn.log, software.log, dns.log
│   ├── csv/                mettre ici les CSV TrafficLabelling
│   └── exemple/            données de test générées
└── output/                 résultats des agents
```

Règle : chaque agent lit le fichier produit par l'agent précédent et écrit le sien dans `output/`.
Comme ça, chacun peut travailler et tester son agent sans attendre les autres.

| Agent | Lit | Écrit |
| --- | --- | --- |
| 1. Découverte | logs Zeek / CSV | `inventaire.json`, `dependances.graphml` |
| 2. Classification | `inventaire.json` | `actifs_classes.json` |
| 3. Vulnérabilités | `actifs_classes.json` | `vulnerabilites.json` |
| 4. Risque | `vulnerabilites.json` | `risques.json` |
| 5. Remédiation | `risques.json` | `rapport.md` |

## Démarrage rapide (sans les vraies données)

```bash
pip install -r requirements.txt
python outils/creer_exemple.py
python main.py --zeek data/exemple --sortie output/exemple
```

## Passer aux vraies données

### Option A : les CSV (rapide, sans versions de logiciels)

1. Sur la page CICIDS2017 de l'UNB, télécharger le dossier **TrafficLabelling**
   (aussi appelé GeneratedLabelledFlows). Ne pas prendre MachineLearningCVE : il n'a pas les IP.
2. Mettre 1 ou 2 fichiers (ex. mercredi et jeudi) dans `data/csv/`.
3. `python main.py`

Un fichier contient des centaines de milliers de lignes : comptez une à deux minutes.

### Option B : Zeek sur les PCAP (recommandé, donne les versions)

Les versions de logiciels (Apache 2.4.18, OpenSSH 7.2...) sont indispensables pour l'agent 3.
Seul Zeek les extrait.

1. Télécharger le PCAP d'un jour (attention, plus de 10 Go).
2. Installer Zeek, ou utiliser Docker :
   ```bash
   docker run --rm -v "$PWD/data/zeek:/data" -w /data zeek/zeek \
       zeek -C -r Wednesday-WorkingHours.pcap local
   ```
   - `-C` ignore les erreurs de checksum (fréquentes dans CICIDS2017)
   - `local` active les scripts qui détectent les logiciels (sinon pas de `software.log`)
3. `python main.py` (les CSV dans `data/csv/` servent alors seulement de vérité terrain)

## Vérité terrain

Si des CSV sont présents, l'agent 1 écrit `output/verite_terrain.json` : les machines attaquées
et le type d'attaque. **Les agents ne doivent jamais lire ce fichier.** Il sert uniquement à
vérifier à la fin si les actifs jugés les plus à risque sont bien ceux qui ont été attaqués.

Topologie publiée de CICIDS2017 (pour vérifier l'agent 1) :

| IP | Machine |
| --- | --- |
| 192.168.10.3 | Windows Server 2016 (contrôleur de domaine, DNS) |
| 192.168.10.50 | Serveur web Ubuntu 16 |
| 192.168.10.51 | Serveur Ubuntu 12 |
| 192.168.10.5, .8, .9, .14, .15 | Postes Windows |
| 192.168.10.12, .16, .17, .19 | Postes Ubuntu |
| 192.168.10.25 | Mac |

## Utilisation de l'IA

Ce code a été produit avec l'aide d'une IA générative (niveau "production partagée",
à déclarer dans le rapport avec le pictogramme UQAC).
