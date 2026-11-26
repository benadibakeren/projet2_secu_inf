"""
Agent 4 : évaluation du risque.

Rôle : combiner, pour chaque actif,
  - son importance pour l'organisation   (criticité, agent 2)
  - la gravité de ses failles            (CVSS, agent 3)
  - la probabilité qu'elles soient exploitées (KEV, EPSS)
  - leur accessibilité pour un attaquant (exploitable à distance ? exposé à Internet ?)

Formule (chaque terme s'explique en une phrase) :

    menace(CVE)  = gravité × probabilité d'exploitation × accessibilité
        gravité         = CVSS / 10
        probabilité     = 1 si la CVE est dans KEV (exploitation prouvée), sinon EPSS
        accessibilité   = 1   si exploitable à distance et logiciel exposé à Internet
                          0,7 si exploitable à distance depuis le réseau interne
                          0,4 si l'attaquant doit déjà être sur la machine

    risque(actif) = criticité / 5 × menace de sa pire CVE, ramené sur 100

Signal supplémentaire : une machine interne qui balaie ses voisines (vu par l'agent 1)
est très probablement compromise. C'est un incident, pas un risque : elle est classée
Critique quel que soit le calcul.

Cet agent n'utilise pas de LLM : un score de risque doit être reproductible et vérifiable.
Il ne lit JAMAIS la vérité terrain (étiquettes d'attaque) : voir outils/evaluer.py.

Entrées : output/vulnerabilites.json (agent 3), output/balayages.json (agent 1)
Sortie  : output/risques.json
"""

import json
from pathlib import Path

import requests

import config
from agents.decouverte import est_interne


# ---------------------------------------------------------------------------
# 1. EPSS : probabilité d'exploitation, avec cache
# ---------------------------------------------------------------------------

def charger_epss(identifiants: set[str], dossier_cache: Path = config.DOSSIER_CACHE) -> dict:
    """
    Renvoie {CVE: probabilité d'exploitation dans les 30 jours (0 à 1)}.

    L'API EPSS accepte 100 CVE par requête. Les réponses sont gardées en cache.
    Remarque pour le rapport : EPSS donne la probabilité calculée aujourd'hui,
    pas celle de 2017 (EPSS n'existe que depuis 2021).
    """
    fichier = Path(dossier_cache) / "epss.json"
    cache = json.loads(fichier.read_text(encoding="utf-8")) if fichier.exists() else {}
    manquants = sorted(i for i in identifiants if i not in cache)

    for debut in range(0, len(manquants), 100):
        lot = manquants[debut:debut + 100]
        try:
            r = requests.get(config.EPSS_URL, params={"cve": ",".join(lot), "limit": 100}, timeout=60)
            r.raise_for_status()
            trouves = {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
        except (requests.RequestException, ValueError) as e:
            print(f"[Agent 4] EPSS injoignable ({type(e).__name__}) : probabilité 0 pour ces CVE")
            break
        for i in lot:  # une CVE absente d'EPSS reçoit 0 : rien n'indique qu'elle est exploitée
            cache[i] = trouves.get(i, 0.0)

    fichier.parent.mkdir(parents=True, exist_ok=True)
    fichier.write_text(json.dumps(cache), encoding="utf-8")
    return cache


# ---------------------------------------------------------------------------
# 2. Calcul
# ---------------------------------------------------------------------------

def accessibilite(cve: dict, logiciel: dict) -> tuple[float, str]:
    """Facteur d'accessibilité et sa raison, en clair."""
    a_distance = cve["vecteur"] in ("NETWORK", "ADJACENT_NETWORK")
    if a_distance and logiciel["expose_internet"]:
        return config.ACCES_INTERNET, "exploitable depuis Internet"
    if a_distance:
        return config.ACCES_INTERNE, "exploitable depuis le réseau interne"
    return config.ACCES_LOCAL, "nécessite un accès à la machine"


def menace_cve(cve: dict, logiciel: dict, epss: dict) -> dict:
    """Calcule la menace d'une CVE et garde le détail du calcul."""
    gravite = (cve["score"] or 0) / 10
    probabilite = 1.0 if cve["dans_kev"] else epss.get(cve["id"], 0.0)
    acces, raison_acces = accessibilite(cve, logiciel)
    return {
        "id": cve["id"],
        "logiciel": logiciel["nom"],
        "cvss": cve["score"],
        "dans_kev": cve["dans_kev"],
        "rancongiciel": cve["rancongiciel"],
        "epss": round(epss.get(cve["id"], 0.0), 4),
        "acces": raison_acces,
        "menace": round(gravite * probabilite * acces, 4),
        "produits": cve.get("produits", []),
        "description": cve["description"],
    }


def niveau(score: float) -> str:
    for seuil, nom in config.SEUILS_RISQUE:
        if score >= seuil:
            return nom
    return "Faible"


def evaluer_actif(actif: dict, epss: dict, scanners: dict) -> dict:
    criticite = actif["classification"]["criticite"]
    menaces = [
        menace_cve(c, l, epss)
        for l in actif["logiciels_analyses"]
        for c in l["cves_prioritaires"]
    ]
    # une même CVE peut venir de deux logiciels : on garde sa pire menace
    par_id = {}
    for m in sorted(menaces, key=lambda m: m["menace"]):
        par_id[m["id"]] = m
    menaces = sorted(par_id.values(), key=lambda m: -m["menace"])

    pire = menaces[0]["menace"] if menaces else 0.0
    score = round(100 * criticite / 5 * pire, 1)
    risque = {
        "score": score,
        "niveau": niveau(score),
        "criticite": criticite,
        "menace_max": pire,
        "raisons": [],
        "cves_a_traiter": menaces[:config.NB_CVE_A_TRAITER],
    }

    if menaces:
        m = menaces[0]
        probabilite = "exploitation prouvée (KEV)" if m["dans_kev"] else f"EPSS {m['epss']}"
        risque["raisons"].append(
            f"Pire faille : {m['id']} ({m['logiciel']}), CVSS {m['cvss']}, {probabilite}, {m['acces']}."
        )
    if not actif["resume_vulnerabilites"]["logiciels_connus"]:
        risque["niveau"] = "Inconnu"
        risque["raisons"].append("Aucun logiciel connu : impossible d'évaluer ses failles. Compléter l'inventaire.")

    # Incident : la machine balaie le réseau, elle est probablement compromise
    if actif["ip"] in scanners:
        risque["niveau"] = "Critique"
        risque["compromission_probable"] = True
        risque["raisons"].insert(0,
            f"Compromission probable : cette machine a balayé {scanners[actif['ip']]} autres machines du réseau.")
    else:
        risque["compromission_probable"] = False

    return {
        "ip": actif["ip"],
        "role": actif["classification"]["role"],
        "ports_ouverts": [p["port"] for p in actif["ports_ouverts"]],
        "ports_exposes": actif.get("ports_exposes", []),
        "justification_criticite": actif["classification"]["justification"],
        "donnees_probables": actif["classification"].get("donnees_probables", ""),
        "logiciels": [{"nom": l["nom"], "source": l["source"], "expose_internet": l["expose_internet"]}
                      for l in actif["logiciels_analyses"]],
        "resume_vulnerabilites": actif["resume_vulnerabilites"],
        "risque": risque,
    }


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

ORDRE_NIVEAUX = {"Critique": 0, "Élevé": 1, "Moyen": 2, "Faible": 3, "Inconnu": 4}


def executer(dossier_sortie: Path = config.DOSSIER_SORTIE) -> list[dict]:
    dossier_sortie = Path(dossier_sortie)
    actifs = json.loads((dossier_sortie / "vulnerabilites.json").read_text(encoding="utf-8"))

    # Machines internes qui ont balayé le réseau, et combien de cibles
    scanners = {}
    chemin_balayages = dossier_sortie / "balayages.json"
    if chemin_balayages.exists():
        for b in json.loads(chemin_balayages.read_text(encoding="utf-8")):
            if est_interne(b["source"]):
                scanners[b["source"]] = scanners.get(b["source"], 0) + 1

    identifiants = {c["id"] for a in actifs for l in a["logiciels_analyses"] for c in l["cves_prioritaires"]}
    epss = charger_epss(identifiants)
    print(f"[Agent 4] EPSS : {sum(1 for i in identifiants if epss.get(i))} CVE sur {len(identifiants)} ont une probabilité")

    resultats = [evaluer_actif(a, epss, scanners) for a in actifs]
    resultats.sort(key=lambda r: (ORDRE_NIVEAUX[r["risque"]["niveau"]], -r["risque"]["score"]))

    with open(dossier_sortie / "risques.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)

    print(f"\n  {'Rang':<5}{'IP':<16}{'Rôle':<38}{'Crit.':>5}{'Score':>7}  Niveau")
    for rang, r in enumerate(resultats, 1):
        q = r["risque"]
        print(f"  {rang:<5}{r['ip']:<16}{r['role']:<38}{q['criticite']:>5}{q['score']:>7}  {q['niveau']}")
        print(f"       {q['raisons'][0] if q['raisons'] else ''}")
    return resultats
