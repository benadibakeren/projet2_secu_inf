"""
Agent 2 : classification des actifs.

Rôle : pour chaque actif trouvé par l'agent 1, déterminer
  - son rôle (serveur web, contrôleur de domaine, poste de travail...)
  - sa criticité, de 1 (peu important) à 5 (vital pour l'organisation)
  - les données qu'il manipule probablement

Critères demandés par le sujet :
  - fréquence d'utilisation      -> nombre de connexions et de clients
  - exposition sur le réseau     -> services utilisés depuis Internet, balayages subis
  - rôle dans les processus      -> déduit des services offerts
  - données manipulées           -> déduit du rôle

Partage du travail entre règles et LLM :
  - Le RÔLE est décidé par des règles. Reconnaître un contrôleur de domaine à ses
    ports, c'est de la reconnaissance de signature : des règles le font de façon
    fiable et explicable. (Lors des tests, le LLM se trompait sur des cas simples.)
  - La CRITICITÉ, les DONNÉES et la JUSTIFICATION sont décidées par le LLM.
    Là il faut un jugement : un serveur web exposé et balayé, qui contient peut-être
    des données clients, n'a pas la même importance qu'un serveur interne.
  - Si le LLM pense que le rôle est faux, il le signale dans "desaccord_role".
  - Sans LLM (pas de clé, panne), la criticité vient aussi des règles.

Entrée  : output/inventaire.json   (agent 1)
Sortie  : output/actifs_classes.json
"""

import json
import os
import re
import time
from pathlib import Path

import config


# ---------------------------------------------------------------------------
# 1. Fiche courte envoyée au LLM
# ---------------------------------------------------------------------------

def fiche_resumee(actif: dict) -> dict:
    """
    Garde seulement ce qui aide à juger l'actif.

    Pourquoi : chaque mot envoyé au LLM compte dans les limites gratuites,
    et un texte trop long rend sa réponse moins précise.
    """
    ports = sorted(actif["ports_ouverts"], key=lambda p: -p["connexions"])[:15]
    return {
        "ip": actif["ip"],
        "noms_dns": actif["noms_dns"],
        "ports_ouverts": [
            {"port": p["port"], "service": p["service"], "connexions": p["connexions"]}
            for p in ports
        ],
        "ports_exposes_a_internet": actif.get("ports_exposes", []),
        "logiciels": [f"{l['nom']} {l['version']}" for l in actif["logiciels"]],
        "connexions_recues": actif["connexions_recues"],
        "connexions_emises": actif["connexions_emises"],
        "nb_clients_uniques": actif["nb_clients_uniques"],
        "nb_balayages_recus": len(actif.get("balayages_recus", [])),
        "indices_role": actif["indices_role"],
        # Comptes vus dans les authentifications (si Zeek a été lancé)
        "comptes_qui_se_connectent_depuis_cette_machine": actif.get("comptes_utilises", [])[:10],
        "nb_comptes_authentifies_par_cette_machine": actif.get("nb_comptes_servis", 0),
    }


# ---------------------------------------------------------------------------
# 2. Règles : rôle (toujours) et criticité de base
# ---------------------------------------------------------------------------

def classer_par_regles(fiche: dict) -> dict:
    """
    Décide le rôle à partir des ports ouverts, par ordre de priorité.

    L'ordre compte : une machine avec Kerberos (88) et un site web (80) est
    d'abord un contrôleur de domaine. Le rôle retenu est le plus important
    pour l'organisation, pas le plus utilisé.
    """
    ports = {p["port"] for p in fiche["ports_ouverts"]}
    passerelle = any("passerelle" in i for i in fiche["indices_role"])

    if {88, 389} & ports:
        role, criticite = "Contrôleur de domaine", 5
    elif passerelle:
        role, criticite = "Équipement réseau (pare-feu, routeur)", 4
    elif {1433, 3306, 5432} & ports:
        role, criticite = "Serveur de base de données", 4
    elif {80, 443, 8080} & ports:
        role, criticite = "Serveur web", 3
    elif 53 in ports:
        role, criticite = "Serveur DNS", 3
    elif {139, 445} & ports:
        role, criticite = "Serveur de fichiers", 3
    elif 22 in ports:
        role, criticite = "Serveur d'administration (SSH)", 3
    elif not ports:
        role, criticite = "Poste de travail", 2
    else:
        role, criticite = "Inconnu", 2

    # Un service utilisé depuis Internet est plus exposé : +1
    if fiche["ports_exposes_a_internet"] and criticite < 5:
        criticite += 1

    return {
        "role": role,
        "criticite": criticite,
        "confiance": "moyenne",
        "donnees_probables": "",
        "justification": "Rôle et criticité déduits des ports ouverts et de l'exposition.",
        "desaccord_role": "",
        "methode": "regles",
    }


# ---------------------------------------------------------------------------
# 3. LLM : criticité, données, justification
# ---------------------------------------------------------------------------

CONSIGNE_SYSTEME = """Tu es un analyste en cybersécurité dans un SOC.
On te donne la fiche d'une machine observée dans le trafic réseau d'une organisation,
et son rôle, déjà déterminé par des règles à partir de ses ports.

Ta tâche : évaluer sa criticité pour l'organisation, de 1 (faible) à 5 (vitale).
Critères :
- rôle dans les processus d'affaires (un contrôleur de domaine est vital, un poste de travail l'est moins)
- sensibilité des données qu'elle manipule probablement
- exposition : services utilisés depuis Internet, balayages subis
- fréquence d'utilisation : connexions, nombre de clients
- comptes : un poste où se connecte un compte administrateur, ou un serveur qui authentifie
  beaucoup de comptes, compte davantage

Règles :
- Base-toi uniquement sur la fiche. N'invente aucun logiciel ni aucune version.
- Garde le rôle donné. Si la fiche le contredit clairement, explique pourquoi
  dans "desaccord_role" (sinon laisse ce champ vide).
- Réponds uniquement avec un objet JSON, sans texte autour, au format :
{"criticite": 1, "confiance": "faible|moyenne|elevee",
 "donnees_probables": "...", "justification": "2 ou 3 phrases en français simple",
 "desaccord_role": ""}"""


def creer_client():
    """
    Crée le client LLM, ou renvoie None si aucune clé n'est configurée.

    La clé n'est JAMAIS écrite dans le code : elle est lue dans une variable
    d'environnement, pour ne pas finir publiée sur GitHub.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("[Agent 2] Bibliothèque openai absente : pip install openai")
        return None

    if config.LLM_VARIABLE_CLE is None:          # Ollama : pas besoin de clé
        return OpenAI(base_url=config.LLM_URL, api_key="ollama")

    cle = os.environ.get(config.LLM_VARIABLE_CLE)
    if not cle:
        print(f"[Agent 2] Variable {config.LLM_VARIABLE_CLE} absente : règles seulement")
        return None
    # max_retries=0 : nos agents gèrent eux-mêmes les nouveaux essais et affichent l'attente
    return OpenAI(base_url=config.LLM_URL, api_key=cle, max_retries=0, timeout=120)


def extraire_json(texte: str) -> dict:
    """
    Récupère l'objet JSON dans la réponse du LLM.

    Pourquoi : même quand on demande "uniquement du JSON", certains modèles
    ajoutent une phrase ou des ``` autour. On prend ce qui est entre { et }.
    """
    trouve = re.search(r"\{.*\}", texte, re.DOTALL)
    if not trouve:
        raise ValueError("Pas de JSON dans la réponse")
    return json.loads(trouve.group(0))


def valider(resultat: dict, role: str) -> dict:
    """Vérifie que la réponse du LLM respecte le format attendu."""
    try:
        criticite = min(5, max(1, int(resultat.get("criticite", 3))))
    except (TypeError, ValueError):
        criticite = 3
    return {
        "role": role,  # le rôle reste celui des règles
        "criticite": criticite,
        "confiance": str(resultat.get("confiance", "moyenne")),
        "donnees_probables": str(resultat.get("donnees_probables", "")),
        "justification": str(resultat.get("justification", "")),
        "desaccord_role": str(resultat.get("desaccord_role", "") or ""),
        "methode": "regles + llm",
    }


def evaluer_par_llm(client, fiche: dict, role: str, essais: int = 3) -> dict:
    """
    Demande au LLM la criticité d'un actif dont le rôle est connu.

    En cas d'erreur (limite de requêtes dépassée, réponse mal formée),
    on attend un peu et on réessaie. Après 3 échecs, on abandonne.
    """
    message = json.dumps({"role": role, "fiche": fiche}, ensure_ascii=False)
    for essai in range(1, essais + 1):
        try:
            reponse = client.chat.completions.create(
                model=config.LLM_MODELE,
                temperature=0,  # 0 = réponses stables d'un lancement à l'autre
                messages=[
                    {"role": "system", "content": CONSIGNE_SYSTEME},
                    {"role": "user", "content": message},
                ],
            )
            return valider(extraire_json(reponse.choices[0].message.content), role)
        except Exception as erreur:
            print(f"[Agent 2] {fiche['ip']} : essai {essai} raté ({type(erreur).__name__})")
            time.sleep(5 * essai)
    raise RuntimeError("LLM indisponible")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def executer(dossier_sortie: Path = config.DOSSIER_SORTIE, utiliser_llm: bool = True) -> list[dict]:
    dossier_sortie = Path(dossier_sortie)
    inventaire = json.loads((dossier_sortie / "inventaire.json").read_text(encoding="utf-8"))
    client = creer_client() if utiliser_llm else None

    resultats = []
    for actif in inventaire:
        fiche = fiche_resumee(actif)
        par_regles = classer_par_regles(fiche)

        classification = par_regles
        if client is not None:
            try:
                classification = evaluer_par_llm(client, fiche, par_regles["role"])
            except RuntimeError:
                print(f"[Agent 2] {fiche['ip']} : on garde la classification par règles")

        # On garde aussi l'avis des règles seules : utile pour comparer dans le rapport
        resultats.append({
            **actif,
            "classification": classification,
            "classification_regles": par_regles,
        })
        c = classification
        alerte = "  [désaccord sur le rôle]" if c["desaccord_role"] else ""
        print(f"[Agent 2] {actif['ip']:<16} {c['role']:<38} criticité {c['criticite']}"
              f"  ({c['methode']}){alerte}")

    resultats.sort(key=lambda a: -a["classification"]["criticite"])
    with open(dossier_sortie / "actifs_classes.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    return resultats