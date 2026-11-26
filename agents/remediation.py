"""
Agent 5 : remédiation.

Rôle : transformer le classement des risques en actions concrètes et produire
le rapport de recommandations.

Partage du travail :
  - Des RÈGLES produisent les recommandations qui découlent directement des faits
    (machine compromise, faille KEV, système plus maintenu, port sensible exposé,
    inventaire manquant). Elles ne peuvent pas se tromper sur les faits.
  - Le LLM reçoit la fiche de la machine et ces recommandations, puis rédige un plan
    d'action priorisé et lisible. Il peut ajouter des mesures (MFA, segmentation...).
  - Garde-fou : chaque CVE citée par le LLM est vérifiée. Si elle n'a pas été trouvée
    par l'agent 3, elle est retirée et signalée (un LLM peut inventer des identifiants).
  - Sans LLM (pas de clé, panne), le plan est construit à partir des règles seules.

Le rapport final (rapport.md) est assemblé par du code : tous les chiffres viennent
des données. Le LLM n'écrit que le texte des plans d'action.

Entrée  : output/risques.json (agent 4), output/ecarts_inventaire.json et
          output/balayages.json (agents 3 et 1)
Sorties : output/remediation.json, output/rapport.md
"""

import json
import re
import time
from datetime import date
from pathlib import Path

import config
from agents.classification import creer_client, extraire_json

PRIORITES = ["immédiate", "court terme", "moyen terme"]
NIVEAUX_AVEC_LLM = {"Critique", "Élevé", "Moyen", "Inconnu"}


# ---------------------------------------------------------------------------
# 1. Recommandations par règles
# ---------------------------------------------------------------------------

def fin_de_support(logiciel: dict) -> str | None:
    """Date de fin de support du système, s'il est connu."""
    for prefixe, date_fin in config.FIN_DE_SUPPORT.items():
        if logiciel.get("cpe", "").startswith(prefixe):
            return date_fin
    return None


def recommandations_par_regles(actif: dict) -> list[dict]:
    """Recommandations qui découlent directement des faits. Chacune dit pourquoi."""
    risque = actif["risque"]
    recos = []

    if risque.get("compromission_probable"):
        recos.append({
            "priorite": "immédiate",
            "action": "Isoler la machine du réseau, conserver ses journaux pour l'analyse, "
                      "la réinstaller, puis changer les mots de passe des comptes utilisés dessus.",
            "justification": risque["raisons"][0],
            "cves": [],
        })

    kev = [c for c in risque["cves_a_traiter"] if c["dans_kev"]]
    if kev:
        recos.append({
            "priorite": "immédiate",
            "action": "Appliquer les mises à jour de sécurité qui corrigent les failles déjà "
                      "exploitées par des attaquants : " + ", ".join(c["id"] for c in kev) + ".",
            "justification": "Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.",
            "cves": [c["id"] for c in kev],
        })

    autres = [c for c in risque["cves_a_traiter"] if not c["dans_kev"] and (c["cvss"] or 0) >= 7]
    if autres:
        recos.append({
            "priorite": "court terme",
            "action": "Corriger les autres failles graves (CVSS 7 ou plus) : "
                      + ", ".join(c["id"] for c in autres) + ".",
            "justification": "Failles graves, sans exploitation prouvée à ce jour.",
            "cves": [c["id"] for c in autres],
        })

    for l in actif["logiciels"]:
        fin = fin_de_support(l)
        if fin and fin <= config.DATE_CAPTURE:
            recos.append({
                "priorite": "court terme",
                "action": f"Remplacer {l['nom']} par une version maintenue.",
                "justification": f"Plus aucun correctif de sécurité depuis le {fin} : "
                                 f"les failles découvertes après cette date ne seront jamais corrigées.",
                "cves": [],
            })

    sensibles = [p for p in actif["ports_exposes"] if p in config.PORTS_SENSIBLES]
    if sensibles:
        noms = ", ".join(f"{config.PORTS_SENSIBLES[p]} ({p})" for p in sensibles)
        recos.append({
            "priorite": "immédiate",
            "action": f"Fermer l'accès depuis Internet à {noms}, ou le limiter à un VPN "
                      f"ou à une liste d'adresses autorisées.",
            "justification": "Ces services d'administration ou de transfert de fichiers sont "
                             "utilisés depuis Internet, ce qui les expose aux attaques par force brute.",
            "cves": [],
        })

    if risque["niveau"] == "Inconnu":
        recos.append({
            "priorite": "court terme",
            "action": "Compléter l'inventaire : système, logiciels et versions installés.",
            "justification": "Sans inventaire, impossible de savoir si la machine est vulnérable.",
            "cves": [],
        })

    return recos


# ---------------------------------------------------------------------------
# 2. Plan d'action rédigé par le LLM
# ---------------------------------------------------------------------------

CONSIGNE = """Tu es un analyste en cybersécurité. On te donne la fiche d'une machine d'une organisation,
son niveau de risque, ses failles les plus menaçantes et des recommandations déjà établies par des règles.
La situation est celle de la date de référence indiquée dans la fiche (date de la capture du trafic).

Sens des champs (à respecter strictement) :
- "dans_kev": true veut dire que la faille a été exploitée par des attaquants QUELQUE PART DANS LE MONDE
  (catalogue CISA KEV). Cela ne veut PAS dire qu'elle a été exploitée sur ce réseau.
- "acces" dit d'où un attaquant POURRAIT exploiter la faille. Ce n'est pas une attaque observée.
- Seules les "raisons" décrivent ce qui a été réellement observé sur le réseau.

Rédige un plan d'action de 3 à 6 actions concrètes, classées par priorité.
Règles :
- Reprends les recommandations des règles : elles sont justes. Tu peux les reformuler et les compléter
  par des mesures adaptées au rôle de la machine (authentification forte, segmentation du réseau,
  sauvegardes, surveillance, durcissement de la configuration...).
- N'affirme aucun fait absent de la fiche (par exemple : qu'une machine en a infecté d'autres).
- Décris l'effet d'une CVE uniquement à partir de sa description fournie. Ne dis pas "exécution de
  code à distance" si la description ne le dit pas.
- Ne parle de fin de support d'un système que si la fiche donne sa date, et compare-la à la date de référence.
- Cite uniquement des identifiants CVE présents dans la fiche. N'invente aucune CVE, aucun numéro
  de correctif, aucune version.
- Écris en français simple, phrases courtes, sans jargon inutile.
- Réponds uniquement avec un objet JSON, sans texte autour :
{"resume": "1 ou 2 phrases sur la situation de la machine",
 "actions": [{"priorite": "immédiate|court terme|moyen terme", "action": "...",
              "justification": "...", "cves": ["CVE-..."]}]}"""


def fiche_pour_llm(actif: dict, recos: list[dict]) -> dict:
    r = actif["risque"]
    return {
        "date_de_reference": config.DATE_CAPTURE,
        "ip": actif["ip"],
        "role": actif["role"],
        "donnees_probables": actif["donnees_probables"],
        "ports_ouverts": actif["ports_ouverts"],
        "ports_exposes_a_internet": actif["ports_exposes"],
        "logiciels": [{"nom": l["nom"], "source": l["source"],
                       "fin_de_support": fin_de_support(l) or "non fournie"}
                      for l in actif["logiciels"]],
        "niveau_de_risque": r["niveau"],
        "score": r["score"],
        "raisons": r["raisons"],
        "failles_les_plus_menacantes": [
            {"id": c["id"], "logiciel": c["logiciel"], "cvss": c["cvss"], "dans_kev": c["dans_kev"],
             "acces": c["acces"], "description": c["description"]}
            for c in r["cves_a_traiter"]
        ],
        "recommandations_des_regles": recos,
    }


def verifier_cves(plan: dict, connues: set[str]) -> list[str]:
    """Retire du plan les CVE que l'agent 3 n'a pas trouvées. Renvoie celles retirées."""
    inventees = set()
    for a in plan["actions"]:
        cites = set(a.get("cves") or []) | set(re.findall(r"CVE-\d{4}-\d{4,7}", a.get("action", "")))
        faux = cites - connues
        inventees |= faux
        a["cves"] = sorted((set(a.get("cves") or []) | cites) - faux)
        for f in faux:
            a["action"] = a["action"].replace(f, "[CVE retirée : non vérifiée]")
    return sorted(inventees)


def valider_plan(brut: dict) -> dict:
    actions = []
    for a in brut.get("actions", []):
        if not isinstance(a, dict) or not a.get("action"):
            continue
        priorite = a.get("priorite") if a.get("priorite") in PRIORITES else "moyen terme"
        actions.append({"priorite": priorite, "action": str(a["action"]),
                        "justification": str(a.get("justification", "")),
                        "cves": [str(c) for c in (a.get("cves") or [])]})
    if not actions:
        raise ValueError("Plan vide")
    actions.sort(key=lambda a: PRIORITES.index(a["priorite"]))
    return {"resume": str(brut.get("resume", "")), "actions": actions}


def plan_par_llm(client, actif: dict, recos: list[dict], essais: int = 3) -> dict:
    message = json.dumps(fiche_pour_llm(actif, recos), ensure_ascii=False)
    for essai in range(1, essais + 1):
        try:
            reponse = client.chat.completions.create(
                model=config.LLM_MODELE,
                temperature=0,
                messages=[{"role": "system", "content": CONSIGNE},
                          {"role": "user", "content": message}],
            )
            return valider_plan(extraire_json(reponse.choices[0].message.content))
        except Exception as erreur:
            print(f"[Agent 5] {actif['ip']} : essai {essai} raté ({type(erreur).__name__})")
            time.sleep(10 * essai)  # souvent la limite de jetons par minute de Groq
    raise RuntimeError("LLM indisponible")


def plan_par_regles(actif: dict, recos: list[dict]) -> dict:
    r = actif["risque"]
    resume = f"Niveau de risque {r['niveau']} (score {r['score']}). " + (r["raisons"][0] if r["raisons"] else "")
    actions = sorted(recos, key=lambda a: PRIORITES.index(a["priorite"]))
    if not actions:
        actions = [{"priorite": "moyen terme",
                    "action": "Maintenir les mises à jour automatiques et surveiller la machine.",
                    "justification": "Aucune faille prioritaire.", "cves": []}]
    return {"resume": resume.strip(), "actions": actions}


# ---------------------------------------------------------------------------
# 3. Rapport Markdown
# ---------------------------------------------------------------------------

def ecrire_rapport(plans: list[dict], ecarts: dict, balayages: list[dict], chemin: Path) -> None:
    """Assemble le rapport. Tous les chiffres viennent des données, pas du LLM."""
    compte = {}
    for p in plans:
        compte[p["niveau"]] = compte.get(p["niveau"], 0) + 1
    ordre = ["Critique", "Élevé", "Moyen", "Faible", "Inconnu"]

    l = [
        "# Rapport de recommandations",
        "",
        f"Généré le {date.today().isoformat()} par la chaîne d'agents, à partir du trafic de "
        f"CICIDS2017 du {config.DATE_CAPTURE}. Ce rapport a été produit avec l'aide d'une IA générative.",
        "",
        "## Résumé",
        "",
        f"{len(plans)} actifs analysés : " + ", ".join(f"{compte[n]} {n.lower()}" for n in ordre if n in compte) + ".",
        "",
    ]
    compromis = [p["ip"] for p in plans if p["compromission_probable"]]
    if compromis:
        l += [f"**Incident en cours :** {', '.join(compromis)} balaie le réseau interne et est probablement "
              f"compromise. Elle doit être isolée immédiatement.", ""]

    l += ["## Classement des risques", "",
          "| Rang | Actif | Rôle | Score | Niveau | Raison principale |",
          "| --- | --- | --- | --- | --- | --- |"]
    for i, p in enumerate(plans, 1):
        raison = p["raisons"][0] if p["raisons"] else ""
        l.append(f"| {i} | {p['ip']} | {p['role']} | {p['score']} | {p['niveau']} | {raison} |")

    # Construite à partir des règles seulement : identique avec ou sans LLM,
    # et une action vitale ne peut pas être oubliée par le LLM.
    l += ["", "## Actions immédiates, toutes machines confondues", ""]
    for p in plans:
        for a in p["recommandations_regles"]:
            if a["priorite"] == "immédiate":
                l.append(f"- **{p['ip']}** ({p['role']}) : {a['action']}")

    l += ["", "## Plan d'action par actif", ""]
    for p in plans:
        l += [f"### {p['ip']} : {p['role']} ({p['niveau']}, score {p['score']})", "", p["plan"]["resume"], ""]
        if p["recommandations_regles"] and p["methode"] != "règles":
            l += ["**Constats établis par les règles**", ""]
            for a in p["recommandations_regles"]:
                l.append(f"- ({a['priorite']}) {a['action']}")
            l += ["", "**Plan d'action détaillé**", ""]
        for prio in PRIORITES:
            actions = [a for a in p["plan"]["actions"] if a["priorite"] == prio]
            if actions:
                l.append(f"*Priorité {prio}*")
                l.append("")
                for a in actions:
                    l.append(f"- {a['action']} *{a['justification']}*")
                l.append("")
        if p["cves_retirees"]:
            l += [f"*Contrôle : CVE citées par le LLM mais non vérifiées, retirées : "
                  f"{', '.join(p['cves_retirees'])}.*", ""]
        l += [f"*Plan rédigé par : {p['methode']}.*", ""]

    l += ["## Inventaire et observations", ""]
    if ecarts.get("vus_mais_non_declares"):
        l.append(f"- Machines vues sur le réseau mais absentes de l'inventaire : {', '.join(ecarts['vus_mais_non_declares'])}.")
    if ecarts.get("declares_mais_non_vus"):
        l.append(f"- Machines déclarées mais jamais vues : {', '.join(ecarts['declares_mais_non_vus'])}.")
    if ecarts.get("sans_logiciel_connu"):
        l.append(f"- Machines sans logiciel connu : {', '.join(ecarts['sans_logiciel_connu'])}.")
    sources = sorted({b["source"] for b in balayages})
    if sources:
        l.append(f"- Balayages de ports observés : {len(balayages)}, depuis {', '.join(sources)}.")

    chemin.write_text("\n".join(l) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def _lire(chemin: Path, defaut):
    return json.loads(chemin.read_text(encoding="utf-8")) if chemin.exists() else defaut


def executer(dossier_sortie: Path = config.DOSSIER_SORTIE, utiliser_llm: bool = True) -> list[dict]:
    dossier_sortie = Path(dossier_sortie)
    actifs = json.loads((dossier_sortie / "risques.json").read_text(encoding="utf-8"))
    ecarts = _lire(dossier_sortie / "ecarts_inventaire.json", {})
    balayages = _lire(dossier_sortie / "balayages.json", [])
    client = creer_client() if utiliser_llm else None

    plans = []
    for actif in actifs:
        recos = recommandations_par_regles(actif)
        connues = {c["id"] for c in actif["risque"]["cves_a_traiter"]}
        plan, methode, retirees = plan_par_regles(actif, recos), "règles", []

        if client is not None and actif["risque"]["niveau"] in NIVEAUX_AVEC_LLM:
            try:
                plan = plan_par_llm(client, actif, recos)
                retirees = verifier_cves(plan, connues)
                methode = "règles + LLM"
                time.sleep(config.PAUSE_LLM)
            except RuntimeError:
                print(f"[Agent 5] {actif['ip']} : on garde le plan par règles")

        r = actif["risque"]
        plans.append({
            "ip": actif["ip"], "role": actif["role"], "niveau": r["niveau"], "score": r["score"],
            "raisons": r["raisons"], "compromission_probable": r.get("compromission_probable", False),
            "recommandations_regles": recos, "plan": plan, "methode": methode, "cves_retirees": retirees,
        })
        alerte = f"  [{len(retirees)} CVE inventée(s) retirée(s)]" if retirees else ""
        print(f"[Agent 5] {actif['ip']:<16} {r['niveau']:<9} {len(plan['actions'])} actions  ({methode}){alerte}")

    with open(dossier_sortie / "remediation.json", "w", encoding="utf-8") as f:
        json.dump(plans, f, indent=2, ensure_ascii=False)
    ecrire_rapport(plans, ecarts, balayages, dossier_sortie / "rapport.md")
    print(f"[Agent 5] Rapport écrit : {dossier_sortie / 'rapport.md'}")
    return plans