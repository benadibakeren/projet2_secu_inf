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


def ids_bulletins(cves: list[dict]) -> list[str]:
    """Identifiants uniques des bulletins de sécurité de ces CVE (ex. MS17-010)."""
    return sorted({b["id"] for c in cves for b in c.get("bulletins", []) if b.get("id")})


def _avec_bulletins(texte: str, cves: list[dict]) -> str:
    ids = ids_bulletins(cves)
    return texte + (f" Bulletins de sécurité correspondants : {', '.join(ids)}." if ids else "")


def correctifs_de_la_machine(actif: dict, maximum: int = 8) -> list[str]:
    """
    Bulletins qui corrigent le plus de failles déjà exploitées (KEV) sur cette machine.
    On regarde toutes ses failles KEV, pas seulement les 5 plus menaçantes.
    """
    compte = {}
    for c in actif.get("cves_kev", []):
        for b in c.get("bulletins", []):
            if b.get("id"):
                compte[b["id"]] = compte.get(b["id"], 0) + 1
    return [bid for bid, _ in sorted(compte.items(), key=lambda x: (-x[1], x[0]))[:maximum]]


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

    # Failles KEV parmi les plus menaçantes, complétées par les autres failles KEV de la machine
    # (une faille KEV locale peut être hors des 5 plus menaçantes, ex. Dirty COW sur le serveur web).
    kev = [c for c in risque["cves_a_traiter"] if c["dans_kev"]]
    deja = {c["id"] for c in kev}
    for c in sorted(actif.get("cves_kev", []), key=lambda c: -(c.get("score") or 0)):
        if len(kev) >= config.NB_CVE_A_TRAITER:
            break
        if c["id"] not in deja:
            kev.append(c); deja.add(c["id"])
    if kev:
        recos.append({
            "priorite": "immédiate",
            "action": _avec_bulletins("Appliquer les mises à jour de sécurité qui corrigent les failles déjà "
                                      "exploitées par des attaquants : " + ", ".join(c["id"] for c in kev) + ".",
                                      kev),
            "justification": "Ces failles sont dans le catalogue CISA KEV : leur exploitation réelle est prouvée.",
            "cves": [c["id"] for c in kev],
        })

    autres = [c for c in risque["cves_a_traiter"] if not c["dans_kev"] and (c["cvss"] or 0) >= 7]
    if autres:
        recos.append({
            "priorite": "court terme",
            "action": _avec_bulletins("Corriger les autres failles graves (CVSS 7 ou plus) : "
                                      + ", ".join(c["id"] for c in autres) + ".", autres),
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
- Cite uniquement des identifiants CVE et des bulletins (ex. MS17-010, USN-3105-1) présents dans la
  fiche. "correctifs_disponibles_pour_failles_kev" liste les bulletins qui corrigent le plus de failles
  déjà exploitées sur cette machine : nomme-les, c'est ce qu'un administrateur applique.
  N'invente aucune CVE, aucun bulletin, aucun numéro de correctif, aucune version.
- N'attribue une CVE qu'au logiciel indiqué dans son champ "logiciel".
- Ne généralise pas (par exemple "toutes les failles concernent Flash") si les descriptions ne le montrent pas.
- Ne dis pas qu'un logiciel est obsolète ou plus maintenu si la fiche ne donne pas sa fin de support.
- Ne cite aucun produit ni aucune version sortis après la date de référence (pas de Windows 11,
  pas d'Ubuntu 18.04 ou 20.04) : écris plutôt "une version maintenue".
- N'écris jamais le nom d'un champ de la fiche (par exemple correctifs_disponibles_pour_failles_kev) :
  écris "les correctifs disponibles".
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
             "acces": c["acces"], "bulletins": ids_bulletins([c]), "description": c["description"]}
            for c in r["cves_a_traiter"]
        ],
        "recommandations_des_regles": recos,
        "correctifs_disponibles_pour_failles_kev": correctifs_de_la_machine(actif),
    }


MOTIF_BULLETIN = re.compile(r"\b(?:Apple HT\d+|MS\d{2}-\d{3}|USN-\d{3,5}-\d+|RHSA-\d{4}:\d{4,5}|DSA-\d{3,5}(?:-\d+)?)\b")


def verifier_cves(plan: dict, connues: set[str], bulletins_connus: set[str] = frozenset()) -> list[str]:
    """
    Retire du plan les CVE et les bulletins que l'agent 3 n'a pas trouvés.
    Un LLM peut inventer un identifiant qui a l'air vrai : on ne garde que ceux vérifiés.
    Renvoie les identifiants retirés.
    """
    inventees = set()
    for a in plan["actions"]:
        cites = set(a.get("cves") or []) | set(re.findall(r"CVE-\d{4}-\d{4,7}", a.get("action", "")))
        faux = cites - connues
        inventees |= faux
        a["cves"] = sorted((set(a.get("cves") or []) | cites) - faux)
        for f in faux:
            a["action"] = a["action"].replace(f, "[CVE retirée : non vérifiée]")
        for champ in ("action", "justification"):
            for b in set(MOTIF_BULLETIN.findall(a.get(champ, ""))) - bulletins_connus:
                inventees.add(b)
                a[champ] = a[champ].replace(b, "[bulletin retiré : non vérifié]")
    return sorted(inventees)


CHAMPS_INTERNES = {"correctifs_disponibles_pour_failles_kev": "les correctifs disponibles",
                   "failles_les_plus_menacantes": "les failles les plus menaçantes",
                   "recommandations_des_regles": "les recommandations", "dans_kev": "KEV"}


def _texte_propre(texte: str) -> str:
    """Remplace les noms de champs que le LLM recopie parfois par des mots simples."""
    for champ, mots in CHAMPS_INTERNES.items():
        texte = texte.replace(champ, mots)
    return texte


def valider_plan(brut: dict) -> dict:
    actions = []
    for a in brut.get("actions", []):
        if not isinstance(a, dict) or not a.get("action"):
            continue
        priorite = a.get("priorite") if a.get("priorite") in PRIORITES else "moyen terme"
        actions.append({"priorite": priorite, "action": _texte_propre(str(a["action"])),
                        "justification": _texte_propre(str(a.get("justification", ""))),
                        "cves": [str(c) for c in (a.get("cves") or [])]})
    if not actions:
        raise ValueError("Plan vide")
    actions.sort(key=lambda a: PRIORITES.index(a["priorite"]))
    return {"resume": _texte_propre(str(brut.get("resume", ""))), "actions": actions}


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

def regrouper_correctifs(plans: list[dict]) -> list[dict]:
    """
    Correctifs à déployer, à partir de toutes les failles déjà exploitées (KEV).

    1. Pour chaque bulletin : quelles machines il protège, quelles failles il corrige.
    2. Les bulletins équivalents (exactement les mêmes failles sur les mêmes machines,
       par exemple un bulletin Ubuntu par version du système) sont regroupés.
    3. Classement : nombre de machines protégées, puis failles de rançongiciels d'abord,
       puis nombre de failles corrigées.
    Utilisée par le rapport et par le tableau de bord, pour qu'ils affichent la même chose.
    """
    par_bulletin = {}
    for p in plans:
        for c in p.get("cves_kev", []):
            for b in c.get("bulletins", []):
                if not b.get("id"):
                    continue
                info = par_bulletin.setdefault(b["id"], {"url": b["url"], "machines": set(), "cves": set(),
                                                         "rancongiciel": False})
                info["machines"].add(p["ip"])
                info["cves"].add(c["id"])
                info["rancongiciel"] |= bool(c.get("rancongiciel"))

    # Un lien du guide Microsoft (MSRC) est inutile si un bulletin nommé (ex. MS17-010)
    # corrige déjà la même faille sur les mêmes machines
    for bid in [b for b in par_bulletin if b.startswith("MSRC ")]:
        info = par_bulletin[bid]
        if any(autre != bid and not autre.startswith("MSRC ") and info["cves"] <= a["cves"]
               and info["machines"] <= a["machines"] for autre, a in par_bulletin.items()):
            del par_bulletin[bid]

    groupes = {}
    for bid, info in par_bulletin.items():
        if bid.startswith("MSRC "):
            # Depuis 2017, Microsoft publie une mise à jour cumulative par mois qui corrige
            # toutes les failles d'un coup : un seul groupe par ensemble de machines.
            cle = (frozenset(info["machines"]), "MSRC")
        else:
            cle = (frozenset(info["machines"]), frozenset(info["cves"]))
        g = groupes.setdefault(cle, {"ids": [], "urls": {}, "machines": info["machines"],
                                     "cves": set(), "rancongiciel": False,
                                     "cumulative_microsoft": cle[1] == "MSRC"})
        g["ids"].append(bid)
        g["urls"][bid] = info["url"]
        g["cves"] |= info["cves"]
        g["rancongiciel"] |= info["rancongiciel"]
    for g in groupes.values():
        # les bulletins MSxx-xxx (les plus connus) d'abord, puis l'ordre alphabétique
        g["ids"].sort(key=lambda b: (not re.match(r"MS\d{2}-", b), b))
    return sorted(groupes.values(), key=lambda g: (-len(g["machines"]), not g["rancongiciel"],
                                                   -len(g["cves"]), g["ids"][0]))


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
        f"{len(plans)} actifs analysés. Par niveau de risque : "
        + ", ".join(f"{n} {compte[n]}" for n in ordre if n in compte) + ".",
        "",
    ]
    for p in plans:
        if p["compromission_probable"]:
            # la première raison décrit les indices observés (balayage, outils d'attaque)
            l += [f"**Incident en cours sur {p['ip']} :** {p['raisons'][0]} "
                  f"La machine doit être isolée immédiatement.", ""]

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

    groupes = regrouper_correctifs(plans)
    if groupes:
        l += ["", "## Correctifs prioritaires", "",
              "Bulletins des éditeurs qui corrigent des failles déjà exploitées (CISA KEV). Les bulletins "
              "équivalents (mêmes failles, mêmes machines, par exemple un bulletin Ubuntu par version) sont "
              "regroupés. Classés par nombre de machines protégées, puis rançongiciels d'abord, puis nombre "
              "de failles corrigées.", "",
              "| Bulletins | Machines | Failles KEV corrigées | Rançongiciel | Adresses |",
              "| --- | --- | --- | --- | --- |"]
        for g in groupes[:15]:
            if g["cumulative_microsoft"]:
                noms = f"[Mises à jour cumulatives Microsoft (guide MSRC)]({g['urls'][g['ids'][0]]})"
            else:
                noms = ", ".join(f"[{bid}]({g['urls'][bid]})" for bid in g["ids"])
            cves = ", ".join(sorted(g["cves"])[:3]) + (" ..." if len(g["cves"]) > 3 else "")
            l.append(f"| {noms} | {len(g['machines'])} | {len(g['cves'])} ({cves}) | "
                     f"{'oui' if g['rancongiciel'] else ''} | {', '.join(sorted(g['machines']))} |")
        if len(groupes) > 15:
            l += ["", f"*Et {len(groupes) - 15} autres groupes de bulletins, détaillés dans le tableau de bord.*"]

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
            l += [f"*Contrôle : identifiants cités par le LLM mais non vérifiés, retirés : "
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
        connues = {c["id"] for c in actif["risque"]["cves_a_traiter"] + actif.get("cves_kev", [])}
        plan, methode, retirees = plan_par_regles(actif, recos), "règles", []

        if client is not None and actif["risque"]["niveau"] in NIVEAUX_AVEC_LLM:
            try:
                plan = plan_par_llm(client, actif, recos)
                bulletins_connus = set(ids_bulletins(actif["risque"]["cves_a_traiter"]
                                                     + actif.get("cves_kev", [])))
                retirees = verifier_cves(plan, connues, bulletins_connus)
                methode = "règles + LLM"
                time.sleep(config.PAUSE_LLM)
            except RuntimeError:
                print(f"[Agent 5] {actif['ip']} : on garde le plan par règles")

        r = actif["risque"]
        plans.append({
            "ip": actif["ip"], "role": actif["role"], "niveau": r["niveau"], "score": r["score"],
            "raisons": r["raisons"], "compromission_probable": r.get("compromission_probable", False),
            "recommandations_regles": recos, "plan": plan, "methode": methode, "cves_retirees": retirees,
            "cves_kev": actif.get("cves_kev", []),
        })
        alerte = f"  [identifiant(s) inventé(s) retiré(s) : {', '.join(retirees)}]" if retirees else ""
        print(f"[Agent 5] {actif['ip']:<16} {r['niveau']:<9} {len(plan['actions'])} actions  ({methode}){alerte}")

    with open(dossier_sortie / "remediation.json", "w", encoding="utf-8") as f:
        json.dump(plans, f, indent=2, ensure_ascii=False)
    ecrire_rapport(plans, ecarts, balayages, dossier_sortie / "rapport.md")
    print(f"[Agent 5] Rapport écrit : {dossier_sortie / 'rapport.md'}")
    return plans