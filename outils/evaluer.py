"""
Évaluation finale : le classement des risques correspond-il aux attaques réelles ?

C'est le SEUL programme qui lit la vérité terrain (output/verite_terrain.json,
les étiquettes d'attaque de CICIDS2017). Les agents ne la lisent jamais :
sinon ils pourraient "tricher" en classant à risque les machines attaquées.

Questions posées :
  1. Les machines attaquées sont-elles en haut du classement des risques ?
  2. La machine qui a balayé le réseau a-t-elle été repérée ?

Utilisation :  python outils/evaluer.py
"""

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))
DOSSIER = RACINE / "output"


def main():
    risques = json.loads((DOSSIER / "risques.json").read_text(encoding="utf-8"))
    chemin = DOSSIER / "verite_terrain.json"
    if not chemin.exists():
        print("Pas de vérité terrain (output/verite_terrain.json) : lancer l'agent 1 sur les CSV.")
        return
    verite = json.loads(chemin.read_text(encoding="utf-8"))
    recues, emises = verite.get("recues", {}), verite.get("emises", {})

    rang = {r["ip"]: i for i, r in enumerate(risques, 1)}
    print(f"{len(risques)} actifs classés. Machines attaquées selon les étiquettes :\n")
    print(f"  {'IP':<16}{'Rang':>5}  {'Niveau':<9} Attaques reçues")
    for ip, attaques in sorted(recues.items(), key=lambda x: -sum(x[1].values())):
        r = next((x for x in risques if x["ip"] == ip), None)
        detail = ", ".join(f"{k} ({v})" for k, v in sorted(attaques.items(), key=lambda x: -x[1]))
        if r:
            print(f"  {ip:<16}{rang[ip]:>5}  {r['risque']['niveau']:<9} {detail}")
        else:
            print(f"  {ip:<16}{'-':>5}  {'absent':<9} {detail}")

    compromis = {r["ip"] for r in risques if r["risque"].get("compromission_probable")}
    print("\nMachines internes qui ENVOIENT des attaques (donc compromises) selon les étiquettes :")
    for ip, attaques in sorted(emises.items(), key=lambda x: -sum(x[1].values())):
        detail = ", ".join(f"{k} ({v})" for k, v in sorted(attaques.items(), key=lambda x: -x[1]))
        trouve = "repérée par nos agents" if ip in compromis else "NON repérée"
        print(f"  {ip:<16} {trouve:<24} {detail}")
    fausses = compromis - set(emises)
    print(f"\nSignalées compromises à tort : {sorted(fausses) or 'aucune'}")


if __name__ == "__main__":
    main()
