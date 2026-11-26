"""
Affiche la fiche complète d'un actif de l'inventaire, et s'il a été attaqué.

Pourquoi : le résumé de main.py ne montre que le top 5. Cet outil permet
de vérifier n'importe quelle machine, par exemple le serveur web.

Utilisation :  python outils/voir_actif.py 192.168.10.50
"""

import json
import sys
from pathlib import Path

DOSSIER = Path(__file__).resolve().parent.parent / "output"


def main():
    if len(sys.argv) < 2:
        print("Utilisation : python outils/voir_actif.py <ip>")
        return
    ip = sys.argv[1]

    inventaire = json.loads((DOSSIER / "inventaire.json").read_text(encoding="utf-8"))
    fiche = next((a for a in inventaire if a["ip"] == ip), None)
    if fiche is None:
        print(f"{ip} n'est pas dans l'inventaire.")
        return

    print(json.dumps(fiche, indent=2, ensure_ascii=False))

    verite = DOSSIER / "verite_terrain.json"
    if verite.exists():
        v = json.loads(verite.read_text(encoding="utf-8"))
        print("\nAttaques reçues (vérité terrain) :", v.get("recues", {}).get(ip) or "aucune")
        print("Attaques envoyées (vérité terrain) :", v.get("emises", {}).get(ip) or "aucune")


if __name__ == "__main__":
    main()
