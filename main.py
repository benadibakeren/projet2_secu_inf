"""
Point d'entrée du projet : lance les agents dans l'ordre.

Pour l'instant seul l'agent 1 existe. Les autres seront ajoutés ici
au fur et à mesure (puis remplacés par un graphe LangGraph).

Utilisation :
    python main.py                       # lit data/zeek et data/csv
    python main.py --zeek data/exemple   # lit un autre dossier Zeek
"""

import argparse
from pathlib import Path

import config
from agents import decouverte


def main():
    parser = argparse.ArgumentParser(description="Découverte des actifs et des vulnérabilités")
    parser.add_argument("--zeek", type=Path, default=config.DOSSIER_ZEEK,
                        help="Dossier contenant conn.log, software.log, dns.log")
    parser.add_argument("--csv", type=Path, default=config.DOSSIER_CSV,
                        help="Dossier contenant les CSV TrafficLabelling de CICIDS2017")
    parser.add_argument("--sortie", type=Path, default=config.DOSSIER_SORTIE)
    args = parser.parse_args()

    csvs = sorted(args.csv.glob("*.csv")) if args.csv.exists() else []

    # Agent 1 : découverte des actifs
    inventaire = decouverte.executer(args.zeek, csvs, args.sortie)

    # Petit résumé à l'écran
    print("\nTop 5 des actifs les plus sollicités :")
    for a in inventaire[:5]:
        ports = ", ".join(str(p["port"]) for p in a["ports_ouverts"][:8]) or "aucun"
        logiciels = ", ".join(f"{l['nom']} {l['version']}" for l in a["logiciels"]) or "aucun détecté"
        print(f"  {a['ip']:<16} ports: {ports:<25} logiciels: {logiciels}")

    # Agents 2 à 5 : à venir
    # classification.executer(...)
    # vulnerabilites.executer(...)
    # risque.executer(...)
    # remediation.executer(...)


if __name__ == "__main__":
    main()
