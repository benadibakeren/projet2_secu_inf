"""
Tableau de bord du projet.

Il ne fait que LIRE les fichiers produits par les agents dans output/ :
aucun calcul, aucun appel au LLM ni à Internet. Il marche donc pendant
la présentation même sans réseau.

Lancement :
    streamlit run dashboard.py
    streamlit run dashboard.py -- output/exemple     (autre dossier de résultats)

Le thème sombre est réglé dans .streamlit/config.toml.
"""

import html
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

import config
from agents.remediation import regrouper_correctifs

DOSSIER = Path(sys.argv[1]) if len(sys.argv) > 1 else config.DOSSIER_SORTIE

PROJET = "Découverte des actifs et gestion des vulnérabilités"
EQUIPE = ["Keren BENADIBA", "Luc LENNE", "Matthieu ZOZOR"]
COURS = "8INF857 Sécurité informatique, UQAC, automne 2026"
ENSEIGNANT = "Fehmi Jaafar"

# Couleurs des niveaux de risque, choisies pour rester lisibles sur fond sombre
COULEURS = {"Critique": "#ef4444", "Élevé": "#f97316", "Moyen": "#eab308",
            "Faible": "#22c55e", "Inconnu": "#64748b"}
ORDRE = list(COULEURS)
COULEURS_PRIORITE = {"immédiate": "#ef4444", "court terme": "#f97316", "moyen terme": "#38bdf8"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, [class*="css"], .stMarkdown, .stTabs { font-family: 'Inter', sans-serif; }
.block-container { padding-top: 2rem; max-width: 1400px; }
header[data-testid="stHeader"] { background: transparent; }

.mono { font-family: 'JetBrains Mono', monospace; }
.muted { color: #8b95a7; }

.hero { padding: 1.6rem 1.8rem; border: 1px solid #232b38; border-radius: 16px;
        background: radial-gradient(120% 140% at 0% 0%, #13243a 0%, #0f1520 55%, #0b0f17 100%);
        margin-bottom: 1.2rem; }
.hero .kicker { font-size: .75rem; letter-spacing: .14em; text-transform: uppercase; color: #38bdf8;
                font-weight: 600; }
.hero h1 { font-size: 2.1rem; font-weight: 800; margin: .3rem 0 .4rem 0; line-height: 1.15;
           color: #f1f5f9; }
.hero .sub { color: #8b95a7; font-size: .95rem; }

.alerte { display: flex; gap: .9rem; align-items: center; padding: 1rem 1.2rem; border-radius: 12px;
          background: rgba(239,68,68,.10); border: 1px solid rgba(239,68,68,.45); margin-bottom: 1.2rem; }
.alerte .point { width: 12px; height: 12px; border-radius: 50%; background: #ef4444; flex: none;
                 box-shadow: 0 0 0 0 rgba(239,68,68,.7); animation: pulse 1.8s infinite; }
@keyframes pulse { 0% {box-shadow: 0 0 0 0 rgba(239,68,68,.7);} 70% {box-shadow: 0 0 0 12px rgba(239,68,68,0);}
                   100% {box-shadow: 0 0 0 0 rgba(239,68,68,0);} }
.alerte b { color: #fca5a5; }

.kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: .8rem; margin-bottom: .8rem; }
.kpi { background: #141a24; border: 1px solid #232b38; border-radius: 12px; padding: .9rem 1rem;
       border-top: 3px solid var(--c); }
.kpi .v { font-size: 2rem; font-weight: 800; color: #f1f5f9; line-height: 1.1; }
.kpi .l { font-size: .78rem; color: #8b95a7; text-transform: uppercase; letter-spacing: .08em; }

.repartition { display: flex; height: 10px; border-radius: 6px; overflow: hidden; margin: .2rem 0 1.6rem 0;
               border: 1px solid #232b38; }

.carte { background: #141a24; border: 1px solid #232b38; border-radius: 12px; padding: 1rem 1.2rem;
         margin-bottom: .7rem; }
.carte .titre { display: flex; justify-content: space-between; align-items: center; gap: .8rem; }
.carte .ip { font-family: 'JetBrains Mono', monospace; font-weight: 600; color: #f1f5f9; }
.carte .role { color: #8b95a7; font-size: .9rem; }
.carte .raison { color: #aab3c2; font-size: .85rem; margin-top: .5rem; }
.jauge { height: 6px; background: #1e2633; border-radius: 4px; margin-top: .7rem; overflow: hidden; }
.jauge > div { height: 100%; border-radius: 4px; }

.pastille { display: inline-block; padding: .15rem .6rem; border-radius: 999px; font-size: .75rem;
            font-weight: 700; color: #0b0f17; white-space: nowrap; }
.score { font-family: 'JetBrains Mono', monospace; font-weight: 600; color: #f1f5f9; }

.section { font-size: .8rem; letter-spacing: .12em; text-transform: uppercase; color: #8b95a7;
           font-weight: 600; margin: .4rem 0 .8rem 0; }
.obs { display: flex; gap: .7rem; align-items: flex-start; padding: .7rem 0; border-bottom: 1px solid #1e2633; }
.obs:last-child { border-bottom: none; }
.obs .ico { width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center;
            justify-content: center; flex: none; font-size: .95rem; }

.action { padding: .6rem .8rem; border-left: 3px solid var(--c); background: #10151e; border-radius: 6px;
          margin-bottom: .5rem; }
.action .j { color: #8b95a7; font-size: .85rem; margin-top: .2rem; }

.equipe { display: grid; grid-template-columns: repeat(3, 1fr); gap: .8rem; margin: .6rem 0 1.4rem 0; }
.membre { background: #141a24; border: 1px solid #232b38; border-radius: 12px; padding: 1.1rem; text-align: center; }
.membre .avatar { width: 52px; height: 52px; border-radius: 50%; margin: 0 auto .6rem auto; display: flex;
                  align-items: center; justify-content: center; font-weight: 800; color: #0b0f17;
                  background: linear-gradient(135deg, #38bdf8, #a78bfa); }
.membre .nom { font-weight: 700; color: #f1f5f9; }

.chaine { display: flex; align-items: stretch; gap: .4rem; flex-wrap: wrap; margin: .6rem 0 1rem 0; }
.etape { flex: 1; min-width: 150px; background: #141a24; border: 1px solid #232b38; border-radius: 10px;
         padding: .8rem; border-top: 3px solid var(--c); }
.etape .n { font-size: .72rem; color: #8b95a7; text-transform: uppercase; letter-spacing: .08em; }
.etape .t { font-weight: 700; color: #f1f5f9; margin: .15rem 0; }
.etape .d { font-size: .8rem; color: #aab3c2; }
.fleche { display: flex; align-items: center; color: #475569; }

.pied { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #1e2633; color: #64748b;
        font-size: .8rem; display: flex; justify-content: space-between; flex-wrap: wrap; gap: .5rem; }

@media (max-width: 900px) { .kpis { grid-template-columns: repeat(3, 1fr); }
                            .equipe { grid-template-columns: 1fr; } }
</style>
"""


# ---------------------------------------------------------------------------
# Lecture des fichiers et petits éléments d'affichage
# ---------------------------------------------------------------------------

@st.cache_data
def lire(nom: str, defaut=None):
    chemin = DOSSIER / nom
    if not chemin.exists():
        return defaut
    if chemin.suffix == ".json":
        return json.loads(chemin.read_text(encoding="utf-8"))
    if chemin.suffix == ".csv":
        return pd.read_csv(chemin)
    return chemin.read_text(encoding="utf-8")


def e(texte) -> str:
    """Échappe le texte avant de l'insérer dans du HTML (certains textes viennent du LLM)."""
    return html.escape(str(texte))


def pastille(niveau: str) -> str:
    return f"<span class='pastille' style='background:{COULEURS.get(niveau, '#64748b')}'>{e(niveau)}</span>"


def carte_actif(r: dict) -> str:
    q = r["risque"]
    c = COULEURS.get(q["niveau"], "#64748b")
    raison = e(q["raisons"][0]) if q["raisons"] else ""
    largeur = max(2, min(100, q["score"]))
    return f"""
    <div class='carte'>
      <div class='titre'>
        <div>{pastille(q['niveau'])} &nbsp;<span class='ip'>{e(r['ip'])}</span>
             <span class='role'>&nbsp;· {e(r['role'])}</span></div>
        <div class='score'>{q['score']:.1f}<span class='muted'> / 100</span></div>
      </div>
      <div class='raison'>{raison}</div>
      <div class='jauge'><div style='width:{largeur}%;background:{c}'></div></div>
    </div>"""


def pied_de_page():
    st.markdown(f"<div class='pied'><span>{e(PROJET)}</span>"
                f"<span>{' · '.join(e(n) for n in EQUIPE)} · {e(COURS)}</span></div>",
                unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Actifs et vulnérabilités", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

st.markdown(f"""
<div class='hero'>
  <div class='kicker'>Chaîne d'agents IA · CICIDS2017 · trafic du {e(config.DATE_CAPTURE)}</div>
  <h1>{e(PROJET)}</h1>
  <div class='sub'>{' · '.join(e(n) for n in EQUIPE)} &nbsp;|&nbsp; {e(COURS)}</div>
</div>""", unsafe_allow_html=True)

risques = lire("risques.json")
if not risques:
    st.error("Pas de résultats. Lancer d'abord la chaîne d'agents : python main.py")
    st.stop()

inventaire = lire("inventaire.json", [])
remediation = {p["ip"]: p for p in lire("remediation.json", [])}
balayages = lire("balayages.json", [])
ecarts = lire("ecarts_inventaire.json", {})
comptes = lire("comptes.json", [])

onglets = st.tabs(["Vue d'ensemble", "Inventaire", "Graphe des dépendances",
                   "Vulnérabilités et risques", "Recommandations", "Évaluation", "À propos"])

# ---------------------------------------------------------------------------
# 1. Vue d'ensemble
# ---------------------------------------------------------------------------
with onglets[0]:
    for r in risques:
        if r["risque"].get("compromission_probable"):
            st.markdown(f"""
            <div class='alerte'><div class='point'></div>
              <div><b>Incident en cours sur <span class='mono'>{e(r['ip'])}</span> :</b> {e(r['risque']['raisons'][0])}
              Action immédiate : l'isoler du réseau.</div>
            </div>""", unsafe_allow_html=True)

    compte = pd.Series([r["risque"]["niveau"] for r in risques]).value_counts()
    cartes = [f"<div class='kpi' style='--c:#38bdf8'><div class='l'>Actifs</div>"
              f"<div class='v'>{len(risques)}</div></div>"]
    for niveau in ORDRE:
        cartes.append(f"<div class='kpi' style='--c:{COULEURS[niveau]}'><div class='l'>{niveau}</div>"
                      f"<div class='v'>{int(compte.get(niveau, 0))}</div></div>")
    st.markdown(f"<div class='kpis'>{''.join(cartes)}</div>", unsafe_allow_html=True)

    # Barre de répartition des niveaux
    segments = "".join(
        f"<div title='{n} : {int(compte[n])}' style='flex:{int(compte[n])};background:{COULEURS[n]}'></div>"
        for n in ORDRE if compte.get(n, 0))
    st.markdown(f"<div class='repartition'>{segments}</div>", unsafe_allow_html=True)

    gauche, droite = st.columns([3, 2], gap="large")
    with gauche:
        st.markdown("<div class='section'>Les 5 actifs les plus à risque</div>", unsafe_allow_html=True)
        st.markdown("".join(carte_actif(r) for r in risques[:5]), unsafe_allow_html=True)
    with droite:
        st.markdown("<div class='section'>Observations du réseau</div>", unsafe_allow_html=True)
        obs = []
        sources = sorted({b["source"] for b in balayages})
        obs.append(("#ef4444", "⌁", f"<b>{len(balayages)}</b> balayages de ports depuis "
                    f"<span class='mono'>{e(', '.join(sources) or 'aucune source')}</span>"))
        for r in risques:
            if r["ports_exposes"]:
                obs.append(("#f97316", "⇄", f"<span class='mono'>{e(r['ip'])}</span> : ports utilisés "
                            f"depuis Internet <span class='mono'>{e(', '.join(map(str, r['ports_exposes'])))}</span>"))
        if ecarts.get("sans_logiciel_connu"):
            obs.append(("#64748b", "?", "Sans inventaire logiciel : <span class='mono'>"
                        f"{e(', '.join(ecarts['sans_logiciel_connu']))}</span>"))
        nb_kev = sum(r["resume_vulnerabilites"]["nb_kev"] for r in risques)
        obs.append(("#eab308", "!", f"<b>{nb_kev}</b> failles déjà exploitées dans le monde (CISA KEV), "
                    f"toutes machines confondues"))
        st.markdown("<div class='carte'>" + "".join(
            f"<div class='obs'><div class='ico' style='background:{c}22;color:{c}'>{i}</div><div>{t}</div></div>"
            for c, i, t in obs) + "</div>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# 2. Inventaire
# ---------------------------------------------------------------------------
with onglets[1]:
    st.markdown("<div class='section'>Inventaire des actifs · agents 1 et 2</div>", unsafe_allow_html=True)
    st.caption("Rôle décidé par des règles à partir des ports. Criticité (1 à 5) et justification par le LLM.")
    lignes = [{
        "IP": r["ip"],
        "Rôle": r["role"],
        "Criticité": r["risque"]["criticite"],
        "Ports ouverts": ", ".join(map(str, r["ports_ouverts"])),
        "Exposés à Internet": ", ".join(map(str, r["ports_exposes"])),
        "Logiciels": ", ".join(l["nom"] for l in r["logiciels"]),
    } for r in risques]
    st.dataframe(pd.DataFrame(lignes), hide_index=True, width="stretch", column_config={
        "Criticité": st.column_config.ProgressColumn("Criticité", min_value=0, max_value=5, format="%d / 5"),
    })

    st.markdown("<div class='section'>Comptes vus dans les authentifications (Kerberos, NTLM)</div>",
                unsafe_allow_html=True)
    if comptes:
        humains = [c for c in comptes if c["type"] == "utilisateur"]
        st.caption(f"{len(humains)} comptes utilisateurs et {len(comptes) - len(humains)} comptes machines "
                   "(nom terminé par $ : c'est l'ordinateur qui s'authentifie). Source : journaux Zeek.")
        st.dataframe(pd.DataFrame([{
            "Compte": c["nom"], "Type": c["type"], "Domaine": c["domaine"],
            "Privilèges probables": "oui" if c["privilege_probable"] else "",
            "Depuis les machines": ", ".join(c["machines_sources"]),
            "Auprès des serveurs": ", ".join(c["serveurs"]),
            "Authentifications": c["authentifications"], "Échecs": c["echecs"],
            "Protocoles": ", ".join(c["protocoles"]),
        } for c in comptes]), hide_index=True, width="stretch")
    else:
        st.info("Aucun compte : les CSV ne contiennent pas de noms d'utilisateurs. Lancer Zeek sur le PCAP "
                "et placer kerberos.log et ntlm.log dans data/zeek/ pour les découvrir.")

    choix = st.selectbox("Détail d'un actif", [r["ip"] for r in risques])
    r = next(x for x in risques if x["ip"] == choix)
    fiche = next((a for a in inventaire if a["ip"] == choix), {})
    a, b = st.columns([3, 2], gap="large")
    with a:
        st.markdown(f"""
        <div class='carte'>
          <div class='titre'><div>{pastille(r['risque']['niveau'])} &nbsp;<span class='ip'>{e(r['ip'])}</span>
          <span class='role'>&nbsp;· {e(r['role'])}</span></div></div>
          <div class='raison'><b>Pourquoi cette criticité :</b> {e(r['justification_criticite'])}</div>
          {"<div class='raison'><b>Données probables :</b> " + e(r['donnees_probables']) + "</div>"
           if r.get('donnees_probables') else ""}
          <div class='raison'>{''.join(f"<div>· {e(l['nom'])} <span class='muted'>({e(l['source'])})</span></div>"
                                       for l in r['logiciels'])}</div>
        </div>""", unsafe_allow_html=True)
    with b:
        if fiche:
            m1, m2, m3 = st.columns(3)
            m1.metric("Connexions reçues", f"{fiche.get('connexions_recues', 0):,}".replace(",", " "))
            m2.metric("Émises", f"{fiche.get('connexions_emises', 0):,}".replace(",", " "))
            m3.metric("Clients", fiche.get("nb_clients_uniques", 0))
            if fiche.get("ports_ouverts"):
                st.dataframe(pd.DataFrame(fiche["ports_ouverts"]).rename(columns={
                    "port": "Port", "protocole": "Protocole", "service": "Service",
                    "connexions": "Connexions", "nb_clients": "Clients"}), hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# 3. Graphe des dépendances
# ---------------------------------------------------------------------------
with onglets[2]:
    st.markdown("<div class='section'>Qui utilise qui · agent 1</div>", unsafe_allow_html=True)
    st.caption("Une flèche A vers B veut dire que A utilise B. Toutes les adresses externes sont "
               "regroupées en un seul nœud « Internet », sinon le graphe compte des milliers de nœuds.")
    liens = lire("dependances.csv")
    if liens is None or liens.empty:
        st.info("Pas de fichier dependances.csv.")
    else:
        internes = {r["ip"]: r for r in risques}
        nom = lambda ip: ip if ip in internes else "Internet"
        df = liens.assign(source=liens["source"].map(nom), target=liens["target"].map(nom))
        df = df[df["source"] != df["target"]].groupby(["source", "target"], as_index=False)["poids"].sum()
        seuil = st.slider("Masquer les liens de moins de N connexions", 1, 500, 20)
        avec_comptes = st.toggle("Afficher les comptes utilisateurs", value=False, disabled=not comptes,
                                 help="Relations compte → machine, à partir des journaux Zeek")
        df = df[df["poids"] >= seuil]
        scanners = {b["source"] for b in balayages}

        # size limite la taille du dessin : sans ça, les cases deviennent géantes
        dot = ["digraph G {", 'rankdir=LR; bgcolor=transparent; size="11,7"; ranksep=1.2; nodesep=0.35;',
               'node [style="filled,rounded", fontname="Helvetica", fontsize=11, fontcolor="#0b0f17", '
               'shape=box, color="#0b0f17", penwidth=1];',
               'edge [color="#475569", arrowsize=0.6];']
        noeuds = set(df["source"]) | set(df["target"])
        if avec_comptes:
            # les machines reliées à un compte sont toujours dessinées, même sous le seuil
            noeuds |= {ip for c in comptes if c["type"] == "utilisateur"
                       for ip in c["machines_sources"] if ip in internes}
        for n in sorted(noeuds):
            if n == "Internet":
                dot.append('"Internet" [shape=ellipse, style=filled, fillcolor="#1e293b", '
                           'fontcolor="#e5e9f0", color="#38bdf8", penwidth=2];')
            else:
                q = internes[n]["risque"]
                bord = ', penwidth=4, color="#f8fafc"' if n in scanners else ""
                dot.append(f'"{n}" [label="{n}\\n{internes[n]["role"]}", '
                           f'fillcolor="{COULEURS[q["niveau"]]}"{bord}];')
        if avec_comptes:
            # Un nœud violet par compte utilisateur, relié aux machines depuis lesquelles il se connecte
            for c in comptes:
                if c["type"] != "utilisateur":
                    continue
                forme = "doubleoctagon" if c["privilege_probable"] else "ellipse"
                dot.append(f'"compte:{c["nom"]}" [label="{c["nom"]}", shape={forme}, style=filled, '
                           f'fillcolor="#a78bfa", fontcolor="#0b0f17"];')
                for ip in c["machines_sources"]:
                    if ip in internes:
                        dot.append(f'"compte:{c["nom"]}" -> "{ip}" [style=dashed, color="#a78bfa", '
                                   f'arrowhead=none];')
        maxi = df["poids"].max() if not df.empty else 1
        for _, l in df.iterrows():
            epaisseur = 0.5 + 3 * l["poids"] / maxi
            dot.append(f'"{l["source"]}" -> "{l["target"]}" [penwidth={epaisseur:.1f}, '
                       f'tooltip="{int(l["poids"])} connexions"];')
        dot.append("}")
        st.graphviz_chart("\n".join(dot))
        legende = " &nbsp; ".join(f"{pastille(n)}" for n in ORDRE)
        st.markdown(f"<div class='muted' style='font-size:.85rem'>{legende} &nbsp;·&nbsp; "
                    f"bord blanc épais = machine qui a balayé le réseau"
                    f"{' &nbsp;·&nbsp; violet = compte utilisateur (octogone : privilèges probables)' if avec_comptes else ''}"
                    f"</div>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# 4. Vulnérabilités et risques
# ---------------------------------------------------------------------------
with onglets[3]:
    st.markdown("<div class='section'>Classement des risques · agents 3 et 4</div>", unsafe_allow_html=True)
    st.latex(r"\text{risque} = 100 \times \frac{\text{criticité}}{5} \times "
             r"\max\left(\frac{\text{CVSS}}{10} \times \text{probabilité} \times \text{accessibilité}\right)")
    st.caption("Probabilité : 1 si la faille est dans CISA KEV, sinon EPSS. Accessibilité : 1 depuis Internet, "
               "0,7 depuis le réseau interne, 0,4 en local. Une machine qui balaie le réseau, ou dont le trafic contient des outils d'attaque, "
               "est classée Critique.")

    tableau = pd.DataFrame([{
        "Rang": i, "IP": r["ip"], "Rôle": r["role"], "Niveau": r["risque"]["niveau"],
        "Score": r["risque"]["score"], "Criticité": r["risque"]["criticite"],
        "CVE": r["resume_vulnerabilites"]["nb_cve"], "KEV": r["resume_vulnerabilites"]["nb_kev"],
        "CVSS max": r["resume_vulnerabilites"]["cvss_max"],
    } for i, r in enumerate(risques, 1)])

    g, d = st.columns([3, 2], gap="large")
    with g:
        st.dataframe(
            tableau.style.map(lambda v: f"background-color:{COULEURS.get(v, '')};color:#0b0f17;font-weight:700"
                              if v in COULEURS else "", subset=["Niveau"])
            .format({"Score": "{:.1f}", "CVSS max": "{:.1f}"}),
            hide_index=True, width="stretch", height=38 * (len(tableau) + 1))
    with d:
        # Barres triées par score, colorées par niveau
        st.vega_lite_chart(tableau, {
            "background": "transparent",
            "mark": {"type": "bar", "cornerRadiusEnd": 4, "height": {"band": 0.7}},
            "encoding": {
                "y": {"field": "IP", "type": "nominal", "sort": "-x", "title": None,
                      "axis": {"labelFont": "JetBrains Mono", "labelColor": "#aab3c2"}},
                "x": {"field": "Score", "type": "quantitative", "title": "Score de risque (0 à 100)",
                      "scale": {"domain": [0, 100]},
                      "axis": {"gridColor": "#1e2633", "labelColor": "#8b95a7", "titleColor": "#8b95a7"}},
                "color": {"field": "Niveau", "type": "nominal",
                          "scale": {"domain": ORDRE, "range": [COULEURS[n] for n in ORDRE]},
                          "legend": {"orient": "bottom", "title": None, "labelColor": "#aab3c2"}},
                "tooltip": [{"field": "IP"}, {"field": "Rôle"}, {"field": "Score", "format": ".1f"},
                            {"field": "Niveau"}],
            },
            "height": {"step": 26},
            "config": {"view": {"stroke": None}},
        }, width="stretch", theme=None)
        st.caption("Barres triées par score. Le classement suit d'abord le niveau : une machine "
                   "probablement compromise est Critique même avec un score bas.")

    st.markdown("<div class='section'>Failles à traiter</div>", unsafe_allow_html=True)
    choix = st.selectbox("Actif", [r["ip"] for r in risques], key="cve", label_visibility="collapsed")
    r = next(x for x in risques if x["ip"] == choix)
    st.markdown(carte_actif(r), unsafe_allow_html=True)
    cves = r["risque"]["cves_a_traiter"]
    if cves:
        def premier_bulletin(c):
            b = (c.get("bulletins") or [None])[0]
            return b["url"] if b else None

        st.dataframe(pd.DataFrame([{
            "CVE": c["id"], "Logiciel": c["logiciel"], "CVSS": c["cvss"],
            "KEV": "oui" if c["dans_kev"] else "", "Rançongiciel": "oui" if c["rancongiciel"] else "",
            "EPSS": c["epss"], "Accès": c["acces"], "Menace": c["menace"],
            "Bulletins": ", ".join(b["id"] or b["editeur"] or "lien" for b in c.get("bulletins", [])),
            "Lien": premier_bulletin(c), "Description": c["description"],
        } for c in cves]), hide_index=True, width="stretch", column_config={
            "CVSS": st.column_config.NumberColumn(format="%.1f"),
            "Menace": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f"),
            "Lien": st.column_config.LinkColumn("Bulletin", display_text="ouvrir"),
        })

# ---------------------------------------------------------------------------
# 5. Recommandations
# ---------------------------------------------------------------------------
with onglets[4]:
    st.markdown("<div class='section'>Plans d'action · agent 5</div>", unsafe_allow_html=True)
    st.caption("Les constats des règles sont toujours affichés. Le plan détaillé est rédigé par le LLM, "
               "et chaque CVE ou bulletin qu'il cite est vérifié.")
    rapport = lire("rapport.md")
    if rapport:
        st.download_button("Télécharger le rapport complet (Markdown)", rapport,
                           file_name="rapport.md", mime="text/markdown")

    # Correctifs prioritaires : quel bulletin déployer, sur quelles machines.
    # Même calcul que le rapport (fonction partagée de l'agent 5).
    groupes = regrouper_correctifs(list(remediation.values()))
    if groupes:
        st.markdown("<div class='section'>Correctifs prioritaires (failles déjà exploitées)</div>",
                    unsafe_allow_html=True)
        st.caption("Bulletins équivalents regroupés. Classés par nombre de machines protégées, "
                   "puis rançongiciels d'abord, puis nombre de failles corrigées.")
        st.dataframe(pd.DataFrame([{
            "Bulletins": ("Mises à jour cumulatives Microsoft (guide MSRC)" if g["cumulative_microsoft"]
                          else ", ".join(g["ids"])),
            "Machines": len(g["machines"]),
            "Failles KEV corrigées": len(g["cves"]), "Rançongiciel": "oui" if g["rancongiciel"] else "",
            "Adresses": ", ".join(sorted(g["machines"])), "CVE corrigées": ", ".join(sorted(g["cves"])),
            "Lien": g["urls"][g["ids"][0]],
        } for g in groupes]), hide_index=True, width="stretch", column_config={
            "Lien": st.column_config.LinkColumn("Lien", display_text="ouvrir le bulletin")})

    for r in risques:
        p = remediation.get(r["ip"])
        if not p:
            continue
        titre = f"{r['ip']} · {r['role']} · {p['niveau']} ({p['score']:.1f})"
        with st.expander(titre, expanded=p["niveau"] == "Critique"):
            st.markdown(f"<div class='raison' style='margin-bottom:.8rem'>{e(p['plan']['resume'])}</div>",
                        unsafe_allow_html=True)
            if p["methode"] != "règles" and p["recommandations_regles"]:
                st.markdown("<div class='section'>Constats établis par les règles</div>", unsafe_allow_html=True)
                st.markdown("".join(
                    f"<div class='action' style='--c:{COULEURS_PRIORITE[a['priorite']]}'>"
                    f"<span class='pastille' style='background:{COULEURS_PRIORITE[a['priorite']]}'>"
                    f"{e(a['priorite'])}</span> &nbsp;{e(a['action'])}</div>"
                    for a in p["recommandations_regles"]), unsafe_allow_html=True)
                st.markdown("<div class='section'>Plan d'action détaillé</div>", unsafe_allow_html=True)
            st.markdown("".join(
                f"<div class='action' style='--c:{COULEURS_PRIORITE[a['priorite']]}'>"
                f"<span class='pastille' style='background:{COULEURS_PRIORITE[a['priorite']]}'>"
                f"{e(a['priorite'])}</span> &nbsp;{e(a['action'])}"
                f"<div class='j'>{e(a['justification'])}</div></div>"
                for a in p["plan"]["actions"]), unsafe_allow_html=True)
            if p["cves_retirees"]:
                st.warning(f"Identifiants inventés par le LLM et retirés : {', '.join(p['cves_retirees'])}")
            st.caption(f"Rédigé par : {p['methode']}")

# ---------------------------------------------------------------------------
# 6. Évaluation
# ---------------------------------------------------------------------------
with onglets[5]:
    st.markdown("<div class='section'>Évaluation avec la vérité terrain</div>", unsafe_allow_html=True)
    st.warning("Cet onglet affiche les étiquettes d'attaque de CICIDS2017. Aucun agent ne les lit : "
               "elles servent uniquement à vérifier le résultat final.")
    verite = lire("verite_terrain.json")
    if not verite or "recues" not in verite:
        st.info("Vérité terrain absente ou à l'ancien format : relancer l'agent 1 (python main.py).")
    else:
        rang = {r["ip"]: (i, r["risque"]["niveau"]) for i, r in enumerate(risques, 1)}
        compromis = {r["ip"] for r in risques if r["risque"].get("compromission_probable")}
        fausses = compromis - set(verite["emises"])
        trouvees = sum(1 for ip in verite["emises"] if ip in compromis)

        k1, k2, k3 = st.columns(3)
        if verite["recues"]:
            ip_max = max(verite["recues"], key=lambda ip: sum(verite["recues"][ip].values()))
            k1.metric(f"Rang de la machine la plus attaquée ({ip_max})",
                      f"{rang.get(ip_max, ('absent',))[0]} / {len(risques)}")
        k2.metric("Machines compromises repérées", f"{trouvees} / {len(verite['emises'])}")
        k3.metric("Fausses alertes de compromission", len(fausses))

        st.markdown("<div class='section'>Machines attaquées selon les étiquettes</div>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame([{
            "IP": ip, "Rang dans notre classement": rang.get(ip, ("absent", ""))[0],
            "Niveau": rang.get(ip, ("", ""))[1], "Attaques reçues": sum(a.values()),
            "Détail": ", ".join(f"{k} ({v})" for k, v in a.items()),
        } for ip, a in sorted(verite["recues"].items(), key=lambda x: -sum(x[1].values()))]),
            hide_index=True, width="stretch")

        st.markdown("<div class='section'>Machines internes qui envoient des attaques</div>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame([{
            "IP": ip, "Repérée par nos agents": "oui" if ip in compromis else "non",
            "Détail": ", ".join(f"{k} ({v})" for k, v in a.items()),
        } for ip, a in verite["emises"].items()]), hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# 7. À propos
# ---------------------------------------------------------------------------
with onglets[6]:
    st.markdown("<div class='section'>Le projet</div>", unsafe_allow_html=True)
    st.markdown(f"""
    <div class='carte'>
      <div style='font-size:1.3rem;font-weight:800;color:#f1f5f9'>{e(PROJET)}</div>
      <div class='raison'>Projet 2 du cours {e(COURS)}. Enseignant : {e(ENSEIGNANT)}.</div>
      <div class='raison'>Une chaîne de cinq agents part du trafic réseau d'une organisation pour découvrir ses
      actifs, juger leur importance, leur associer des vulnérabilités connues, mesurer le risque et proposer des
      actions. Jeu de données : CICIDS2017 (Université du Nouveau-Brunswick), trafic du jeudi 6 juillet 2017.</div>
    </div>""", unsafe_allow_html=True)

    st.markdown("<div class='section'>L'équipe</div>", unsafe_allow_html=True)
    initiales = lambda n: "".join(m[0] for m in n.split()[:2]).upper()
    st.markdown("<div class='equipe'>" + "".join(
        f"<div class='membre'><div class='avatar'>{e(initiales(n))}</div><div class='nom'>{e(n)}</div></div>"
        for n in EQUIPE) + "</div>", unsafe_allow_html=True)

    st.markdown("<div class='section'>La chaîne d'agents</div>", unsafe_allow_html=True)
    etapes = [
        ("1", "Découverte", "Machines, services, graphe, balayages", "#38bdf8", "code"),
        ("2", "Classification", "Rôle par règles, criticité par LLM", "#a78bfa", "règles + LLM"),
        ("3", "Vulnérabilités", "NVD, CISA KEV, filtre de date", "#38bdf8", "code + API"),
        ("4", "Risque", "Criticité × CVSS × probabilité × accès", "#38bdf8", "code + EPSS"),
        ("5", "Remédiation", "Plans d'action, rapport", "#a78bfa", "règles + LLM"),
    ]
    blocs = []
    for i, (n, t, d, c, techno) in enumerate(etapes):
        blocs.append(f"<div class='etape' style='--c:{c}'><div class='n'>Agent {n} · {techno}</div>"
                     f"<div class='t'>{t}</div><div class='d'>{d}</div></div>")
        if i < len(etapes) - 1:
            blocs.append("<div class='fleche'>→</div>")
    st.markdown(f"<div class='chaine'>{''.join(blocs)}</div>", unsafe_allow_html=True)
    st.caption("Bleu : code Python (exact, reproductible). Violet : LLM (jugement et rédaction), "
               "toujours encadré par des règles.")

    st.markdown("<div class='section'>Outils</div>", unsafe_allow_html=True)
    st.markdown("Python, pandas, networkx, Streamlit · API NVD 2.0, catalogue CISA KEV, EPSS (FIRST) · "
                "LLM : gpt-oss-120b via Groq (offre gratuite)")

    st.markdown("<div class='section'>Usage de l'IA générative</div>", unsafe_allow_html=True)
    st.info("Ce projet a été réalisé avec l'aide d'une IA générative (niveau « production partagée »). "
            "Les agents 2 et 5 utilisent un LLM ; tous leurs résultats sont encadrés par des règles et vérifiés.")

pied_de_page()
