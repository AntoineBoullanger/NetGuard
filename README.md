# NetGuard

**NetGuard** est une application de bureau développée en Python permettant de surveiller les connexions réseau d'un ordinateur, de visualiser son activité réseau et de détecter certains comportements potentiellement suspects.

Le projet utilise une interface graphique PySide6, la bibliothèque psutil pour accéder aux informations réseau et SQLite pour conserver un historique des alertes.

**Version :** 1.0.0  
**Statut :** Version 1 terminée  
**Langage :** Python  
**Interface :** PySide6

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Technologies](#technologies)
- [Structure du projet](#structure-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Lancement de l'application](#lancement-de-lapplication)
- [Tests automatisés](#tests-automatisés)
- [Surveillance réseau](#surveillance-réseau)
- [Détection des alertes](#détection-des-alertes)
- [Stockage des données](#stockage-des-données)
- [Limitations](#limitations)
- [Sécurité et utilisation responsable](#sécurité-et-utilisation-responsable)
- [Améliorations possibles](#améliorations-possibles)
- [Licence](#licence)

---

## Fonctionnalités

### Tableau de bord

Le tableau de bord permet de consulter plusieurs indicateurs liés à l'activité réseau :

- Nombre de connexions actives.
- Volume de données envoyées.
- Volume de données reçues.
- Débit entrant, appelé Download.
- Débit sortant, appelé Upload.
- Visualisation graphique de l'évolution du trafic réseau.

Les statistiques de trafic sont calculées à partir des compteurs réseau du système.

### Surveillance des connexions

NetGuard récupère les connexions réseau visibles depuis le système d'exploitation.

Les informations présentées comprennent :

- Le protocole réseau.
- L'adresse locale.
- L'adresse distante.
- L'état de la connexion.
- L'identifiant du processus, ou PID.
- Le nom du processus lorsqu'il est disponible.

Le tableau des connexions permet de consulter et de trier les informations affichées.

### Alertes de sécurité

NetGuard analyse les connexions à l'aide de règles de détection simples.

Les alertes peuvent être consultées dans l'interface graphique et enregistrées dans une base de données locale.

L'interface permet notamment de consulter les détails des alertes, de rechercher des informations, de filtrer les alertes par niveau de gravité et de supprimer une alerte sélectionnée.

### Historique et export

Les alertes sont enregistrées dans une base de données SQLite.

Les fonctionnalités associées comprennent :

- La conservation locale de l'historique.
- La consultation des alertes récentes.
- La suppression d'alertes.
- L'exportation des alertes au format CSV.

---

## Technologies

| Technologie | Utilisation                                           |
| ----------- | ----------------------------------------------------- |
| Python      | Logique de l'application                              |
| PySide6     | Interface graphique                                   |
| psutil      | Surveillance réseau et informations sur les processus |
| Matplotlib  | Graphiques du trafic réseau                           |
| SQLite      | Stockage local des alertes                            |
| pytest      | Tests automatisés                                     |

---

## Structure du projet

```text
NetGuard/
├── app/
│   ├── main.py
│   ├── network/
│   │   └── monitor.py
│   ├── ui/
│   │   └── dashboard.py
│   ├── detection/
│   │   └── rules.py
│   └── storage/
│       └── database.py
├── tests/
│   ├── test_monitor.py
│   ├── test_rules.py
│   └── test_database.py
├── screenshots/
├── .gitignore
├── README.md
└── requirements.txt
```

Le dossier `app/` contient le code de l'application.

Le dossier `tests/` contient les tests automatisés.

Le dossier `screenshots/` est destiné aux captures d'écran du projet.

Le fichier `requirements.txt` répertorie les dépendances Python.

---

## Prérequis

Pour exécuter NetGuard depuis ses sources, les éléments suivants sont nécessaires :

- Python 3.10 ou une version ultérieure.
- pip.
- Windows ou un système compatible avec les dépendances utilisées.
- Les droits nécessaires pour consulter les informations réseau souhaitées.

La visibilité des connexions et des processus peut varier en fonction du système d'exploitation et des permissions accordées.

---

## Installation

### 1. Récupérer le projet

Clonez le dépôt Git :

```bash
git clone <URL_DU_DEPOT_GITHUB>
```

Remplacez `<URL_DU_DEPOT_GITHUB>` par l'adresse réelle du dépôt.

Placez-vous ensuite dans le dossier du projet :

```bash
cd NetGuard
```

### 2. Créer un environnement virtuel

Sous Windows, ouvrez un terminal à la racine du projet et exécutez :

```powershell
python -m venv .venv
```

### 3. Activer l'environnement virtuel

Avec PowerShell :

```powershell
.\.venv\Scripts\Activate.ps1
```

Avec l'invite de commandes Windows :

```cmd
.venv\Scripts\activate.bat
```

### 4. Installer les dépendances

Une fois l'environnement virtuel activé :

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Les bibliothèques nécessaires seront installées dans l'environnement virtuel.

---

## Lancement de l'application

Depuis la racine du projet, avec l'environnement virtuel activé, exécutez :

```powershell
python -m app.main
```

La fenêtre NetGuard doit s'ouvrir.

L'application permet alors de consulter le tableau de bord, les connexions réseau et les alertes disponibles.

Si certaines informations sur les processus ne sont pas accessibles, vérifiez les permissions de votre compte Windows.

---

## Tests automatisés

NetGuard utilise pytest pour exécuter ses tests automatisés.

Pour lancer l'ensemble des tests, exécutez :

```powershell
python -m pytest -v
```

Pour exécuter uniquement les tests du moniteur réseau :

```powershell
python -m pytest tests/test_monitor.py -v
```

Pour exécuter les tests des règles de détection :

```powershell
python -m pytest tests/test_rules.py -v
```

Pour exécuter les tests de la base de données :

```powershell
python -m pytest tests/test_database.py -v
```

Les tests permettent de vérifier le comportement des principales fonctions du projet.

---

## Surveillance réseau

NetGuard utilise psutil pour récupérer les statistiques réseau et les connexions visibles depuis le système.

Les compteurs de trafic permettent de calculer les débits entrants et sortants à partir de la différence entre deux relevés successifs.

Les débits sont affichés en Ko/s.

Les informations de connexion comprennent notamment les adresses locales et distantes, le protocole, l'état de la connexion et le PID lorsqu'il est disponible.

La disponibilité des informations dépend des capacités du système et des permissions accordées à l'application.

---

## Détection des alertes

La détection est implémentée dans :

`app/detection/rules.py`

Les règles de la version 1 comprennent les situations suivantes.

### 1. Connexion vers un port distant sensible

NetGuard signale les connexions vers certains ports :

| Port | Service associé |
| ---: | --------------- |
|   21 | FTP             |
|   23 | Telnet          |
|  445 | SMB             |
| 3389 | RDP             |

La présence d'une connexion vers l'un de ces ports ne signifie pas nécessairement qu'une activité malveillante est en cours.

### 2. Processus non identifié

Une alerte informative peut être générée lorsqu'une connexion est établie et qu'aucun identifiant de processus n'est disponible.

Cette situation peut notamment résulter des restrictions de visibilité du système.

### 3. Connexions répétées vers une même adresse distante

NetGuard repère les adresses distantes apparaissant au moins dix fois dans les connexions analysées.

Cette règle constitue un indicateur simple. Un nombre élevé de connexions peut correspondre à une activité normale ou nécessiter une investigation supplémentaire.

---

## Stockage des données

NetGuard utilise SQLite pour enregistrer les alertes.

La logique de stockage se trouve dans :

`app/storage/database.py`

Les données enregistrées comprennent notamment :

- L'identifiant de l'alerte.
- La date et l'heure.
- Le niveau de gravité.
- La règle de détection.
- Le message associé.
- L'adresse distante, lorsqu'elle est disponible.
- Le PID, lorsqu'il est disponible.

Le fichier de base de données est créé localement par l'application.

Le fichier `netguard.db` est exclu du dépôt Git afin de ne pas publier l'historique local des alertes.

---

## Limitations

NetGuard est un outil de surveillance réseau et de détection heuristique. Il ne constitue pas une solution complète de cybersécurité.

Les limitations de la version 1 comprennent notamment :

- Les règles de détection sont simples et peuvent produire des faux positifs.
- Une connexion vers un port sensible n'est pas nécessairement malveillante.
- Les informations sur les processus peuvent être incomplètes.
- Les connexions visibles dépendent du système et des permissions.
- La détection ne remplace pas une analyse approfondie du trafic réseau.
- Les résultats doivent être interprétés dans leur contexte.

NetGuard ne garantit pas la détection de toutes les activités malveillantes.

---

## Sécurité et utilisation responsable

NetGuard est destiné à l'apprentissage, à l'observation de l'activité réseau et à la surveillance de systèmes que l'utilisateur est autorisé à administrer.

Utilisez l'application uniquement sur votre propre ordinateur ou sur des systèmes pour lesquels vous disposez d'une autorisation appropriée.

NetGuard ne remplace pas un pare-feu, un antivirus, un système professionnel de détection d'intrusion ou une plateforme de supervision de sécurité.

---

## Améliorations possibles

Les évolutions envisageables pour de futures versions comprennent :

- Des règles de détection plus avancées.
- Une déduplication persistante des alertes.
- Une surveillance détaillée par interface réseau.
- Des options de configuration supplémentaires.
- Des tests automatisés plus étendus.
- Une amélioration de la présentation des alertes.
- Une documentation illustrée par des captures d'écran.

Ces éléments sont des pistes d'évolution et ne sont pas nécessairement présents dans la version 1.

---

## Licence

Aucune licence open source n'est actuellement spécifiée dans ce dépôt.

En l'absence de licence, les conditions de réutilisation, de modification et de redistribution du code ne sont pas explicitement accordées.

Si le projet doit être distribué publiquement, une licence adaptée pourra être ajoutée ultérieurement.

---

## Version 1.0.0

La version 1 constitue la première version finalisée de NetGuard.

Elle rassemble une interface graphique de surveillance réseau, des règles de détection, un historique d'alertes local et des outils de consultation des connexions.

Le projet pourra évoluer dans de futures versions en fonction des besoins et des améliorations identifiées.
