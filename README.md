# NetWatch — Outil d'Analyse de Trafic Réseau

## Description
Application web complète pour capturer et analyser le trafic réseau en temps réel,
avec détection de connexions suspectes, analyse de fichiers PCAP, et génération de rapports.

## Fonctionnalités
- Authentification sécurisée
- Capture de trafic en temps réel (Live)
- Analyse de fichiers PCAP uploadés
- Détection automatique de connexions suspectes
- Tableau de bord avec statistiques et graphiques
- Génération de rapports complets
- Filtres par IP, protocole, statut
- Export JSON des rapports

## Installation et Démarrage

### Étape 1 — Prérequis
- Python 3.8 ou plus récent
- pip installé

### Étape 2 — Installer les dépendances
```
pip install flask flask-socketio scapy eventlet
```
Ou avec le fichier requirements :
```
pip install -r requirements.txt
```

### Étape 3 — Lancer l'application

**Sur Linux / macOS (nécessite sudo pour la vraie capture réseau) :**
```
sudo python3 app.py
```

**Sur Windows :**
```
python app.py
```
> Note : Sur Windows, installez Npcap depuis https://npcap.com pour la capture réelle.

### Étape 4 — Ouvrir dans le navigateur
```
http://localhost:5000
```

## Identifiants par défaut
- Utilisateur : `admin`
- Mot de passe : `admin123`

## Note sur la capture réseau
- **Avec Scapy installé + droits root** : capture réelle des paquets
- **Sans droits root ou sans Scapy** : mode démonstration automatique (simulation réaliste)

## Structure du projet
```
network-analyzer/
├── app.py              # Application Flask principale
├── requirements.txt    # Dépendances Python
├── templates/
│   ├── base.html       # Layout commun
│   ├── login.html      # Page de connexion
│   ├── dashboard.html  # Tableau de bord
│   ├── capture.html    # Capture en temps réel
│   ├── pcap.html       # Analyse fichier PCAP
│   └── reports.html    # Génération de rapports
├── uploads/            # Fichiers PCAP uploadés
└── reports/            # Rapports générés (JSON)
```

## Technologies utilisées
- **Backend** : Python, Flask, Flask-SocketIO
- **Capture** : Scapy
- **Frontend** : HTML5, CSS3, JavaScript vanilla
- **Graphiques** : Chart.js
- **Temps réel** : WebSockets (Socket.IO)
=======
# ICMD — Network Traffic Analyzer 🔐

Outil d'analyse de trafic réseau en temps réel
développé dans le cadre d'un projet académique.

## 📋 Description
ICMD permet de capturer et analyser le trafic
réseau en temps réel et de détecter automatiquement
les comportements suspects.

## ⚙️ Fonctionnalités
- Capture réseau en temps réel via Scapy
- Détection automatique des attaques
- Analyse des fichiers PCAP
- Génération de rapports PDF
- Interface web temps réel (WebSocket)

## 🔍 Attaques Détectées
- SYN Scan et Xmas Scan
- Connexions sur ports dangereux
- Flags TCP suspects
- Paquets anormalement grands

## 🛠️ Stack Technique
- Python 3.8+
- Flask + Flask-SocketIO
- Scapy
- ReportLab
- HTML5 / CSS3 / JavaScript

## 🚀 Installation
# Cloner le projet
git clone https://github.com/username/ICMD.git
cd ICMD

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'application
sudo python3 app.py

# Ouvrir le navigateur
http://localhost:5000

## 👤 Connexion par défaut
Login    : admin
Password : admin123

## 👨‍💻 Auteurs
- Dada Mohammed
- Idriss Chrigui

## 👨‍🏫 Encadrant
M. Agrima Abdellah

## 🎓 Université
EST Safi — Université Cadi Ayyad
A.U 2025/2026

