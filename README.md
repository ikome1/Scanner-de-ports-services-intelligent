# 🔍 Scanner de Ports & Services Intelligent

Un scanner de ports TCP complet et intelligent qui identifie les services, détecte les ports sensibles et génère un rapport des risques de sécurité.

## ✨ Fonctionnalités

- ✅ **Scan de ports TCP** - Scan rapide et efficace avec gestion multi-threadée
- 🔍 **Identification des services** - Détection automatique des services via banner grabbing
- ⚠️ **Détection de ports sensibles** - Identification des ports critiques (SSH, FTP, SMB, RDP, etc.)
- 📊 **Analyse des risques** - Classification automatique des risques (CRITIQUE, ÉLEVÉ, MOYEN, FAIBLE)
- 📝 **Rapport détaillé** - Rapport complet avec recommandations de sécurité
- 🎨 **Interface colorée** - Affichage console avec codes couleur pour une meilleure lisibilité
- 💾 **Export de rapport** - Possibilité de sauvegarder le rapport dans un fichier

## 📋 Prérequis

- Python 3.6 ou supérieur
- Aucune dépendance externe requise (utilise uniquement les bibliothèques standard)

## 🚀 Installation

1. Clonez ou téléchargez le projet
2. Assurez-vous d'avoir Python 3.6+ installé :

```bash
python3 --version
```

3. Rendez le script exécutable (optionnel) :

```bash
chmod +x Scanner-ports.py
```

## 📖 Utilisation

### Utilisation de base

```bash
python3 Scanner-ports.py <cible>
```

Exemple :
```bash
python3 Scanner-ports.py 192.168.1.1
python3 Scanner-ports.py scanme.nmap.org
```

### Options disponibles

```bash
python3 Scanner-ports.py <cible> [options]
```

**Options :**

- `-p, --ports PORTS` : Spécifier les ports à scanner (ex: `80,443,22` ou `1-1000`)
- `-t, --threads N` : Nombre de threads pour le scan (défaut: 100)
- `--timeout SECONDS` : Timeout pour chaque connexion en secondes (défaut: 1.0)
- `-o, --output FICHIER` : Sauvegarder le rapport dans un fichier
- `--fast` : Scan rapide des ports communs uniquement
- `-h, --help` : Afficher l'aide

### Exemples d'utilisation

**Scan complet d'une adresse IP :**
```bash
python3 Scanner-ports.py 192.168.1.1
```

**Scan de ports spécifiques :**
```bash
python3 Scanner-ports.py 192.168.1.1 -p 80,443,22,3389,445
```

**Scan d'une plage de ports :**
```bash
python3 Scanner-ports.py 192.168.1.1 -p 1-1000
```

**Scan rapide (ports communs uniquement) :**
```bash
python3 Scanner-ports.py 192.168.1.1 --fast
```

**Scan avec plus de threads (plus rapide) :**
```bash
python3 Scanner-ports.py 192.168.1.1 -t 200
```

**Sauvegarder le rapport :**
```bash
python3 Scanner-ports.py 192.168.1.1 -o rapport_scan.txt
```

**Combinaison d'options :**
```bash
python3 Scanner-ports.py 192.168.1.1 -p 1-5000 -t 300 --timeout 0.5 -o scan_resultat.txt
```

## 📊 Types de risques détectés

### 🔴 CRITIQUE
- **Telnet (23)** : Protocole non chiffré - doit être remplacé par SSH

### 🟠 ÉLEVÉ
- **SSH (22)** : Accès à distance - utiliser des clés SSH
- **RDP (3389)** : Accès bureau à distance - activer NLA, utiliser VPN
- **SMB (445)** : Partage de fichiers Windows - vérifier les versions, désactiver SMBv1
- **VNC (5900)** : Accès bureau distant non chiffré par défaut

### 🔵 MOYEN
- **FTP (21)** : Protocole non chiffré - utiliser SFTP/FTPS
- **MySQL (3306)**, **MSSQL (1433)**, **PostgreSQL (5432)** : Bases de données - restreindre l'accès réseau
- **MongoDB (27017)** : Base de données NoSQL - vérifier l'authentification

### 🟢 FAIBLE
- **HTTP (80)** : Serveur web - rediriger vers HTTPS
- **HTTPS (443)** : Serveur web sécurisé - vérifier les certificats
- **SMTP (25)** : Serveur de messagerie - vérifier la configuration

## 📝 Format du rapport

Le rapport contient :

1. **Informations générales** : Date, durée du scan, nombre de ports scannés
2. **Ports ouverts** : Liste des ports ouverts avec les services détectés
3. **Banners** : Informations de service récupérées (si disponibles)
4. **Classification des risques** : Ports classés par niveau de risque
5. **Recommandations** : Suggestions de sécurité pour chaque port sensible

## ⚠️ Avertissements légaux

- Ce scanner est destiné à un usage éducatif et pour l'audit de sécurité de vos propres systèmes
- **NE SCANNEZ PAS** des systèmes sans autorisation explicite
- Le scan de ports non autorisé peut être illégal dans de nombreux pays
- Assurez-vous d'avoir les autorisations nécessaires avant d'utiliser cet outil

## 🔧 Dépannage

**Problème : "Permission denied"**
- Sur certains systèmes, les scans rapides nécessitent des privilèges administrateur
- Essayez avec `sudo` si nécessaire (mais ce n'est généralement pas requis)

**Problème : Scan très lent**
- Augmentez le nombre de threads avec `-t 200` ou plus
- Réduisez le timeout avec `--timeout 0.5`
- Utilisez `--fast` pour scanner uniquement les ports communs

**Problème : Pas de couleurs dans le terminal**
- Les codes couleur ANSI nécessitent un terminal compatible
- Le rapport fichier (`-o`) ne contient pas de codes couleur

## 📄 Licence

Ce projet est fourni tel quel, à des fins éducatives.

## 👤 Auteur

Scanner de Ports & Services Intelligent - Projet Python

---

**Note** : Utilisez cet outil de manière responsable et éthique. Le scan de ports non autorisé est illégal dans la plupart des juridictions.

