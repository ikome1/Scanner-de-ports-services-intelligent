# 📖 Guide d'Utilisation - Scanner de Ports

## Comment lancer un test sur un site web

### Méthode 1 : Scan rapide (recommandé pour commencer)

Pour tester rapidement un site web et voir les ports communs ouverts :

```bash
cd "/Users/idrissakome/Desktop/projet python/Scanner de ports & services intelligent"
python3 Scanner-ports.py example.com --fast
```

**Exemples concrets :**

```bash
# Test sur Google (scan rapide des ports communs)
python3 Scanner-ports.py google.com --fast

# Test sur un site avec résolution DNS automatique
python3 Scanner-ports.py github.com --fast

# Test avec sauvegarde du rapport
python3 Scanner-ports.py example.com --fast -o rapport_example.txt
```

### Méthode 2 : Scan des ports web courants

Pour scanner uniquement les ports HTTP/HTTPS et autres ports web :

```bash
# Ports web (80, 443, 8080, 8443)
python3 Scanner-ports.py example.com -p 80,443,8080,8443

# Ports web + SSH
python3 Scanner-ports.py example.com -p 22,80,443,8080,8443
```

### Méthode 3 : Scan complet (plus long)

Pour scanner une large plage de ports :

```bash
# Scan de tous les ports de 1 à 1000 (par défaut)
python3 Scanner-ports.py example.com

# Scan avec plus de threads (plus rapide)
python3 Scanner-ports.py example.com -t 200

# Scan d'une plage spécifique
python3 Scanner-ports.py example.com -p 1-5000 -t 300
```

### Méthode 4 : Scan avec timeout personnalisé

Pour les sites lents ou avec firewall :

```bash
# Timeout plus court (scan plus rapide mais peut manquer des ports)
python3 Scanner-ports.py example.com --timeout 0.5

# Timeout plus long (plus précis mais plus lent)
python3 Scanner-ports.py example.com --timeout 2.0
```

## 🌐 Exemples de sites de test

### Sites de test publics (légaux à scanner) :

1. **scanme.nmap.org** - Site de test officiel de Nmap
   ```bash
   python3 Scanner-ports.py scanme.nmap.org --fast
   ```

2. **testphp.vulnweb.com** - Site de test pour la sécurité web
   ```bash
   python3 Scanner-ports.py testphp.vulnweb.com -p 80,443
   ```

### Sites à ne PAS scanner sans autorisation :
- ❌ Sites gouvernementaux
- ❌ Sites bancaires
- ❌ Sites d'entreprises
- ❌ Tout site sans permission explicite

## 📊 Comprendre les résultats

### Exemple de sortie :

```
[*] Démarrage du scan de example.com
[*] Ports à scanner: 20
[*] Threads: 100

======================================================================
RAPPORT DE SCAN - example.com
======================================================================
Date: 2024-01-15 10:30:45
Durée du scan: 2.45 secondes
Ports scannés: 20
Ports ouverts: 2

PORTS OUVERTS ET SERVICES:

[FAIBLE]
  Port    80 - HTTP            | Apache/2.4.41
  Port   443 - HTTPS           | Apache/2.4.41 (OpenSSL/1.1.1)

======================================================================
RÉSUMÉ DES RISQUES DE SÉCURITÉ
======================================================================

CRITIQUE: 0
ÉLEVÉ:    0
MOYEN:    0
FAIBLE:   2
TOTAL:    2 ports ouverts
```

## ⚠️ Important : Utilisation éthique

**AVANT de scanner un site :**
1. ✅ Vérifiez que vous avez l'autorisation
2. ✅ Utilisez des sites de test publics si vous apprenez
3. ✅ Respectez les conditions d'utilisation des sites
4. ❌ Ne scannez JAMAIS sans autorisation

## 🚀 Commandes rapides de référence

```bash
# Scan rapide d'un site
python3 Scanner-ports.py <site.com> --fast

# Scan des ports web uniquement
python3 Scanner-ports.py <site.com> -p 80,443,8080,8443

# Scan complet avec rapport sauvegardé
python3 Scanner-ports.py <site.com> -o rapport.txt

# Scan optimisé (rapide et efficace)
python3 Scanner-ports.py <site.com> --fast -t 200 --timeout 0.5 -o resultat.txt
```

## 💡 Conseils

- Commencez toujours par `--fast` pour un aperçu rapide
- Utilisez `-o fichier.txt` pour sauvegarder les résultats
- Augmentez `-t` (threads) pour accélérer sur les grandes plages
- Réduisez `--timeout` si vous voulez scanner plus vite (mais moins précis)

