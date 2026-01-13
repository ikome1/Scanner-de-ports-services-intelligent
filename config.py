#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration centralisée pour Scanner de Ports & Services Intelligent
"""

from pathlib import Path
from typing import Dict

# Chemins par défaut
BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / 'reports'
LOGS_DIR = BASE_DIR / 'logs'

# Configuration du scanner
SCANNER_CONFIG = {
    'default_threads': 100,
    'default_timeout': 1.0,
    'default_ports': list(range(1, 1001)),
    'max_ports': 65535,
}

# Dictionnaire des ports et services communs
SERVICES_COMMON = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

# Ports sensibles avec niveaux de risque
SENSITIVE_PORTS = {
    # Très critique
    22: {'service': 'SSH', 'risk': 'HIGH', 'description': 'Accès à distance - Utiliser des clés SSH, désactiver l\'authentification par mot de passe'},
    23: {'service': 'Telnet', 'risk': 'CRITICAL', 'description': 'Protocole non chiffré - Remplacer par SSH'},
    3389: {'service': 'RDP', 'risk': 'HIGH', 'description': 'Accès bureau à distance - Activer NLA, utiliser VPN'},
    445: {'service': 'SMB', 'risk': 'HIGH', 'description': 'Partage de fichiers Windows - Vérifier les versions, désactiver SMBv1'},
    139: {'service': 'NetBIOS', 'risk': 'MEDIUM', 'description': 'Service réseau Windows - Peut révéler des informations'},
    135: {'service': 'MSRPC', 'risk': 'MEDIUM', 'description': 'RPC Microsoft - Peut être exploité'},
    5900: {'service': 'VNC', 'risk': 'HIGH', 'description': 'Accès bureau distant - Non chiffré par défaut, utiliser SSH tunnel'},
    
    # Moyennement critique
    21: {'service': 'FTP', 'risk': 'MEDIUM', 'description': 'Protocole non chiffré - Utiliser SFTP/FTPS'},
    1433: {'service': 'MSSQL', 'risk': 'MEDIUM', 'description': 'Base de données - Restreindre l\'accès réseau'},
    3306: {'service': 'MySQL', 'risk': 'MEDIUM', 'description': 'Base de données - Restreindre l\'accès réseau'},
    5432: {'service': 'PostgreSQL', 'risk': 'MEDIUM', 'description': 'Base de données - Restreindre l\'accès réseau'},
    27017: {'service': 'MongoDB', 'risk': 'MEDIUM', 'description': 'Base de données NoSQL - Vérifier l\'authentification'},
    
    # Informations
    80: {'service': 'HTTP', 'risk': 'LOW', 'description': 'Serveur web - Rediriger vers HTTPS'},
    443: {'service': 'HTTPS', 'risk': 'LOW', 'description': 'Serveur web sécurisé - Vérifier les certificats'},
    25: {'service': 'SMTP', 'risk': 'LOW', 'description': 'Serveur de messagerie - Vérifier la configuration'},
}

# Configuration du logging
LOGGING_CONFIG = {
    'level': 'INFO',
    'log_dir': str(LOGS_DIR),
    'log_file': 'port_scanner_{timestamp}.log',
    'console': True,
    'file': True,
}

def get_config() -> Dict:
    """Retourne la configuration complète"""
    return {
        'scanner': SCANNER_CONFIG,
        'services_common': SERVICES_COMMON,
        'sensitive_ports': SENSITIVE_PORTS,
        'logging': LOGGING_CONFIG,
    }
