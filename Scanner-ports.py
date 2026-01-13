#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de Ports & Services Intelligent
Scanne les ports TCP, identifie les services et détecte les risques de sécurité
"""

import socket
import threading
import argparse
import time
import logging
from queue import Queue
from datetime import datetime
from typing import List, Dict, Tuple
import sys
import os

# Ajoute le répertoire parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.colors import Colors
from utils.logger import setup_logger, get_logger
from utils.validators import validate_target, validate_port_range, ValidationError
from config import SERVICES_COMMON, SENSITIVE_PORTS, SCANNER_CONFIG, LOGGING_CONFIG

# Configure le logging
logger = get_logger('port_scanner')

class PortScanner:
    def __init__(self, target: str, ports: List[int] = None, threads: int = None, timeout: float = None):
        # Valide la cible
        try:
            self.target = validate_target(target)
            logger.info(f"Initialisation du scanner pour: {target} (résolu: {self.target})")
        except ValidationError as e:
            logger.error(f"Erreur de validation de la cible: {e}")
            raise
        
        self.ports = ports if ports else SCANNER_CONFIG.get('default_ports', list(range(1, 1001)))
        self.threads = threads if threads else SCANNER_CONFIG.get('default_threads', 100)
        self.timeout = timeout if timeout else SCANNER_CONFIG.get('default_timeout', 1.0)
        self.open_ports = []
        self.services = {}
        self.lock = threading.Lock()
        self.queue = Queue()
        self.scan_start_time = None
        
    def get_service_banner(self, port: int) -> Tuple[str, str]:
        """Tente d'identifier le service et de récupérer le banner"""
        service_name = SERVICES_COMMON.get(port, 'Unknown')
        banner = ''
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Tente de recevoir le banner
                try:
                    sock.settimeout(2.0)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        # Essaye de détecter le service depuis le banner
                        banner_upper = banner.upper()
                        if 'SSH' in banner_upper:
                            service_name = 'SSH'
                        elif 'FTP' in banner_upper:
                            service_name = 'FTP'
                        elif 'HTTP' in banner_upper or 'Apache' in banner_upper or 'Nginx' in banner_upper:
                            service_name = 'HTTP' if port != 443 else 'HTTPS'
                        elif 'SMTP' in banner_upper:
                            service_name = 'SMTP'
                        elif 'MYSQL' in banner_upper or 'MARIADB' in banner_upper:
                            service_name = 'MySQL'
                        elif 'POSTGRES' in banner_upper:
                            service_name = 'PostgreSQL'
                        elif 'MSSQL' in banner_upper or 'MICROSOFT' in banner_upper:
                            service_name = 'MSSQL'
                        elif 'RDP' in banner_upper or 'TERMINAL' in banner_upper:
                            service_name = 'RDP'
                        elif 'VNC' in banner_upper:
                            service_name = 'VNC'
                        elif 'SMB' in banner_upper or 'Samba' in banner_upper:
                            service_name = 'SMB'
                except socket.timeout:
                    logger.debug(f"Timeout lors de la récupération du banner pour le port {port}")
                except socket.error as e:
                    logger.debug(f"Erreur socket lors de la récupération du banner pour le port {port}: {e}")
                except UnicodeDecodeError:
                    logger.debug(f"Erreur de décodage du banner pour le port {port}")
                finally:
                    if sock:
                        sock.close()
        except socket.error as e:
            logger.debug(f"Erreur de connexion pour le port {port}: {e}")
        except Exception as e:
            logger.warning(f"Erreur inattendue lors de la récupération du banner pour le port {port}: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return service_name, banner
    
    def scan_port(self, port: int) -> bool:
        """Scanne un port individuel"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Port ouvert, récupère les informations du service
                service_name, banner = self.get_service_banner(port)
                
                with self.lock:
                    self.open_ports.append(port)
                    self.services[port] = {
                        'name': service_name,
                        'banner': banner[:100] if banner else None  # Limite à 100 caractères
                    }
                
                logger.debug(f"Port {port} ouvert - Service: {service_name}")
                return True
            else:
                return False
        except socket.timeout:
            logger.debug(f"Timeout lors du scan du port {port}")
            return False
        except socket.error as e:
            logger.debug(f"Erreur socket lors du scan du port {port}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Erreur inattendue lors du scan du port {port}: {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def worker(self):
        """Fonction de travail pour les threads"""
        while True:
            port = self.queue.get()
            if port is None:
                break
            
            self.scan_port(port)
            self.queue.task_done()
    
    def scan(self) -> Dict:
        """Lance le scan complet"""
        print(f"{Colors.CYAN}[*] Démarrage du scan de {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Ports à scanner: {len(self.ports)}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Threads: {self.threads}{Colors.RESET}\n")
        
        self.scan_start_time = time.time()
        
        # Ajoute les ports à la queue
        for port in self.ports:
            self.queue.put(port)
        
        # Lance les threads workers
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        # Attend la fin de tous les threads
        self.queue.join()
        
        # Arrête les threads
        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()
        
        scan_duration = time.time() - self.scan_start_time
        
        # Trie les ports ouverts
        self.open_ports.sort()
        
        return {
            'target': self.target,
            'open_ports': self.open_ports,
            'services': self.services,
            'scan_duration': scan_duration,
            'total_ports_scanned': len(self.ports)
        }

class RiskAnalyzer:
    def __init__(self, scan_results: Dict):
        self.target = scan_results['target']
        self.open_ports = scan_results['open_ports']
        self.services = scan_results['services']
        self.risks = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
    
    def analyze(self) -> Dict:
        """Analyse les risques de sécurité"""
        for port in self.open_ports:
            service_info = self.services.get(port, {})
            service_name = service_info.get('name', 'Unknown')
            
            if port in SENSITIVE_PORTS:
                risk_info = SENSITIVE_PORTS[port]
                risk_level = risk_info['risk']
                
                self.risks[risk_level].append({
                    'port': port,
                    'service': service_name,
                    'description': risk_info['description'],
                    'banner': service_info.get('banner')
                })
            elif port < 1024:  # Ports privilégiés
                self.risks['LOW'].append({
                    'port': port,
                    'service': service_name,
                    'description': f'Port système ({service_name}) - Vérifier la configuration',
                    'banner': service_info.get('banner')
                })
            else:
                self.risks['LOW'].append({
                    'port': port,
                    'service': service_name,
                    'description': f'Service {service_name} détecté - Vérifier la configuration',
                    'banner': service_info.get('banner')
                })
        
        return self.risks
    
    def get_summary(self) -> str:
        """Génère un résumé des risques"""
        summary = []
        
        total_critical = len(self.risks['CRITICAL'])
        total_high = len(self.risks['HIGH'])
        total_medium = len(self.risks['MEDIUM'])
        total_low = len(self.risks['LOW'])
        
        summary.append(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        summary.append(f"{Colors.BOLD}RÉSUMÉ DES RISQUES DE SÉCURITÉ{Colors.RESET}")
        summary.append(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        
        summary.append(f"{Colors.RED}CRITIQUE: {total_critical}{Colors.RESET}")
        summary.append(f"{Colors.YELLOW}ÉLEVÉ:    {total_high}{Colors.RESET}")
        summary.append(f"{Colors.BLUE}MOYEN:    {total_medium}{Colors.RESET}")
        summary.append(f"{Colors.GREEN}FAIBLE:   {total_low}{Colors.RESET}")
        summary.append(f"{Colors.CYAN}TOTAL:    {len(self.open_ports)} ports ouverts{Colors.RESET}\n")
        
        return '\n'.join(summary)

class ReportGenerator:
    def __init__(self, scan_results: Dict, risks: Dict):
        self.scan_results = scan_results
        self.risks = risks
        self.analyzer = RiskAnalyzer(scan_results)
    
    def generate_console_report(self):
        """Génère un rapport dans la console"""
        target = self.scan_results['target']
        open_ports = self.scan_results['open_ports']
        services = self.scan_results['services']
        duration = self.scan_results['scan_duration']
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}RAPPORT DE SCAN - {target}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Durée du scan: {duration:.2f} secondes")
        print(f"Ports scannés: {self.scan_results['total_ports_scanned']}")
        print(f"Ports ouverts: {len(open_ports)}\n")
        
        if not open_ports:
            print(f"{Colors.GREEN}[+] Aucun port ouvert détecté{Colors.RESET}\n")
            return
        
        print(f"{Colors.BOLD}PORTS OUVERTS ET SERVICES:{Colors.RESET}\n")
        
        # Affiche les ports par niveau de risque
        for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            risk_ports = self.risks.get(risk_level, [])
            if risk_ports:
                color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.YELLOW,
                    'MEDIUM': Colors.BLUE,
                    'LOW': Colors.GREEN
                }.get(risk_level, Colors.RESET)
                
                print(f"{color}{Colors.BOLD}[{risk_level}]{Colors.RESET}")
                for item in risk_ports:
                    port = item['port']
                    service = item['service']
                    banner = item.get('banner')
                    
                    print(f"  {Colors.CYAN}Port {port:5d}{Colors.RESET} - {Colors.MAGENTA}{service:15s}{Colors.RESET}", end='')
                    if banner:
                        banner_preview = banner[:50] + '...' if len(banner) > 50 else banner
                        print(f" | {Colors.YELLOW}{banner_preview}{Colors.RESET}")
                    else:
                        print()
                print()
        
        # Résumé des risques
        print(self.analyzer.get_summary())
        
        # Détails des risques
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}RÉCOMMANDATIONS DE SÉCURITÉ{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        
        for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
            risk_items = self.risks.get(risk_level, [])
            if risk_items:
                color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.YELLOW,
                    'MEDIUM': Colors.BLUE
                }.get(risk_level, Colors.RESET)
                
                print(f"{color}{Colors.BOLD}[{risk_level}]{Colors.RESET}")
                for item in risk_items:
                    print(f"  {Colors.CYAN}Port {item['port']:5d} ({item['service']}):{Colors.RESET}")
                    print(f"    {item['description']}\n")
        
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    
    def generate_file_report(self, filename: str):
        """Génère un rapport dans un fichier"""
        with open(filename, 'w', encoding='utf-8') as f:
            target = self.scan_results['target']
            open_ports = self.scan_results['open_ports']
            duration = self.scan_results['scan_duration']
            
            f.write("="*70 + "\n")
            f.write(f"RAPPORT DE SCAN - {target}\n")
            f.write("="*70 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Durée du scan: {duration:.2f} secondes\n")
            f.write(f"Ports scannés: {self.scan_results['total_ports_scanned']}\n")
            f.write(f"Ports ouverts: {len(open_ports)}\n\n")
            
            if open_ports:
                f.write("PORTS OUVERTS ET SERVICES:\n\n")
                for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    risk_ports = self.risks.get(risk_level, [])
                    if risk_ports:
                        f.write(f"[{risk_level}]\n")
                        for item in risk_ports:
                            f.write(f"  Port {item['port']:5d} - {item['service']:15s}")
                            if item.get('banner'):
                                f.write(f" | {item['banner']}")
                            f.write("\n")
                        f.write("\n")
                
                # Résumé
                f.write("="*70 + "\n")
                f.write("RÉSUMÉ DES RISQUES\n")
                f.write("="*70 + "\n")
                f.write(f"CRITIQUE: {len(self.risks['CRITICAL'])}\n")
                f.write(f"ÉLEVÉ:    {len(self.risks['HIGH'])}\n")
                f.write(f"MOYEN:    {len(self.risks['MEDIUM'])}\n")
                f.write(f"FAIBLE:   {len(self.risks['LOW'])}\n\n")
                
                # Recommandations
                f.write("="*70 + "\n")
                f.write("RÉCOMMANDATIONS DE SÉCURITÉ\n")
                f.write("="*70 + "\n\n")
                
                for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    risk_items = self.risks.get(risk_level, [])
                    if risk_items:
                        f.write(f"[{risk_level}]\n")
                        for item in risk_items:
                            f.write(f"  Port {item['port']:5d} ({item['service']}):\n")
                            f.write(f"    {item['description']}\n\n")

def parse_ports(port_string: str) -> List[int]:
    """Parse une chaîne de ports (ex: '80,443,8000-8010')"""
    try:
        return validate_port_range(port_string)
    except ValidationError as e:
        logger.error(f"Erreur de validation des ports: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(
        description='Scanner de Ports & Services Intelligent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python Scanner-ports.py 192.168.1.1
  python Scanner-ports.py 192.168.1.1 -p 80,443,22,3389
  python Scanner-ports.py 192.168.1.1 -p 1-1000 -t 200
  python Scanner-ports.py scanme.nmap.org -o rapport.txt
        """
    )
    
    parser.add_argument('target', help='Adresse IP ou domaine cible')
    parser.add_argument('-p', '--ports', type=str, help='Ports à scanner (ex: 80,443 ou 1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Nombre de threads (défaut: 100)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout en secondes (défaut: 1.0)')
    parser.add_argument('-o', '--output', type=str, help='Fichier de sortie pour le rapport')
    parser.add_argument('--fast', action='store_true', help='Scan rapide (ports communs seulement)')
    
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Niveau de logging (défaut: INFO)')
    parser.add_argument('--log-file', type=str, help='Fichier de log (optionnel)')
    
    args = parser.parse_args()
    
    # Configure le logging
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    log_file = args.log_file or LOGGING_CONFIG.get('log_file', '').format(
        timestamp=datetime.now().strftime('%Y%m%d_%H%M%S')
    )
    
    setup_logger(
        name='port_scanner',
        level=log_level,
        log_file=log_file if LOGGING_CONFIG.get('file', True) else None,
        log_dir=LOGGING_CONFIG.get('log_dir', 'logs')
    )
    
    logger.info("=" * 70)
    logger.info("Démarrage du Scanner de Ports & Services Intelligent")
    logger.info("=" * 70)
    
    # Valide la cible
    try:
        target_ip = validate_target(args.target)
        if target_ip != args.target:
            print(f"{Colors.CYAN}[*] {args.target} résolu en {target_ip}{Colors.RESET}")
            logger.info(f"Cible résolue: {args.target} -> {target_ip}")
    except ValidationError as e:
        logger.error(f"Erreur de validation de la cible: {e}")
        print(f"{Colors.RED}[!] Erreur: {e}{Colors.RESET}")
        sys.exit(1)
    
    # Détermine les ports à scanner
    if args.fast:
        ports = list(SERVICES_COMMON.keys())
        print(f"{Colors.YELLOW}[!] Mode rapide: scan des ports communs uniquement{Colors.RESET}\n")
        logger.info(f"Mode rapide: {len(ports)} ports communs")
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
            logger.info(f"Ports spécifiés: {len(ports)} port(s)")
        except ValidationError as e:
            logger.error(f"Erreur de validation des ports: {e}")
            print(f"{Colors.RED}[!] Erreur: {e}{Colors.RESET}")
            sys.exit(1)
    else:
        ports = None  # Utilisera la valeur par défaut (1-1000)
        logger.info("Utilisation des ports par défaut (1-1000)")
    
    # Lance le scan
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        scan_results = scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrompu par l'utilisateur{Colors.RESET}")
        sys.exit(1)
    
    # Analyse les risques
    analyzer = RiskAnalyzer(scan_results)
    risks = analyzer.analyze()
    
    # Génère le rapport
    report_generator = ReportGenerator(scan_results, risks)
    report_generator.generate_console_report()
    
    # Sauvegarde dans un fichier si demandé
    if args.output:
        report_generator.generate_file_report(args.output)
        print(f"{Colors.GREEN}[+] Rapport sauvegardé dans {args.output}{Colors.RESET}\n")

if __name__ == '__main__':
    main()

