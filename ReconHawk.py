#!/usr/bin/env python3

import os
import subprocess
import requests
from lxml import html
from urllib.parse import urlparse

# Definición de colores
class Colores:
    VERDE = "\033[92m"
    ROJO = "\033[91m"
    AMARILLO = "\033[93m"
    CYAN = "\033[96m"  # Añadido el color CYAN
    RESET = "\033[0m"

def imprimir_banner():
    """Imprime un banner de bienvenida."""
    banner = r"""
     _____   _             ___     __    __   ___               ___   _         _ 
    |_   _| | |_    ___   / _ \   / _|  / _| / __|  ___   __   / __| (_)  _ _  | |
      | |   | ' \  / -_) | (_) | |  _| |  _| \__ \ / -_) / _| | (_ | | | | '_| | |
      |_|   |_||_| \___|  \___/  |_|   |_|   |___/ \___| \__|  \___| |_| |_|   |_|
    """
    print(Colores.VERDE + banner + Colores.RESET)

def validar_url(url):
    """Valida que la URL sea correcta."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Análisis de vulnerabilidades
def verificar_csrf(formulario):
    """Verifica si hay un token CSRF en el formulario."""
    csrf_token = formulario.xpath('//input[@name="csrf_token"]')
    if not csrf_token:
        print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad CSRF en el formulario." + Colores.RESET)
    else:
        print(Colores.VERDE + "✅ Token CSRF encontrado." + Colores.RESET)

def verificar_inyeccion_sql(url, user_agent=None):
    """Verifica inyección SQL enviando payloads comunes."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "' AND 1=1--"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}", headers=headers, timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                print(Colores.AMARILLO + f"⚠️ Posible vulnerabilidad de inyección SQL con el payload: {payload}" + Colores.RESET)
                vulnerable = True
        except requests.RequestException as e:
            print(Colores.ROJO + f"❌ Error al verificar inyección SQL avanzada: {e}" + Colores.RESET)
    if not vulnerable:
        print(Colores.VERDE + "✅ No se detectaron inyecciones SQL." + Colores.RESET)

def verificar_xss(url, user_agent=None):
    """Verifica vulnerabilidades XSS enviando payloads comunes."""
    payload = "<script>alert('XSS')</script>"
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, params={"q": payload}, headers=headers, timeout=10)
        if payload in response.text:
            print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad de Cross-Site Scripting (XSS) reflejado." + Colores.RESET)
        else:
            print(Colores.VERDE + "✅ No se detectaron vulnerabilidades XSS reflejado." + Colores.RESET)
    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al verificar XSS avanzado: {e}" + Colores.RESET)

def escanear_vulnerabilidades(url, opciones, user_agent=None):
    """Escanea la URL en busca de las vulnerabilidades seleccionadas."""
    if not validar_url(url):
        print(Colores.ROJO + "❌ URL inválida. Por favor, ingrese una URL válida." + Colores.RESET)
        return

    try:
        headers = {'User-Agent': user_agent} if user_agent else {}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        root = html.fromstring(response.content)

        # Verificar vulnerabilidades según las opciones seleccionadas
        formularios = root.xpath('//form')
        for formulario in formularios:
            if 'csrf' in opciones:
                verificar_csrf(formulario)
        if 'sql' in opciones:
            verificar_inyeccion_sql(url, user_agent)
        if 'xss' in opciones:
            verificar_xss(url, user_agent)

    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al escanear la URL: {e}" + Colores.RESET)

# Reconocimiento de subdominios usando Subfinder y HTTPX
def reconocimiento_dominio(dominio, user_agent=None):
    print(Colores.CYAN + f"[*] Iniciando reconocimiento de subdominios para {dominio}" + Colores.RESET)
    subfinder_cmd = f"subfinder -d {dominio} -silent -o subdomains.txt"
    httpx_cmd = f"httpx -l subdomains.txt -silent -o active_subdomains.txt"

    if user_agent:
        subfinder_cmd += f" --header 'User-Agent: {user_agent}'"
        httpx_cmd += f" --header 'User-Agent: {user_agent}'"

    try:
        subprocess.run(subfinder_cmd, shell=True, check=True)
        print(Colores.VERDE + "[+] Subfinder completado. Subdominios guardados en subdomains.txt" + Colores.RESET)
        subprocess.run(httpx_cmd, shell=True, check=True)
        print(Colores.VERDE + "[+] HTTPX completado. Subdominios activos guardados en active_subdomains.txt" + Colores.RESET)
    except subprocess.CalledProcessError as e:
        print(Colores.ROJO + f"❌ Error en el reconocimiento de subdominios: {e}" + Colores.RESET)

# Escaneo de puertos usando Nmap
def escaneo_puertos():
    print(Colores.CYAN + "[*] Iniciando escaneo de puertos en subdominios activos" + Colores.RESET)

    # Verificar si el archivo contiene subdominios
    if os.path.isfile("active_subdomains.txt") and os.path.getsize("active_subdomains.txt") > 0:
        nmap_cmd = "nmap -iL active_subdomains.txt -T4 -F -oN nmap_scan.txt"
        try:
            subprocess.run(nmap_cmd, shell=True, check=True)
            print(Colores.VERDE + "[+] Escaneo de puertos completado. Resultados guardados en nmap_scan.txt" + Colores.RESET)
        except subprocess.CalledProcessError as e:
            print(Colores.ROJO + f"❌ Error en el escaneo de puertos: {e}" + Colores.RESET)
    else:
        print(Colores.ROJO + "❌ No se encontraron subdominios activos para escanear." + Colores.RESET)

if __name__ == "__main__":
    imprimir_banner()  # Imprime el banner al inicio

    print("Seleccione la tarea que desea realizar:")
    print("1. Análisis de vulnerabilidades en URL")
    print("2. Reconocimiento de subdominios")
    print("3. Escaneo de puertos")
    print("4. Todas las anteriores")

    tarea = input("Ingrese el número de la opción: ")

    # Preguntar si desea usar un User-Agent personalizado
    usar_agente = input("¿Deseas añadir un User-Agent personalizado para evitar bloqueos del WAF? (y/n): ")
    user_agent = None
    if usar_agente.lower() == 'y':
        user_agent = input("Introduce el User-Agent que deseas usar: ")

    if tarea == '1':
        url_a_escanear = input("Ingrese la URL a escanear: ")
        print("Seleccione las vulnerabilidades a comprobar:")
        print("1. CSRF")
        print("2. Inyección SQL")
        print("3. XSS")
        print("4. Todas")

        seleccion = input("Ingrese el número de la opción: ")

        opciones_seleccionadas = []
        if seleccion == '1':
            opciones_seleccionadas.append('csrf')
        elif seleccion == '2':
            opciones_seleccionadas.append('sql')
        elif seleccion == '3':
            opciones_seleccionadas.append('xss')
        elif seleccion == '4':
            opciones_seleccionadas = ['csrf', 'sql', 'xss']
        else:
            print(Colores.ROJO + "❌ Opción no válida. Saliendo." + Colores.RESET)
            exit()

        escanear_vulnerabilidades(url_a_escanear, opciones_seleccionadas, user_agent)

    elif tarea == '2':
        dominio = input("Ingrese el dominio para el reconocimiento: ")
        reconocimiento_dominio(dominio, user_agent)

    elif tarea == '3':
        escaneo_puertos()

    elif tarea == '4':
        dominio = input("Ingrese el dominio para el reconocimiento y escaneo: ")
        reconocimiento_dominio(dominio, user_agent)
        escaneo_puertos()

    else:
        print(Colores.ROJO + "❌ Opción no válida. Saliendo." + Colores.RESET)
        exit()
