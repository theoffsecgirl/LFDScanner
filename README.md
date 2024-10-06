# ReconHawk

## Descripción

**ReconHawk** es una herramienta todo en uno para Bug Bounty Hunters, diseñada para automatizar el reconocimiento y el análisis de vulnerabilidades en sitios web. Esta herramienta simplifica las tareas clave que los cazadores de bugs necesitan, como:

1. **Análisis de vulnerabilidades** (CSRF, SQL Injection, XSS).
2. **Reconocimiento de subdominios** utilizando Subfinder y HTTPX.
3. **Escaneo de puertos** utilizando Nmap.
4. Posibilidad de utilizar un **User-Agent personalizado** para evitar bloqueos de WAF (Web Application Firewall).

## Características

- **Análisis de vulnerabilidades**:
  - Verifica formularios para encontrar posibles vulnerabilidades de CSRF.
  - Envía payloads comunes para detectar posibles inyecciones SQL.
  - Envía payloads para verificar si el sitio es vulnerable a XSS reflejado.

- **Reconocimiento de subdominios**:
  - Usa Subfinder para detectar subdominios de un dominio específico.
  - Verifica qué subdominios están activos usando HTTPX.

- **Escaneo de puertos**:
  - Usa Nmap para escanear los puertos abiertos en los subdominios activos.

- **User-Agent personalizado**:
  - Se puede agregar un **User-Agent** personalizado en el análisis de vulnerabilidades y en el reconocimiento de subdominios.

## Requisitos

- **Python 3.x**
- **Subfinder** y **HTTPX** instalados para el reconocimiento de subdominios.
- **Nmap** instalado para el escaneo de puertos.

### Instalación de herramientas necesarias:

#### Instalar Subfinder
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
````
#### Instalar HTTPX
```
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```
#### Instalar Nmap
```
sudo apt-get install nmap
```
#### Instalación de dependencias de Python
```
pip install requests lxml
```
# Uso
## Ejecutar el script:
```
python3 ReconHawk.py

```

### Opciones:

1.	Análisis de vulnerabilidades en URL: Escanea una URL para verificar vulnerabilidades de CSRF, SQL Injection o XSS. Puedes seleccionar cuál o todas.
2.	Reconocimiento de subdominios: Detecta subdominios de un dominio específico y verifica cuáles están activos.
3.	Escaneo de puertos: Realiza un escaneo de puertos en los subdominios activos utilizando Nmap.4.	Todas las anteriores: Realiza todas las tareas mencionadas anteriormente.






