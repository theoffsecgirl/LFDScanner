
# 🔍 LFDScanner.py

LFDScanner es un script diseñado para detectar vulnerabilidades de **Local File Disclosure (LFD)** y **Directory Traversal** en una lista de dominios. Utiliza rutas comunes para comprobar si los servidores son vulnerables. 🚀

## ✨ Características

- 🖇️ Soporte para múltiples dominios desde un archivo de entrada.
- ✅ Validación automática de URLs.
- 🔍 Pruebas con rutas comunes de **Directory Traversal**.
- 🛠️ Personalización del `User-Agent`.
- 📜 Manejo detallado de errores HTTP y de conexión.
- ⚡ Escaneo multiproceso para máxima velocidad.
- 🎨 Interfaz colorida gracias a `colorama`.

## 🛠️ Instalación

1. Clona este repositorio o descarga el archivo `LFDScanner.py`.  
2. Asegúrate de tener **Python 3.6+** instalado.  
3. Instala las dependencias necesarias:

```bash
pip install -r requirements.txt
```

### 📄 Archivo `requirements.txt`

```plaintext
requests
colorama
```

## 🚀 Uso

Ejecuta el script con las siguientes opciones:

```bash
python LFDScanner.py -L <archivo_de_dominios> [-A <user_agent>] [-t <timeout>] [-c <archivo_configuración>]
```

### 🔧 Argumentos

| Argumento        | Descripción                                                                                 |
|-------------------|---------------------------------------------------------------------------------------------|
| `-L`, `--list`    | 📂 Archivo con los dominios a escanear (uno por línea).                                     |
| `-A`, `--agent`   | 🌐 `User-Agent` personalizado (por defecto: Mozilla/5.0 compatible).                        |
| `-t`, `--timeout` | ⏳ Tiempo máximo en segundos para esperar respuesta del servidor (por defecto: 5).          |
| `-c`, `--config`  | ⚙️ Archivo de configuración adicional (opcional).                                          |

### 🔥 Ejemplo

```bash
python LFDScanner.py -L dominios.txt -A "CustomUserAgent/1.0" -t 10
```

## 📝 Configuración

Puedes personalizar las rutas de prueba modificando esta sección del script:

```python
traversal_paths = [
    "../../../../etc/passwd",
    "../../../../etc/hosts",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts"
]
```

## 📌 Notas

- ⚠️ **Asegúrate de usar este script únicamente en dominios donde tengas permiso para realizar pruebas.**
- 📄 Las respuestas con contenido sensible (como `/etc/passwd`) se resaltan en los logs.

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! 💡 Si tienes mejoras o ideas, abre un issue o envía un pull request. 🚀

## 📜 Licencia

Este proyecto está bajo la licencia **MIT**. 🛡️
