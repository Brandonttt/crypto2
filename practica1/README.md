# Práctica: Criptografía Híbrida — código (Rama2)

La documentación completa está en el [README de la raíz](../README.md):
explicación del esquema, guía de la interfaz pestaña por pestaña, formato de
los archivos, guion del video y referencias.

## Ejecución rápida

```powershell
cd d:\crypto2\practica1
pip install -r requirements.txt
python archivo.py
```

Ejecuta siempre desde esta carpeta: el programa importa `pgp`, `motor` y
`protocolo`, que están aquí.

## Prueba automatizada

```powershell
python prueba_escenarios.py CARPETA_CON_LAS_LLAVES
```

## Módulos

| Archivo | Qué contiene |
|---|---|
| `archivo.py` | Interfaz gráfica (punto de entrada) |
| `pgp.py` | Lector OpenPGP RFC 4880 en Python puro |
| `motor.py` | Diffie‑Hellman, AES‑CBC, SHA‑256 |
| `protocolo.py` | Formato de los archivos y verificación |
| `prueba_escenarios.py` | Escenarios A–F del enunciado |

Cada módulo lleva sus referencias bibliográficas en el encabezado.
