# Práctica: Criptografía Híbrida — **Rama2**

**ESCOM / IPN** — Dra. Nidia A. Cortez Duarte

Esta rama implementa el **esquema híbrido con Diffie‑Hellman**, es decir el
**diagrama inferior** del enunciado: la llave `K` y el vector de inicialización
`IV` de AES‑CBC se acuerdan mediante dos intercambios Diffie‑Hellman
independientes, y la firma digital es RSA sobre el hash SHA‑256 del mensaje en
claro, usando las llaves OpenPGP que cada integrante ya tiene publicadas.

> **En este esquema RSA nunca cifra: solo firma.** Lo que cifra es AES, con una
> llave que ninguna de las dos partes llegó a enviar. Si esta frase no te queda
> clara todavía, lee la sección [Cómo funciona, paso a paso](#cómo-funciona-paso-a-paso).

---

## Índice

1. [Servicios criptográficos](#servicios-criptográficos)
2. [Instalación y ejecución](#instalación-y-ejecución)
3. [Estructura del código](#estructura-del-código)
4. [Qué hace cada llave](#qué-hace-cada-llave)
5. [Preparación previa](#preparación-previa-una-sola-vez)
6. [Guía de la interfaz, pestaña por pestaña](#guía-de-la-interfaz-pestaña-por-pestaña)
7. [Cómo funciona, paso a paso](#cómo-funciona-paso-a-paso)
8. [Formato de los archivos](#formato-de-los-archivos)
9. [Prueba automatizada](#prueba-automatizada)
10. [Guion para el video](#guion-para-el-video)
11. [Diferencias con el diagrama del PDF](#diferencias-con-el-diagrama-del-pdf)
12. [Problemas comunes](#problemas-comunes)
13. [Referencias](#referencias)

---

## Servicios criptográficos

| Servicio | Cómo se ofrece | Dónde ocurre |
|---|---|---|
| **Confidencialidad** | AES‑128‑CBC; `K` e `IV` derivados por Diffie‑Hellman (RFC 3526, grupo de 2048 bits) | `motor.py` |
| **Integridad** | SHA‑256 del mensaje, protegido por la firma | `motor.py`, `protocolo.py` |
| **Autenticación** | La firma solo verifica con la llave pública que el autor publicó en su página web | `protocolo.py` |
| **No repudio** | Solo el poseedor de la llave privada RSA pudo producir esa firma | `protocolo.py` |

El usuario elige **uno de dos o dos de dos** servicios, desde el menú `Proceso`
o desde las casillas de la pestaña del emisor.

---

## Instalación y ejecución

```powershell
cd d:\crypto2\practica1
pip install -r requirements.txt
python archivo.py
```

**Ejecuta siempre desde la carpeta `practica1`**, no desde la raíz: el programa
importa `pgp`, `motor` y `protocolo`, que viven ahí. Desde otra carpeta falla
con `ModuleNotFoundError`.

`tkinter` viene incluido con Python en Windows y macOS. En Debian/Ubuntu:
`sudo apt install python3-tk`.

Desde VS Code basta abrir `practica1/archivo.py` y pulsar **F5**.

---

## Estructura del código

| Archivo | Qué contiene | Líneas aprox. |
|---|---|---|
| `practica1/archivo.py` | Interfaz gráfica: menú, las tres pestañas de trabajo y la de referencias | 850 |
| `practica1/pgp.py` | **Lector OpenPGP RFC 4880 en Python puro**. Desarma el `.asc`, recorre los paquetes, extrae `n` y `e`, y descifra el material privado protegido con S2K para obtener `d`, `p`, `q` | 530 |
| `practica1/motor.py` | Diffie‑Hellman, derivación de llave, AES‑CBC y SHA‑256 | 145 |
| `practica1/protocolo.py` | Formato de los archivos que viajan por la nube, firma/verificación e identificación del autor | 380 |
| `practica1/prueba_escenarios.py` | Prueba automatizada de los escenarios A–F del enunciado, sin interfaz | 205 |
| `practica1/requirements.txt` | Dependencias: `cryptography`, `requests` | — |

Cada módulo lleva al inicio las **referencias bibliográficas** de los algoritmos
que reutiliza, como exige el enunciado. La pestaña 4 de la aplicación las
muestra completas.

### Por qué `pgp.py` existe

Las llaves del equipo son archivos `.asc` de GnuPG. Para firmar con ellas hace
falta el material matemático que hay dentro, y ninguna librería estándar de
Python lo lee. Este módulo lo hace:

1. `dearmor()` — quita el `-----BEGIN PGP-----`, decodifica Base64, valida el CRC‑24.
2. `iter_packets()` — recorre los paquetes (formatos antiguo y nuevo de cabecera).
3. `_parse_public_body()` — del paquete de llave pública saca el módulo `n` y el exponente `e`.
4. `s2k_derive()` — convierte tu **frase de paso** en una llave simétrica (S2K: Simple, Salted o Iterated+Salted).
5. Con esa llave descifra en modo CFB el bloque privado y obtiene `d`, `p`, `q`.
6. `_build_private()` — reconstruye la llave RSA usable, recalculando los parámetros CRT.

Solo se soportan llaves **RSA**. Si alguien del equipo generó su llave con
GnuPG 2.3 o posterior sin especificar el algoritmo, puede tener Ed25519 y el
programa lo dirá con un mensaje claro.

---

## Qué hace cada llave

| Llave | Única función | ¿Se publica? |
|---|---|---|
| Tu `.asc` **privado** | Firmar tus mensajes y derivar tus exponentes DH `b`, `d` | **Nunca** |
| Tu `.asc` **público** | Que otros verifiquen tus firmas | Sí, en tu página web |
| `Kb`, `Kd` (tus valores DH públicos) | Que otros deriven `K` e `IV` para escribirte | Sí, en tu página web |
| `Ka`, `Kc` (efímeros del emisor) | Que el receptor derive los mismos `K` e `IV` | Sí, dentro del paquete |
| `K`, `IV` de AES | Cifrar y descifrar | **Nunca**: existen solo en memoria, en los dos extremos |

Tu llave privada nunca sale de tu computadora; solo vive en memoria mientras la
aplicación está abierta.

---

## Preparación previa (una sola vez)

### 1. Exportar tus llaves

```powershell
# pública (la que ya tienes publicada)
gpg --output mi_pub.asc  --armor --export             TU_CORREO

# privada
gpg --output mi_priv.asc --armor --export-secret-keys TU_CORREO
```

Usa `--output`, **no** `>`: en PowerShell 5.1 la redirección puede reescribir el
archivo en UTF‑16 y corromperlo. Tampoco abras ni guardes un `.asc` con Notepad.

Verifica que quedó completo — debe terminar con una línea corta que empieza con
`=` y luego `-----END PGP ... KEY BLOCK-----`:

```powershell
Get-Content mi_priv.asc -Tail 2
```

### 2. Publicar dos archivos en tu página web

| Archivo | De dónde sale |
|---|---|
| `mi_pub.asc` | Del comando de arriba (probablemente ya lo tienes publicado) |
| `mi_dh.json` | Lo genera la aplicación: **Llaves → Exportar mis parámetros DH públicos** |

El segundo contiene `Kb` (para derivar la llave `K` de AES) y `Kd` (para derivar
el `IV`), **firmados con tu llave privada RSA**. Quien los descargue verifica esa
firma contra tu `.asc` de la misma página: eso convierte el intercambio en un
**Diffie‑Hellman autenticado**, inmune al ataque de hombre en medio. Si alguien
sustituye los valores en el camino, la aplicación los rechaza y no cifra.

Tu exponente privado DH **se deriva de tu propia llave RSA privada**, así que no
hay archivo de estado que perder: al recargar el mismo `.asc` salen siempre los
mismos `Kb` y `Kd` que publicaste.

---

## Guía de la interfaz, pestaña por pestaña

### Menú superior

| Menú | Opción | Qué hace |
|---|---|---|
| **Proceso** | Cifrado + Firma (dos de dos) | Marca ambos servicios y salta a la pestaña 2 |
| | Solo Cifrado | Marca confidencialidad y salta a la pestaña 2 |
| | Solo Firma | Marca firma y salta a la pestaña 2 |
| | Descifrado / Verificación | Salta a la pestaña 3 |
| **Llaves** | Cargar mi llave privada `.asc` | Igual que el botón de la pestaña 1 |
| | Exportar mis parámetros DH públicos | Genera el `.json` para tu página web |
| **Ayuda** | Referencias y algoritmos | Abre la pestaña 4 |

Este menú es el que pide el enunciado: permite elegir *cifrado/descifrado*,
*firma/verificación*, uno de dos o dos de dos.

---

### Pestaña 1 — *Mi identidad (.asc)*

**Siempre es el primer paso**, seas emisor o receptor.

| Elemento | Qué hacer |
|---|---|
| **Seleccionar mi llave privada .asc** | Elige tu archivo. Si está protegida, pedirá la frase de paso |
| **Exportar mis parámetros DH públicos** | Guarda el `.json` que subirás a tu página web |
| *Detalle del certificado* | Muestra lo que el programa leyó del archivo |

Al cargarla verás:

```
[OK] Usuario (User ID)  : Alicia Ramirez <alicia@escom.ipn.mx>
[  ] Key ID             : 8E2800F8BD664B99
[  ] Huella digital     : 8E28 00F8 D9D9 DBC6 63FD EFD1 6C10 6884 BD66 4B99
[  ] Algoritmo          : RSA (cifrado y firma), 2048 bits

Par Diffie-Hellman estático derivado de esta llave:
     Kb (para la llave K de AES) : 17bbe95033bd77e7...
     Kd (para el IV de AES)      : 4ff7af0a32120a9d...
```

**Qué señalar en el video:** que la frase de paso es lo que descifra el material
privado dentro del `.asc`, y que `Kb`/`Kd` se derivan de la llave privada, por
lo que nadie más puede reproducirlos.

---

### Pestaña 2 — *Emisor: cifrar y firmar*

Es la pestaña de Alicia y de Candy. Cuatro bloques, en orden.

#### Bloque 1 — Servicios criptográficos a ofrecer

Dos casillas independientes:

- **Confidencialidad** (Diffie‑Hellman + AES‑128‑CBC)
- **Firma digital** (autenticación + integridad + no repudio)

Puedes marcar una, la otra, o ambas. A la derecha aparece qué identidad firmará.

#### Bloque 2 — Destinatario

**El orden importa: primero el `.asc`, después los parámetros DH.**

| Campo | Qué poner | Botones |
|---|---|---|
| *URL llave pública .asc* | La URL de la página web del destinatario | **Descargar** / **Archivo local** |
| *URL parámetros DH* | La URL de su `mi_dh.json` | **Descargar** / **Archivo local** |

Al descargar el `.asc` verás su UID y su huella digital. Al descargar los
parámetros DH, el programa **verifica su firma** contra ese `.asc`:

```
[OK] Parametros Diffie-Hellman obtenidos de la web y VERIFICADOS
     La firma RSA de los parametros corresponde a la llave publica del destinatario:
     Diffie-Hellman autenticado, sin riesgo de hombre en medio.
```

Si intentas cargar los parámetros antes que el `.asc`, avisa que falta la llave
pública. Si alguien alteró los parámetros, los **rechaza** y no deja cifrar.

> Si solo marcaste *Firma*, este bloque no hace falta: no hay a quién cifrarle.

#### Bloque 3 — Mensaje en claro (m)

Escribe el mensaje, o pulsa **Cargar mensaje desde archivo .txt**.

#### Bloque 4 — Generar

**Generar paquete criptográfico y guardarlo para el Drive** te pide dónde
guardar el `.json` que subirás a la nube. La bitácora narra cada paso, con los
valores reales:

```
[OK] CONFIDENCIALIDAD: AES-128-CBC con K e IV acordados por Diffie-Hellman
     DH #1: Ka enviado, K = SHA-256(Kb^a mod p)[:16] = 7fa3805b46c35f58...
     DH #2: Kc enviado, IV = SHA-256(Kd^c mod p)[:16] = bb13d5a858646160...
     AES-128-CBC: 49 bytes en claro -> 64 bytes cifrados
[OK] AUTENTICACION + INTEGRIDAD + NO REPUDIO: firma RSA sobre SHA-256(m)
     SHA-256(m) = 50c44db0ccda9563f0fd62627c81e3cd...
     Firma RSA-2048 de Alicia Ramirez <alicia@escom.ipn.mx> (BD664B99)
```

**Qué señalar en el video:** que el archivo generado **no contiene** ninguna
exponente privada de Diffie‑Hellman ni copia de la llave pública del firmante.
La bitácora lo dice explícitamente al guardar.

---

### Pestaña 3 — *Receptor: descifrar y verificar*

Es la pestaña de Betito. Recuerda cargar antes tu llave privada en la pestaña 1.

#### Bloque 1 — Archivos descargados de la nube (x, y, z)

| Botón | Qué hace |
|---|---|
| **Seleccionar archivos** | Permite elegir **varios a la vez** (`x.json`, `y.json`, `z.json`) |
| **Vaciar lista** | Limpia la lista para empezar de nuevo |

#### Bloque 2 — Llavero: llaves públicas de los posibles autores

Aquí agregas las llaves de **todos los que pudieron haber escrito**: Alicia,
Candy, quien sea.

| Elemento | Qué hace |
|---|---|
| Campo de URL + **Descargar de la web** | Descarga el `.asc` en ese momento, como pide el enunciado |
| **Agregar desde archivo local .asc** | Alternativa; admite varios archivos a la vez |

Cada llave agregada muestra su key ID, su UID y su huella. Las repetidas se
detectan y no se duplican.

#### Bloque 3 — Analizar

**Descifrar, verificar e identificar al autor de cada archivo** procesa **todos**
los archivos de la lista y produce, para cada uno, un bloque como este:

```
ARCHIVO: x.json
[  ] Servicios declarados en el paquete: confidencialidad, firma
     K = SHA-256(Ka^b mod p)[:16] = 10cc54acd13c26c6...
     IV = SHA-256(Kc^d mod p)[:16] = b0859b918fc9ed79...
     AES-128-CBC descifrado, relleno PKCS#7 correcto.
     SHA-256 del mensaje recibido = 3cd29bd8c0ea3e93...
[OK] CONFIDENCIALIDAD: descifrado AES-CBC correcto con K e IV de Diffie-Hellman.
[OK] AUTENTICACION: el autor es Alicia Ramirez <alicia@escom.ipn.mx> (BD664B99)
     Verificado con la llave publica 8E28 00F8 D9D9 DBC6 ...
[OK] INTEGRIDAD: el SHA-256 recibido coincide con el firmado. Nada fue alterado.
[OK] NO REPUDIO: solo esa llave privada pudo generar esta firma.

CONTENIDO DEL MENSAJE:
Betito, la reunion es el viernes a las 7. -Alicia
```

**El autor no se toma del nombre que trae el archivo.** El programa prueba la
firma contra cada llave del llavero y gana la que verifica. Por eso puede decir
quién escribió `x`, `y` y `z` aunque estén renombrados, y por eso detecta las
suplantaciones:

```
[!!] AVISO: el paquete DECIA venir de 'Alicia Ramirez <...>', pero la
     firma demuestra que el autor real es 'Candy Lopez <...>'.
```

##### Los tres modos de fallo, y cómo se distinguen

| Qué alteró Candy | Qué muestra Betito |
|---|---|
| Un byte del criptograma | *INTEGRIDAD COMPROMETIDA: el archivo fue alterado en la nube.* Aclara que la firma **no llegó a evaluarse** porque el descifrado falló |
| La firma | *VERIFICACIÓN FALLIDA: la firma no verifica con ninguna llave del llavero* |
| Solo el nombre del emisor | Nada: sigue identificando al autor real por la firma |

Ninguno detiene el análisis de los demás archivos.

---

### Pestaña 4 — *Referencias*

Lista de todos los algoritmos implementados con su norma o artículo original
(RFC 3526, FIPS 197, SP 800‑38A, RFC 5652, FIPS 180‑4, RFC 8017, RFC 4880), y
las decisiones de diseño que conviene explicar en el video. Es material listo
para citar.

---

## Cómo funciona, paso a paso

### Fase 0 — Preparación

| Paso | Qué interviene | Función |
|---|---|---|
| Cargar el `.asc` privado | Tu llave privada + tu frase de paso | `pgp.load_secret_key()` |
| Derivar el par DH estático | Tu llave privada RSA | `motor.derivar_par_estatico()` |
| Publicar `Kb`, `Kd` firmados | Tu llave privada RSA (para firmar) | `protocolo.construir_dhpub()` |

```
b  = SHA-512("...DH-v1|K-AES|" + n + d) mod (p-4) + 2      ← privado
Kb = g^b mod p                                              ← público
```

### Fase 1 — Alicia cifra y firma

| Paso | Qué interviene | Función |
|---|---|---|
| Descargar el `.asc` de Betito | `B_pub` | `pgp.load_public_key()` |
| Verificar sus parámetros DH | `B_pub` contra la firma del `.json` | `protocolo.verificar_dhpub()` |
| Acordar `K` e `IV` | `a`, `c` efímeros + `Kb`, `Kd` públicos | `motor.secreto_compartido()` |
| Cifrar | `K`, `IV` | `motor.cifrar_aes_cbc()` |
| Firmar | **`A_priv`** | `protocolo.firmar_hash()` |

```
a, Ka = g^a mod p          c, Kc = g^c mod p     (efímeros, nuevos cada vez)
K  = SHA-256(Kb^a mod p)[:16]
IV = SHA-256(Kd^c mod p)[:16]
C  = AES-128-CBC(m, K, IV)
h  = SHA-256(m)              firma = RSA_PKCS1v15(A_priv, h)
```

Al terminar, Alicia **descarta `a` y `c`**. Ni ella misma puede volver a leer el
mensaje: solo Betito puede.

### Fase 2 — Betito descifra y verifica

| Paso | Qué interviene | Función |
|---|---|---|
| Recalcular `b`, `d` | **`B_priv`** | `motor.derivar_par_estatico()` |
| Reconstruir `K`, `IV` | `Ka`, `Kc` del paquete + `b`, `d` | `motor.secreto_compartido()` |
| Descifrar | `K`, `IV` | `motor.descifrar_aes_cbc()` |
| Identificar al autor | Las llaves **públicas** del llavero | `protocolo.analizar_paquete()` |

```
K  = SHA-256(Ka^b mod p)[:16]  = SHA-256(g^(ab))[:16]   ← el mismo que calculó Alicia
IV = SHA-256(Kc^d mod p)[:16]
m  = AES-128-CBC⁻¹(C, K, IV)
h' = SHA-256(m)

para cada llave pública del llavero:
    ¿verifica RSA(pub, firma, h')?  → sí: ESE es el autor
```

Alicia calculó `Kb^a` y Betito calcula `Ka^b`. Son el mismo número, `g^(ab) mod p`,
y **nunca viajó por la red**. Un atacante ve `g^a` y `g^b`; llegar de ahí a
`g^(ab)` es el problema Diffie‑Hellman computacional, y despejar `a` o `b` es el
logaritmo discreto: con un primo de 2048 bits, inviable.

---

## Formato de los archivos

### Parámetros DH públicos (`mi_dh.json`, va en tu página web)

```json
{
  "formato": "PARAMETROS-DH-PUBLICOS-v1",
  "grupo": "RFC3526-MODP-2048-bit-Group-14",
  "propietario": "Betito Hernandez <betito@escom.ipn.mx>",
  "key_id": "1B9F398834794F8B",
  "huella": "1B9F3988566AF712C55EEA8BC530660E34794F8B",
  "Kb_hex": "17bbe95033bd77e7...",
  "Kd_hex": "4ff7af0a32120a9d...",
  "firma_algoritmo": "RSASSA-PKCS1-v1_5 sobre SHA-256",
  "firma_b64": "..."
}
```

La firma cubre `formato|grupo|key_id|Kb|Kd`. Cambiar cualquiera de esos campos
la invalida.

### Paquete criptográfico (el que se sube al Drive)

```json
{
  "formato": "CRIPTO-HIBRIDA-DH-v1",
  "servicios": { "confidencialidad": true, "firma": true },
  "destinatario": { "uid": "Betito ...", "key_id": "1B9F398834794F8B" },
  "cifrado": {
    "algoritmo": "AES-128-CBC (llave e IV derivados por Diffie-Hellman)",
    "grupo_dh": "RFC3526-MODP-2048-bit-Group-14",
    "kdf": "SHA-256(g^xy mod p) truncado a 16 bytes",
    "Ka_hex": "362c24dea997f358...",
    "Kc_hex": "5255b9faa64b49a7..."
  },
  "contenido_b64": "wmOfKKN27hNZ9L/8bbmiALAe3ug...",
  "firma": {
    "algoritmo": "RSASSA-PKCS1-v1_5 sobre SHA-256",
    "hash_algoritmo": "SHA-256",
    "valor_b64": "..."
  },
  "emisor_declarado_no_confiable": "Alicia Ramirez <alicia@escom.ipn.mx>"
}
```

#### Lo que **no** contiene, y por qué importa

- **Ninguna exponente privada de Diffie‑Hellman.** Solo viajan los valores
  públicos efímeros `Ka` y `Kc`. Si viajara una privada, cualquiera que abriera
  el archivo en el Drive podría recalcular `K` y descifrar.
- **Ninguna copia de la llave pública del firmante.** La llave con la que se
  verifica se descarga siempre de la página web del autor. Si viajara dentro del
  paquete, Candy podría firmar con una llave propia, ponerla en el archivo, y la
  verificación pasaría siempre.
- El campo `emisor_declarado_no_confiable` es solo una pista para ordenar
  archivos. **La autoría se decide probando la firma**, nunca leyendo ese texto.

---

## Prueba automatizada

Reproduce los escenarios A–F del enunciado sin interfaz gráfica:

```powershell
cd d:\crypto2\practica1
python prueba_escenarios.py CARPETA_CON_LAS_LLAVES
```

La carpeta debe contener `alicia_pub.asc`, `alicia_priv.asc` y lo mismo para
`betito` y `candy`. Las frases de paso se piden por consola, o se toman de las
variables `PASS_ALICIA`, `PASS_BETITO`, `PASS_CANDY`.

Son **25 comprobaciones**. Entre otras cosas verifica que:

- Betito identifica correctamente al autor de `x`, `y` y `z`;
- si Candy firma un mensaje y **miente** en el nombre del emisor, la firma
  delata que el autor real es Candy;
- cambiar **un solo bit** del criptograma rompe la verificación;
- restaurar el archivo la hace verificar de nuevo;
- sustituir los parámetros Diffie‑Hellman publicados se detecta y se rechaza;
- Candy **no** puede descifrar lo que Alicia cifró para Betito;
- los modos "uno de dos" (solo cifrado, solo firma) funcionan por separado.

---

## Guion para el video

Duración máxima 17 minutos. Primero las diapositivas, luego media pantalla con
el código o las diapositivas y la otra media con la interfaz, y la miniatura de
video visible todo el tiempo.

| Paso | Qué mostrar |
|---|---|
| **A** | Alicia carga su privada (pestaña 1), descarga de la web el `.asc` y los parámetros DH de Betito — señalando que la firma de los parámetros se verifica —, cifra, firma y sube `x` al Drive |
| **B** | Candy hace lo mismo y sube `y` |
| **C** | Candy altera los archivos, duplica uno y los renombra `x`, `y`, `z` |
| **D** | Betito carga los tres, arma el llavero descargando las llaves públicas **en ese momento** de las páginas web, y muestra autor y contenido de cada uno |
| **E** | Candy cambia un byte de `x`; Betito muestra que falla la verificación y explica qué servicio se rompió |
| **F** | Candy restaura el archivo; Betito verifica correctamente |
| **G** | Sin compartir pantalla, conclusiones individuales |

Al narrar cada paso conviene nombrar el servicio que se está ofreciendo: la
bitácora los escribe explícitamente (`CONFIDENCIALIDAD`, `AUTENTICACIÓN`,
`INTEGRIDAD`, `NO REPUDIO`).

---

## Diferencias con el diagrama del PDF

La mitad de la firma está implementada **literalmente** como la dibuja el
diagrama inferior: `m` → hash → RSA con `A_Privada` → firma digital, y del otro
lado RSA con `A_Pública` y comparación. Esa parte no cambia.

Hay tres diferencias que **deben reflejarse en la diapositiva**, como pide el
enunciado:

1. **La derivación de `K` e `IV`.** El diagrama dice `K = S = Kb^a mod n`, es
   decir que el secreto compartido *es* la llave. Pero `S` mide 2048 bits y
   AES‑128 necesita 16 bytes, así que el código hace
   `K = SHA-256(Kb^a mod p)[:16]`. Hay que dibujar ese paso de hash.
2. **El intercambio no es en vivo.** El diagrama dibuja flechas en ambos
   sentidos. Como los archivos van por Drive, Betito no está presente: sus
   valores `Kb` y `Kd` están **publicados de antemano**, y solo `Ka` y `Kc`
   viajan dentro del paquete.
3. **Los parámetros DH van firmados.** No aparece en el diagrama original. Es
   Diffie‑Hellman **autenticado**, y evita que alguien publique valores falsos
   haciéndose pasar por Betito.

Detalle de notación: el diagrama llama `n` al módulo primo; el código lo llama
`p` (RFC 3526). Conviene unificarlo para no confundirlo con el `n` de RSA.

---

## Problemas comunes

| Síntoma | Causa y solución |
|---|---|
| *El bloque de llave está INCOMPLETO* | El `.asc` se copió o exportó a medias. Reexporta con `gpg --output llave.asc --armor --export-secret-keys TU_CORREO` |
| *El archivo no contiene un bloque ASCII‑armor* | El `.asc` está en UTF‑16 (típico de exportar con `>` en PowerShell). **El programa ya lo detecta y lo lee solo**; si aun así falla, reexporta con `--output` |
| *Ese archivo no contiene una llave PRIVADA* | Seleccionaste la pública. Necesitas la de `--export-secret-keys` |
| *Frase de paso incorrecta* | El material privado no se pudo descifrar. Revisa la contraseña de tu llave GPG |
| *La llave no es RSA (algoritmo 22)* | Es Ed25519. Genera una nueva con `gpg --full-generate-key` eligiendo RSA |
| *Llave protegida con AEAD (S2K usage 253)* | GnuPG muy reciente. Reexporta la llave secreta con GnuPG clásico |
| `ModuleNotFoundError: No module named 'pgp'` | Estás ejecutando desde la raíz. Haz `cd practica1` primero |
| *FIRMA INVÁLIDA en los parámetros Diffie‑Hellman* | El `.json` no corresponde al `.asc` que cargaste, o fue alterado. Descarga ambos de la misma página |
| El programa no deja cifrar | Falta descargar el `.asc` del destinatario **y** sus parámetros DH, en ese orden |

---

## Referencias

**Diffie‑Hellman**
- W. Diffie y M. Hellman, *New Directions in Cryptography*, IEEE Trans. on Information Theory, vol. IT‑22, n.º 6, 1976.
- RFC 3526 §3, *More MODP Diffie‑Hellman groups for IKE* — grupo de 2048 bits (Group 14).
- NIST SP 800‑56A rev 3 §5.8 — derivación de llave a partir del secreto compartido.
- Menezes, van Oorschot y Vanstone, *Handbook of Applied Cryptography*, cap. 12 §12.6 — Diffie‑Hellman autenticado.

**AES‑CBC**
- NIST FIPS 197, *Advanced Encryption Standard*.
- NIST SP 800‑38A §6.2 — modo de operación CBC.
- RFC 5652 §6.3 — relleno PKCS#7.

**Hash y firma**
- NIST FIPS 180‑4 — SHA‑256.
- R. Rivest, A. Shamir y L. Adleman, *A Method for Obtaining Digital Signatures and Public‑Key Cryptosystems*, CACM, 1978.
- RFC 8017 (PKCS #1 v2.2) §8.2 *RSASSA‑PKCS1‑v1_5* y §9.2 *EMSA‑PKCS1‑v1_5*.

**OpenPGP**
- RFC 4880, *OpenPGP Message Format*: §3.2 MPI, §3.7 S2K, §4.2 cabeceras de paquete, §5.5.2 llave pública, §5.5.3 llave secreta, §6.1 CRC‑24, §6.2 ASCII armor, §9.1 y §9.2 algoritmos, §12.2 huella digital v4.

**Implementaciones reutilizadas**
- pyca/cryptography — AES, RSA, padding: <https://cryptography.io/en/latest/>
- `hashlib` de la biblioteca estándar de Python — SHA‑256, SHA‑512, SHA‑1, MD5.
- requests — descarga de las llaves públicas: <https://requests.readthedocs.io/>

---

## Nota sobre las firmas

Las firmas de esta práctica son **RSASSA‑PKCS1‑v1_5 sobre SHA‑256** (RFC 8017),
calculadas con el material de llave RSA extraído del `.asc`. No son paquetes de
firma OpenPGP (RFC 4880 §5.2), de modo que no se verifican con `gpg --verify`:
se verifican con esta misma aplicación, usando la llave pública descargada de la
página web del autor. El par de llaves es exactamente el mismo que el publicado.
