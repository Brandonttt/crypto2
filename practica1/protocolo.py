"""
Protocolo de la practica: formato de los archivos que viajan por la nube.

Hay dos tipos de archivo:

1. PARAMETROS DH PUBLICOS  (*.dhpub.json)
   Cada persona lo publica en su pagina web JUNTO a su llave publica .asc.
   Contiene sus dos valores publicos Diffie-Hellman (Kb para la llave K de AES
   y Kd para el IV) y va FIRMADO con su llave privada RSA. Quien lo descarga
   verifica esa firma contra el .asc de la misma pagina, de modo que un tercero
   no puede sustituir los valores DH: eso convierte el intercambio en un
   Diffie-Hellman AUTENTICADO, inmune al ataque de hombre en medio.

2. PAQUETE CRIPTOGRAFICO   (*.json)
   Es el archivo que se sube al Drive. Contiene el criptograma AES-CBC, los
   valores publicos efimeros del emisor (Ka y Kc) y la firma RSA sobre el hash
   SHA-256 del mensaje en claro.

Lo que este formato NUNCA incluye, a diferencia de una implementacion ingenua:
  - ninguna exponente privada de Diffie-Hellman;
  - ninguna copia de la llave publica del firmante.
La llave con la que se verifica la firma SIEMPRE se descarga de la pagina web
del autor; si viajara dentro del paquete, cualquiera podria firmar con una
llave propia y la verificacion pasaria.

Referencias
-----------
* RFC 8017 sec 8.2 "RSASSA-PKCS1-v1_5" (firma RSA) y sec 9.2 (EMSA-PKCS1-v1_5).
* Menezes, van Oorschot, Vanstone, "Handbook of Applied Cryptography", cap. 12
  sec 12.6: Diffie-Hellman autenticado.
* pyca/cryptography: metodos sign()/verify() con Prehashed.
"""

import base64
import json
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

import motor
from pgp import PGPKey, leer_texto

FORMATO_PAQUETE = "CRIPTO-HIBRIDA-DH-v1"
FORMATO_DHPUB = "PARAMETROS-DH-PUBLICOS-v1"
ALGORITMO_FIRMA = "RSASSA-PKCS1-v1_5 sobre SHA-256"
ALGORITMO_CIFRADO = "AES-128-CBC (llave e IV derivados por Diffie-Hellman)"


class ErrorProtocolo(Exception):
    """El archivo no cumple el formato del protocolo."""


# ---------------------------------------------------------------------------
# Firma y verificacion RSA sobre el hash
# ---------------------------------------------------------------------------
def firmar_hash(private_key: rsa.RSAPrivateKey, digest: bytes) -> bytes:
    """Firma un digest SHA-256 ya calculado (RSASSA-PKCS1-v1_5, RFC 8017)."""
    return private_key.sign(
        digest,
        asym_padding.PKCS1v15(),
        asym_utils.Prehashed(hashes.SHA256()),
    )


def verificar_hash(public_key: rsa.RSAPublicKey, firma: bytes, digest: bytes) -> bool:
    """True si la firma corresponde al digest y a esa llave publica."""
    try:
        public_key.verify(
            firma,
            digest,
            asym_padding.PKCS1v15(),
            asym_utils.Prehashed(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# 1. Parametros DH publicos (lo que se sube a la pagina web)
# ---------------------------------------------------------------------------
def _canonico_dhpub(key_id: str, kb_hex: str, kd_hex: str) -> bytes:
    """Cadena canonica que se firma. Cualquier cambio invalida la firma."""
    return "|".join([FORMATO_DHPUB, motor.GRUPO_DH, key_id, kb_hex, kd_hex]).encode("utf-8")


def construir_dhpub(llave: PGPKey) -> Dict:
    """Genera el archivo de parametros DH publicos, firmado por su duenio."""
    if llave.private_key is None:
        raise ErrorProtocolo("Se necesita la llave PRIVADA para publicar los parametros DH.")

    _, kb = motor.derivar_par_estatico(llave.private_key, motor.ETIQUETA_K)
    _, kd = motor.derivar_par_estatico(llave.private_key, motor.ETIQUETA_IV)
    kb_hex, kd_hex = format(kb, "x"), format(kd, "x")

    digest = motor.sha256(_canonico_dhpub(llave.key_id, kb_hex, kd_hex))
    firma = firmar_hash(llave.private_key, digest)

    return {
        "formato": FORMATO_DHPUB,
        "grupo": motor.GRUPO_DH,
        "propietario": llave.uid,
        "key_id": llave.key_id,
        "huella": llave.fingerprint,
        "Kb_hex": kb_hex,
        "Kd_hex": kd_hex,
        "firma_algoritmo": ALGORITMO_FIRMA,
        "firma_b64": base64.b64encode(firma).decode(),
        "_nota": (
            "Publica este archivo en tu pagina web junto a tu llave publica .asc. "
            "Kb se usa para derivar la llave K de AES y Kd para derivar el IV."
        ),
    }


def verificar_dhpub(dhpub: Dict, llave_publica_autor: PGPKey) -> Dict:
    """Valida el archivo de parametros DH contra la llave publica del autor.

    Devuelve {'Kb': int, 'Kd': int}. Lanza ErrorProtocolo si la firma no
    corresponde: eso significaria que los valores DH fueron sustituidos.
    """
    if dhpub.get("formato") != FORMATO_DHPUB:
        raise ErrorProtocolo("El archivo no es un bloque de parametros DH publicos.")
    if dhpub.get("grupo") != motor.GRUPO_DH:
        raise ErrorProtocolo(f"Grupo Diffie-Hellman distinto: {dhpub.get('grupo')}.")

    key_id = dhpub.get("key_id", "")
    if key_id.upper() != llave_publica_autor.key_id.upper():
        raise ErrorProtocolo(
            f"Los parametros DH dicen pertenecer a la llave {key_id}, pero la llave "
            f"publica descargada es {llave_publica_autor.key_id}."
        )

    kb_hex, kd_hex = dhpub.get("Kb_hex", ""), dhpub.get("Kd_hex", "")
    digest = motor.sha256(_canonico_dhpub(key_id, kb_hex, kd_hex))
    firma = base64.b64decode(dhpub.get("firma_b64", ""))
    if not verificar_hash(llave_publica_autor.public_key, firma, digest):
        raise ErrorProtocolo(
            "FIRMA INVALIDA en los parametros Diffie-Hellman: alguien los sustituyo "
            "en el camino (ataque de hombre en medio). No se debe cifrar con ellos."
        )

    kb, kd = int(kb_hex, 16), int(kd_hex, 16)
    motor.validar_publica_dh(kb)
    motor.validar_publica_dh(kd)
    return {"Kb": kb, "Kd": kd}


# ---------------------------------------------------------------------------
# 2. Paquete criptografico (lo que se sube al Drive)
# ---------------------------------------------------------------------------
def construir_paquete(
    mensaje: bytes,
    confidencialidad: bool,
    firma: bool,
    llave_emisor: Optional[PGPKey] = None,
    dh_destinatario: Optional[Dict] = None,
    uid_destinatario: str = "",
    key_id_destinatario: str = "",
) -> Dict:
    """Arma el paquete aplicando los servicios seleccionados.

    Devuelve el diccionario listo para serializar como JSON. Los campos
    'traza_*' existen solo para poder narrar el proceso en la interfaz.
    """
    paquete: Dict = {
        "formato": FORMATO_PAQUETE,
        "servicios": {"confidencialidad": confidencialidad, "firma": firma},
    }
    traza: List[str] = []

    # --- Confidencialidad: Diffie-Hellman + AES-CBC ---
    if confidencialidad:
        if not dh_destinatario:
            raise ErrorProtocolo(
                "Para ofrecer confidencialidad hace falta descargar los parametros "
                "DH publicos del destinatario."
            )
        a, ka = motor.generar_par_efimero()
        c, kc = motor.generar_par_efimero()

        llave_k = motor.derivar_material(motor.secreto_compartido(dh_destinatario["Kb"], a), 16)
        iv = motor.derivar_material(motor.secreto_compartido(dh_destinatario["Kd"], c), 16)
        criptograma = motor.cifrar_aes_cbc(mensaje, llave_k, iv)

        paquete["destinatario"] = {"uid": uid_destinatario, "key_id": key_id_destinatario}
        paquete["cifrado"] = {
            "algoritmo": ALGORITMO_CIFRADO,
            "grupo_dh": motor.GRUPO_DH,
            "kdf": "SHA-256(g^xy mod p) truncado a 16 bytes",
            "Ka_hex": format(ka, "x"),  # publica efimera para la llave K
            "Kc_hex": format(kc, "x"),  # publica efimera para el IV
        }
        paquete["contenido_b64"] = base64.b64encode(criptograma).decode()
        traza.append(f"DH #1: Ka enviado, K = SHA-256(Kb^a mod p)[:16] = {llave_k.hex()}")
        traza.append(f"DH #2: Kc enviado, IV = SHA-256(Kd^c mod p)[:16] = {iv.hex()}")
        traza.append(f"AES-128-CBC: {len(mensaje)} bytes en claro -> {len(criptograma)} bytes cifrados")
    else:
        paquete["contenido_b64"] = base64.b64encode(mensaje).decode()
        traza.append("Sin cifrado: el contenido viaja en claro (solo Base64, que no es cifrado).")

    # --- Autenticacion, integridad y no repudio: firma RSA sobre SHA-256(m) ---
    if firma:
        if llave_emisor is None or llave_emisor.private_key is None:
            raise ErrorProtocolo("Para firmar hace falta cargar tu llave privada .asc.")
        digest = motor.sha256(mensaje)
        valor = firmar_hash(llave_emisor.private_key, digest)
        paquete["firma"] = {
            "algoritmo": ALGORITMO_FIRMA,
            "hash_algoritmo": "SHA-256",
            "valor_b64": base64.b64encode(valor).decode(),
        }
        # Pista NO confiable: solo sirve para ordenar archivos, jamas para decidir
        # la autoria. La autoria se decide verificando la firma.
        paquete["emisor_declarado_no_confiable"] = llave_emisor.uid
        traza.append(f"SHA-256(m) = {digest.hex()}")
        traza.append(f"Firma RSA-{llave_emisor.bits} de {llave_emisor.uid} ({llave_emisor.short_id()})")

    paquete["traza_emisor"] = traza
    return paquete


def guardar_json(ruta: str, datos: Dict) -> None:
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(datos, fh, indent=2, ensure_ascii=False)


def cargar_json(ruta: str) -> Dict:
    # leer_texto detecta UTF-16, tal como con las llaves .asc.
    return json.loads(leer_texto(ruta))


class Resultado:
    """Resultado del analisis de un paquete en el receptor."""

    def __init__(self, nombre_archivo: str):
        self.archivo = nombre_archivo
        self.formato_ok = False
        self.confidencialidad_pedida = False
        self.firma_pedida = False
        self.descifrado_ok = False
        self.firma_evaluada = False  # se llego a comprobar la firma?
        self.firma_ok = False
        self.autor: Optional[PGPKey] = None
        self.emisor_declarado = ""
        self.mensaje: Optional[bytes] = None
        self.digest: Optional[bytes] = None
        self.problemas: List[str] = []
        self.pasos: List[str] = []

    @property
    def integridad_ok(self) -> bool:
        """Integridad demostrada = descifrado coherente y firma valida."""
        if self.firma_pedida:
            return self.firma_ok
        return self.descifrado_ok

    def texto(self) -> str:
        if self.mensaje is None:
            return ""
        return self.mensaje.decode("utf-8", errors="replace")


def analizar_paquete(
    paquete: Dict,
    nombre_archivo: str,
    llave_receptor: Optional[PGPKey],
    llavero: List[PGPKey],
) -> Resultado:
    """Descifra y verifica un paquete, identificando al autor por criptografia.

    El autor NO se toma del campo 'emisor_declarado_no_confiable': se prueba la
    firma contra cada llave publica del llavero y gana la que verifica. Si
    ninguna verifica, el archivo fue alterado o lo firmo un desconocido.
    """
    res = Resultado(nombre_archivo)

    if paquete.get("formato") != FORMATO_PAQUETE:
        res.problemas.append(
            f"Formato desconocido: {paquete.get('formato')!r}. Se esperaba {FORMATO_PAQUETE}."
        )
        return res

    res.formato_ok = True
    servicios = paquete.get("servicios", {})
    res.confidencialidad_pedida = bool(servicios.get("confidencialidad"))
    res.firma_pedida = bool(servicios.get("firma"))
    res.emisor_declarado = paquete.get("emisor_declarado_no_confiable", "")

    try:
        contenido = base64.b64decode(paquete.get("contenido_b64", ""), validate=True)
    except Exception:  # noqa: BLE001
        res.problemas.append("El campo 'contenido_b64' no es Base64 valido: archivo alterado.")
        return res

    # --- Confidencialidad ---
    if res.confidencialidad_pedida:
        if llave_receptor is None or llave_receptor.private_key is None:
            res.problemas.append(
                "Necesitas cargar tu llave privada .asc para derivar K e IV por Diffie-Hellman."
            )
            return res
        destino = paquete.get("destinatario", {})
        if destino.get("key_id") and destino["key_id"].upper() != llave_receptor.key_id.upper():
            res.problemas.append(
                f"Este paquete fue cifrado para la llave {destino['key_id']} "
                f"({destino.get('uid', '?')}), no para la tuya ({llave_receptor.key_id})."
            )
            return res
        try:
            cifrado = paquete["cifrado"]
            b, _ = motor.derivar_par_estatico(llave_receptor.private_key, motor.ETIQUETA_K)
            d, _ = motor.derivar_par_estatico(llave_receptor.private_key, motor.ETIQUETA_IV)
            llave_k = motor.derivar_material(
                motor.secreto_compartido(int(cifrado["Ka_hex"], 16), b), 16
            )
            iv = motor.derivar_material(
                motor.secreto_compartido(int(cifrado["Kc_hex"], 16), d), 16
            )
            res.mensaje = motor.descifrar_aes_cbc(contenido, llave_k, iv)
            res.descifrado_ok = True
            res.pasos.append(f"K = SHA-256(Ka^b mod p)[:16] = {llave_k.hex()}")
            res.pasos.append(f"IV = SHA-256(Kc^d mod p)[:16] = {iv.hex()}")
            res.pasos.append("AES-128-CBC descifrado, relleno PKCS#7 correcto.")
        except (KeyError, ValueError) as exc:
            res.problemas.append(f"Campos de cifrado ausentes o corruptos: {exc}")
            return res
        except motor.ErrorMotor as exc:
            res.problemas.append(str(exc))
            return res
    else:
        res.mensaje = contenido
        res.descifrado_ok = True
        res.pasos.append("El paquete no pidio confidencialidad: contenido en claro.")

    # --- Autenticacion, integridad y no repudio ---
    if res.firma_pedida:
        try:
            firma = base64.b64decode(paquete["firma"]["valor_b64"], validate=True)
        except Exception:  # noqa: BLE001
            res.problemas.append("La firma no es Base64 valido: archivo alterado.")
            return res

        res.digest = motor.sha256(res.mensaje)
        res.pasos.append(f"SHA-256 del mensaje recibido = {res.digest.hex()}")

        if not llavero:
            res.problemas.append(
                "El llavero esta vacio: descarga de las paginas web las llaves publicas "
                "de los posibles autores para poder verificar."
            )
            return res

        res.firma_evaluada = True
        for candidata in llavero:
            if verificar_hash(candidata.public_key, firma, res.digest):
                res.autor = candidata
                res.firma_ok = True
                break

        if not res.firma_ok:
            res.problemas.append(
                "La firma RSA no verifica con NINGUNA de las llaves publicas del llavero: "
                "el mensaje fue alterado despues de firmarse, o lo firmo alguien ajeno."
            )
    else:
        res.pasos.append(
            "El paquete no trae firma: no hay autenticacion, ni integridad demostrable, "
            "ni no repudio."
        )

    return res
