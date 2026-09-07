"""
Motor criptografico: Diffie-Hellman, derivacion de llaves, AES-CBC y SHA-256.

Corresponde al esquema hibrido inferior del enunciado: K e IV de AES-CBC se
obtienen mediante DOS intercambios Diffie-Hellman independientes (uno para la
llave K y otro para el vector de inicializacion IV), y la firma digital es RSA
sobre el hash SHA-256 del mensaje en claro.

Referencias
-----------
* RFC 3526 sec 3 "More Modular Exponential (MODP) Diffie-Hellman groups":
  grupo MODP de 2048 bits (Group 14), primo p y generador g = 2.
  https://www.rfc-editor.org/rfc/rfc3526
* W. Diffie y M. Hellman, "New Directions in Cryptography", IEEE Trans. on
  Information Theory, 1976.
* NIST FIPS 197 (AES) y NIST SP 800-38A sec 6.2 (modo de operacion CBC).
* RFC 5652 sec 6.3: relleno PKCS#7.
* NIST FIPS 180-4: SHA-256.
* NIST SP 800-56A rev 3 sec 5.8: derivacion de llave a partir del secreto
  compartido mediante una funcion hash.
* pyca/cryptography: https://cryptography.io/en/latest/hazmat/primitives/
"""

import hashlib
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Grupo Diffie-Hellman: RFC 3526 sec 3, MODP Group 14 (2048 bits)
# ---------------------------------------------------------------------------
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2
GRUPO_DH = "RFC3526-MODP-2048-bit-Group-14"

# Etiquetas de dominio: separan el par DH usado para K del usado para el IV.
ETIQUETA_K = b"K-AES"
ETIQUETA_IV = b"IV-AES"


class ErrorMotor(Exception):
    """Fallo en una operacion criptografica del motor."""


# ---------------------------------------------------------------------------
# Diffie-Hellman
# ---------------------------------------------------------------------------
def generar_par_efimero() -> Tuple[int, int]:
    """Genera (privada, publica) efimeras. La publica es g^priv mod p."""
    priv = int.from_bytes(os.urandom(32), "big") + 2  # 256 bits, en [2, p-2]
    return priv, pow(DH_G, priv, DH_P)


def derivar_par_estatico(private_key: rsa.RSAPrivateKey, etiqueta: bytes) -> Tuple[int, int]:
    """Deriva de forma determinista el par DH estatico de una identidad.

    La exponente privada se obtiene de la propia llave RSA privada del duenio,
    asi que NO hay que guardar ningun archivo de estado: cargando el mismo .asc
    siempre se recuperan los mismos valores publicos Kb y Kd que se publicaron
    en la pagina web. Solo quien posee la llave privada RSA puede reproducirla.
    """
    numeros = private_key.private_numbers()
    n = numeros.public_numbers.n
    semilla = hashlib.sha512(
        b"PRACTICA-CRIPTOGRAFIA-HIBRIDA-DH-v1|"
        + etiqueta
        + b"|"
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
        + b"|"
        + numeros.d.to_bytes((numeros.d.bit_length() + 7) // 8, "big")
    ).digest()
    priv = (int.from_bytes(semilla, "big") % (DH_P - 4)) + 2
    return priv, pow(DH_G, priv, DH_P)


def validar_publica_dh(valor: int) -> None:
    """Rechaza valores publicos degenerados (subgrupos pequenios)."""
    if not (2 <= valor <= DH_P - 2):
        raise ErrorMotor(
            "Valor publico Diffie-Hellman fuera del rango valido [2, p-2]: "
            "posible intento de ataque de subgrupo pequenio."
        )


def secreto_compartido(publica_ajena: int, privada_propia: int) -> int:
    """Calcula el secreto compartido s = (g^x)^y mod p."""
    validar_publica_dh(publica_ajena)
    return pow(publica_ajena, privada_propia, DH_P)


def derivar_material(secreto: int, longitud: int = 16) -> bytes:
    """KDF: SHA-256 del secreto compartido, truncado (NIST SP 800-56A sec 5.8)."""
    crudo = secreto.to_bytes((secreto.bit_length() + 7) // 8, "big")
    return hashlib.sha256(crudo).digest()[:longitud]


# ---------------------------------------------------------------------------
# AES-CBC con relleno PKCS#7
# ---------------------------------------------------------------------------
def cifrar_aes_cbc(claro: bytes, llave: bytes, iv: bytes) -> bytes:
    rellenador = padding.PKCS7(algorithms.AES.block_size).padder()
    con_relleno = rellenador.update(claro) + rellenador.finalize()
    cifrador = Cipher(algorithms.AES(llave), modes.CBC(iv), backend=default_backend()).encryptor()
    return cifrador.update(con_relleno) + cifrador.finalize()


def descifrar_aes_cbc(cifrado: bytes, llave: bytes, iv: bytes) -> bytes:
    """Descifra y quita el relleno. Lanza ErrorMotor si el relleno no es valido.

    Un relleno PKCS#7 invalido es la primera senial de que el criptograma fue
    alterado: es un fallo del servicio de INTEGRIDAD, no un error del programa.
    """
    if len(cifrado) == 0 or len(cifrado) % 16 != 0:
        raise ErrorMotor(
            "El criptograma no es multiplo del bloque de AES (16 bytes): "
            "el archivo fue alterado o truncado."
        )
    descifrador = Cipher(algorithms.AES(llave), modes.CBC(iv), backend=default_backend()).decryptor()
    con_relleno = descifrador.update(cifrado) + descifrador.finalize()
    quitador = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return quitador.update(con_relleno) + quitador.finalize()
    except ValueError as exc:
        raise ErrorMotor(
            "Relleno PKCS#7 invalido al descifrar: el criptograma fue modificado "
            "o la llave/IV derivados no corresponden a este destinatario."
        ) from exc


def sha256(datos: bytes) -> bytes:
    """Hash SHA-256 (FIPS 180-4). Es el 'embudo' de los diagramas del enunciado."""
    return hashlib.sha256(datos).digest()
