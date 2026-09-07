"""
Lector autonomo de llaves OpenPGP (.asc) en Python puro.

Este modulo SI parsea los paquetes OpenPGP: extrae el material matematico de la
llave RSA (modulo n y exponente publico e) del paquete de llave publica, y para
las llaves secretas descifra el material privado protegido con S2K para obtener
(d, p, q, u). Con esos numeros se construye un objeto de llave RSA de pyca/
cryptography que puede firmar y verificar de verdad.

Referencias
-----------
* RFC 4880 "OpenPGP Message Format" (Callas et al., 2007)
  - sec 3.1  Scalar numbers            - sec 3.2  Multiprecision Integers (MPI)
  - sec 3.7  String-to-Key (S2K)       - sec 4.2  Packet headers
  - sec 5.5.2 Public-Key packet        - sec 5.5.3 Secret-Key packet
  - sec 6.2  Forming ASCII Armor       - sec 6.1  CRC-24
  - sec 9.1  Public-Key algorithms     - sec 9.2  Symmetric-Key algorithms
  https://www.rfc-editor.org/rfc/rfc4880
* RFC 8017 "PKCS #1 v2.2: RSA Cryptography Specifications" (parametros CRT).
* pyca/cryptography, modulos hazmat.primitives.asymmetric.rsa y hazmat.ciphers.
  https://cryptography.io/en/latest/

Limitacion consciente: solo se soportan llaves RSA (algoritmos 1, 2 y 3 de
RFC 4880 sec 9.1), que es lo que usa el equipo en esta practica.
"""

import base64
import hashlib
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# TripleDES / CAST5 / Blowfish se movieron a "decrepit" en cryptography 43+.
try:  # pragma: no cover - depende de la version instalada
    from cryptography.hazmat.decrepit.ciphers.algorithms import (
        CAST5,
        Blowfish,
        TripleDES,
    )
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.algorithms import (  # type: ignore
        CAST5,
        Blowfish,
        TripleDES,
    )

# CFB tambien se movio a "decrepit" en versiones recientes de cryptography.
try:  # pragma: no cover
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # pragma: no cover
    CFB = modes.CFB  # type: ignore[assignment]


class PGPError(Exception):
    """Cualquier fallo al interpretar un archivo OpenPGP."""


# ---------------------------------------------------------------------------
# ASCII Armor (RFC 4880 sec 6.1 y 6.2)
# ---------------------------------------------------------------------------
_CRC24_INIT = 0x00B704CE
_CRC24_POLY = 0x01864CFB


def crc24(data: bytes) -> int:
    """CRC-24 de OpenPGP, RFC 4880 sec 6.1."""
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x01000000:
                crc ^= _CRC24_POLY
    return crc & 0x00FFFFFF


def dearmor(text: str) -> bytes:
    """Convierte un bloque -----BEGIN PGP ...----- en su payload binario."""
    lines = text.splitlines()
    start = end = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start is None and stripped.startswith("-----BEGIN PGP"):
            start = i
        elif start is not None and stripped.startswith("-----END PGP"):
            end = i
            break
    if start is None:
        raise PGPError(
            "El archivo no contiene un bloque ASCII-armor de OpenPGP "
            "(-----BEGIN PGP ... KEY BLOCK-----)."
        )
    if end is None:
        raise PGPError(
            "El bloque de llave esta INCOMPLETO: empieza con -----BEGIN PGP-----\n"
            "pero le falta la linea de cierre -----END PGP ... KEY BLOCK-----.\n\n"
            "El archivo se copio o se exporto a medias. Vuelve a exportarlo dejando\n"
            "que GnuPG escriba el archivo directamente:\n\n"
            "  gpg --output llave.asc --armor --export-secret-keys TU_CORREO"
        )

    body = lines[start + 1 : end]

    # Saltar las cabeceras "Clave: valor" hasta la primera linea en blanco.
    first = 0
    for i, line in enumerate(body):
        if line.strip() == "":
            first = i + 1
            break
        if ":" not in line:
            first = i
            break

    b64_parts = []
    crc_text: Optional[str] = None
    for line in body[first:]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("="):
            crc_text = stripped[1:]
            break
        b64_parts.append(stripped)

    try:
        data = base64.b64decode("".join(b64_parts))
    except Exception as exc:  # noqa: BLE001
        raise PGPError(f"Base64 del bloque armor invalido: {exc}") from exc

    if crc_text:
        try:
            expected = int.from_bytes(base64.b64decode(crc_text), "big")
        except Exception:  # noqa: BLE001
            expected = None
        if expected is not None and crc24(data) != expected:
            raise PGPError(
                "CRC-24 invalido: el archivo de llave esta corrupto o fue alterado."
            )
    return data


# ---------------------------------------------------------------------------
# Paquetes y MPIs (RFC 4880 sec 4.2 y 3.2)
# ---------------------------------------------------------------------------
TAG_SECRET_KEY = 5
TAG_PUBLIC_KEY = 6
TAG_SECRET_SUBKEY = 7
TAG_USER_ID = 13
TAG_PUBLIC_SUBKEY = 14


def iter_packets(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Recorre los paquetes OpenPGP produciendo pares (tag, cuerpo)."""
    i, total = 0, len(data)
    while i < total:
        header = data[i]
        i += 1
        if not header & 0x80:
            raise PGPError("Cabecera de paquete invalida (bit 7 en 0).")

        if header & 0x40:  # formato nuevo, RFC 4880 sec 4.2.2
            tag = header & 0x3F
            first = data[i]
            i += 1
            if first < 192:
                length = first
            elif first < 224:
                length = ((first - 192) << 8) + data[i] + 192
                i += 1
            elif first == 255:
                length = int.from_bytes(data[i : i + 4], "big")
                i += 4
            else:
                raise PGPError(
                    "Paquete con longitud parcial (partial body length) no soportado."
                )
        else:  # formato antiguo, RFC 4880 sec 4.2.1
            tag = (header & 0x3C) >> 2
            length_type = header & 0x03
            if length_type == 0:
                length = data[i]
                i += 1
            elif length_type == 1:
                length = int.from_bytes(data[i : i + 2], "big")
                i += 2
            elif length_type == 2:
                length = int.from_bytes(data[i : i + 4], "big")
                i += 4
            else:
                length = total - i

        if i + length > total:
            raise PGPError("Paquete truncado: la longitud declarada excede el archivo.")
        yield tag, data[i : i + length]
        i += length


def read_mpi(buf: bytes, offset: int) -> Tuple[int, int]:
    """Lee un Multiprecision Integer (RFC 4880 sec 3.2). Devuelve (valor, offset)."""
    bits = int.from_bytes(buf[offset : offset + 2], "big")
    nbytes = (bits + 7) // 8
    offset += 2
    value = int.from_bytes(buf[offset : offset + nbytes], "big")
    return value, offset + nbytes


# ---------------------------------------------------------------------------
# String-to-Key (RFC 4880 sec 3.7) y algoritmos simetricos (sec 9.2)
# ---------------------------------------------------------------------------
_HASH_ALGOS = {1: "md5", 2: "sha1", 3: "ripemd160", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}

# id -> (nombre, tamano de bloque, tamano de llave) en bytes
_SYM_ALGOS = {
    2: ("TripleDES", 8, 24),
    3: ("CAST5", 8, 16),
    4: ("Blowfish", 8, 16),
    7: ("AES-128", 16, 16),
    8: ("AES-192", 16, 24),
    9: ("AES-256", 16, 32),
}


def _new_hash(algo_id: int):
    name = _HASH_ALGOS.get(algo_id)
    if name is None:
        raise PGPError(f"Algoritmo de hash S2K no soportado (id {algo_id}).")
    try:
        return hashlib.new(name)
    except ValueError as exc:
        raise PGPError(
            f"El hash '{name}' no esta disponible en esta instalacion de Python."
        ) from exc


def s2k_derive(
    passphrase: bytes,
    key_len: int,
    s2k_type: int,
    hash_algo: int,
    salt: bytes = b"",
    count: Optional[int] = None,
) -> bytes:
    """Deriva la llave simetrica desde la frase de paso (RFC 4880 sec 3.7.1)."""
    out = b""
    prefix = 0
    while len(out) < key_len:
        h = _new_hash(hash_algo)
        h.update(b"\x00" * prefix)
        if s2k_type == 0:  # Simple S2K
            h.update(passphrase)
        elif s2k_type == 1:  # Salted S2K
            h.update(salt + passphrase)
        elif s2k_type == 3:  # Iterated and Salted S2K
            block = salt + passphrase
            total = count if count and count > len(block) else len(block)
            whole, rest = divmod(total, len(block))
            h.update(block * whole)
            h.update(block[:rest])
        else:
            raise PGPError(f"Especificador S2K no soportado (tipo {s2k_type}).")
        out += h.digest()
        prefix += 1
    return out[:key_len]


def _sym_cipher(algo_id: int, key: bytes, iv: bytes) -> Cipher:
    if algo_id in (7, 8, 9):
        alg = algorithms.AES(key)
    elif algo_id == 2:
        alg = TripleDES(key)
    elif algo_id == 3:
        alg = CAST5(key)
    elif algo_id == 4:
        alg = Blowfish(key)
    else:
        name = _SYM_ALGOS.get(algo_id, ("desconocido",))[0]
        raise PGPError(
            f"Algoritmo simetrico de proteccion no soportado (id {algo_id}, {name})."
        )
    # RFC 4880 sec 5.5.3: el material secreto va cifrado en modo CFB con el IV dado.
    return Cipher(alg, CFB(iv), backend=default_backend())


# ---------------------------------------------------------------------------
# Llaves
# ---------------------------------------------------------------------------
_RSA_ALGOS = {1: "RSA (cifrado y firma)", 2: "RSA (solo cifrado)", 3: "RSA (solo firma)"}


@dataclass
class PGPKey:
    """Una llave OpenPGP RSA ya convertida a objetos de pyca/cryptography."""

    uid: str
    key_id: str
    fingerprint: str
    bits: int
    algo_name: str
    public_key: rsa.RSAPublicKey
    private_key: Optional[rsa.RSAPrivateKey] = None

    @property
    def is_secret(self) -> bool:
        return self.private_key is not None

    def short_id(self) -> str:
        return self.key_id[-8:]

    def pretty_fingerprint(self) -> str:
        fp = self.fingerprint
        return " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))


def _parse_public_body(body: bytes) -> Tuple[int, int, int, int, int]:
    """Devuelve (version, algo, n, e, offset_tras_mpis) del cuerpo de un paquete."""
    version = body[0]
    if version == 4:
        algo = body[5]
        offset = 6
    elif version in (2, 3):
        algo = body[7]
        offset = 8
    else:
        raise PGPError(f"Version de paquete de llave no soportada: v{version}.")

    if algo not in _RSA_ALGOS:
        raise PGPError(
            f"La llave no es RSA (algoritmo {algo} de RFC 4880 sec 9.1). "
            "Esta practica esta implementada para llaves RSA; regenera la llave con "
            "'gpg --full-generate-key' eligiendo RSA."
        )

    n, offset = read_mpi(body, offset)
    e, offset = read_mpi(body, offset)
    return version, algo, n, e, offset


def _exigir_v4(version: int) -> None:
    """La huella y el Key ID de esta practica se calculan como en la version 4.

    Las llaves v3 usan otro calculo (MD5 de n||e, RFC 4880 sec 12.2) y ningun
    GnuPG moderno las genera; se rechazan antes que devolver una huella falsa.
    """
    if version != 4:
        raise PGPError(
            f"Llave OpenPGP version {version}: obsoleta y no soportada. "
            "Genera una llave nueva con 'gpg --full-generate-key' eligiendo RSA."
        )


def _fingerprint_v4(pub_body: bytes) -> str:
    """Huella digital v4 = SHA-1(0x99 || len16 || cuerpo) (RFC 4880 sec 12.2)."""
    data = b"\x99" + len(pub_body).to_bytes(2, "big") + pub_body
    return hashlib.sha1(data).hexdigest().upper()  # noqa: S324 - lo exige el RFC


def _build_public(n: int, e: int) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def _build_private(n: int, e: int, d: int, p: int, q: int) -> rsa.RSAPrivateKey:
    """Construye la llave privada recalculando los parametros CRT.

    OpenPGP guarda (p, q, u) con p < q y u = p^-1 mod q, mientras que PKCS#1
    (RFC 8017 sec 3.2) espera iqmp = q^-1 mod p. En lugar de reordenar a mano y
    arriesgar una confusion, se recalculan dmp1, dmq1 e iqmp desde (d, p, q).
    """
    public_numbers = rsa.RSAPublicNumbers(e, n)
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=public_numbers,
    )
    return numbers.private_key(default_backend())


def _decrypt_secret_material(body: bytes, offset: int, passphrase: bytes) -> bytes:
    """Descifra (si hace falta) el bloque de MPIs secretas. RFC 4880 sec 5.5.3."""
    usage = body[offset]
    offset += 1

    if usage == 253:
        raise PGPError(
            "La llave secreta usa proteccion AEAD (S2K usage 253 de RFC 9580), que "
            "este lector no implementa. Reexportala con GnuPG clasico:\n"
            "  gpg --export-secret-keys --armor TU_ID > privada.asc"
        )

    if usage == 0:
        material = body[offset:]
        data, checksum = material[:-2], material[-2:]
        if sum(data) % 65536 != int.from_bytes(checksum, "big"):
            raise PGPError("Checksum del material secreto invalido (archivo corrupto).")
        return data

    if usage in (254, 255):
        sym_algo = body[offset]
        offset += 1
        s2k_type = body[offset]
        offset += 1
        hash_algo = body[offset]
        offset += 1
        salt, count = b"", None
        if s2k_type in (1, 3):
            salt = body[offset : offset + 8]
            offset += 8
        if s2k_type == 3:
            coded = body[offset]
            offset += 1
            # RFC 4880 sec 3.7.1.3: cuenta codificada en un octeto.
            count = (16 + (coded & 15)) << ((coded >> 4) + 6)
        elif s2k_type not in (0, 1):
            raise PGPError(f"Especificador S2K no soportado (tipo {s2k_type}).")
    else:
        # Modo heredado: el octeto es directamente el algoritmo simetrico y el
        # S2K es Simple con MD5 (RFC 4880 sec 5.5.3).
        sym_algo, s2k_type, hash_algo, salt, count = usage, 0, 1, b"", None

    if sym_algo not in _SYM_ALGOS:
        raise PGPError(f"Algoritmo simetrico de proteccion no soportado (id {sym_algo}).")
    _, block_size, key_len = _SYM_ALGOS[sym_algo]

    iv = body[offset : offset + block_size]
    offset += block_size
    encrypted = body[offset:]

    key = s2k_derive(passphrase, key_len, s2k_type, hash_algo, salt, count)
    decryptor = _sym_cipher(sym_algo, key, iv).decryptor()
    plain = decryptor.update(encrypted) + decryptor.finalize()

    if usage == 254:
        data, digest = plain[:-20], plain[-20:]
        if hashlib.sha1(data).digest() != digest:  # noqa: S324 - lo exige el RFC
            raise PGPError("Frase de paso incorrecta (el SHA-1 de verificacion no coincide).")
    else:
        data, checksum = plain[:-2], plain[-2:]
        if sum(data) % 65536 != int.from_bytes(checksum, "big"):
            raise PGPError("Frase de paso incorrecta (el checksum no coincide).")
    return data


def _find_uid(data: bytes) -> str:
    for tag, body in iter_packets(data):
        if tag == TAG_USER_ID:
            return body.decode("utf-8", errors="replace").strip()
    return "(sin User ID)"


def load_public_key(text: str) -> PGPKey:
    """Carga la llave publica primaria de un bloque .asc."""
    data = dearmor(text)
    uid = _find_uid(data)
    for tag, body in iter_packets(data):
        if tag in (TAG_PUBLIC_KEY, TAG_SECRET_KEY):
            version, algo, n, e, end = _parse_public_body(body)
            _exigir_v4(version)
            fingerprint = _fingerprint_v4(body[:end])
            return PGPKey(
                uid=uid,
                key_id=fingerprint[-16:],
                fingerprint=fingerprint,
                bits=n.bit_length(),
                algo_name=_RSA_ALGOS[algo],
                public_key=_build_public(n, e),
            )
    raise PGPError("El archivo no contiene ningun paquete de llave publica primaria.")


def load_secret_key(text: str, passphrase: str = "") -> PGPKey:
    """Carga y descifra la llave privada primaria de un bloque .asc."""
    data = dearmor(text)
    uid = _find_uid(data)
    for tag, body in iter_packets(data):
        if tag != TAG_SECRET_KEY:
            continue
        version, algo, n, e, end = _parse_public_body(body)
        _exigir_v4(version)
        pub_body = body[:end]
        material = _decrypt_secret_material(body, end, passphrase.encode("utf-8"))

        d, off = read_mpi(material, 0)
        p, off = read_mpi(material, off)
        q, off = read_mpi(material, off)
        # u = p^-1 mod q se lee pero no se usa: los parametros CRT se recalculan.
        try:
            private_key = _build_private(n, e, d, p, q)
        except ValueError as exc:
            raise PGPError(
                f"El material privado no es coherente ({exc}). "
                "Suele indicar una frase de paso incorrecta."
            ) from exc

        fingerprint = _fingerprint_v4(pub_body)
        return PGPKey(
            uid=uid,
            key_id=fingerprint[-16:],
            fingerprint=fingerprint,
            bits=n.bit_length(),
            algo_name=_RSA_ALGOS[algo],
            public_key=_build_public(n, e),
            private_key=private_key,
        )
    raise PGPError(
        "El archivo no contiene una llave PRIVADA. Exportala con:\n"
        "  gpg --export-secret-keys --armor TU_ID > privada.asc"
    )


def needs_passphrase(text: str) -> bool:
    """True si el paquete de llave secreta esta protegido con frase de paso."""
    try:
        data = dearmor(text)
        for tag, body in iter_packets(data):
            if tag == TAG_SECRET_KEY:
                _, _, _, _, end = _parse_public_body(body)
                return body[end] != 0
    except PGPError:
        pass
    return False


def looks_like_secret_key(text: str) -> bool:
    return "PRIVATE KEY BLOCK" in text or "SECRET KEY BLOCK" in text
