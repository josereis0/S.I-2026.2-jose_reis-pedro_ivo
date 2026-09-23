"""
MÓDULO CRIPTOGRÁFICO DO CHAT UABJ
Implementa:
- FFDH (Diffie-Hellman) para acordo de chaves
- HKDF-SHA256 para derivação de 64 bytes (AES-256 + HMAC-SHA256)
- Encrypt-then-MAC (AES-256-CBC + HMAC-SHA-256)
- Inspeção e validação estrita de integridade com descarte prévio
- Controlo e rotação dinâmica de sessão (Seção 6.4)
"""


import os
import time
import json
import hmac
import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

INTERVALO_MENSAGENS = (3, 8)
INTERVALO_TEMPO_SEGUNDOS = (30 * 60, 60 * 60)


def derivar_chaves(segredo_compartilhado: bytes, salt: bytes) -> tuple[bytes, bytes]:
    saida = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"chave-aes-dh-seguranca-info",
    ).derive(segredo_compartilhado)
    return saida[:32], saida[32:]


def cifrar_com_mac(chave_aes: bytes, chave_hmac: bytes, texto_claro: str) -> dict:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    dados_padded = padder.update(texto_claro.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(dados_padded) + encryptor.finalize()

    mac = hmac.new(chave_hmac, iv + cifrado, hashlib.sha256).digest()
    return {
        "iv": iv.hex(),
        "cifrado": cifrado.hex(),
        "mac": mac.hex()
    }


def verificar_mac_e_decifrar(chave_aes: bytes, chave_hmac: bytes, iv: bytes, cifrado: bytes, mac_recebido: bytes) -> str:
    conteudo = iv + cifrado
    mac_esperado = hmac.new(chave_hmac, conteudo, hashlib.sha256).digest()

    if not hmac.compare_digest(mac_recebido, mac_esperado):
        raise ValueError("MAC inválido: pacote corrompido ou adulterado.")

    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(cifrado) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    texto_claro = unpadder.update(dados_padded) + unpadder.finalize()
    return texto_claro.decode("utf-8")


class SessaoCripto:
    def __init__(self, session_id: str, chave_aes: bytes, chave_hmac: bytes, limite_mensagens: int = None):
        self.session_id = session_id
        self.chave_aes = chave_aes
        self.chave_hmac = chave_hmac
        self.inicio = time.time()
        self.contador_mensagens = 0
        self.limite_mensagens = limite_mensagens or secrets.SystemRandom().randint(*INTERVALO_MENSAGENS)
        self.limite_tempo = secrets.SystemRandom().randint(*INTERVALO_TEMPO_SEGUNDOS)

    def registrar_uso(self):
        self.contador_mensagens += 1

    def precisa_renovar(self) -> bool:
        if self.contador_mensagens >= self.limite_mensagens:
            return True
        if (time.time() - self.inicio) > self.limite_tempo:
            return True
        return False

    def cifrar_envelope(self, pacote_dict: dict) -> dict:
        # Apenas mensagens reais contam para a rotação de chaves
        if pacote_dict.get("action") == "send_message":
            self.registrar_uso()

        texto_json = json.dumps(pacote_dict)
        cifra = cifrar_com_mac(self.chave_aes, self.chave_hmac, texto_json)
        return {
            "action": "secure_envelope",
            "session_id": self.session_id,
            "iv": cifra["iv"],
            "cifrado": cifra["cifrado"],
            "mac": cifra["mac"]
        }

    def decifrar_envelope(self, envelope_dict: dict) -> dict:
        iv = bytes.fromhex(envelope_dict["iv"])
        cifrado = bytes.fromhex(envelope_dict["cifrado"])
        mac = bytes.fromhex(envelope_dict["mac"])
        texto_json = verificar_mac_e_decifrar(self.chave_aes, self.chave_hmac, iv, cifrado, mac)
        dados = json.loads(texto_json)

        if dados.get("action") == "send_message":
            self.registrar_uso()

        return dados