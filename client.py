"""
CLIENTE
Trabalho de Segurança da Informação - Diffie-Hellman

Este processo é totalmente separado do servidor: só conversa com ele
por HTTP (poderia estar em outra máquina). Ele:

1. Busca as chaves públicas do diffie hellman no servidor (p e g).

2. Gera a chave privada  (privada nunca sai daqui).

3. Envia sua chave pública, recebe a do servidor e o id da sessão.
4. Calcula o segredo compartilhado -> deriva a mesma chave AES do servidor.
5. Cifra um dado sensível localmente e manda só o resultado cifrado.
6. Busca o dado de volta e descriptografa localmente.

Rode com: python3 client.py


"""

import os
import time
import hmac
import hashlib
import requests

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVIDOR = "http://127.0.0.1:5000"

LIMITE_MENSAGENS = 100
LIMITE_TEMPO_SEGUNDOS = 60 * 60  # 60 minutos


class ControleSessao:
    """Monitora localmente a validade da sessão por tempo e total de mensagens."""
    def __init__(self, session_id: str, chave_aes: bytes, chave_hmac: bytes):
        self.session_id = session_id
        self.chave_aes = chave_aes
        self.chave_hmac = chave_hmac
        self.inicio = time.time()
        self.contador_mensagens = 0

    def registrar_mensagem(self):
        self.contador_mensagens += 1

    def tempo_ativo(self) -> int:
        return int(time.time() - self.inicio)

    def status(self) -> str:
        return f"Mensagens: {self.contador_mensagens}/{LIMITE_MENSAGENS} | Idade da sessão: {self.tempo_ativo()}s"


def derivar_chaves(segredo_compartilhado: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """
    Deriva 64 bytes via HKDF-SHA256:
    - Chave 1 (primeiros 32 bytes): AES-256
    - Chave 2 (últimos 32 bytes): HMAC-SHA-256
    """
    saida = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"chave-aes-dh-seguranca-info",
    ).derive(segredo_compartilhado)
    return saida[:32], saida[32:]


def cifrar_com_mac(chave_aes: bytes, chave_hmac: bytes, texto_claro: str) -> dict:
    """
    Encrypt-then-MAC:
    1. Cifra com AES-256-CBC (Chave 1)
    2. Calcula HMAC-SHA256 sobre (IV + Cifrado) (Chave 2)
    """
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
    """
    Regra do edital:
    1. O receptor recalcula o MAC usando a Chave 2.
    2. Se os MACs não baterem, o pacote é descartado imediatamente sem decifrar.
    3. Só decifra com AES-256 (Chave 1) se o MAC for válido.
    """
    conteudo = iv + cifrado
    mac_esperado = hmac.new(chave_hmac, conteudo, hashlib.sha256).digest()

    if not hmac.compare_digest(mac_recebido, mac_esperado):
        print("[CLIENTE - SEGURANÇA] MAC inválido! Integridade violada. Descartando mensagem.")
        raise ValueError("MAC inválido: a mensagem foi adulterada e descartada.")

    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(cifrado) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    texto_claro = unpadder.update(dados_padded) + unpadder.finalize()
    return texto_claro.decode("utf-8")


def main():
    print("=== Cliente: iniciando troca de chaves com o servidor ===")

    # 1) Busca os parâmetros públicos do grupo (p, g)
    resp = requests.get(f"{SERVIDOR}/dh/parametros")
    resp.raise_for_status()
    dados_params = resp.json()
    p = int(dados_params["p"], 16)
    g = dados_params["g"]

    numeros_parametros = dh.DHParameterNumbers(p, g)
    parametros = numeros_parametros.parameters()

    # 2) Gera seu próprio par de chaves dentro desse grupo e o salt efêmero
    chave_privada_cliente = parametros.generate_private_key()
    chave_publica_cliente = chave_privada_cliente.public_key()
    y_cliente = chave_publica_cliente.public_numbers().y
    salt_cliente = os.urandom(16)

    # 3) Envia sua chave pública e o salt, recebe a do servidor e o id da sessão
    resp = requests.post(
        f"{SERVIDOR}/dh/trocar-chave",
        json={
            "chave_publica": hex(y_cliente),
            "salt": salt_cliente.hex()
        },
    )
    resp.raise_for_status()
    resposta = resp.json()
    session_id = resposta["session_id"]
    y_servidor = int(resposta["chave_publica"], 16)

    numeros_publicos_servidor = dh.DHPublicNumbers(y_servidor, numeros_parametros)
    chave_publica_servidor = numeros_publicos_servidor.public_key()

    # 4) Calcula o segredo compartilhado -> deriva Chave 1 (AES) e Chave 2 (HMAC)
    segredo = chave_privada_cliente.exchange(chave_publica_servidor)
    chave_aes, chave_hmac = derivar_chaves(segredo, salt_cliente)
    
    # Inicializa o controle da sessão (Cronômetro e Contador)
    sessao = ControleSessao(session_id, chave_aes, chave_hmac)
    print(f"Sessão estabelecida: {sessao.session_id}")
    print("Chaves de sessão (AES-256 e HMAC-SHA256) derivadas localmente via HKDF.\n")

    # 5) Cifra o dado sensível localmente e envia só o resultado cifrado com o MAC
    nome = "Maria Silva"
    dado_sensivel = "CPF: 123.456.789-00"
    pacote = cifrar_com_mac(sessao.chave_aes, sessao.chave_hmac, dado_sensivel)

    resp = requests.post(
        f"{SERVIDOR}/usuarios",
        json={
            "session_id": sessao.session_id,
            "nome": nome,
            "iv": pacote["iv"],
            "cifrado": pacote["cifrado"],
            "mac": pacote["mac"],
        },
    )
    resp.raise_for_status()
    sessao.registrar_mensagem()
    usuario_id = resp.json()["id"]

    print(f"Dado enviado e gravado no banco do servidor (id={usuario_id}).")
    print("O servidor NUNCA viu o CPF em texto claro.")
    print(f"[STATUS SESSÃO] {sessao.status()}\n")

    # 6) Busca o dado de volta e descriptografa localmente (verificando o MAC primeiro)
    resp = requests.get(
        f"{SERVIDOR}/usuarios/{usuario_id}",
        params={"session_id": sessao.session_id},
    )
    resp.raise_for_status()
    sessao.registrar_mensagem()
    linha = resp.json()

    dado_recebido = verificar_mac_e_decifrar(
        chave_aes=sessao.chave_aes,
        chave_hmac=sessao.chave_hmac,
        iv=bytes.fromhex(linha["iv"]),
        cifrado=bytes.fromhex(linha["cifrado"]),
        mac_recebido=bytes.fromhex(linha["mac"]),
    )
    print(f"Lido de volta do servidor -> nome: {linha['nome']}, dado: {dado_recebido}")
    print(f"[STATUS SESSÃO] {sessao.status()}\n")


if __name__ == "__main__":
    main()