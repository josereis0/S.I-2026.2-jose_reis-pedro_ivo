"""
TESTES UNITÁRIOS DAS PRIMITIVAS CRIPTOGRÁFICAS
Trabalho de Segurança da Informação

Valida de forma isolada (sem depender de servidor ou conexões de rede):
1. Diffie-Hellman Ephemeral (DHE): acordo de chaves e igualdade do segredo.
2. HKDF-SHA256: expansão de 64 bytes e separação das Chaves 1 (AES) e 2 (HMAC).
3. AES-256-CBC: cifragem e decifragem com preenchimento PKCS#7.
4. HMAC-SHA256: integridade estrita e detecção de adulteração (descarte imediato).
"""

import os
import unittest
from cryptography.hazmat.primitives.asymmetric import dh

# Importa as funções diretamente da sua implementação
from client import (
    derivar_chaves,
    cifrar_com_mac,
    verificar_mac_e_decifrar,
)


class TestPrimitivasCriptograficas(unittest.TestCase):

    def test_01_diffie_hellman_acordo_de_chaves(self):
        """Valida se cliente e servidor geram exatamente o mesmo segredo compartilhado."""
        # Usa grupo de 1024 bits exclusivamente para o teste unitário rodar rápido
        parametros = dh.generate_parameters(generator=2, key_size=1024)

        # Alice (Cliente)
        privada_alice = parametros.generate_private_key()
        publica_alice = privada_alice.public_key()

        # Bob (Servidor)
        privada_bob = parametros.generate_private_key()
        publica_bob = privada_bob.public_key()

        # Cálculo cruzado do segredo
        segredo_alice = privada_alice.exchange(publica_bob)
        segredo_bob = privada_bob.exchange(publica_alice)

        self.assertEqual(segredo_alice, segredo_bob, "Os segredos compartilhados devem ser idênticos.")
        self.assertGreater(len(segredo_alice), 0, "O segredo não pode ser vazio.")

    def test_02_hkdf_derivacao_e_divisao_de_chaves(self):
        """Garante a derivação correta de 64 bytes (32B para AES e 32B para HMAC)."""
        segredo_simulado = os.urandom(32)
        salt_simulado = os.urandom(16)

        chave_aes, chave_hmac = derivar_chaves(segredo_simulado, salt_simulado)

        # Checa tamanhos das chaves (256 bits cada = 32 bytes)
        self.assertEqual(len(chave_aes), 32, "Chave AES-256 deve ter 32 bytes.")
        self.assertEqual(len(chave_hmac), 32, "Chave HMAC-SHA256 deve ter 32 bytes.")
        self.assertNotEqual(chave_aes, chave_hmac, "As chaves AES e HMAC devem ser diferentes entre si.")

        # Valida reprodutibilidade (mesmo segredo + mesmo salt = mesmas chaves)
        chave_aes_rep, chave_hmac_rep = derivar_chaves(segredo_simulado, salt_simulado)
        self.assertEqual(chave_aes, chave_aes_rep)
        self.assertEqual(chave_hmac, chave_hmac_rep)

    def test_03_aes_cifragem_e_decifragem_integra(self):
        """Valida que uma mensagem legítima é cifrada e decifrada perfeitamente."""
        chave_aes = os.urandom(32)
        chave_hmac = os.urandom(32)
        mensagem_original = "Dado ultra secreto: CPF 999.888.777-66"

        pacote = cifrar_com_mac(chave_aes, chave_hmac, mensagem_original)

        # Executa verificação e decifração
        texto_decifrado = verificar_mac_e_decifrar(
            chave_aes=chave_aes,
            chave_hmac=chave_hmac,
            iv=bytes.fromhex(pacote["iv"]),
            cifrado=bytes.fromhex(pacote["cifrado"]),
            mac_recebido=bytes.fromhex(pacote["mac"]),
        )

        self.assertEqual(texto_decifrado, mensagem_original, "O texto decifrado deve ser idêntico ao original.")

    def test_04_hmac_descarte_de_mensagem_adulterada(self):
        """Garante que qualquer alteração de 1 bit é detectada e a decifração é impedida."""
        chave_aes = os.urandom(32)
        chave_hmac = os.urandom(32)
        mensagem_original = "Transferir R$ 10.000 para conta X"

        pacote = cifrar_com_mac(chave_aes, chave_hmac, mensagem_original)

        # Simula ataque no trânsito: inverte 1 byte do texto cifrado
        cifrado_bytes = bytearray(bytes.fromhex(pacote["cifrado"]))
        cifrado_bytes[0] ^= 0x01  # Altera o primeiro bit
        cifrado_adulterado = bytes(cifrado_bytes)

        # Deve disparar ValueError (descarte imediato sem tentar decifrar)
        with self.assertRaises(ValueError):
            verificar_mac_e_decifrar(
                chave_aes=chave_aes,
                chave_hmac=chave_hmac,
                iv=bytes.fromhex(pacote["iv"]),
                cifrado=cifrado_adulterado,
                mac_recebido=bytes.fromhex(pacote["mac"]),
            )


if __name__ == "__main__":
    unittest.main()