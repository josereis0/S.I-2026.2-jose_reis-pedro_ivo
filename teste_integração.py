"""
TESTE DE INTEGRAÇÃO - HANDSHAKE E COMUNICAÇÃO COMPLETA
Projeto de Segurança da Informação

Valida o ciclo de vida ponta a ponta:
1. Obtenção dos parâmetros públicos DH (p, g) via endpoint HTTP.
2. Troca de chaves públicas efêmeras e geração do segredo compartilhado.
3. Derivação local das chaves de sessão (AES-256 e HMAC-SHA256) via HKDF.
4. Envio de payload cifrado com MAC (Encrypt-then-MAC) e gravação no banco.
5. Leitura do dado cifrado e validação estrita do MAC antes da decifração.
6. Rejeição com status 403 ao enviar pacote adulterado no trânsito.
"""

import os
import json
import unittest
from cryptography.hazmat.primitives.asymmetric import dh

from server import app, criar_banco
from client import (
    derivar_chaves,
    cifrar_com_mac,
    verificar_mac_e_decifrar,
)


class TestIntegracaoHandshakeCompleto(unittest.TestCase):

    def setUp(self):
        """Inicializa o banco de dados e o cliente de testes da aplicação Flask."""
        criar_banco()
        self.app = app.test_client()
        self.app.testing = True

    def test_fluxo_completo_e_rejeicao_de_adulteracao(self):
        # -------------------------------------------------------------
        # ETAPA 1: Obter parâmetros públicos DH do servidor
        # -------------------------------------------------------------
        resp_params = self.app.get("/dh/parametros")
        self.assertEqual(resp_params.status_code, 200)
        dados_params = resp_params.get_json()

        p = int(dados_params["p"], 16)
        g = dados_params["g"]
        parametros_dh = dh.DHParameterNumbers(p, g).parameters()

        # -------------------------------------------------------------
        # ETAPA 2: Cliente gera par efêmero e realiza o handshake
        # -------------------------------------------------------------
        chave_privada_cliente = parametros_dh.generate_private_key()
        y_cliente = chave_privada_cliente.public_key().public_numbers().y
        salt_cliente = os.urandom(16)

        resp_troca = self.app.post(
            "/dh/trocar-chave",
            data=json.dumps({
                "chave_publica": hex(y_cliente),
                "salt": salt_cliente.hex()
            }),
            content_type="application/json"
        )
        self.assertEqual(resp_troca.status_code, 200)
        dados_troca = resp_troca.get_json()

        session_id = dados_troca["session_id"]
        y_servidor = int(dados_troca["chave_publica"], 16)
        self.assertTrue(len(session_id) > 0)

        # -------------------------------------------------------------
        # ETAPA 3: Derivar chaves simétricas de sessão no cliente
        # -------------------------------------------------------------
        numeros_servidor = dh.DHPublicNumbers(y_servidor, dh.DHParameterNumbers(p, g))
        chave_publica_servidor = numeros_servidor.public_key()
        segredo_compartilhado = chave_privada_cliente.exchange(chave_publica_servidor)

        chave_aes, chave_hmac = derivar_chaves(segredo_compartilhado, salt_cliente)
        self.assertEqual(len(chave_aes), 32)
        self.assertEqual(len(chave_hmac), 32)

        # -------------------------------------------------------------
        # ETAPA 4: Envio legítimo com Encrypt-then-MAC
        # -------------------------------------------------------------
        dado_confidencial = "CPF: 123.456.789-99"
        pacote = cifrar_com_mac(chave_aes, chave_hmac, dado_confidencial)

        resp_envio = self.app.post(
            "/usuarios",
            data=json.dumps({
                "session_id": session_id,
                "nome": "Carlos Drummond",
                "iv": pacote["iv"],
                "cifrado": pacote["cifrado"],
                "mac": pacote["mac"]
            }),
            content_type="application/json"
        )
        self.assertEqual(resp_envio.status_code, 200)
        usuario_id = resp_envio.get_json()["id"]

        # -------------------------------------------------------------
        # ETAPA 5: Leitura de volta e decifração bem-sucedida
        # -------------------------------------------------------------
        resp_leitura = self.app.get(f"/usuarios/{usuario_id}?session_id={session_id}")
        self.assertEqual(resp_leitura.status_code, 200)
        dados_recebidos = resp_leitura.get_json()

        texto_decifrado = verificar_mac_e_decifrar(
            chave_aes=chave_aes,
            chave_hmac=chave_hmac,
            iv=bytes.fromhex(dados_recebidos["iv"]),
            cifrado=bytes.fromhex(dados_recebidos["cifrado"]),
            mac_recebido=bytes.fromhex(dados_recebidos["mac"])
        )
        self.assertEqual(texto_decifrado, dado_confidencial)

        # -------------------------------------------------------------
        # ETAPA 6: Simulação de ataque em trânsito (MAC forjado/adulterado)
        # -------------------------------------------------------------
        resp_ataque = self.app.post(
            "/usuarios",
            data=json.dumps({
                "session_id": session_id,
                "nome": "Atacante Injetando Pacote",
                "iv": pacote["iv"],
                "cifrado": pacote["cifrado"],
                "mac": os.urandom(32).hex()  # MAC adulterado
            }),
            content_type="application/json"
        )
        # O servidor deve rejeitar com status 403 Forbidden
        self.assertEqual(resp_ataque.status_code, 403)


if __name__ == "__main__":
    unittest.main()