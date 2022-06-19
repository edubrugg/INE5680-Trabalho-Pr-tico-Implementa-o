import time
import json
import pyotp
import msvcrt

import sys
from time import sleep

from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import unpad

from datetime import datetime
from datetime import timedelta

class User:
  def __init__(self, nome_de_usuario, hash_senha):
    self.nome_de_usuario = nome_de_usuario
    self.hash_senha = hash_senha

class Servidor:
  def __init__(self):
    self.usuarios = []
    self.codigo_2fa_usado_no_acesso = ''
    self.pbkdf2_codigo_2fa_usado_no_acesso = ''
    self.contador_de_mensagem = 1
    self.ultima_mensagem_recebida = ''
    self.ultima_mensagem_recebida_cifrada = ''

  def criptografar(self, usuario: str, token: str):
    salt = usuario[::-1]
    chave_scrypt = scrypt(token, salt, 16, N=2**14, r=8, p=1)
    return chave_scrypt

  class TimeoutExpired(Exception):
    "Exceção gerada quando o usuário leva mais de 30 segundos" 
    def __init__(self):
      super().__init__("Novo código de autenticação gerado: ")

  def input_com_timeout(self, prompt, timeout, timer=time.monotonic):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    endtime = timer() + timeout
    result = []
    while timer() < endtime:
        if msvcrt.kbhit():
            result.append(msvcrt.getwche())
            if result[-1] == '\r':
                return ''.join(result[:-1])
        time.sleep(0.04)

  def gerar_2fa(self, horario):
    segredo = pyotp.random_base32()
    totp = pyotp.TOTP(segredo)
    print('Código de autenticação: ' + totp.now())
    horario_login_mais_30 = horario + timedelta(seconds=30)
    print('\n')
    while True:
      codigo_do_usuario = self.input_com_timeout('Qual o código de autenticação? ', 30)
      if horario_login_mais_30 < datetime.now():
        print('\n')
        print('Novo código de autenticação: ' + totp.now())
        print('\n')
        horario_login_mais_30 += timedelta(seconds=30)
        continue
      else:
        break
    if totp.verify(codigo_do_usuario):
      print('\n')
      print('Login feito com sucesso!')
      self.codigo_2fa_usado_no_login = codigo_do_usuario
      return codigo_do_usuario
    else:
      return False

  def login(self, usuario: User, token: str, horario: str):
    hash_senha_digitada = self.criptografar(usuario.nome_de_usuario, token)
    salt = usuario.nome_de_usuario[::-1]

    if usuario.hash_senha == hash_senha_digitada:
      autenticacao = self.gerar_2fa(horario)
      if autenticacao == False:
        print('\n')
        print('Código incorreto!')
        return False
      else:
        codigo_pbkdf2 = PBKDF2(self.codigo_2fa_usado_no_login, salt, 32, count=10000, hmac_hash_module=SHA512)
        self.pbkdf2_codigo_2fa_usado_no_acesso = codigo_pbkdf2
        return autenticacao
    else:
      print('A senha está incorreta.')
      return

  def buscar_usuario(self, nome: str):
    for usuario in self.usuarios:
      if usuario.nome_de_usuario == nome:
        return usuario
    return None

  def cadastrar_usuario(self, nome: str, chave: str):
    chave_scrypt = self.criptografar(nome, chave)
    usuario_a_cadastrar = User(nome, chave_scrypt)
    self.usuarios.append(usuario_a_cadastrar)

  def receber_mensagem(self, mensagem):
    ''' Descriptografia da mensagem enviada pelo cliente. '''
    chave = self.pbkdf2_codigo_2fa_usado_no_acesso
    try:
      b64 = json.loads(mensagem)
      json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
      jv = {k:b64decode(b64[k]) for k in json_k}

      self.ultima_mensagem_recebida_cifrada = jv['ciphertext']
      cipher = AES.new(chave, AES.MODE_GCM, nonce=jv['nonce'])
      cipher.update(jv['header'])
      mensagem_decifrada = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
      self.ultima_mensagem_recebida = mensagem_decifrada.decode("utf-8")
    except (ValueError, KeyError):
      print('Ocorreu um erro na descriptografia')

  def enviar_mensagem(self):
    mensagem = "Mensagem " + str(self.contador_de_mensagem) + " recebida foi \"" + self.ultima_mensagem_recebida + '\"'

    chave = self.pbkdf2_codigo_2fa_usado_no_acesso
    self.contador_de_mensagem += 1

    # Encriptografando a mensagem
    cipher = AES.new(chave, AES.MODE_GCM)
    header = b'header'
    cipher.update(header)
    b_message = mensagem.encode('utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(b_message)

    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag ]]
    mensagem_encriptografada = json.dumps(dict(zip(json_k, json_v)))

    # Enviando mensagem pro servidor
    print('- Servidor -------------------------------------------------')
    print('\n')
    print('Mensagem cifrada recebida pelo servidor: ', self.ultima_mensagem_recebida_cifrada)
    print('\n')
    print('Mensagem decifrada pelo servidor: ', self.ultima_mensagem_recebida)
    print('\n')
    print('Mensagem enviada pelo servidor: ', mensagem)
    print('\n')
    print('Mensagem criptografada enviada para o cliente: ', ciphertext)
    print('\n')

    return mensagem_encriptografada

