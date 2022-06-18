import sys
from time import sleep
from Crypto.Protocol.KDF import scrypt
from datetime import datetime
from datetime import timedelta
import msvcrt
import time
import pyotp

class User:
  def __init__(self, nome_de_usuario, hash_senha):
    self.nome_de_usuario = nome_de_usuario
    self.hash_senha = hash_senha

class Servidor:
  def __init__(self):
    self.usuarios = []

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
      self.iniciar_comunicacao()
    else:
      return False

  def iniciar_comunicacao(self):
    print('Comunicando...')

  def login(self, usuario: User, token: str, horario: str):
    hash_senha_digitada = self.criptografar(usuario.nome_de_usuario, token)

    if usuario.hash_senha == hash_senha_digitada:
      if self.gerar_2fa(horario) == False:
        print('\n')
        print('Código incorreto!')
    else:
      print('A senha está incorreta.')

  def buscar_usuario(self, nome: str):
    for usuario in self.usuarios:
      if usuario.nome_de_usuario == nome:
        return usuario
    return None

  def cadastrar_usuario(self, nome: str, chave: str):
    chave_scrypt = self.criptografar(nome, chave)
    usuario_a_cadastrar = User(nome, chave_scrypt)
    self.usuarios.append(usuario_a_cadastrar)

