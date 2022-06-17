from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

from src.servidor import Servidor

class Cliente:
  def __init__(self):
    self.usuarios = []
    self.servidor = Servidor()


  def cadastrar(self):
    # Input do usuário
    print('-------------- Cadastro --------------')
    usuario = input('Informe o nome do usuário: ')
    senha = input('Informe a senha do usuário: ')
    print('\n')

    # Validação do nome do usuário
    if self.servidor.buscar_usuario(usuario) != None:
      print('Usuário já existente.')
      print('\n')
      return
    if not usuario:
      print('Por favor informe um nome válido para o usuário.')
      print('\n')
      return

    # Chama o servidor pra fazer o cadastro
    salt = usuario[::-1]
    chave_PBKDF2 = PBKDF2(senha, salt, 32, count=10000, hmac_hash_module=SHA512)
    self.servidor.cadastrar_usuario(usuario, chave_PBKDF2)
    print('Usuário ' + usuario + ' cadastrado!')
    print('\n')

  def login(self):
    # TODO
    print('--------------- Login ---------------')
    usuario = input('Usuário: ')
    senha = input('Senha: ')
    print('\n')

    # Busca o cadastro do usuário
    usuario_buscado = self.servidor.buscar_usuario(usuario)
    if usuario_buscado == None:
      print('Este usuário é inválido ou não está cadastrado.')
      print('\n')
      return

    salt = usuario[::-1]
    chave_PBKDF2 = PBKDF2(senha, salt, 32, count=10000, hmac_hash_module=SHA512)
    horario = str(datetime.now())[11:]
    horario_formatado = str(horario)[:8]
    self.servidor.login(usuario_buscado, chave_PBKDF2, horario_formatado)
