from Crypto.Protocol.KDF import scrypt
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

  def gerar_2fa(self, horario):
    segredo = pyotp.random_base32()
    totp = pyotp.TOTP(segredo)
    print('Código de autenticação: ' + totp.now())
    print('\n')
    codigo_do_usuario = input('Qual o código de autenticação? ')
    totp.verify(codigo_do_usuario)

  def login(self, usuario: User, token: str, horario: str):
    senha_digitada = self.criptografar(usuario.nome_de_usuario, token)

    if usuario.hash_senha == senha_digitada:
      # TODO
      self.gerar_2fa(horario)
      print('Login feito com sucesso!')
      print('\n')
    else:
      print('A senha está incorreta.')
      print('\n')

  def buscar_usuario(self, nome: str):
    for usuario in self.usuarios:
      if usuario.nome_de_usuario == nome:
        return usuario
    return None

  def cadastrar_usuario(self, nome: str, chave: str):
    chave_scrypt = self.criptografar(nome, chave)
    usuario_a_cadastrar = User(nome, chave_scrypt)
    self.usuarios.append(usuario_a_cadastrar)

