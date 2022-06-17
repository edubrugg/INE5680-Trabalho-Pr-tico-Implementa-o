from Crypto.Protocol.KDF import scrypt

class User:
  def __init__(self, nome_de_usuario, hash_senha):
    self.nome_de_usuario = nome_de_usuario
    self.hash_senha = hash_senha

class Servidor:
  def __init__(self):
    self.usuarios = []

  def criptografar(self, usuario: str, chave: str):
    salt = usuario[::-1]
    chave_scrypt = scrypt(chave, salt, 16, N=2**14, r=8, p=1)
    return chave_scrypt

  def login(self):
    print('---------------Cadastro---------------')
    usuario = input('Informe o nome do usuário: ')
    senha = input('Informe a senha do usuário: ')

  def buscar_usuario(self, nome: str):
    for usuario in self.usuarios:
      if usuario.nome_de_usuario == nome:
        return usuario
    return None

  def cadastrar_usuario(self, nome: str, chave: str):
    chave_scrypt = self.criptografar(nome, chave)
    usuario_a_cadastrar = User(nome, chave_scrypt)
    self.usuarios.append(usuario_a_cadastrar)

