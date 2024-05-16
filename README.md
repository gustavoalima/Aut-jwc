Trabalho Prático: Autenticação com JWT em Node.js e Express com Sequelize e SQLite

 executar = node server.js

Dependências = npm install express sequelize sqlite3 jsonwebtoken bcrypt



Como Usar as Rotas:
Registrar um Novo Usuário:

Método: POST
URL: http://localhost:3000/api/auth/register
Corpo da Requisição:
json
Copiar código
{
  "name": "Nome do Usuário",
  "email": "usuario@email.com",
  "password": "senha123"
}
Fazer Login e Obter Token JWT:

Método: POST
URL: http://localhost:3000/api/auth/login
Corpo da Requisição:
json
Copiar código
{
  "email": "usuario@email.com",
  "password": "senha123"
}
Resposta:
json
Copiar código
{
  "token": "seu_token_jwt_aqui"
}
Acessar Rota Protegida:

Método: GET
URL: http://localhost:3000/api/protegida
Cabeçalho da Requisição:
makefile
Copiar código
Authorization: Bearer seu_token_jwt_aqui
Certifique-se de substituir seu_token_jwt_aqui pelo token JWT obtido na resposta de login.
