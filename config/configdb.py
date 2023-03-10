from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

app = Flask(__name__, template_folder="templates", static_folder="static")

#jwt = JWTManager(app)
#app.config['JWT_SECRET_KEY'] = 'super-secret' # Exemplo de configuração do token
#app.config['JWT_TOKEN_LOCATION'] = ['headers'] # Aqui é onde a linha de código deve ser adicionada


app.secret_key = 'chave secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:cs0209012@127.0.0.1/DB_POWERHUB_HM'
db = SQLAlchemy(app)