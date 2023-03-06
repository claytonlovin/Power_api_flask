from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, template_folder="templates", static_folder="static")

app.secret_key = 'chave secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:cs0209012@127.0.0.1/DB_POWERHUB_HM'
db = SQLAlchemy(app)