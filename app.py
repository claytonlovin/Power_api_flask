from flask import Flask, request, redirect, url_for, session, jsonify
import jwt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token
from flasgger import Swagger, swag_from
import hashlib


app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = 'chave secreta'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:cs0209012@127.0.0.1/DB_POWERHUB_HM'
db = SQLAlchemy(app)

## config swagger
SWAGGER_TEMPLATE = {"securityDefinitions": {"APIKeyHeader": {"type": "apiKey", "name": "x-access-token", "in": "header"}}}

swagger = Swagger(app, template=SWAGGER_TEMPLATE)
"""
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "Minha API",
        "description": "Descrição da minha API",
        "version": "1.0.0"
    }
})"""

class User(db.Model):
    __tablename__ = 'TB_USUARIO'
    id = db.Column('ID_USUARIO', db.Integer, primary_key=True)
    name = db.Column('NOME_USUARIO', db.String(100))
    email = db.Column('DS_EMAIL', db.String(100))
    password = db.Column('DS_SENHA', db.String(100))
    is_owner = db.Column('FL_PROPRIETARIO_CONTA', db.Boolean)
    organization_id = db.Column('ID_ORGANIZACAO', db.Integer)
    is_admin = db.Column('FL_ADMINISTRADOR', db.Boolean)
    #organization = db.relationship('Organization', backref='users', lazy=True)

class Organization(db.Model):
    __tablename__ = 'tb_organizacao'
    id = db.Column('ID_ORGANIZACAO', db.Integer, primary_key=True)
    name = db.Column('NOME_ORGANIZACAO', db.String(100))
    is_premium = db.Column('PREMIUM', db.Boolean)

@app.route('/login', methods=['POST'])
@swag_from({
    'summary': 'Autentica o usuário',
    'description': 'Autentica o usuário com email e senha.',
    'tags': ['login'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {
                        'type': 'string',
                        'description': 'O email do usuário'
                    },
                    'password': {
                        'type': 'string',
                        'description': 'A senha do usuário'
                    }
                }
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Usuário autenticado com sucesso',
            'schema': {
                'type': 'object',
                'properties': {
                    'msg': {
                        'type': 'string',
                        'description': 'Mensagem de sucesso'
                    },
                    'user_info': {
                        'type': 'object',
                        'properties': {
                            'id_user': {
                                'type': 'integer',
                                'description': 'ID do usuário autenticado'
                            },
                            'nome_user': {
                                'type': 'string',
                                'description': 'Nome do usuário autenticado'
                            },
                            'email_user': {
                                'type': 'string',
                                'description': 'Email do usuário autenticado'
                            }
                        }
                    }
                }
            }
        },
        '400': {
            'description': 'Senha incorreta ou usuário não encontrado',
            'schema': {
                'type': 'object',
                'properties': {
                    'success': {
                        'type': 'boolean',
                        'description': 'Indica se a autenticação foi bem sucedida'
                    },
                    'message': {
                        'type': 'string',
                        'description': 'Mensagem de erro'
                    }
                }
            }
        }
    }
})

def login():
    msg = ''
    if request.method == 'POST':
        req_data = request.get_json()
        email = req_data['email']
        password = req_data['password']
        user = User.query.filter_by(email=email).first()
        if user:
            password_criptografada = hashlib.sha256(password.encode()).hexdigest()
            if password_criptografada == user.password:
                # Constrói o dicionário com as informações do usuário
                user_info = {
                    'id_user': user.id,
                    'nome_user': user.name,
                    'email_user': user.email
                }
                # Gera um token JWT
                token = jwt.encode(user_info, 'mysecretkey', algorithm='HS256')
                response = {'success': True, 'message': 'Autenticado com sucesso', 'token': token}
                return jsonify(response), 200
        else:
            response = {'success': False, 'message': 'Senha incorreta!'}
            return jsonify(response), 401
    else:
        response = {'success': False, 'message': 'Usuário não encontrado!'}
        return jsonify(response), 401

if __name__ == '__main__':
    app.run(debug=True)

