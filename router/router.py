from config.configdb import *
from models.models import *
from flasgger import Swagger, swag_from
from flask import Flask, request, redirect, url_for, session, jsonify
import hashlib
import jwt


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
                            },
                            'organizacao': {
                                'type': 'string',
                                'description': 'ID da organização'
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
                    'email_user': user.email,
                    'organizacao': user.organization_id
                }
                # Gera um token JWT
                token = jwt.encode(user_info, 'mysecretkey', algorithm='HS256')
                response = ({'success': True, 'message': 'Autenticado com sucesso', 'token': token}, {'user_info': user_info})
                return jsonify(response), 200
        else:
            response = {'success': False, 'message': 'Senha incorreta!'}
            return jsonify(response), 401
    else:
        response = {'success': False, 'message': 'Usuário não encontrado!'}
        return jsonify(response), 401