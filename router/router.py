from config.configdb import *
from models.models import *
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from flasgger import Swagger, swag_from
from flask import Flask, request, redirect, url_for, session, jsonify
import hashlib
import jwt
import re
from datetime import datetime

@app.route('/login', methods=['POST'])
@swag_from({
    'summary': 'AuthenticateUser',
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
                    'id_user': user.user_id,
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


# HOME

@app.route('/register', methods=['POST'])
@swag_from({
    'summary': 'CreateOrganizationandUser',
    'description': 'Cria Organizacao.',
    'tags': ['login'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'organization_name': {
                        'type': 'string',
                        'description': 'Nome da empresa'
                    },
                    'cnpj': {
                        'type': 'string',
                        'description': 'CNPJ Empresa'
                    },
                    'email' :{
                        'type': 'string',
                        'description': 'Email da Empresa'
                    },
                    'phone_number': {
                        'type': 'string',
                        'Description': 'Numero Telefone'
                    },
                    'name': {
                        'type': 'string',
                        'Description': 'Nome do Responsável'
                    },
                    'password': {
                        'type': 'string',
                        'Description': 'Senha do Usuário'
                    }
                    
                }
            }
        }
    ],
    'responses': {
        '201': {
            'description': 'Organizacao criada com sucesso',
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
                        'organization_name': {
                            'type': 'string',
                            'description': 'Nome da empresa'
                        },
                        'cnpj': {
                            'type': 'string',
                            'description': 'CNPJ Empresa'
                        },
                        'email' :{
                            'type': 'string',
                            'description': 'Email da Empresa'
                        },
                        'phone_number': {
                            'type': 'string',
                            'Description': 'Numero Telefone'
                        },
                        'name': {
                            'type': 'string',
                            'Description': 'Nome do Responsável'
                        },
                        'password': {
                            'type': 'string',
                            'Description': 'Senha do Usuário'
                        }
                        
                }
                    }
                }
            }
        },
        400: {
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

def register():
    if not request.is_json:
        return jsonify({'error': 'Dados enviados em formato incorreto'}), 400

    json_data = request.get_json()
    organization_name = json_data.get('organization_name')
    cnpj = json_data.get('cnpj')
    email = json_data.get('email')
    phone_number = json_data.get('phone_number')
    name = json_data.get('name')
    password = json_data.get('password')

    user_info = {
                'organization_name': organization_name,
                'cnpj': cnpj,
                'email': email,
                'phone_number': phone_number,
                'name': name,
                'password': password
                }

    senha_criptografada = hashlib.sha256(password.encode()).hexdigest()
    if not all([organization_name, cnpj, email, phone_number, name, password]):
        return jsonify({'error': 'Por favor, preencha todos os campos obrigatórios'}), 400

    if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify({'error': 'E-mail inválido'}), 400

    if not re.match(r'[0-9]{2}[0-9]{5}[0-9]{4}', phone_number):
        return jsonify({'error': 'Telefone inválido'}), 400

    try:
        # criar sessão
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=db.engine)
        session = Session()

        # executar procedure
        SQL = text('CALL sp_create_organizacao_and_user(:param1, :param2, :param3, :param4, :param5, :param6, :param7, :param8, :param9, :param10, :param11, :param12, :param13, :param14, :param15, :param16, :param17, :param18, :param19, :param20, :param21, :param22, :param23, :param24)')

        params = {
        'param1': 0, 'param2': organization_name, 'param3': datetime.now(), 'param4': 1, 'param5': 0, 'param6': cnpj,
        'param7': 0, 'param8': 'PW Grupo', 'param9': datetime.now(),'param10': 1, 'param11': 0,
        'param12': 0, 'param13': name, 'param14': phone_number, 'param15': email, 'param16': email, 'param17': senha_criptografada, 'param18': 1, 'param19': 0, 'param20': 1,
        'param21': 0, 'param22': 0, 'param23': 0, 'param24': 0
        }

        
        with db.engine.connect() as conn:
            conn.execute(SQL, params)
            conn.commit()
        print('Dados criados com sucesso!')

        
    except IntegrityError as e:
        db.session.rollback()
        error_info = str(e.orig)
        if 'UNIQUE' in error_info and 'email' in error_info:
            return jsonify({'error': 'Alguém está utilizando esse mesmo login ou senha'}), 400
        elif 'UNIQUE' in error_info and 'cnpj' in error_info:
            return jsonify({'error': 'CNPJ Já cadastrado!'}), 400
        elif 'UNIQUE' in error_info and 'phone_number' in error_info:
            return jsonify({'error': 'Número de telefone já cadastrado!'}), 400
        else:
            return jsonify({'error': 'Erro ao inserir no banco de dados'}, {'error': error_info}), 400

    response = ({'success': True, 'message': 'Organização criada com sucesso'}, {'user_info': user_info})
    return jsonify(response), 201



