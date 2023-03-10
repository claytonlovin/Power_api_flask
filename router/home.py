
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





from flask_jwt_extended import jwt_required, get_jwt_identity
@app.route('/powerhub/home', methods=['GET'])
@swag_from({
    'summary': 'ListUserGroup',
    'description': 'Cria Organizacao.',
    'tags': ['Home'],
    'parameters': [
        {
            'name': 'user_id',
            'in': 'query',
            'required': True,
            'description': 'ID do usuário',
            'type': 'integer'
        }
    ],
    'responses': {
        '200': {
            'description': 'Lista de grupos do usuário',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'ID_GRUPO': {
                            'type': 'integer',
                            'description': 'ID do grupo'
                        },
                        'ID_USUARIO': {
                            'type': 'integer',
                            'description': 'ID do usuário'
                        },
                        'NOME_DO_GRUPO': {
                            'type': 'string',
                            'description': 'Nome do grupo'
                        }, 
                        'DATA_CRIACAO':{
                            'type': 'string',
                            'description': 'Data Criação'
                        }
                    }
                }
            }
        },
        '400': {
            'description': 'Erro de requisição',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'description': 'Descrição do erro'
                    }
                }
            }
        }
    }
})
#@jwt_required()
#@jwt_required(optional=True, fresh=True)

def home():
   
    user_id = request.args.get('user_id')
    if user_id is None:
        return jsonify({"message": "user_id parameter is required"}), 400 
    grupos_usuario = GroupUser.query.join(Grupo).join(Organizacao).join(User). \
                    filter_by(user_id=user_id).all()
    list_grupo_usuario = [{
        "ID_GRUPO": g.group_id,     
        "ID_USUARIO": g.user_id,     
        "NOME_DO_GRUPO": g.grupo.NOME_DO_GRUPO,     
        "DATA_CRIACAO": g.grupo.DATA_CRIACAO,    
        "NOME_ORGANIZACAO": g.organizacao.NOME_ORGANIZACAO,    
        "NOME_USUARIO": g.user.name} 
        for g in grupos_usuario]

    return jsonify(list_grupo_usuario)
