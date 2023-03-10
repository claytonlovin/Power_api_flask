from flask import Flask, request, redirect, url_for, session, jsonify
from flask_jwt_extended import create_access_token
from flasgger import Swagger, swag_from

from config.configdb import *
from router.router import *

## config swagger
SWAGGER_TEMPLATE = {
    "securityDefinitions": {
        "APIKeyHeader": {
            "type": "apiKey",
            "name": "x-access-token",
            "in": "header"
        }
    },
    "info": {
        "title": "PowerHUB API",
        "description": "Versão da api do powerhub com autenticação JWT",
        "version": "1.0.0"
    }
}

swagger = Swagger(app, template=SWAGGER_TEMPLATE)

if __name__ == '__main__':
    app.run(debug=True)
