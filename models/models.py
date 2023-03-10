from sqlalchemy import Integer, ForeignKey, String, Column, Boolean
from config.configdb import *



class Organizacao(db.Model):
    __tablename__ = 'TB_ORGANIZACAO'
    ID_ORGANIZACAO = db.Column(db.Integer, primary_key=True)
    DS_ORGANIZACAO = db.Column(db.String(100), nullable=False)
    DS_CNPJ = db.Column(db.String(45), nullable=False, unique=True)
    DT_CRIACAO = db.Column(db.DateTime, nullable=False)
    FL_ATIVO = db.Column('FL_ATIVO', db.Boolean)
    PREMIUM = db.Column('PREMIUM', db.Boolean)
    #users = db.relationship('User', backref='organization', lazy=True)

    
class User(db.Model):
    __tablename__ = 'TB_USUARIO'
    id = db.Column('ID_USUARIO', db.Integer, primary_key=True)
    name = db.Column('NOME_USUARIO', db.String(100))
    email = db.Column('DS_EMAIL', db.String(100))
    phone_number = db.Column('DS_TELEFONE', db.String(15))
    password = db.Column('DS_SENHA', db.String(100))
    is_owner = db.Column('FL_PROPRIETARIO_CONTA', db.Boolean)
    organization_id = db.Column('ID_ORGANIZACAO', db.String(256))
    is_admin = db.Column('FL_ADMINISTRADOR', db.Boolean)
    #organization = db.relationship('Organization', backref='users', lazy=True)
    #organization_id = Column(Integer, ForeignKey('TB_ORGANIZACAO.ID_ORGANIZACAO'))


class Grupo(db.Model):
    __tablename__ = 'TB_GRUPO'
    ID_GRUPO = db.Column(db.Integer, primary_key = True)
    NOME_DO_GRUPO = db.Column(db.String(500), nullable=False)
    DATA_CRIACAO = db.Column(db.DateTime, nullable=False)
    FL_ATIVO = db.Column(db.Boolean)
    ID_ORGANIACAO = db.Column(db.Integer, ForeignKey('TB_ORGANIZACAO.ID_ORGANIZACAO'),  nullable=False)




class GroupUser(db.Model):
    __tablename__ = 'TB_GRUPO_USUARIO'
    user_group_id = db.Column('ID_GRUPO_USUARIO', db.Integer, primary_key = True)
    group_id = db.Column('ID_GRUPO', db.Integer, ForeignKey('TB_GRUPO.ID_GRUPO'), nullable=False)
    user_id = db.Column('ID_USUARIO', db.Integer, ForeignKey('TB_USUARIO.ID_USUARIO'), nullable=False)
    id_organization = db.Column('ID_ORGANIZACAO', db.Integer, ForeignKey('TB_ORGANIZACAO.ID_ORGANIACAO'), nullable=False)
    