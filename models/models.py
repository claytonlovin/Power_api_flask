from sqlalchemy import Integer, ForeignKey, String, Column
from config.configdb import *

class User(db.Model):
    __tablename__ = 'TB_USUARIO'
    id = db.Column('ID_USUARIO', db.Integer, primary_key=True)
    name = db.Column('NOME_USUARIO', db.String(100))
    email = db.Column('DS_EMAIL', db.String(100))
    password = db.Column('DS_SENHA', db.String(100))
    is_owner = db.Column('FL_PROPRIETARIO_CONTA', db.Boolean)
    organization_id = db.Column('ID_ORGANIZACAO', db.String(256))
    is_admin = db.Column('FL_ADMINISTRADOR', db.Boolean)
    #organization = db.relationship('Organization', backref='users', lazy=True)
    #organization_id = Column(Integer, ForeignKey('tb_organizacao.id'))

class Organization(db.Model):
    __tablename__ = 'tb_organizacao'
    id = db.Column('ID_ORGANIZACAO', db.Integer, primary_key=True)
    name = db.Column('NOME_ORGANIZACAO', db.String(100))
    is_premium = db.Column('PREMIUM', db.Boolean)