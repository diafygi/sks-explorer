import os
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON

# sks-explorer specific imports
from views import app

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
db = SQLAlchemy(app)

class PublicKey(db.Model):
    __tablename__ = "publickey"
    id = db.Column(db.Integer, primary_key=True)
    search_string = db.Column(db.Text, index=True)
    fingerprint = db.Column(db.String(40), index=True)
    key_id = db.Column(db.String(16), index=True)
    json_hash = db.Column(db.String(64), index=True)
    json_obj = db.Column(JSON)

class SubKey(db.Model):
    __tablename__ = "subkey"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)
    fingerprint = db.Column(db.String(40), index=True)
    key_id = db.Column(db.String(16), index=True)
    json_obj = db.Column(JSON)

class UserID(db.Model):
    __tablename__ = "userid"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)
    json_obj = db.Column(JSON)

class UserAttribute(db.Model):
    __tablename__ = "userattribute"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)
    json_obj = db.Column(JSON)

class Image(db.Model):
    __tablename__ = "image"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("userattribute.id"), index=True)
    json_obj = db.Column(JSON)

class Signature(db.Model):
    __tablename__ = "signature"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)
    subkey = db.Column(db.ForeignKey("subkey.id"), index=True)
    userid = db.Column(db.ForeignKey("userid.id"), index=True)
    userattribute = db.Column(db.ForeignKey("userattribute.id"), index=True)
    signer_key_id = db.Column(db.String(16), index=True)
    signer_publickey = db.Column(db.ForeignKey("publickey.id"), index=True)
    signer_subkey = db.Column(db.ForeignKey("subkey.id"), index=True)
    is_valid = db.Column(db.Boolean)
    json_obj = db.Column(JSON)

