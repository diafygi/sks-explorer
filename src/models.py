import os
from flask.ext.sqlalchemy import SQLAlchemy

# sks-explorer specific imports
from views import app

# See README for how to set this environmental variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
db = SQLAlchemy(app)

class PublicKey(db.Model):
    __tablename__ = "publickey"
    id = db.Column(db.Integer, primary_key=True)
    json_sha512 = db.Column(db.String(128), index=True)
    pub_sha512 = db.Column(db.String(128), index=True)
    search_string = db.Column(db.Text, index=True)
    fingerprint = db.Column(db.String(40), index=True)
    key_id = db.Column(db.String(16), index=True)
    json_raw = db.Column(db.Text())

class SubKey(db.Model):
    __tablename__ = "subkey"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)
    fingerprint = db.Column(db.String(40), index=True)
    key_id = db.Column(db.String(16), index=True)

class UserID(db.Model):
    __tablename__ = "userid"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)

class UserAttribute(db.Model):
    __tablename__ = "userattribute"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("publickey.id"), index=True)

class Image(db.Model):
    __tablename__ = "image"
    id = db.Column(db.Integer, primary_key=True)
    publickey = db.Column(db.ForeignKey("userattribute.id"), index=True)

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

