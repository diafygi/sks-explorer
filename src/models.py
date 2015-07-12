import os
from flask.ext.sqlalchemy import SQLAlchemy

# sks-explorer specific imports
from views import app

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
db = SQLAlchemy(app)

class PublicKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(40), index=True)
    long_key_id = db.Column(db.String(16))
    short_key_id = db.Column(db.String(8))
