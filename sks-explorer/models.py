from flask.ext.sqlalchemy import SQLAlchemy

# sks-explorer specific imports
from views import app

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)

class PublicKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    short_key_id = db.Column(db.String(8))
    long_key_id = db.Column(db.String(16))
    fingerprint = db.Column(db.String(40))
