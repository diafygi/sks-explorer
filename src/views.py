"""
These are the dynamic website pages for sks-explorer.
"""

import os
from sqlalchemy import func
from flask import Flask, render_template

# sks-explorer specific imports
import models

app = Flask(__name__)

@app.route("/")
def home():
    q = models.PublicKey.query.all()
    for k in q:
        print "Key {}".format(k.fingerprint)
    print "{} keys total".format(len(q))
    return render_template("home.html")

@app.route("/search")
def search():
    return "Not implemented...yet"

@app.route("/key/<fingerprint>")
def key():
    return "Not implemented...yet"

if __name__ == "__main__":
    app.run(debug=True)

