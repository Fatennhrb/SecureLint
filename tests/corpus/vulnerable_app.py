"""Corpus: a small web application with several kinds of problem at once."""

import os
import pickle
import sqlite3

import yaml
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "dev-secret-do-not-share"  # expect: SL104

ADMIN_PASSWORD = "admin1234"  # expect: SL104


def database():
    return sqlite3.connect("notes.db")


@app.route("/notes")
def notes():
    author = request.args["author"]
    cursor = database().cursor()
    cursor.execute(f"SELECT title FROM notes WHERE author = '{author}'")  # expect: SL105
    return {"notes": cursor.fetchall()}


@app.route("/calculate")
def calculate():
    return {"result": eval(request.args["expression"])}  # expect: SL101


@app.route("/export")
def export():
    name = request.args["name"]
    os.system("zip -r exports/" + name + ".zip notes/")  # expect: SL102
    return {"file": name + ".zip"}


@app.route("/import", methods=["POST"])
def import_notes():
    settings = yaml.load(request.files["settings"].read())  # expect: SL103
    notes = pickle.loads(request.files["notes"].read())  # expect: SL103
    return {"imported": len(notes), "settings": settings}
