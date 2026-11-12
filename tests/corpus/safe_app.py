"""Corpus: the same small web application, written safely.

Nothing in this file should be reported.
"""

import ast
import json
import os
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET_KEY"]

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


def database():
    return sqlite3.connect("notes.db")


@app.route("/notes")
def notes():
    author = request.args["author"]
    cursor = database().cursor()
    cursor.execute("SELECT title FROM notes WHERE author = ?", (author,))
    return {"notes": cursor.fetchall()}


@app.route("/calculate")
def calculate():
    return {"result": ast.literal_eval(request.args["expression"])}


@app.route("/export")
def export():
    name = request.args["name"]
    subprocess.run(["zip", "-r", f"exports/{name}.zip", "notes/"], check=True)
    return {"file": name + ".zip"}


@app.route("/import", methods=["POST"])
def import_notes():
    settings = yaml.safe_load(request.files["settings"].read())
    notes = json.loads(request.files["notes"].read())
    return {"imported": len(notes), "settings": settings}
