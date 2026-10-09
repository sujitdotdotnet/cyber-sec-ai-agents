"""Deliberately vulnerable demo service. DO NOT DEPLOY.

This file exists so the Vulnerability Scanner Agent has realistic findings to report:
SQL injection, command injection, path traversal, unsafe YAML, weak hashing, hardcoded
secrets and debug mode.
"""

import hashlib
import os
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key-123"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "admin123"


def db():
    return sqlite3.connect("shop.db")


@app.route("/products")
def products():
    product_id = request.args.get("id", "1")
    cur = db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id = " + product_id)
    return {"rows": cur.fetchall()}


@app.route("/api/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/download")
def download():
    name = request.args.get("file", "readme.txt")
    return send_file(os.path.join("/srv/files", name))


@app.route("/import", methods=["POST"])
def import_config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return {"keys": list(cfg)}


@app.route("/register", methods=["POST"])
def register():
    pw_hash = hashlib.md5(request.form["password"].encode()).hexdigest()
    return {"hash": pw_hash}


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
