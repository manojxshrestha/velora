"""Intentionally vulnerable demo target for `velora scan`.

Run:  velora scan examples/app.py        (symbolic)
      velora scan examples/app.py --ai   (symbolic + LLM tiers)
"""

import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
DB = sqlite3.connect("app.db")


@app.route("/login")
def login():
    user = request.args.get("user", "")
    cur = DB.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user + "'")
    return str(cur.fetchall())


@app.route("/run")
def run():
    name = request.args.get("name", "world")
    subprocess.run("echo hello " + name, shell=True)
    return "done"


if __name__ == "__main__":
    app.run()
