from flask import Flask, request, render_template
from pyhocon import ConfigFactory
import os, psycopg2

conf = ConfigFactory.parse_file('db.conf')
host = conf['databases.postgres.host']
user = conf['databases.postgres.user']
database = conf['databases.postgres.database']
password = conf['databases.postgres.password']

app = Flask(__name__)























if __name__ == '__main__':
    app.run(host='127.0.0.1', port='8080')
