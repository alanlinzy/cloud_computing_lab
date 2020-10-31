from flask import Flask, request, render_template
from pyhocon import ConfigFactory
import os, psycopg2

conf = ConfigFactory.parse_file('db.conf')
host = conf['databases.postgres.host']
user = conf['databases.postgres.user']
database = conf['databases.postgres.database']
password = conf['databases.postgres.password']

print(host)
print(user)
print(database)
print(password)
