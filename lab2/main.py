import os
import datetime
import json
import bcrypt

from flask import Flask, render_template, request, jsonify,send_from_directory,redirect
from google.cloud import datastore

app = Flask(__name__)

DS = datastore.Client()
EVENT = 'Event'
USERINFO = 'Login'
USERSESS = 'Sess'
SALT = 10

if os.getenv('GAE_ENV','').startswith('standard'):
    ROOT = DS.key('Entities','root')
    USER = DS.key('Entities','user_root')
else:
    ROOT = DS.key('Entities','dev')
    USER = DS.key('Entities','user_dev')
    
def to_json(events):
    payload = []
    content = {}

    for e in events:
        content = {'id':e.id,'name':e['name'],'date':e['date']}
        payload.append(content)
        content = {}
    event_l = {'events':payload}
    print(json.dumps(event_l))
    return json.dumps(event_l)

def put_event(name,date_str):
    entity = datastore.Entity(key = DS.key(EVENT,parent=ROOT))
    entity.update({'name':name,'date':date_str})
    DS.put(entity)
    return

def delete_event(del_id):
    del_k = DS.key(EVENT, del_id,parent=ROOT )
    DS.delete(del_k)
    return

def fetch_events(limit=None):
    if limit != None:
        query = DS.query(kind = 'Event')
        query.order = ['date']
        events = query.fetch(limit = limit)
    else:
        query = DS.query(kind = 'Event')
        query.order = ['date']
        events = query.fetch()
    return events

def checkCookies(cookie):#unfin
    query = DS.query(kind = USERSESS)
    query.add_filter('cookie', '=', cookie)
    pwd_hash = query.fetch()
    return False

@app.route('/')
@app.route('/index.html',methods = ['GET'])
def root():
    print(request.cookies)
    if not checkCookies(request.cookies):#check session
        return redirect('static/login.html',code = 302)
    print('root')
    #return render_template("index.html",user = 'back')  
    return send_from_directory('static','index.html')

@app.route('/events',methods = ['GET'])
def getEvent():
    print('GET event')
    events = fetch_events()
    data = to_json(events)
    return jsonify(data)

@app.route('/event',methods = ['POST'])
def postEvent():
    print('POST event')
    name,date = request.json['name'], request.json['date']
    print(name,date)
    put_event(name,date)
    return ''

@app.route('/event',methods = ['DELETE'])
def delEvent():
    print('DEL event')
    del_id = request.json['id']
    delete_event(del_id)
    return ''

def check_user(user,pwd):#unfin
    query = DS.query(kind = USERINFO)
    query.add_filter('user', '=', user)
    pwd_hash = query.fetch()
    print('pwd_hash',pwd_hash)
    # vaild? expire? empty?
    if bcrypt.hashpw(pwd, pwd_hash) == pwd_hash:
        return True
    else:
        return False

def put_user(user,pwd):
    entity = datastore.Entity(key = DS.key(USERINFO,parent=USER))
    pwd_hash = bcrypt.hashpw(pwd, bcrypt.gensalt(SALT))
    entity.update({'user':user,'pwd':pwd_hash})
    DS.put(entity)
    return

@app.route('/login',methods = ['GET'])
def getPwd():
    print('GET  login')
    query = DS.query(kind = 'User')
    pwd = query.fetch()
    payload = []
    content = {}
    for p in pwd:
        content = {'id':p.id,'user':p['user'],'pwd':e['pwd']}
        payload.append(content)
        content = {}
    pwd_l = {'pwds':payload}
    print(json.dumps(pwd_l))
    data = json.dumps(pwd_l)
    return jsonify(data)

@app.route('/login',methods = ['POST'])
def postLogin():
    print('POST login')
    print(request.json['user'],request.json['pwd'])
    user,pwd = request.json['user'], request.json['pwd']
    check_user(user,pwd)
    session = {'session':'cookie','msg':'?'}
    return redirect('static/index.html',code = 200)

@app.route('/register',methods = ['POST'])
def postRegister():
    print('POST register')
    print(request.json)
    print(request.json['pwd'])
    print(request.json['user'],request.json['pwd'])
    user,pwd = request.json['user'], request.json['pwd']
    put_user(user,pwd)
    return ''


if __name__ == '__main__':
    app.run(host ='127.0.0.1',port = 8080,debug=True)
