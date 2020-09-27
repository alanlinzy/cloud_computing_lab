import os
import datetime
import json
import bcrypt

from flask import Flask, render_template, request, jsonify,send_from_directory,redirect,make_response
from google.cloud import datastore

app = Flask(__name__)

DS = datastore.Client()
EVENT = 'Event'
USERINFO = 'Login'
USERSESS = 'Sess'
SALT = 10
EXP = 1

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
    if cookie == None:
        return False
    sess_k = DS.key(USERSESS, cookie,parent=USER )
    query = DS.query(kind = USERSESS)
    query.GqlQuery('SELECT * FROM ' + USERSESS + 'WHERE id = ' + cookie)
    #query.key_filter(sess_k,'=')
    #print(cookie)
    now = datetime.datetime.now()
    sess_db = list(query.fetch())
    print(sess_db)
    if len(sess_db) > 0:
        if (now - sess_db['exp'].replace(tzinfo = None)).days <=1:#[0]
            return True
    return False
    

@app.route('/')
@app.route('/index.html',methods = ['GET'])
def root():
    print(request.cookies.get('sess'))
    if not checkCookies(request.cookies.get('sess')):#check session
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

def check_sess(user,pwd_hash):
    query = DS.query(kind = USERSESS)
    query.add_filter('user', '=', user)
    query.add_filter('pwd', '=', pwd_hash)
    sess = list(query.fetch())
    now = datetime.datetime.now()
    exp = sess[0]['exp'].replace(tzinfo = None)#TypeError: can't subtract offset-naive and offset-aware datetimes
    print(exp)
    print(sess)
    
    if len(sess)>0 and (now - exp).days <=1:
        print('valid')
        return True
    else:
           
        return False

def check_user(user,pwd):#unfin
    pwd_hash = check_exist(user)
    if pwd_hash == '':
        print('not exist')
        return False
    # vaild? expire? empty?
    if bcrypt.hashpw(pwd.encode("utf8"), pwd_hash) != pwd_hash:
        print('wrong pass')
        return False
    if not check_sess(user,pwd_hash):
        print('no sess')
        return False

    return True
    
    
def check_exist(user):#unfin
    query = DS.query(kind = USERINFO)
    query.add_filter('user', '=', user)
    pwd_hash = list(query.fetch())
    if len(pwd_hash) == 0:
        return ''
    else:
        print(pwd_hash[0]['pwd'])
        return pwd_hash[0]['pwd']
    

def put_user(user,pwd):
    if not check_exist(user):
        entity = datastore.Entity(key = DS.key(USERINFO,parent=USER))
        #Unicode-objects must be encoded before hashing
        pwd_hash = bcrypt.hashpw(pwd.encode("utf8"), bcrypt.gensalt(SALT))
        entity.update({'user':user,'pwd':pwd_hash})
        DS.put(entity)
        return True
    else:
        print('exist')
        return False
    
def put_sess(user,pwd):
    entity = datastore.Entity(key = DS.key(USERSESS,parent=USER))
    pwd_hash = check_exist(user)
    #Unicode-objects must be encoded before hashing
    #pwd_hash = bcrypt.hashpw(pwd.encode("utf8"), bcrypt.gensalt(SALT))
    entity.update({'user':user,'pwd':pwd_hash,'exp':datetime.datetime.now()})
    DS.put(entity)
    return

def get_sess(user,pwd):
    pwd_hash = check_exist(user)
    query = DS.query(kind = USERSESS)
    query.add_filter('user', '=', user)
    query.add_filter('pwd', '=', pwd_hash)
    sess = list(query.fetch())[0]
    print(sess)
    return sess.id

def del_sess(sess):
    return 

@app.route('/login',methods = ['GET'])
def getPwd():
    print('GET  login')
    query = DS.query(kind = USERINFO)
    pwd = query.fetch()
    payload = []
    content = {}
    for p in pwd:
        content = {'id':p.id,'user':p['user'],'pwd':str(p['pwd'])}
        payload.append(content)
        content = {}
    pwd_l = {'pwds':payload}
    print(json.dumps(pwd_l))
    data = json.dumps(pwd_l)
    return jsonify(data)

@app.route('/login',methods = ['POST'])
def postLogin():
    print('POST login')
    print(request.json)
    user,pwd = request.json['user'], request.json['pwd']
    if check_user(user,pwd):
        print('sesson exist')
        session = get_sess(user,pwd)
        print(session)
        resp = make_response(redirect('static/index.html',code = 302))
        print('redirect main')
        resp.set_cookie('sess',str(session))
        return resp
    else:
        put_sess(user,pwd)
        print('sesson not exist')
        session = get_sess(user,pwd)
        print(session)
        resp = make_response(redirect('static/index.html',code = 302))
        print('redirect main')
        resp.set_cookie('sess',str(session))
        return resp

@app.route('/register',methods = ['POST'])
def postRegister():
    print('POST register')
    print(request.json)
    user,pwd = request.json['user'], request.json['pwd']
    put_user(user,pwd)
    return ''

@app.route('/logout',methods = ['POST'])
def postLogout():
    print('POST logout')
    print(request.json)
    sess = request.cookies.get('sess')
    del_sess(sess)
    return redirect('static/login.html',code = 302)


if __name__ == '__main__':
    app.run(host ='127.0.0.1',port = 8080,debug=True)
