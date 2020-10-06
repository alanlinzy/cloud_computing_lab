import os
import datetime
import json
import bcrypt
import requests
import hashlib

from flask import Flask,Blueprint,render_template, request, jsonify,send_from_directory,redirect,make_response,url_for,flash
from base64 import b64encode, urlsafe_b64decode
from google.cloud import datastore

auth = Blueprint('auth', __name__)
DS = datastore.Client()
EVENT = 'Event'
USERINFO = 'Login'
USERSESS = 'Sess'
REDIRECT_URI = 'https://project03zlin32.ue.r.appspot.com/oidcauth'
#REDIRECT_URI = 'https://8080-cs-513279187698-default.us-central1.cloudshell.dev/'
CLIENT_ID = DS.get(DS.key('secret', 'oidc'))['client_id']
STATE = hashlib.sha256(os.urandom(1024)).hexdigest()
NONCE = hashlib.sha256(os.urandom(1024)).hexdigest()
NO_USER = 0
WRONG_PASS = 1
NO_SESS = 2
HAVE_SESS = 3
SALT = 10

if os.getenv('GAE_ENV','').startswith('standard'):
    EVE = DS.key('Entities','event_root')
    USER = DS.key('Entities','user_root')
else:
    EVE = DS.key('Entities','event_dev')
    USER = DS.key('Entities','user_dev')

def check_exist(user):
    query = DS.query(kind = USERINFO)
    query.add_filter('user', '=', user)
    pwd_hash = list(query.fetch())
    if len(pwd_hash) == 0:
        return ''
    else:
        print(pwd_hash[0]['pwd'])
        return pwd_hash[0]['pwd']
    
def check_user(user,pwd):
    pwd_hash = check_exist(user)
    # no user 0; wrong pass 1; no sess;2 true 3
    if pwd_hash == '':
        print('not exist')
        return NO_USER
    # vaild? expire? empty?
    if bcrypt.hashpw(pwd.encode("utf8"), pwd_hash) != pwd_hash:
        print('wrong pass')
        return WRONG_PASS
    if not check_sess(user,pwd_hash):
        print('no sess')
        return NO_SESS

    return HAVE_SESS

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

def check_sess(user,pwd_hash):
    query = DS.query(kind = USERSESS)
    query.add_filter('user', '=', user)
    sess = list(query.fetch())
    now = datetime.datetime.now()
    print(sess)
    if len(sess)==0:
        return False
    exp = sess[0]['exp'].replace(tzinfo = None)#TypeError: can't subtract offset-naive and offset-aware datetimes
    print(exp)
    
    if (now - exp).hours <=1:
        print('valid')
        return True
    else:
        return False
    
def put_sess(user):
    entity = datastore.Entity(key = DS.key(USERSESS,parent=USER))
    #pwd_hash = check_exist(user)
    #Unicode-objects must be encoded before hashing
    #pwd_hash = bcrypt.hashpw(pwd.encode("utf8"), bcrypt.gensalt(SALT))
    entity.update({'user':user,'exp':datetime.datetime.now()})
    DS.put(entity)
    return

def get_sess(user):
    #pwd_hash = check_exist(user)
    query = DS.query(kind = USERSESS)
    query.add_filter('user', '=', user)
    sess = list(query.fetch())[0]
    print(sess)
    return sess.id

def del_sess(sess):
    print('DEL event')
    print(sess)
    if sess == '':
        return ''
    del_k = DS.key(USERSESS, int(sess),parent=USER )
    DS.delete(del_k)
    return ''

@auth.route('/login', methods=['GET', 'POST'])
@auth.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method=='GET':
        print('GET  login')
        return render_template('login.html')
    
    elif request.method == 'POST':
        print('POST login')
        user,pwd = request.json['user'], request.json['pwd']
        cu = check_user(user,pwd)
        expired = datetime.datetime.now() - datetime.timedelta(hours=1)
        if cu == HAVE_SESS:
            print('sesson exist')
            session = get_sess(user)
            print(session)
            #resp = make_response(redirect('static/index.html',code = 301))
            resp = make_response(redirect(url_for('events.root')))
            print('redirect main')
            resp.set_cookie('sess',str(session), expires=expired, secure=True)
            print(resp)
            #return redirect(url_for('static',filename='index.html'))
            return resp
        elif cu == NO_SESS:
            put_sess(user)
            print('sesson not exist')
            session = get_sess(user)
            print(session)
            #resp = make_response(redirect('static/index.html',code = 301))
            resp = make_response(redirect(url_for('events.root')))
            print('redirect main')
            resp.set_cookie('sess',str(session), expires=expired, secure=True)
            print(resp)
            #return redirect(url_for('static',filename='index.html'))
            return resp
        else:
            return redirect(url_for('auth.login'))
        
    

        
@auth.route('/register',methods = ['POST'])
def postRegister():
    print('POST register')
    print(request.json)
    user,pwd = request.json['user'], request.json['pwd']
    result = put_user(user,pwd)
    if result == True:
        return redirect(url_for('auth.login'))
    expired = datetime.datetime.now() - datetime.timedelta(hours=1)
    put_sess(user)
    print('sesson not exist')
    session = get_sess(user)
    print(session)
    #resp = make_response(redirect('static/index.html',code = 301))
    resp = make_response(redirect(url_for('events.root')))
    print('redirect main')
    resp.set_cookie('sess',str(session), expires=expired, secure=True)
    print(resp)
    #return redirect(url_for('static',filename='index.html'))
    return resp

@auth.route('/logout',methods = ['POST'])
def postLogout():
    print('POST logout')
    print(request.json)
    sess = request.cookies.get('sess')
    del_sess(sess)
    resp = make_response(redirect(url_for('auth.login')))
    #resp = make_response(send_from_directory('static','login.html'))
    resp.set_cookie('sess','')

    print(resp)
    #return redirect(url_for('static',filename='login.html'))
    return resp



