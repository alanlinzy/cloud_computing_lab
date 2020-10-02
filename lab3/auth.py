import os
import datetime
import json
import bcrypt
import requests

from flask import Flask,Blueprint,render_template, request, jsonify,send_from_directory,redirect,make_response,url_for,flash
from base64 import b64encode, urlsafe_b64decode
from google.cloud import datastore

auth = Blueprint('auth', __name__)
DS = datastore.Client()
EVENT = 'Event'
USERINFO = 'Login'
USERSESS = 'Sess'
REDIRECT_URI = 'https://project03zlin32.appspot.com/oidcauth'
STATE = hashlib.sha256(os.urandom(1024)).hexdigest()
NONCE = hashlib.sha256(os.urandom(1024)).hexdigest()

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
    if pwd_hash == '':
        print('not exist')
        return 'wrong'
    # vaild? expire? empty?
    if bcrypt.hashpw(pwd.encode("utf8"), pwd_hash) != pwd_hash:
        print('wrong pass')
        return 'wrong'
    if not check_sess(user,pwd_hash):
        print('no sess')
        return 'pass'

    return True

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
    print('DEL event')
    print(sess)
    if sess == '':
        return ''
    del_k = DS.key(USERSESS, int(sess),parent=USER )
    DS.delete(del_k)
    return ''

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='GET':
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

        delta = datetime.datetime.now() + datetime.timedelta(hours=1)
        res = make_response(
            render_template('login.html',
                client_id=CLIENT_ID,
                state=STATE,
                nonce=NONCE,
                redirect_uri=REDIRECT_URI,
                base_uri=pull_from_discovery('authorization_endpoint'),
                data = data
                            ))
        res.set_cookie('app_oidc_state', STATE, max_age=(60*60), expires=delta, domain='project03zlin32.appspot.com', secure=True)
        res.set_cookie('app_oidc_nonce', NONCE, max_age=(60*60), expires=delta, domain='project03zlin32.appspot.com', secure=True)
        return res
    elif request.method == 'POST':
        print('POST login')
        user,pwd = request.json['user'], request.json['pwd']
        ch = check_user(user,pwd)
        if ch == 'wrong':
            print('sesson exist')
            session = get_sess(user,pwd)
            print(session)
            #resp = make_response(redirect('static/index.html',code = 301))
            resp = make_response(redirect('/static/index.html'))
            print('redirect main')
            resp.set_cookie('sess',str(session))
            print(resp)
            #return redirect(url_for('static',filename='index.html'))
            return resp
        elif ch == 'pass':
            put_sess(user,pwd)
            print('sesson not exist')
            session = get_sess(user,pwd)
            print(session)
            #resp = make_response(redirect('static/index.html',code = 301))
            resp = make_response(redirect('/static/index.html'))
            print('redirect main')
            resp.set_cookie('sess',str(session))
            print(resp)
            #return redirect(url_for('static',filename='index.html'))
            return resp
        else:
            return ''
        
        # Find u_id in Users Datastore
        key = DS.key('Users', u_id)
        entity = DS.query(kind='Users', ancestor=key).fetch()
        for ent in list(entity):
            # hash pwd and compare to Users['password']
            if ent['username'] == u_id and ent['password'] == pwd_stretch(password, ent['password']):
                return createSession(u_id)
            else:
                flash("Username or password is incorrect. Please try again")
                return redirect(url_for('auth.login'))
        else:
            flash("Username or password does not match our records. Please try again")
            return redirect(url_for('auth.login'))
    else:
        console.log('Unexpected request during login: %s' %(request.method))

        
@auth.route('/register',methods = ['POST'])
def postRegister():
    print('POST register')
    print(request.json)
    user,pwd = request.json['user'], request.json['pwd']
    put_user(user,pwd)
    return ''

@auth.route('/logout',methods = ['POST'])
def postLogout():
    print('POST logout')
    print(request.json)
    sess = request.cookies.get('sess')
    del_sess(sess)
    resp = make_response(redirect(url_for('auth.login')))
    #resp = make_response(send_from_directory('static','login.html'))
    resp.set_cookie('sess','')
    resp.set_cookie('app_oidc_nonce', '')
    res.set_cookie('app_oidc_state','')
    print(resp)
    #return redirect(url_for('static',filename='login.html'))
    return resp

@auth.route('/oidcauth', methods=['GET'])
def getAuth():
    if request.args['state'] != request.cookies.get('app_oidc_state'):
        flash('Something went wrong.')
        return redirect(url_for('auth.login'))
    else:
        response = requests.post(pull_from_discovery('token_endpoint'),{
            'code': request.args['code'],
            'client_id': CLIENT_ID,
            'client_secret': DS.get(DS.key('secret', 'oidc'))['client_secret'],
            'redirect_uri': REDIRECT_URI,
            'grant_type': 'authorization_code'
        })

        # Parse JWT using code from lab document
        j_token = response.json()
        id_token = j_token['id_token']
        _, body, _ = id_token.split('.')
        body += '=' * (-len(body) % 4)
        claims = json.loads(urlsafe_b64decode(body.encode('utf-8')))

        # Check datastore for user, than register or login.
        u_id = claims['sub']
        q_key = DS.key('Users', u_id)
        user_q = DS.query(kind='Users', ancestor=q_key)

        for ent in list(user_q.fetch()):
            if ent['sub']==u_id:
                return createSession(u_id)
            #else:
        with DS.transaction():
            user = datastore.Entity(key=q_key)
            user.update({
                'sub': u_id,
                'name': claims['name'],
                'email': claims['email'],
                'username': ''
            })
            DS.put(user)

        return createSession(u_id)
