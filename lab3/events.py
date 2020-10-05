import os
import datetime
import json
import bcrypt

from functools import wraps

from flask import Flask,Blueprint,render_template, request, jsonify,send_from_directory,redirect,make_response,url_for,flash

from google.cloud import datastore

events = Blueprint('events', __name__)

DS = datastore.Client()
EVENT = 'Event'
USERSESS = 'Sess'

if os.getenv('GAE_ENV','').startswith('standard'):
    EVE = DS.key('Entities','event_root')
    USER = DS.key('Entities','user_root')
else:
    EVE = DS.key('Entities','event_dev')
    USER = DS.key('Entities','user_dev')

#decorator to check login
def login_check(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        user = request.cookies.get('user')
        sess = request.cookies.get('sess')
        if user:
            query_key = DS.key(USERSESS,int(sess))
            query = list(DS.query(kind = USERSESS,ancestor = query_key).fetch())
            for i in query:
                if user != i['user'] or (datetime.datetime.now() - sess_db['exp'].replace(tzinfo = None)).hours >=1:
                    flash('expired')
                    return redirect(url_for('auth.logout'))
                else:
                    return func(*args,**kwargs)
        else:
            flash('please login')
            return redirect(url_for('auth.login'))
        flash('error')
        return redirect(url_for('auth.login'))
    return wrapper
            

def put_event(name,date_str):
    entity = datastore.Entity(key = DS.key(EVENT,parent=EVE ))
    entity.update({'name':name,'date':date_str})
    DS.put(entity)
    return

def delete_event(del_id):
    del_k = DS.key(EVENT, del_id,parent=EVE )
    DS.delete(del_k)
    return

def fetch_events(limit=None):
    if limit != None:
        query = DS.query(kind = EVENT )
        query.order = ['date']
        events = query.fetch(limit = limit)
    else:
        query = DS.query(kind = EVENT )
        query.order = ['date']
        events = query.fetch()
    return events

@events.route('/')
@login_check
def root():
    #return render_template("index.html",user = 'back')  
    return render_template('events.html', data=getEvent())

@events.route('/events',methods = ['GET'])
@login_check
def getEvent():
    print('GET event')
    events = fetch_events()
    payload = []
    content = {}
    for e in events:
        content = {'id':e.id,'name':e['name'],'date':e['date']}
        payload.append(content)
        content = {}
    event_l = {'events':payload}
    print(json.dumps(event_l))
    data = json.dumps(event_l)
    return jsonify(data)

@events.route('/event',methods = ['POST'])
@login_check
def postEvent():
    print('POST event')
    name,date = request.json['name'], request.json['date']
    print(name,date)
    put_event(name,date)
    return ''

@events.route('/event',methods = ['DELETE'])
@login_check
def delEvent():
    print('DEL event')
    del_id = request.json['id']
    delete_event(del_id)
    return getEvent()
