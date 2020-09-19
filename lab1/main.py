import os
import datetime
import json

from flask import Flask, render_template, request, jsonify,send_from_directory
from google.cloud import datastore

app = Flask(__name__)

DS = datastore.Client()
EVENT = 'Event'

if os.getenv('GAE_ENV','').startswith('standard'):
    ROOT = DS.key('Entities','root')
else:
    ROOT = DS.key('Entities','dev')
    
def to_json(events):
    payload = []
    content = {}

    for e in events:
        content = {'id':e.id,'name':e['name'],'date':e['date']}
        payload.append(content)
        content = {}
    event_l = {'event':payload}
    print(json.dumps(event_l))
    return json.dumps(event_l)

def put_events(name,date_str):
    entity = datastore.Entity(key = DS.key(EVENT,parent=ROOT))
    entity.update({'name':name,'date':date_str})
    DS.put(entity)
    return

def delete_event(del_id):
    del_k = DS.key(EVENT, parent=ROOT, id = int(del_id))
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
        evnets = query.fetch()
    return events

@app.route('/')
@app.route('/index.html',methods = ['GET'])
def root():
    print('root')
    return send_from_directory('static','index.html')

@app.route('/events',methods = ['GET'])
def getEvent():
    print('GET')
    events = fetch_event()
    data = to_json(events)
    return jsonify(data)

@app.route('/event',methods = ['POST'])
def postEvent():
    print('POST')
    name,date = request.json['name'], request.json['date']
    print(name,date)
    put_evnets(name,date)
    return ''

@app.route('/event',methods = ['DELETE'])
def delEvent():
    print('DEL')
    del_id = request.json['id']
    delete_event(del_id)
    return ''


if __name__ == '__main__':
    app.run(host ='127.0.0.1',port = 8080,debug=True)
