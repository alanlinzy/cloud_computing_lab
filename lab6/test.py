from flask import Flask, request, render_template,jsonify
from pyhocon import ConfigFactory
import os, psycopg2,json

conf = ConfigFactory.parse_file('db.conf')
host = conf['databases.postgres.host']
user = conf['databases.postgres.user']
database = conf['databases.postgres.database']
password = conf['databases.postgres.password']

app = Flask(__name__)

@app.route('/')
@app.route('/<path:path>', methods=['GET'])
def root(path=None):
    curr_path = request.path
    print(curr_path)
    print(path)
    count_path(curr_path)
    return render_template('index.html')

@app.route('/counts', methods=['GET'])
def count():
    data = query()
    json_data = to_json(data)
    print(json_data)
    return jsonify(json_data)
    
    
def count_path(path):
    print('count_path')
    sql = """INSERT INTO pathcount (path, count)
                VALUES (%s, 1)
             ON CONFLICT (path) DO UPDATE
                SET count = pathcount.count + 1
             RETURNING count;"""
    conn = None
    try:
        #conn = psycopg2.connect(host=host ,database=database, user=user, password=password)
        cur = conn.cursor()
        cur.execute(sql, (path,))
        conn.commit()
        cur.close()
    except Exception as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()


def query():
    print('query')
    sql = """SELECT path, count FROM pathcount ORDER BY path"""
    conn = None
    try:
        #conn = psycopg2.connect(host=host ,database=database, user=user, password=password)
        cur = conn.cursor()
        cur.execute(sql)
        data = cur.fetchall()
        conn.commit()
        cur.close()
    except Exception as e:
        data= [['/',9],['/counts',2]]
        print(e)
    finally:
        if conn is not None:
            conn.close()
    return data

def to_json(p_list):
    payload = []
    content = {}
    for p in p_list:
        content = {'path':p[0],'count':p[1]}
        payload.append(content)
        content = {}
    p_l = {'counts':payload}
    data = json.dumps(p_l)
    return data     



if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8080',debug = True)
