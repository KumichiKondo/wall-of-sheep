from flask import Flask, json, render_template
import sqlite3
from Server import init

app = Flask(__name__)

#start_sniffer()

init()


@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/qq_data')
def qq_data():
    conn = sqlite3.connect('qq_id.sqlite3')
    result = conn.execute('select ID,COUNT,TIMESTAMP from QQ where COUNT > 3')
    qq_list = list()
    for qq_id,count,qq_timestamp in sorted(result, key = lambda data: data[2]):
        print(qq_id, count,qq_timestamp)
        qq_list.append({'qq':qq_id})
    return json.dumps({"data":qq_list.reverse()})
    
    
if __name__ == '__main__':
    app.run()
