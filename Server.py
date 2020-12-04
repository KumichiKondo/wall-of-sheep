from sniff_class import Network_Iface, DataBase_interface, channel_2_4_GHz, channel_5_GHz
from http.server import HTTPServer,BaseHTTPRequestHandler
import json


avail_channel = [36, 40, 48, 149, 153]


class Resquest(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        li = []
        if qq_dict:
            for i in qq_dict.keys():
                li.append({"qq":"{}".format(i)})
            self.wfile.write((json.dumps({'data':(li)})).encode('utf-8'))


bfp = 'tcp[tcpflags]&(tcp-push|tcp-ack) != 0 || tcp src port 8080 || tcp dst port 8080 || udp[8]==2'
iface_name = "wlan0mon"
host = ('0.0.0.0', 8881)

def init():
    #iface0 = Network_Iface(iface_name, channel_2_4_GHz+channel_5_GHz)
    iface0 = Network_Iface(iface_name, avail_channel)
    process = DataBase_interface('qq_id.sqlite3')
    try:
        process.create_db()
    except:
        pass

    iface0.start_thread(bfp, process.dect_inf, 1)            
    server = HTTPServer(host, Resquest)
    print("Starting server, listen at: %s:%s" % host)

#input()