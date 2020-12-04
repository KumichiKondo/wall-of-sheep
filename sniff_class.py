from scapy.all import *
import re
import sqlite3
import os
import threading


#channel_2_4_GHz = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
channel_2_4_GHz = [1, 6, 13]
channel_5_GHz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 149, 153, 157, 161, 165]


class Network_Iface:
    
    iface_name = ""
    iface_channel = 1
    iface_avail_channel = []
    iface_current_channel_index = 0
    flag = False

    def __init__(self, name, avail_channel):
        self.iface_name = name
        self.iface_avail_channel = avail_channel


    def hop(self, channel: int):
        if channel not in self.iface_avail_channel:
            return
        try:
            print("iwconfig {} channel {}".format(self.iface_name, channel))
            os.system("iwconfig {} channel {}".format(self.iface_name, channel))
        except:
            return

    
    def auto_hopping(self):
        self.iface_current_channel_index = (self.iface_current_channel_index + 1) % len(self.iface_avail_channel)
        self.hop(self.hop(self.iface_avail_channel[self.iface_current_channel_index]))

    
    def sniff_thread(self, filter, prn, timeout):
        while self.flag:
            sniff(iface=self.iface_name, prn=prn, filter=filter, timeout=timeout)
            self.auto_hopping()


    def start_thread(self, filter, prn, timeout):
        thread = threading.Thread(target = self.sniff_thread, kwargs={"filter": filter, "prn": prn, "timeout": timeout})
        self.flag = True
        thread.daemon = True
        thread.start()

    
    def stop_thread(self):
        self.flag = False



class DataBase_interface:

    con = None

    def __init__(self, db_name):
        self.con = sqlite3.connect(db_name)

    
    def create_db(self):
        self.con.execute('CREATE TABLE QQ\n'
                 '             (ID INT PRIMARY KEY     NOT NULL,\n'
                 '             COUNT INT,\n'
                 '             TIMESTAMP DATETIME DEFAULT CURRENT_TIMESTAMP\n'
                 '             );')

    
    def update_db(self, qq):
        qq = int(qq)
        print("qq:", qq)
        self.con = sqlite3.connect('qq_id.sqlite3')
        cur = self.con.cursor()
        cur.execute('SELECT * FROM QQ WHERE ID=?', (qq,))
        qq_record = cur.fetchone()
        print('qq_record: ', qq_record)
        if qq_record:
            count = qq_record[1]
            self.con.execute("UPDATE QQ SET COUNT = ? WHERE ID = ?", (count + 1, qq,))
        else:
            self.con.execute("INSERT INTO QQ(ID,COUNT) VALUES (?,1)", (qq,))
        print(qq)
    
        self.con.commit()


    def dect_inf(self, pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            #pattern = re.compile(r'\d{7,10}')
            pattern = re.compile(b"(\x00){4}[\x0b-\x0e][\x30-\x39]{7,10}")
            try:
                qq = re.search(pattern, raw_data)[0][5:re.search(pattern, raw_data)[0][4] + 1]
                #print(qq)
                #print("TCP Pkt")
                #print(raw_data)
                self.update_db(qq)
            except:
                pass
        elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
            data = pkt[Raw].load
            if data[0] != 0x02 and data[-1] != 0x03:  # a valid OICQ package.
                return
            #qq_ver = data[0x01:0x02]
            #qq_command = data[0x03:0x04]
            #qq_seq = data[0x05:0x06]
            qq_number = data[0x07:0x0b]
            #print(qq_number)
            self.update_db(str(int.from_bytes(qq_number, byteorder='big')))
        return