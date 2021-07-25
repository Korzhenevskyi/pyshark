__author__ = 'ok'

import pyshark
import json
import requests
import os

# --------------------- Directory creation -----------------------
directory = os.getenv("PYSHARK_RESULTS_FOLDER", "data")

if not os.path.exists(directory):
    os.makedirs(directory)


# --------------------- Store data -------------------------------

class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

def store_packet_as_json(packet, i):
    with open('%s/packet_%d.json' % (directory, i), 'a') as w:
        w.write(json.dumps(packet, cls=CustomEncoder))


# -------------------- Malicious payload detections -----------------
url = os.getenv("CHECKER_URL")

def is_packet_harmful(packet):
    res = requests.post(url=url, json=json.dumps(packet, cls=CustomEncoder))
    res.raise_for_status() # handle this exception!
    res_json = res.json() # this can also throw
    return res_json["result"] != 0

# TODO: check how to block traffic on a machine


# -------------------- Capturing ------------------------------------
capture = pyshark.LiveCapture() # if no interface is given all the interfaces are captured
i = 0

for packet in capture.sniff_continuously(): # capture.apply_on_packets(packet_callback) can be used instead
    print("packet %d is captured" % i)
    store_packet_as_json(packet, i)
    i += 1