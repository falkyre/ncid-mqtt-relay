#!/usr/bin/python3
#-*-coding: utf-8-*-

import socket
import re
import paho.mqtt.client as mqtt
import json
import datetime
import logging
from rich.logging import RichHandler


logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

log = logging.getLogger("rich")

def parse_optional(ip_string, default_port, cast=(lambda x: x)):
    ip, _, port = ip_string.partition(':')
    port = port or default_port
    return ip, cast(port)

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('ncid_server')
    parser.add_argument('mqtt_server')
    parser.add_argument('mqtt_topic')
    parser.add_argument('--mqtt_auth', type=str, default=None)
    return parser.parse_args()

def incoming_call(client, topic, _date, _time, _line, _nmbr, _mesg, _fnmbr, _ntype, _ctry, _loca, _cari, _name):
    print("call", _date, _time, _line, _nmbr, _mesg, _name, _loca, _ctry, _ntype)
    data = {"date": _date,
            "time": _time,
            "line": _line,
            "nmbr": _nmbr,
            "mesg": _mesg,
            "name": _name,
            "location": _loca,
            "country": _ctry,
            "type": _ntype,
            }
    d = datetime.datetime(int(_date[4:8]), int(_date[0:2]), int(_date[2:4]),
                        int(_time[0:2]), int(_time[2:4]))
    now = datetime.datetime.now()
    log.info(data)
    delta = abs(now - d)
    if delta.seconds < 300:
        client.publish(topic, json.dumps(data))
        log.info("published")
    else:
        log.info("delta too large")


actions = [
    (re.compile(
     r'^[PC]ID: '
     r'\*DATE\*(\d{8})'
     r'\*TIME\*(\d{4})'
     r'\*LINE\*([^*]+)'
     r'\*NMBR\*(\d+)'
     r'\*MESG\*([^*]+)'
     r'\*FNMBR\*([^*]+)'
     r'\*NTYPE\*([^*]+)'
     r'\*CTRY\*([^*]+)'
     r'\*LOCA\*([^*]+)'
     r'\*CARI\*([^*]+)'
     r'\*NAME\*([^*]+)'
     r'\*$')
     , incoming_call),
]

def main(ncid_server, mqtt_server, mqtt_topic, mqtt_auth):
    ncid_host, ncid_port = parse_optional(ncid_server, 3333, int)
    mqtt_host, mqtt_port = parse_optional(mqtt_server, 1883, int)

    while True:
        client = mqtt.Client()
        if mqtt_auth:
            mqtt_username, mqtt_password = parse_optional(mqtt_auth, None)
            client.username_pw_set(mqtt_username, mqtt_password)
        client.connect(mqtt_host,
                       mqtt_port,
                       60)
        client.loop_start()
        s = socket.socket()
        try:
            s.connect((ncid_host, ncid_port))
            log.info("connected")
            while True:
                data = s.recv(1024).decode().strip()
                if "CID:" not in data:
                    log.info(data)
                else:
                   log.info("Incoming caller id:  {}".format(data))
                   for regex, func in actions:
                      match = regex.match(data)
                      if match:
                        func(client, mqtt_topic, *match.groups())

        except Exception as E:
            raise E
        finally:
            s.close()
            client.disconnect()

if __name__ == "__main__":
    args = parse_args()
    main(args.ncid_server, args.mqtt_server, args.mqtt_topic, args.mqtt_auth)
