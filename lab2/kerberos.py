#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json


class Kerberos:
    GLOBAL_KEY = 1234   # K as_tgs


class Authenticater(Kerberos):      # AS
    ANSWER = {
        "ticket": {
            "c": None,
            "tgs": 567,
            "t1": None,
            "p1": None,
            "authorizator_key": None    # K c_TGS
        },
        "authorizator_key": None
    }

    def __init__(self):
        self.servers = {}
        self.authorizator_key = 567

    def register(self, key):
        id = 123
        self.servers[id] = key

    def generate_ticket(self, id):
        self._fill_answer(id)
        return 

    def _fill_answer(self, _id):
        Authenticater.ANSWER["ticket"]["c"] = _id
        # TODO: generate real timestamp
        Authenticater.ANSWER["ticket"]["t1"] = 874
        Authenticater.ANSWER["ticket"]["p1"] = 874
        Authenticater.ANSWER["ticket"]["authorizator_key"] = self.authorizator_key
        Authenticater.ANSWER["authorizator_key"] = self.authorizator_key


class Authorizator(Kerberos):       # TGS
    pass


authenticater = Authenticater()
authorizator = Authorizator()


class Client:
    def __init__(self, auth, author):
        # TODO: Random genrate key and id
        self.key = 1234     # K c
        self.id = authenticater.register(self.key)       # c

        self.ticket = None
        self.authorizator_key = None

    def authenticate(self):
        encoded = authenticater.generate_ticket(self.id)
        self.ticket, self.authorizator_key = self._decode_authent(encoded)

    def _decode_authent(self, encoded):
        # TODO: uncomment when des will ready
        # decoded = des.decode(encoded, self.key)
        # json_obj = json.loads(decoded)
        json_obj = json.loads(encoded)
        return json_obj['ticket'], json_obj['authorizator_key']


class Server:
    pass


def main():
    pass


if __name__ == '__main__':
    main()
