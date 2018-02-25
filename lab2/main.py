#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from kerberos import (
    authenticater, authorizator, encode_json, decode_json, EPS, CODING)


class ServerException(Exception):
    def __init__(self, msg):
        super(ServerException, self).__init__(msg)


class Server:
    def __init__(self):
        self.id, self.key = authenticater.register()
        self.ticket = self.K_c_tgs = None
        self.ticket_ss = self.K_c_ss = None

    def authenticate(self):
        encoded_ticket = authenticater.identify_client(self.id)
        decoded_ticket = decode_json(encoded_ticket, self.key)

        self.ticket = decoded_ticket["TGT"].encode(CODING)
        self.K_c_tgs = decoded_ticket["K_c_tgs"]

    def connect(self, server):
        self._authorize(server.id)
        self._connect_to_server(server)

    def identificate(self, request):
        K_tgs_ss = self.K_c_tgs
        ticket = decode_json(request["ticket"].encode(CODING), K_tgs_ss)
        auth_block = decode_json(request["auth"], ticket["K_c_ss"])

        if round(auth_block["t4"]) - round(ticket["t3"]) > EPS:
            raise ServerException("Unmatched timestamps")

        if ticket["t3"] + ticket["p2"] < time.time():
            raise ServerException("Ticket life has ended")

        if ticket["c"] != auth_block["c"]:
            raise ServerException("Unmatched client ids")

        if ticket["ss"] != self.id:
            raise ServerException("Unmatched server ids")

        response = auth_block["t4"] + 1
        return encode_json(response, ticket["K_c_ss"])

    def _authorize(self, server_id):
        authentication_block = {
            "c": self.id,
            "t1": time.time()
        }

        request = {
            "ticket": self.ticket,
            "auth": encode_json(authentication_block, self.K_c_tgs),
            "id": server_id
        }

        encoded_ticket = authorizator.set_connection(request)
        decoded_ticket = decode_json(encoded_ticket, self.K_c_tgs)

        self.ticket_ss = decoded_ticket["TGS"]
        self.K_c_ss = decoded_ticket["K_c_ss"]

    def _connect_to_server(self, server):
        t4 = time.time()
        authentication_block = {
            "c": self.id,
            "t4": t4
        }

        request = {
            "ticket": self.ticket_ss,
            "auth": encode_json(authentication_block, self.K_c_ss)
        }

        encoded = server.identificate(request)
        decoded = decode_json(encoded, self.K_c_ss)
        if t4 + 1 != decoded:
            raise ServerException(
                "Unmatched client timestamps. Server wasn't identified")


def main():
    try:
        client = Server()
        server = Server()
        server.authenticate()
        client.authenticate()

        client.connect(server)
    except ServerException:
        pass
    except KerberosException:
        pass


if __name__ == '__main__':
    main()
