#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import time
import json
from constants import EPS, CODING, PRINT_SYMBOLS
from kerberos import (
    authenticater, authorizator, encode_json, decode_json, KerberosException)

logger = logging.getLogger(__name__)


class ServerException(Exception):
    def __init__(self, msg):
        super(ServerException, self).__init__(msg)


class Server:
    def __init__(self):
        self.id, self.key = authenticater.register()
        self.ticket = self.K_c_tgs = None
        self.ticket_ss = self.K_c_ss = None
        logger.info(
            "  Register in Kerberos system:"
            " id={}, key={}".format(self.id, self.key))

    def authenticate(self):
        logging.info("  Authentication step:")
        encoded_ticket = authenticater.identify_client(self.id)
        decoded_ticket = decode_json(encoded_ticket, self.key)

        self.ticket = decoded_ticket["TGT"].encode(CODING)
        self.K_c_tgs = decoded_ticket["K_c_tgs"]
        logger.info(
            "  Received: TGT={}..., K_c_tgs={}".format(
                self.ticket.decode(CODING)[:PRINT_SYMBOLS], self.K_c_tgs))

    def connect(self, server):
        logger.info("  Client authorize with TGS:")
        self._authorize(server.id)
        logger.info("  Client connect to server {}:".format(server.id))
        self._connect_to_server(server)

    def identificate(self, request):
        logging.info("      Request for identification from client")
        K_tgs_ss = self.K_c_tgs
        logging.info("      Server K_tgs_ss: {}".format(K_tgs_ss))

        ticket = decode_json(request["ticket"].encode(CODING), K_tgs_ss)
        auth_block = decode_json(request["auth"], ticket["K_c_ss"])

        logging.info("      Received ticket: {}".format(json.dumps(ticket)))
        logging.info("      Received auth_block: {}".format(
                        json.dumps(auth_block)))

        logging.info("      Check auth time and ticket time")
        if round(auth_block["t4"]) - round(ticket["t3"]) > EPS:
            raise ServerException("Unmatched timestamps")

        logging.info("      Check if it's still alive")
        if ticket["t3"] + ticket["p2"] < time.time():
            raise ServerException("Ticket life has ended")

        logging.info("      Check client id")
        if ticket["c"] != auth_block["c"]:
            raise ServerException("Unmatched client ids")

        logging.info("      Check server id")
        if ticket["ss"] != self.id:
            raise ServerException("Unmatched server ids")

        response = auth_block["t4"] + 1
        logging.info("      Response for client: {}".format(response))
        return encode_json(response, ticket["K_c_ss"])

    def _authorize(self, server_id):
        authentication_block = {
            "c": self.id,
            "t1": time.time()
        }

        logging.info("    Authentication block: {}".format(
                        json.dumps(authentication_block)))
        request = {
            "ticket": self.ticket,
            "auth": encode_json(authentication_block, self.K_c_tgs),
            "id": server_id
        }

        logging.info("    Connect to TGS...")
        encoded_ticket = authorizator.set_connection(request)
        decoded_ticket = decode_json(encoded_ticket, self.K_c_tgs)

        self.ticket_ss = decoded_ticket["TGS"]
        self.K_c_ss = decoded_ticket["K_c_ss"]

        logging.info("    Response from TGS: {}".format(
                        json.dumps(decoded_ticket)))

    def _connect_to_server(self, server):
        t4 = time.time()
        authentication_block = {
            "c": self.id,
            "t4": t4
        }

        logging.info("    Authentication block: {}".format(
                        json.dumps(authentication_block)))
        request = {
            "ticket": self.ticket_ss,
            "auth": encode_json(authentication_block, self.K_c_ss)
        }

        logging.info("    Connect to Server...")
        encoded = server.identificate(request)
        decoded = decode_json(encoded, self.K_c_ss)
        logging.info("    Response from Server: {}".format(
                        json.dumps(decoded)))
        logging.info("    Check if {:.2f} + 1 != {:.2f}".format(t4, decoded))
        if t4 + 1 != decoded:
            raise ServerException(
                "Unmatched client timestamps. Server wasn't identified")


def main():
    logging.basicConfig(format='%(message)s', level=logging.INFO)
    try:
        logging.info("Client...")
        client = Server()
        client.authenticate()

        logging.info("Server...")
        server = Server()
        server.authenticate()

        logging.info("Connect...")
        client.connect(server)
    except ServerException as e:
        logger.error(e, exc_info=True)
    except KerberosException as e:
        logger.error(e, exc_info=True)

    logging.info("Connection established!")


if __name__ == '__main__':
    main()
