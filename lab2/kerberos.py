#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import random
import json
import time
import logging
from constants import (
    TYPE, KEY_LENGTH, ID_LENGTH,
    TICKET_LIFETIME_SEC, EPS, CODING)
from des import crypt


logger = logging.getLogger(__name__)

# TODO: 1) remove K_c_tgs 2) logging


def random_key():
    return ''.join(
            random.choice('0123456789ABCDEF') for i in range(KEY_LENGTH))


def random_id():
    return ''.join(
            random.choice('0123456789ABCDEF') for i in range(ID_LENGTH))


def encode_json(js, key):
    _js = json.dumps(js, ensure_ascii=False)
    _key = key.encode(CODING)
    return crypt(_js.encode(CODING), _key, TYPE["encrypt"])


def decode_json(enc_js, key):
    _key = key.encode(CODING)
    dec_js = crypt(enc_js, _key, TYPE["decrypt"])
    return json.loads(dec_js.decode(CODING))


class KerberosException(Exception):
    def __init__(self, msg):
        super(KerberosException, self).__init__(msg)


class Kerberos:
    servers = {
        "tgs": random_id(),
        "as": random_id()
    }
    K_AS_TGS = random_key()   # K as_tgs


class Authenticater(Kerberos):      # AS
    def register(self):
        _id, _key = random_id(), random_key()
        while _id in Kerberos.servers.keys():
            _id = random_id()

        server_info = {
            "key": _key,
            "authorizator_key": None
        }
        Kerberos.servers[_id] = server_info
        return _id, _key

    def identify_client(self, client_id):
        if client_id not in Kerberos.servers.keys():
            raise KerberosException("Unidentified client")

        client_key = Kerberos.servers[client_id]["key"]
        authorizator_key = random_key()                # Generate K_c_tgs
        Kerberos.servers[client_id]["authorizator_key"] = authorizator_key

        response = {
            "TGT": self._generate_ticket(client_id),
            "K_c_tgs": authorizator_key
        }
        return encode_json(response, client_key)

    def _generate_ticket(self, client_id):
        ticket = {
            "c": client_id,
            "tgs": Kerberos.servers["tgs"],
            "t1": time.time(),
            "p1": TICKET_LIFETIME_SEC,
            "K_c_tgs": Kerberos.servers[client_id]["authorizator_key"]
        }
        logging.info("      Ticket from AS: {}".format(
                        json.dumps(ticket)))
        return encode_json(ticket, Kerberos.K_AS_TGS).decode(CODING)


class Authorizator(Kerberos):       # TGS
    def set_connection(self, request):
        ticket = decode_json(request["ticket"], Kerberos.K_AS_TGS)
        auth_block = decode_json(
            request["auth"], ticket["K_c_tgs"])

        logging.info("      TGS received ticket: {}".format(
            json.dumps(ticket)))
        logging.info("      TGS auth block: {}".format(
            json.dumps(auth_block)))

        logging.info("      Check timestamp")
        if round(auth_block["t1"]) - round(ticket["t1"]) > EPS:
            raise KerberosException("Unmatched timestamps")

        logging.info("      Check life period")
        if ticket["t1"] + ticket["p1"] < time.time():
            raise KerberosException("Ticket life has ended")

        K_c_ss = random_key()
        response = {
            "TGS": self._generate_ticket(ticket["c"], request["id"], K_c_ss),
            "K_c_ss": K_c_ss
        }
        return encode_json(response, ticket["K_c_tgs"])

    def _generate_ticket(self, client_id, server_id, server_key):
        ticket = {
            "c": client_id,
            "ss": server_id,
            "t3": time.time(),
            "p2": TICKET_LIFETIME_SEC,
            "K_c_ss": server_key
        }
        logging.info("      Ticket from TGS: {}".format(
                        json.dumps(ticket)))
        return encode_json(
            ticket,
            Kerberos.servers[server_id]["authorizator_key"]).decode(CODING)


authenticater = Authenticater()
authorizator = Authorizator()
