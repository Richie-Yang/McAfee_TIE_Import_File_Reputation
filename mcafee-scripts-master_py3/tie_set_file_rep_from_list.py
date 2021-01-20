"""
This sample demonstrates invoking the McAfee Threat Intelligence Exchange
(TIE) DXL service to set the trust level of a file (as identified
by its hashes)

TIE Whitelisting Script Originally by Troja from the McAfee Community
https://community.mcafee.com/t5/Threat-Intelligence-Exchange-TIE/Upload-a-golden-Image-to-TIE-including-
Reputation-and-Comment/td-p/490716, Modified 10/25/18
"""

from __future__ import absolute_import
from __future__ import print_function
import logging
import loggia
import os
import sys
import base64
import codecs
import time
import socket
import json
import re

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel

# Import common logging and configuration
# sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# You must initialize logging, otherwise you'll not see debug output.
loggia.Logging(filename="tie_set_file_rep_from_list")

# Directories to use
# dir_to_whitelist = "C:\\Users\\user1\\Desktop\\whitelist"
# dir_to_blacklist = "C:\\Users\\user1\\Desktop\\blacklist"
whitelist_filename = "hashes.txt"
blacklist_filename = "hashes.txt"
dir_to_whitelist = os.path.dirname(os.path.abspath(__file__)) + "/import_lists/1_whitelist/%s" % whitelist_filename
dir_to_blacklist = os.path.dirname(os.path.abspath(__file__)) + "/import_lists/2_blacklist/%s" % blacklist_filename


# Possible Reputation Values
# Known Trusted Installer   100
# Known trusted 			99
# Most likely trusted 	85
# Might be trusted 		70
# Unknown 				50
# Might be malicious 	30
# Most likely malicious 	15
# Known malicious 		1
# Not set 				0

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)


def whitelist_loop():
    logging.info("whitelist_loop function starts.")
    md5base64 = ""
    sha1base64 = ""
    sha256base64 = ""
    f = open(dir_to_whitelist)
    contents = f.read()
    file_as_list = contents.splitlines()
    for line in file_as_list:
        if re.match(r"^([a-fA-F\d]{32}$)", line):
            md5base64 = line

        elif re.match(r"^([a-fA-F\d]{40}$)", line):
            sha1base64 = line

        elif re.match(r"^([a-fA-F\d]{64}$)", line):
            sha256base64 = line

        else:
            logging.warning("Script only takes SHA-1, SHA-256, or MD5 hashes")

        PresentTimeDate = time.strftime("%c")
        filePath = os.path.normpath(dir_to_whitelist)
        PresentHost = socket.gethostname()

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            # Create the McAfee Threat Intelligence Exchange (TIE) client
            tie_client = TieClient(client)

            # Set the Enterprise reputation for notepad.exe to Known Trusted
            tie_client.set_file_reputation(
                TrustLevel.KNOWN_TRUSTED, {
                    HashType.MD5: md5base64,
                    HashType.SHA1: sha1base64,
                    HashType.SHA256: sha256base64
                },
                filename=str(line),
                comment="Reputation set via OpenDXL")

        rep_string = '[{"sha256":"' + sha256base64 + \
                    '","sha1":"' + sha1base64 + \
                    '", "md5":"' + md5base64 + \
                    '","reputation":"' + "known trusted" + \
                    '","name":"' + str(line) + \
                    '","comment":"' + PresentTimeDate + \
                    " " + "Whitelisted by Script" + \
                    " on Host: " + PresentHost + \
                    "," + " " + "Located at path: " + str(json.dumps(filePath).replace('\"', '')) + '"}]'
        logging.info('Adding Whitelisted Files to TIE Server: ' + rep_string)

    logging.info("whitelist_loop function finished")


def blacklist_loop():
    logging.info("blacklist_loop function starts.")
    md5base64 = ""
    sha1base64 = ""
    sha256base64 = ""
    f = open(dir_to_blacklist)
    contents = f.read()
    file_as_list = contents.splitlines()
    for line in file_as_list:
        if re.match(r"^([a-fA-F\d]{32}$)", line):
            md5base64 = line

        elif re.match(r"^([a-fA-F\d]{40}$)", line):
            sha1base64 = line

        elif re.match(r"^([a-fA-F\d]{64}$)", line):
            sha256base64 = line

        else:
            logging.warning("Script only takes SHA-1, SHA-256, or MD5 hashes")

        PresentTimeDate = time.strftime("%c")
        filePath = os.path.normpath(dir_to_blacklist)
        PresentHost = socket.gethostname()

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            # Create the McAfee Threat Intelligence Exchange (TIE) client
            tie_client = TieClient(client)

            # Set the Enterprise reputation for notepad.exe to Known Trusted
            tie_client.set_file_reputation(
                TrustLevel.KNOWN_MALICIOUS, {
                    HashType.MD5: md5base64,
                    HashType.SHA1: sha1base64,
                    HashType.SHA256: sha256base64
                },
                filename=str(line),
                comment="Reputation set via OpenDXL")

            rep_string = '[{"sha256":"' + sha256base64 + \
                        '","sha1":"' + sha1base64 + \
                        '", "md5":"' + md5base64 + \
                        '","reputation":"' + "known malicios" + \
                        '","name":"' + str(line) + \
                        '","comment":"' + PresentTimeDate + \
                        " " + "Blacklisted by Script" + \
                        " on Host: " + PresentHost + \
                        "," + " " + "Located at path: " + str(json.dumps(filePath).replace('\"', '')) + \
                        "," + " " + "Related to Grey Energy Malware" '"}]'

            logging.info('Adding Blacklisted Files to TIE Server: ' + rep_string)

    logging.info("blacklist_loop function finished")


def __main__():
    whitelist_loop()
    blacklist_loop()


__main__()

# Optional: Track any File under the EPO issues
#           IssueString = "Filename: " + filename + " MD5: " + md5input + " sha1: " + sha1input + " from System: " + PresentHost
#           mc.issue.createIssue(name="Whitelist Entry by Script",desc=IssueString)
