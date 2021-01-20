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
import hashlib
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
loggia.Logging(filename="tie_set_file_rep_from_file")

# Directories to use
# dir_to_whitelist = "C:\\Users\\user1\\Desktop\\whitelist"
# dir_to_blacklist = "C:\\Users\\user1\\Desktop\\blacklist"
dir_to_whitelist = os.path.dirname(os.path.abspath(__file__)) + "/import_files/1_whitelist"
dir_to_blacklist = os.path.dirname(os.path.abspath(__file__)) + "/import_files/2_blacklist"


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

    for root, dirs, files in os.walk(dir_to_whitelist):
        for file in files:
            # print(os.path.join(root, file))
            if file:
                filename = os.path.join(root, file)
                # filename = root + "\\" + file
                try:
                    sha1base64 = hashlib.sha1(open(filename, 'rb').read()).hexdigest()
                    md5base64 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                    sha256base64 = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
                except IOError:
                    logging.error("Unable to open file for hashing")
                    sys.exc_clear()

                PresentTimeDate = time.strftime("%c")
                PresentHost = socket.gethostname()
                filePath = os.path.normpath(filename)

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
                        filename=str(file),
                        comment="Reputation set via OpenDXL")

                rep_string = '[{"sha256":"' + sha256base64 + \
                             '","sha1":"' + sha1base64 + \
                             '", "md5":"' + md5base64 + \
                             '","reputation":"' + "known trusted" + \
                             '","name":"' + str(file) + \
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

    for root, dirs, files in os.walk(dir_to_blacklist):
        for file in files:
            # print(os.path.join(root, file))
            if file:
                filename = os.path.join(root, file)
                # filename = root + "\\" + file
                try:
                    sha1base64 = hashlib.sha1(open(filename, 'rb').read()).hexdigest()
                    md5base64 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                    sha256base64 = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
                except IOError:
                    logging.error("Unable to open file for hashing")
                    sys.exc_clear()

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
                        filename=str(file),
                        comment="Reputation set via OpenDXL")

                    rep_string = '[{"sha256":"' + sha256base64 + \
                                 '","sha1":"' + sha1base64 + \
                                 '", "md5":"' + md5base64 + \
                                 '","reputation":"' + "known malicios" + \
                                 '","name":"' + str(file) + \
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
