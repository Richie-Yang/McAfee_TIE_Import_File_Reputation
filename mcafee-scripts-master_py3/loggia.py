"""
loggia.py v1.10; Author: Richie Yang; Last edited at 2020/12/18.
Compatible Platform list: Most Python Scripts
Description: This script is made to both print out formatted logs and write out log file at the same time.
New Features: Now file handler will rotate log files in order.
known Issues: None
"""

from datetime import datetime
from logging import handlers
import traceback
import logging
import sys
import os


class Logging:

    def __init__(self, filename='testing'):
        log_formatter = logging.Formatter('[%(asctime)s][%(levelname)s][' + filename + ']%(message)s')
        # logging.getLogger().setLevel(logging.DEBUG)
        # requests_log = logging.getLogger("requests.packages.urllib3")
        # requests_log.setLevel(logging.DEBUG)
        # requests_log.propagate = True
        # print("[%s][%s][%s]Logging.__init__ process: logging handler for requests module successfully enabled."
        #       % (datetime.now(), "INFO", "loggia"))
        root_logger = logging.getLogger()

        try:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(log_formatter)
            root_logger.addHandler(console_handler)
            print("[%s][%s][%s]Logging.__init__ process: stream logging handler successfully enabled."
                  % (datetime.now(), "INFO", "loggia"))

            # Using "with statement" to check if the directory and specific file exist or not.
            with open("log/%s.log" % filename) as file:
                file.read(1)

        except FileNotFoundError as file_err:
            trace_output = traceback.print_exc()
            print("[%s][%s][%s]Logging.__init__ error traceback: %s"
                  % (datetime.now(), "WARNING", "loggia", str(trace_output)))
            print("[%s][%s][%s]Logging.__init__ execution failed: %s"
                  % (datetime.now(), "WARNING", "loggia", str(file_err)))
            # traceback.print_exc()
            if os.path.exists("log") is False:
                os.mkdir(os.path.join('', 'log'))
                print("[%s][%s][%s]Logging.__init__ process: folder 'log' has been created."
                      % (datetime.now(), "INFO", "loggia"))
            else:
                print("[%s][%s][%s]Logging.__init__ process: folder 'log' exists, skipping."
                      % (datetime.now(), "INFO", "loggia"))

        except Exception as other_err:
            trace_output = traceback.print_exc()
            print("[%s][%s][%s]Logging.__init__ error traceback: %s"
                  % (datetime.now(), "ERROR", "loggia", str(trace_output)))
            print("[%s][%s][%s]Logging.__init__ execution failed: %s"
                  % (datetime.now(), "ERROR", "loggia", str(other_err)))
            sys.exit()

        finally:
            file_handler = logging.handlers.RotatingFileHandler(
                'log/%s.log' % filename, mode='a', maxBytes=300000, backupCount=3, encoding="utf-8"
            )
            file_handler.setFormatter(log_formatter)
            root_logger.addHandler(file_handler)
            print("[%s][%s][%s]Logging.__init__ process: File logging handler successfully enabled."
                  % (datetime.now(), "INFO", "loggia"))
