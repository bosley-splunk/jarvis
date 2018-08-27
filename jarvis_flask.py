from slackclient import SlackClient
import re
import sqlite3 as lite
import time
#import pytz
#from datetime import datetime
import os
from configparser import ConfigParser
import logging
import logging.handlers
from logging.config import fileConfig
from flask import Flask,abort, jsonify, request
import json
import hmac
import hashlib
import base64

#import shutil

"""
Flask container to handle requests from Slack for JARVIS
"""

#  Static configs go here
source_path = "/opt/projects/jarvis/"
APP_CONFIG_FILE = os.path.join(source_path, "jarvis_flask.cfg")

#  Reading in configs
app_config = ConfigParser()
app_config.read(APP_CONFIG_FILE)
logging_file=app_config.get('DEFAULT', 'log_cfg_file')
logging_cfg=os.path.join(source_path, logging_file)

#  Set Up Syslog Logging - having a hard time writing to a local dir
#  With flask under apache
logging.config.fileConfig(logging_cfg)
logger = logging.getLogger('jarvis')

logging.info("Logging initialized.  Reading in Configs.")

logging.info("Starting Flask")

app = Flask(__name__)
#app.run(debug=True)


#  Define functions
def validate_request(request):
    """
    Validates the request is officially from slack.  See https://api.slack.com/docs/verifying-requests-from-slack
    for more information around this.
    :param request:
    :return:
    """

    #  Set the return value
    validated = False

    #  Get the our signing secret from the config
    internal_slack_signing_secret = app_config.get('Slack_Settings', 'slack_signing_secret')
    encoded_internal_signing = internal_slack_signing_secret.encode()

    #  Get what Slack sent us
    sent_slack_signature = request.headers.get('X-Slack-Signature')
    request_timestamp = request.headers.get('X-Slack-Request-Timestamp')

    #  Get the body of the request.  This was seriously a pain.
    request_body = request.get_data()
    request_body = request_body.decode('utf-8')
    version = "v0"
    separator = ":"

    #  Build the signature line
    request_signature_line = version + separator + request_timestamp + separator + request_body
    encoded_signature_line = request_signature_line.encode()

    #  Now to hash it
    hashed_signature = hmac.new(encoded_internal_signing, encoded_signature_line, hashlib.sha256)
    hexhashedsignature = "v0=" + hashed_signature.hexdigest()

    #  This took me all day, but it works!
    if hexhashedsignature != sent_slack_signature:
        logging.critical("Message not validated!  Something is wrong!")
        validation_error = {'text': 'Your message was\'t accepted due to invalid signing'}
        return jsonify(validation_error)

    else:
        logging.info("Message validated.  Have a great day")


#  Routing definitions go here
#  Message Receiver end point for custom dialogs
@app.route('/message_receiver', methods=['Post'])
def message_receiver():
    """Processes the incoming custom message
    Validates the sender
    Opens a dialog with the requester
    """
    validate_request(request)





@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    logging.info("Heartbeat requested")
    validate_request(request)
    heartbeat_message = {'text':  'I\'m Alive'}
    return jsonify(heartbeat_message)


@app.route('/page_cs', methods=['POST'])
def page_cs():
    """
    Processes /page_cs command -
    end goal is to create a custom dialog requesting ticket number and priority
    :return:
    """
    validate_request(request)

    trigger_id = request.form['trigger_id']
    logging.debug("Paging request received")
    logging.debug("Request trigger_id:  %s", trigger_id)

    #  Dialog JSON here:
    pager_dialog = {
        "trigger_id":  'trigger_id',
        "dialog": {
            "callback_id":  "test123",
            "title":  "Page Cloud Support",
            "submit_label": "Submit",
            "notify_on_cancel": False,
            "elements": [
                {
                    "type":  "text",
                    "label":  "Case Number",
                    "name":  "case_number"
                },
                {
                    "type":  "select",
                    "label":  "Priority",
                    "name":  "priority",
                    "options":  [
                        {
                            "label":  "P1",
                            "value":  "P1"
                        },
                        {
                            "label":  "P2",
                            "value":  "P2"
                        },
                        {
                            "label":  "P3",
                            "value":  "P3"
                        },
                        {
                            "label":  "P4",
                            "value":  "P4"
                        }
                    ]

                },
                {
                    "type":  "textarea",
                    "label":  "Description",
                    "name":  "description",
                    "hint":  "Description of the issue"
                }
            ]

        }
    }

    open_dialog = SlackClient.api_call(open_dialog)

    print(open_dialog)



    #test_message = {'text':  'Testing paging command'}
    #return jsonify(test_message)


#   Main execution section below
#if __name__ == '__main__':
    """
    Flask is going to be running under Apache and wsgi
    So we don't actually have to fire up the flask server 
    Just have it listening.
    """


