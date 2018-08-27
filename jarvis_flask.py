from slackclient import SlackClient
import re
import sqlite3 as lite
import time
# import pytz
# from datetime import datetime
import os
from configparser import ConfigParser
import logging
import logging.handlers
from logging.config import fileConfig
from flask import Flask, abort, jsonify, request
import hmac
import hashlib
from random import randint
import json
from urllib.parse import unquote


"""
Flask container to handle requests from Slack for JARVIS
"""

#  Static configs go here
source_path = "/opt/projects/jarvis/"
APP_CONFIG_FILE = os.path.join(source_path, "jarvis_flask.cfg")

#  Reading in configs
app_config = ConfigParser()
app_config.read(APP_CONFIG_FILE)
logging_file = app_config.get('DEFAULT', 'log_cfg_file')
logging_cfg = os.path.join(source_path, logging_file)

#  Set Up Syslog Logging - having a hard time writing to a local dir
#  With flask under apache
logging.config.fileConfig(logging_cfg)
logger = logging.getLogger('jarvis')

logging.info("Logging initialized - Setting up slack client")
sc = SlackClient(app_config.get('Slack_Settings', 'bot_oauth_key'))

logging.info("Starting Flask")

app = Flask(__name__)


# app.run(debug=True)


#  Define functions
def validate_request(request):
    """
    Validates the request is officially from slack.  See https://api.slack.com/docs/verifying-requests-from-slack
    for more information around this.
    :param request:
    :return:
    """
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


def message_pager(message):
    """
    Takes the message, inserts it into the DB and notifies Cloud Support Channel
    Lets the requester know it's been handled
    :param message:
    :return:
    """

    #  Extract the required information from the payload
    submitter_uid = message["user"]["id"]
    case_number = message["submission"]["case_number"]
    case_priority = message["submission"]["priority"]
    case_description = message["submission"]["description"]
    channel = message["channel"]["id"]

    #  Because of warnings of the real name field being deprecated in the future
    #  Going to do a call to look up the full real name
    full_profile = sc.api_call("users.profile.get", timeoust=None, user='submitter_uid')
    full_name = full_profile['user']['real_name']

    logging.debug("Setting the following per this request:")
    logging.debug("submitter_uid:  %s", submitter_uid)
    logging.debug("case_number:  %s", case_number)
    logging.debug("case_priority:  %s", case_priority)
    logging.debug("case_description:  %s", case_description)
    logging.debug("full_name:  %s", full_name)

    sc.api_call("chat.postEphemeral", timeout=None,
                channel='channel',
                text=":loading:  Working on request",
                user='submitter_uid')





#  Routing definitions go here
#  Message Receiver end point for custom dialogs
@app.route('/message_receiver', methods=['Post'])
def message_receiver():
    """
    Message Endpoint from Slack
        Validates the incoming message
        Pulls the callback_id to determine what app to route to
        Hands off to the specific def for that app to handle

    :return:
    """
    validate_request(request)

    logging.info("Received Message from Slack")

    message = json.loads(request.form['payload'])
    submitter_id = message["user"]["id"]
    request_type = message["callback_id"]

    if request_type.startswith('pagerapp'):
        logging.info("Received request for the pager app")
        message_pager(message)

    return ('', 200)


@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    logging.info("Heartbeat requested")
    validate_request(request)
    heartbeat_message = {'text': 'I\'m Alive'}
    return jsonify(heartbeat_message)


@app.route('/page_cs', methods=['POST'])
def page_cs():
    """
    Processes /page_cs command -
    end goal is to create a custom dialog requesting ticket number and priority
    :return:
    """
    validate_request(request)

    #  Generate random callback_id
    callback_number = randint(10000, 99999)
    callback_id = "pagerapp-" + str(callback_number)

    #  Generate the PopUp
    logging.info("Page Request Received - popping dialog")
    page_dialog = sc.api_call("dialog.open", timeout=None, trigger_id=request.form['trigger_id'],
                              dialog={
                                  "callback_id": callback_id,
                                  "title": "Notify Cloud Support",
                                  "submit_label": "Submit",
                                  "notify_on_cancel": False,
                                  "elements": [
                                      {
                                          "type": "text",
                                          "label": "Case Number",
                                          "name": "case_number"
                                      },
                                      {
                                          "type": "select",
                                          "label": "Priority",
                                          "name": "priority",
                                          "options": [
                                              {
                                                  "label": "P1",
                                                  "value": "P1"
                                              },
                                              {
                                                  "label": "P2",
                                                  "value": "P2"
                                              },
                                              {
                                                  "label": "P3",
                                                  "value": "P3"
                                              },
                                              {
                                                  "label": "P4",
                                                  "value": "P4"
                                              }
                                          ]
                                      },
                                      {
                                          "type": "textarea",
                                          "label": "Description of issue",
                                          "name": "description",
                                          "hint": "Be descriptive as possible"
                                      },
                                  ]
                              }
                              )
    return('', 200)



    #   Main execution section below
    # if __name__ == '__main__':
    """
    Flask is going to be running under Apache and wsgi
    So we don't actually have to fire up the flask server 
    Just have it listening.
    """
