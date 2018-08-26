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
    """Validate the request is truely from Slack
    See https://api.slack.com/docs/verifying-requests-from-slack for more information
    This was more of a pain in the butt getting the request from flask :/
    """

    #  Get the our signing secret from the config
    internal_slack_signing_secret = app_config.get('Slack_Settings', 'slack_signing_secret')

    #  Get what Slack sent us
    sent_slack_signature = request.headers.get('X-Slack-Signature')
    request_timestamp = request.headers.get('X-Slack-Request-Timestamp')


    #  Get the body of the request.  This was seriously a pain.
    request_body = request.get_data()
    version = "v0"


    #  Build the signature line
    request_signature_line = version + ":" + request_timestamp + ":" + request_body
    encoded_line = request_signature_line.encode('utf-8')

    logging.info("Request Signature Line:  %s", encoded_line)

    #  Now to hash it
    hashed_signature = hmac.new(internal_slack_signing_secret, encoded_line, hashlib.sha256)

    logging.info("Calculated Signature:  %s", hashed_signature)
    logging.info("Sent Signature:  %s", sent_slack_signature)



    #logging.debug("Signature Line is:  %s", request_signature_line)

    #is_token_valid = request.form['token'] == app_config.get('Slack_Settings', 'verification_token')
    #is_team_id_valid = request.form['team_id'] == app_config.get('Slack_Settings', 'team_id')

    #logger.debug('Token validation is:  %s', is_token_valid)
    #logger.debug('Team ID is:  %s', is_team_id_valid)

    #if (is_token_valid == False) or (is_team_id_valid == False):
        #logger.warning('Invalid request received')
        #logger.debug('Token Expected:  %s    Token Received:  %s',
        #             app_config.get('Slack_Settings','verification_token'),
        #            request.form['token']
        #             )

        #heartbeat_message = {'text':  'Sorry, your call wasn\'t authenticated - please contact your admin'}
        #return jsonify(heartbeat_message)

    #else:
        #logger.info('Authenticated Request - processing request')


#  Routing definitions
#  Message Receiver end point for custom dialogs
@app.route('/message_receiver', methods=['Post'])
def message_receiver():
    """Processes the incoming custom message
    Validates the sender
    Opens a dialog with the requester
    """
    validate_request(request)

    message_action = json.loads(request.form["payload"])
    user_id = message_action["user"]["id"]

    logging.debug("Message Action received:  %s", message_action)
    logging.debug("UserID:  %s", user_id)



@app.route('/heartbeat', methods=['POST'])
def heartbeat():
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



#   Main execution section below
#if __name__ == '__main__':
    """
    Flask is going to be running under Apache and wsgi
    So we don't actually have to fire up the flask server 
    Just have it listening.
    """


