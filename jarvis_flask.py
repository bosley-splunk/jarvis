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
    #  Validate the request is from Slack.
    #internal_slack_signing_secret = app_config.get('Slack_Settings', 'slack_signing_secret')
    #sent_slack_signing_secret = request.headers.get('X-Slack-Signature')
    #request_timestamp = request.headers.get('X-Slack-Request-Timestamp')
    #request_body = request.form["payload"]
    #version = "v0"
    #request_signature_line = version + ":" + request_timestamp + ":" + request_body

    logging.info("In validation now")

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

    test = request.form('payload')
    logging.debug("Payload = %s", request.form['payload])
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


