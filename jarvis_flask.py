from slackclient import SlackClient
import re
import sqlite3 as lite
import time
#import pytz
#from datetime import datetime
import os
from configparser import ConfigParser
import logging
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
logging_dir=os.path.join(source_path, "jarvis_flask.log"


#  Turn on Logging - cause lord knows I need  it
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(process)d] - (%(funcName)s:%(lineno)s) : %(message)s',
    filename=logging_dir,
    filemode='w'
)

logging.info("Logging initialized.  Reading in Configs.")

logging.info("Starting Flask")

app = Flask(__name__)
#app.run(debug=True)


#  Define functions
def validate_request(request):
    #  Validate the request is from Slack.
    is_token_valid = request.form['token'] == app_config.get('Slack_Settings','verification_token')
    is_team_id_valid = request.form['team_id'] == app_config.get('Slack_Settings','team_id')

    logger.debug('Token validation is:  %s',is_token_valid)
    logger.debug('Team ID is:  %s',is_team_id_valid)

    if (is_token_valid == False) or (is_team_id_valid == False):
        logger.warn('Invalid request recieved')
        logger.debug('Token Expected:  %s    Token Received:  %s',
            app_config.get('Slack_Settings','verification_token'),
            request.form['token']
        )

        heartbeat_message = {'text' :  'Sorry, your call wasn\'t authenticated - please contact your admin'}
        return jsonify(heartbeat_message)

    else:
        logger.info('Authenticated Request - processing request')


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

    status=is_request_valid(request)

    if not status:
        heartbeat_message = {'text' :  'Sorry, your call wasn\'t authenticated - please contact your admin'}
        return jsonify(heartbeat_message)
    else:
        heartbeat_message = {'text' :  'I\'m Alive'}
        return jsonify(heartbeat_message)

#   Main execution section below
#if __name__ == '__main__':
    """
    Flask is going to be running under Apache and wsgi
    So we don't actually have to fire up the flask server 
    Just have it listening.
    """


