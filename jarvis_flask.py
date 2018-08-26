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
APP_CONFIG_FILE = "jarvis_flask.cfg"


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
@app.route('/page_message',methods['POST'])
def page_message():
    """
    This will pop up a message box when requesting attention to a case

    :return:
    """
    validate_request(request)

    #  Parse the payload
    form_json = json.loads(request.form["payload"])






#   Main execution section below
if __name__ == '__main__':

    #  Turn on Logging - cause lord knows I need it
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - [%(process)d] - (%(funcName)s:%(lineno)s) : %(message)s',
        filename='jarvis_flask.log',
        filemode='w'
    )

    logging.info("Logging initialized.  Reading in Configs.")
    app_config = ConfigParser()
    app_config.read(APP_CONFIG_FILE)

    logging.info("Starting Flask")

    app = Flask(__name__)

    app.run(debug=True)
