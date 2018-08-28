from slackclient import SlackClient
import re
import sqlite3 as lite
from sqlite3 import Error
from pytz import timezone
from datetime import datetime
import os
from configparser import ConfigParser
import logging
from logging.config import fileConfig
from flask import Flask, abort, jsonify, request
import hmac
import hashlib
from random import randint
import json
from logging.handlers import TimedRotatingFileHandler

app = Flask(__name__)


#  Define functions
def logging_setup(log_directory):
    """
    Sets up rotating log under log_directory
    :param log_directory:
    :return:
    """
    log_file = "jarvis.log"
    log_path = os.path.join(log_directory, log_file)

    if not os.path.isdir(log_directory):
        os.mkdir(log_directory)

    formatter = logging.Formatter('%(name)s - %(levelname)s - [%(process)d] (%(funcName)s:%(lineno)s) : %(message)s')
    logging_level = logging.DEBUG
    handler = logging.handlers.TimedRotatingFileHandler(log_path,
                                                        when='midnight',
                                                        backupCount=5)
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging_level)

    return logger


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


def lookup_username(user_id):
    """
    Takes the userid and returns the full user name.
    It accomplishes this by connecting to the slack api using users.info
    and getting the real_name_normalized from the results
    This is per Slacks Warning that name will be going away
    sc = slackclient connection
    user_id = user id to look up
    :param sc, user_id:
    :return user_full_name:
    """

    logging.info("Looking up user name from Slack API")
    profile = sc.api_call("users.info", timeout=None, user=user_id)
    user_full_name = profile['user']['profile']['real_name_normalized']

    return user_full_name

def generate_timestamp():
    """
    Generates timestamp for insertion into the DB in epoch format
    Timezone is set to pacific time for standardization
    :return:
    """

    pacific_time = timezone('America/Los_Angeles')
    current_time = datetime.now(pacific_time)
    timestamp = current_time.timestamp()

    return timestamp


def connect_to_db():
    """
    Attempts to connect to sqlite db
    db_path = full path db
    :param:
    :return db object:
    """

    #  Check to ensure db directory exists - building full path
    db_dir = os.path.join(app_config.get('DEFAULT', 'source_path'), app_config.get('DEFAULT', 'database_location'))

    logging.info("Checking to see if db path exists")
    if not os.path.isdir(db_dir):
        logging.critical("Database doesn't exist, please run setup.py")
        return("", 500)

    else:
        db_path = os.path.join(db_dir, app_config.get('DEFAULT', 'database_name'))
        logging.info("Connecting to DB at %s", db_path)

        try:
            db = lite.connect(db_path)

        except Error as e:
            logging.critical("Database connection error: ")
            logging.critical(e)
            return("", 500)

        return db


def message_pager(message):
    """
    Takes the message, inserts it into the DB and notifies Cloud Support Channel
    Lets the requester know it's been handled
    :param message:
    :return:
    """

    #  Extract the required information from the payload
    submitter_uid = message["user"]["id"]
    submitter_name = lookup_username(submitter_uid)
    case_number = message["submission"]["case_number"]
    case_priority = message["submission"]["priority"]
    case_description = message["submission"]["description"]
    channel = message["channel"]["id"]

    logging.info("Sending update to requester")
    message_response = sc.api_call("chat.postEphemeral", timeout=None,
                                   channel=channel,
                                   text="Working on request",
                                   user=submitter_uid)

    logging.info("Results of sending message: %s", message_response['ok'])

    db = connect_to_db()

    timestamp = generate_timestamp()

    c = db.cursor()

    c.execute('''  INSERT INTO TICKET_QUEUE(case_number, creation_timestamp, req_uname, req_uid, priority) 
                VALUES(?,?,?,?,?)''', (case_number, timestamp, submitter_name, submitter_uid, case_priority))






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


#  Main execution section below
if __name__ == '__main__':
    """
    Moving to Flask stand alone vs under Apache
    """

    #  Static configs go here
    APP_CONFIG_FILE = "jarvis.cfg"

    #  Reading in configs
    app_config = ConfigParser()
    app_config.read(APP_CONFIG_FILE)
    log_dir = app_config.get('DEFAULT', 'log_directory')

    #  Set up logging
    logging = logging_setup(log_dir)
    logging.info("Logging initialized - Setting up slack client")

    sc = SlackClient(app_config.get('Slack_Settings', 'bot_oauth_key'))

    logging.info("Starting Flask")

    if app_config.get('DEFAULT', 'remote_environment') == True:
        cert = app_config.get('SSL', 'cert')
        key = app_config.get('SSL', 'key')
        app.run(ssl_context=(app_config.get('SSL', 'cert'), app_config.get('SSL', 'key')))

    else:
        app.run(debug=True)