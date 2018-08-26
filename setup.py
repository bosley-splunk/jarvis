import sqlite3 as lite
from sqlite3 import Error
import os
from configparser import ConfigParser
import logging
import shutil
import sys

"""
Jarvis Install Script
Usage:
    ./setup.py 
    
Make sure you modify the jarvis.cfg file first
"""


#  Functions go below
def db_connect(path_to_db):
    """
    Attempts to connect to the DB.  Pulls configuration information from the config file
    db_name = name of the individual DB file
    db_location = path name to the DB file
    db_path = combination of db_location and name
    :return:
    Returns connection object
    """

    logging.debug("db_path set to:  %s", path_to_db)
    try:
        conn = lite.connect(path_to_db)
        sqliteversion = lite.version

        logging.debug("SQLite version:  %s", sqliteversion
                      )

    except Error as e:
        logging.debug("Issue connecting to DB:")
        logging.debug(e)
        sys.exit(1)

    return conn


def setup(dblocation, dbpath):
    """
    Sets up environment
      db_name = name of the individual DB file
      db_location = path name to the DB file = usually ./db
      db_path = full path name

    If the DB exists, it will be backed up and recreated

    :return:
    Returns success status
    """

    #  Checking if the DB Directory exists, if not create it
    if not os.path.isdir(dblocation):
        logging.info("DB directory not found, creating")


        try:
            os.makedirs(dblocation)

        except PermissionError:
            logging.critical("Unable to create DB Directory at %s.  Exiting.", dblocation)
            sys.exit(1)

        except Error as e:
            logging.critical("Error encountered while interacting with filesystem")
            logging.critical(e)
            sys.exit(1)

        else:
            logging.info("Created DB directory successfully")

    #  Check for existence of the db file
    #  If it does, back it up

    if os.path.isfile(dbpath):
        backup_path = dbpath + ".bak"
        logging.info("DB file found, moving to %s.bak and creating new db", dbpath)

        shutil.move(dbpath, backup_path)

        logging.info("Made backup, creating new database")

    db = db_connect(dbpath)

    logging.info("Connected to the DB successfully, building tables now")

    create_tables(db)


def create_tables(db):
    command = db.cursor()

    #  Build ticket_queue table
    logging.debug("Running table create for ticket_queue")
    command.execute("""CREATE TABLE `ticket_queue` (
        `record_number`	INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
        `case_number`	TEXT NOT NULL,
        `creation_timestamp`	INTEGER NOT NULL,
        `req_uname`	TEXT NOT NULL,
        `req_uid`	TEXT NOT NULL,
        `assignee_uname`	TEXT,
        `assignee_uid`	TEXT,
        `assignedby_uid`	TEXT,
        `assignedby_uname`	TEXT,
        `assigned_timestamp`	INTEGER,
        `current_status`	TEXT,
        `closedby_uname`	TEXT,
        `closedby_uid`	TEXT,
        `closed_timestamp`	INTEGER,
        `priority`	TEXT DEFAULT 'P3',
        `escalated`	TEXT DEFAULT 'N',
        `escalatedby_uname`	TEXT,
        `escalatedby_uid`	TEXT,
        `escalation_date`	INTEGER
    );""")

    logging.debug("Running table create for tech_list")
    command.execute("""CREATE TABLE `tech_list` (
       `record_number`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
       `tech_uid`	TEXT NOT NULL,
        `tech_name`	TEXT NOT NULL,
        `manager_name`	TEXT NOT NULL,
        `manger_uid`	TEXT NOT NULL
        );""")


# Main execution section below
if __name__ == '__main__':

    #  Turn on Logging - cause lord knows I need it
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - [%(process)d] - (%(funcName)s:%(lineno)s) : %(message)s',
        filename='jarvis_setup.log',
        filemode='w'
    )

    logging.info("Logging initialized.  Reading in Configs.")

    #  Read in config file - jarvis_flask.cfg
    app_config = ConfigParser()
    app_config.read('jarvis_flask.cfg')

    #  Setup DB stuff
    logging.debug("Reading in various settings")
    db_name = app_config.get('DEFAULT', 'database_name')
    db_location = app_config.get('DEFAULT', 'database_location')
    db_path = os.path.join(db_location, db_name)

    logging.debug("starting setup")
    setup(db_location, db_path)
