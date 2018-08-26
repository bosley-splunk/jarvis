import sys

source_path = "/opt/projects/jarvis/"

#  Import the main app
sys.path.append(source_path)
from jarvis_flask import app as application