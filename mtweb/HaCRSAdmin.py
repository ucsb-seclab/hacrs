#!/usr/bin/env python
from boto.mturk.connection import MTurkConnection
from boto.mturk.question import ExternalQuestion, AnswerSpecification, QuestionForm, ValidatingXML, FreeTextAnswer, QuestionContent, FormattedContent, Question, Overview, SelectionAnswer
from boto.mturk.price import Price
from boto.mturk.qualification import Qualifications, PercentAssignmentsApprovedRequirement, Requirement, NumberHitsApprovedRequirement
from pprint import pprint
import operator
import psycopg2
import boto3
import glob
import shutil
import json
import pdb
import sys
import os
sys.path.append('../mtutil/')
from HaCRSUtil import HaCRSUtil
from HaCRSDB import HaCRSDB
from HaCRSTurker import HaCRSTurker
from flask import Flask, request
from flask import g
app = Flask(__name__)
from werkzeug.contrib.fixers import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app)
import pystache

# Administrative web API
# Create and query programs and tasklets and/or push tasklets

class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message="", status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


def get_db():
    if not hasattr(g, 'db'):
        g.db = HaCRSDB()
    return g.db

def get_config():
    if not hasattr(g, 'config'):
        g.config = HaCRSUtil.get_config('../config.ini')
    return g.config

def get_mt():
    config = get_config()
    if not hasattr(g, 'MT'):
        g.MT = HaCRSTurker()
    return g.MT

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

@app.route("/create_program/<programname>")
def create_program(programname):
    pass


@app.route("/create_standard_programs", methods=['POST'])
def create_standard_programs():
    db = get_db()
    config = get_config()
    try:
        for program in json.load(open(config.get('general', 'programsjson'))):
            pid = db.lookup_program(program)
            if not pid:
                pid = db.create_program(program)
                print 'Created program {} with ID {}'.format(program, pid)
        return json.dumps({'status': 'OK'})
    except Exception as e:
        raise InvalidUsage()


@app.route("/create_tasklet/seed", methods=['POST'])
def create_seed_tasklet( ):
    input_args = ['programname', 'total_transitions', 'previous_transitions']
    try:
        args = {}
        for x in input_args:
            assert x in request.get_json().keys()
            args[x] = request.get_json()[x]
    except Exception as e:
        raise InvalidUsage('Required argument missing')

    try:
        db = get_db()
        config = get_config()
        pid = db.lookup_program(args['programname'])
        assert pid != None
        rating, base_pay, payout_array = HaCRSUtil.hit_info(int(args['total_transitions']) - int(args['previous_transitions']), int(args['total_transitions']))
        tid = db.create_seed_tasklet(pid, base_pay, payout_array, rating)

    #except Exception as e:
    except IOError as e:
        return repr(e)
        raise InvalidUsage('Error creating tasklet: {}'.format(e))

    try:
        pass
        #mt = get_mt()
        # push tasklet to mturk!
        #mturkid, hit_result = mt.push_tasklet_mturk(tid)
    except Exception as e:
        raise InvalidUsage()
    return json.dumps({'tasklet_id': str(tid), 'base_pay': base_pay, 'rating': rating, 'payout_array': payout_array})


def push_single_entry(difficulty, times ):
    mt = HaCRSTurker()
    # push tasklet to mturk!
    for _ in range(times):
        mturkid, hit_result = mt.push_tasklet_mturk( difficulty )
    return json.dumps({'mturkid': mturkid})

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def xcatchall(path=None):
    return "{} ?\n".format(path)

if __name__ == "__main__":
    #push_single_entry('easy', 50)
    #push_single_entry('medium', 7)
    #push_single_entry('hard', 39)
    #push_single_entry('very_hard', 14)
    #push_single_entry('priority', 30)
    app.run(port=8989, debug=True)

