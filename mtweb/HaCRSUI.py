#!/usr/bin/env python
import ConfigParser
import psycopg2
import operator
import uuid
import json
import glob
import urllib
import sys
import textwrap
sys.path.append('../mtutil/')
from HaCRSUtil import HaCRSUtil
from TurkerResults import TurkerResults
from HaCRSTurker import HaCRSTurker
from HaCRSDB import HaCRSDB
from pprint import pprint
from threading import Thread
import time
import flask
from flask import Flask, request
from flask import g
import flask_login
app = Flask(__name__)
app.secret_key = 'SNIP'
from werkzeug.contrib.fixers import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app)
import tarfile
import pystache
import random
import string
import pdb
import re
import os
from functools import wraps


login_manager = flask_login.LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

sys.path.append('../docker/')
from VNCRunner import VNCRunner

def get_db():
    if not hasattr(g, 'db'):
        g.db = HaCRSDB()
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

@app.before_request
def force_https():
    if request.url.startswith('http:'):
        return flask.redirect("https{}".format(request.url[4:]), code=301)

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Access Denied'

def random_vnc_password():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

def vr_thread_runner(vr):
    vr.do_run()

def do_render(template, data = {}):
    data['header'] = open('static/_js.html').read()
    data['internal_links'] = open('static/internal/_links.html').read()
    return pystache.render(open(template).read(), data)

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(name):
    db = get_db()
    dbuser = db.load_user(name)
    if dbuser == None:
        return

    user = User()
    user.id = dbuser['id']
    user.name = name
    user.permissions = dbuser['permissions']
    user.utype = dbuser['utype']
    return user

@login_manager.request_loader
def request_loader(request):
    uname = request.form.get('uname')
    if uname == None:
        return

    user = User()
    user.id = uname
    db = get_db()

    user.is_authenticated = db.authenticate_user(uname, request.form['password'])
    return user

########################

@app.route("/")
def root():
    render_me = {}
    return do_render('templates/index.html', render_me)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        render_me = {}
        return do_render('templates/login.html', render_me)


    db = get_db()
    uname = flask.request.form['uname']
    pw = flask.request.form['pw']
    if db.authenticate_user(uname, pw):
        user = User()
        user.id = uname
        flask_login.login_user(user)
        return flask.redirect(flask.url_for('showusers'))

    return 'Bad login'

@app.route('/notadmin', methods=['GET', 'POST'])
def notadmin():
    return 'Insufficient privileges'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if flask_login.current_user.permissions == "admin":
            return f(*args, **kwargs)
        else:
            return flask.redirect(flask.url_for('notadmin'))
    return decorated_function

@app.route('/internal/add_user', methods=['GET', 'POST'])
@flask_login.login_required
@admin_required
def add_user():
    if flask.request.method == 'GET':
        render_me = {}
        return do_render('templates/internal/add_user.html', render_me)

    db = get_db()
    uname = flask.request.form['uname']
    uname_pattern = '^[a-zA-Z0-9]+$'
    if re.match(uname_pattern , uname) == None:
        return 'Username has to be {}'.format(uname_pattern)
    pw = flask.request.form['pw']
    permissions = 'standard'
    utype = 'standard'
    added = db.add_user(uname, pw, utype, permissions)
    return 'Added User: {}'.format(added)

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return flask.redirect(flask.url_for('root'))

@app.route("/novnc_loading")
def novncload():
    return do_render('templates/novnc_loading.htm')

def get_seeds(config, program):
    try:
        tdir = "{}/{}/minified_seeds/*.seed".format(config.get('general', 'resultsdir'), program)
        rc = glob.glob(tdir)
        ret = []
        for f in rc:
            ret.append(open(f).read())
        return urllib.quote( json.dumps( list(set(ret))) , safe='~@#$&()*!+=:;,.?/\'')
    except Exception as e:
        return "[]"

def urlescape(ret):
    return urllib.quote( json.dumps( ret ) , safe='~@#$&()*!+=:;,.?/\'')

def get_interactions(config, program):
    try:
        tdir = "{}/{}/minified_seeds/*.compartment_information.json".format(config.get('general', 'resultsdir'), program)
        rc = glob.glob(tdir)
        ret = []
        for f in rc:
            m = re.match('.*minified_seeds/(.+)\.compartment_information\.json', f)
            ret.append(m.group(1))
        return urllib.quote( json.dumps( list(set(ret))) , safe='~@#$&()*!+=:;,.?/\'')
    except Exception as e:
        return "[]"

def get_afl_seeds(config, tasklet):
    tdir = '{}/{}/afl_seeds/*.output'.format(config.get('general', 'resultsdir'), tasklet['program'])
    ret = []
    try:
        for f in get_biggest_files(config, tasklet, glob.glob(tdir), 20):
            m = re.match('.*afl_seeds/(.+)\.output', f)
            ret.append(m.group(1))
        return urllib.quote( json.dumps( list(set(ret))) , safe='~@#$&()*!+=:;,.?/\'')
    except Exception as e:
        return "[]"
    return ret

@app.route("/get_results/<tid>/<assignmentid>/<workerid>/<hid>/")
def get_results(tid, assignmentid, workerid, hid):
    try:
        db = get_db()
        programname = db.get_tasklet_program(tid)
        key = HaCRSUtil.get_compositekey(tid, assignmentid, workerid, hid)

        tasklet = db.get_full_tasklet(tid)
        next_payout, next_transition, curr_payout, curr_transition = -1, -1, -1, -1

        if tasklet == None:
            return "No task found"
        if tasklet['type'] == 'SEED':
            pass
            #render_me['payout_arr'] = tasklet['payout_arr']

        config = HaCRSUtil.get_config('webconfig.ini')
        xfile = HaCRSUtil.find_result_file(config, programname, key)
        results = json.loads(open(xfile).readlines()[-1])
        next_payout, next_transition = HaCRSUtil.get_next_payout_border(tasklet['payout_arr'], results['new_transitions'])
        curr_payout = HaCRSUtil.get_current_payout(tasklet['payout_arr'], results['new_transitions'])
        results['next_payout'] = next_payout
        results['next_transition'] = next_transition
        results['curr_payout'] = curr_payout
        results['min_payout'] = tasklet['amount']
        return json.dumps(results)
    except Exception as e:
        return "{}"


@app.route('/seed_qual_tasklet/')
def qualseed( ):
    tid = '9899b378-bd30-4ae0-96fe-1d6779f419c2'
    randid = random.randint(1,100000)
    return showtid(tid, 'qual-{}'.format(randid),
                        'qual-{}'.format(randid),
                        'qual-{}'.format(randid))

@app.route('/tasklets_picker/')
@flask_login.login_required
def pick_tasklets():
    render_me = {}
    render_me['username'] = flask_login.current_user.name
    return do_render('templates/tasklets_picker.html', render_me)

# To be used for mechanical turk
@app.route('/pick_tasklet/<difficulty>/')
def pick_tasklet_mturk(difficulty):
    db = get_db()
    workerid = request.args.get("workerId", "")
    hitid = request.args.get("hitId", "")
    assignmentid = request.args.get("assignmentId", "")

    # => preview mode
    if assignmentid == "ASSIGNMENT_ID_NOT_AVAILABLE" or assignmentid == "" or len(workerid) == 0:
        return open('instructions/general.html').read()
    else:
        tid = db.get_mturk_assignment(workerid)
        # If working on something - forward there
        # Otherwise: Pick a new tasklet
        if tid == None:
            tid = db.pick_tasklet('SEED', difficulty, workerid)
            # And save that
            if tid != None:
                db.save_mturk_assignment(tid, workerid)

    if tid == None:
        return "No suitable tasklet found, please come back later!"

    return flask.redirect('/tasklet/{}/?assignmentId={}&hitId={}&workerId={}'.format(tid, assignmentid, hitid, workerid), code=302)


@app.route('/pick_tasklet/<ttype>/<difficulty>/<username>/')
@flask_login.login_required
def pick_tasklet(ttype, difficulty, username ):
    if username == None or len(username) == 0:
        return "Error"
    if flask_login.current_user.name != username:
        return "Error"
    db = get_db()
    tid = db.pick_tasklet(ttype, difficulty, "internal_".format(username))

    if tid == None:
        return "No suitable tasklet found!"

    randid = random.randint(1,100000)

    return flask.redirect('/tasklet/{}/?assignmentId={}&hitId={}&workerId={}'.format(tid, 'picked_{}'.format(randid), 'picked_{}'.format(randid), 'internal_{}'.format(username)), code=302)

@app.route('/demos/water_treatment/')
def demo_watertreatment( ):
    tid = 'b531e504-339c-40a7-8834-e2fb4bd4de2f'
    randid = random.randint(1,100000)
    return showtid(tid, 'qual-{}'.format(randid),
                        'qual-{}'.format(randid),
                        'qual-{}'.format(randid))
    
def get_printable_string(s):
    return filter(lambda x: x in string.printable, s)

def make_printable_string(s):
    return ''.join(list(map(lambda x: x if x in string.printable else ' ', s)))

def get_biggest_files(config, tasklet, files, n):
    seedfiles = {}
    for f in files:
        seedfiles[f] = os.stat(f).st_size
    seedfiles = sorted(seedfiles.items(), key=operator.itemgetter(1))
    largest_files = map(lambda x: x[0],seedfiles[-n:])
    return largest_files

@app.route('/add_note/<tid>/', methods=['GET', 'POST'])
@flask_login.login_required
def add_note(tid):
    if not 'note' in request.values:
        return
    note = request.values['note']
    if len(note) == 0:
        return
    db = get_db()
    tasklet = db.get_full_tasklet (tid)
    userid = flask_login.current_user.id
    programid = db.get_program_id(tasklet['program'])
    db.add_note(userid, programid, note)
    return ''

@app.route('/get_notes/<tid>/', methods=['GET', 'POST'])
def get_notes(tid):
    db = get_db()
    notes = db.get_notes_for_tasklet(tid)
    render_me = {}
    render_me['notes'] = notes
    return flask.jsonify({'notes': notes})

@app.route('/tasklet/<tid>/')
def showtid(tid, aid = None, hid=None, wid = None, showinput=None):


    if aid == None:
        aid = request.args.get("assignmentId", "")
    if hid == None:
        hid = request.args.get("hitId", "")
    if wid == None:
        wid = request.args.get("workerId", "")
    if showinput == None:
        showinput = request.args.get("showinput", "")

    instructions = {}
    instructions['SEED'] = 'instructions/seeding.html'

    templates = {}
    templates['SEED'] = 'templates/seedtasklet.html'

    try:
        assert len(tid) == 36
        db = get_db()
        config = HaCRSUtil.get_config('webconfig.ini')
        render_me = {}
        tasklet = db.get_full_tasklet(tid)

        if tasklet == None:
            return "No task found (or not implemented)"

        seeds = get_interactions(config, tasklet['program'])


        if not ( aid  == "" or aid == "ASSIGNMENT_ID_NOT_AVAILABLE"):
            execution_id = uuid.uuid4()

            turkerinfo = HaCRSUtil.get_compositekey(tid, aid, wid, hid)

            password = random_vnc_password()
            vr = VNCRunner(tasklet, turkerinfo, password)
            vr_thread = Thread(target = vr_thread_runner, args = (vr, ))
            vr_thread.start()

            render_me['vrport'] = vr.useport
            render_me['password'] = password

            db.log_session_start(tid, hid, wid, aid, execution_id,
                            str(request.user_agent), request.remote_addr)

        render_me['amazon_host'] =  config.get('mt', 'host')
        render_me['assignment_id'] = aid
        render_me['tasklet_id'] = tid
        render_me['hit_id'] = hid
        render_me['difficulty'] = tasklet['keywords']
        render_me['seeds'] = seeds
        render_me['tasktype'] = tasklet['type']
        render_me['programname'] = tasklet['program'].replace('_', ' ')
        render_me['programinstructions'] = get_printable_string(get_program_description(config, tasklet['program']))
        render_me['worker_id'] = wid
        render_me['taskname'] = HaCRSUtil.get_tasklet_name(tasklet)
        render_me['instructions'] = open(instructions[tasklet['type']]).read()
        render_me['showinput'] = urllib.quote(showinput)

        return do_render(templates[tasklet['type']], render_me)
    except Exception as e:
        return "Couldn't fetch task: {}".format(e)

def get_program_description(config, pname):
    ret = []
    for line in open('../descriptions/{}.desc'.format(pname)).readlines():
        ret.append("\n".join(textwrap.wrap(line)))
    ret.append("\n")
    for line in open('{}/GENERAL_NOTE'.format(config.get('general', 'descriptionsfolder'))).readlines():
        ret.append("\n".join(textwrap.wrap(line)))
    #(textwrap.wrap("".join(open('pdescriptions/{}.desc'.format(pname)).readlines())))
    return "\n".join(ret)

def read_similarities_csv(text):
    if len(text.strip()) == 0:
        return []
    return [list(map(int, l.split(','))) for l in text.strip().split('\n')]

def find_compartment(compartments, character_idx):
    for i, comp in enumerate(compartments):
        if comp['start'] <= character_idx < comp['end']:
            return comp
    return None

@app.route('/get_interaction/<programname>/<xid>')
def get_merged_interactions(programname, xid):
    config = HaCRSUtil.get_config('webconfig.ini')
    if xid.startswith('AUTO'):
        seed_dir = 'afl_seeds'
    else:
        seed_dir = 'minified_seeds'
    xdir = "{}/{}/{}".format(config.get('general', 'resultsdir'), programname.replace(' ', '_'), seed_dir)

    influence = json.loads(get_printable_string(open('{}/{}.influence.json'.format(xdir,xid) ).read()))
    output = make_printable_string(open('{}/{}.output'.format(xdir, xid)).read())
    interactions = json.loads(get_printable_string(open('{}/{}.interaction.json'.format(xdir,xid)).read()))
    print 'pulled {}/{}.interaction.json'.format(xdir, xid)

    #character_similarities = read_similarities_csv(open('{}/{}.character_similarities.csv'.format(xdir,xid)).read())
    compartments = json.loads(get_printable_string(open('{}/{}.compartment_information.json'.format(xdir, xid)).read()))
    print 'pulled {}/{}.compartment_information.json'.format(xdir, xid)

    in_out_merge = {}
    try:
        for interaction in interactions:
            if interaction['type'] == 'write':
                for offset in interaction['offsets']:
                    in_out_merge[str(len(in_out_merge))]={'value': output[offset], 'type': 'input'}
            elif interaction['type'] == 'read':
                for offset in interaction['offsets']:
                    in_out_merge[str(len(in_out_merge))]={'value': influence[str(offset)]['value'] ,
                                                          'reachable_strings': influence[str(offset)]['reachable_strings'] ,
                                                          'other_options': influence[str(offset)]['other_options'] ,
                                                          #'similarities': character_similarities[offset],
                                                          'compartment': find_compartment(compartments, offset),
                                                          'type': 'output'}
            else:
                sys.stderr.write('?\n')
    except Exception as e:
        import traceback
        #print offset, len(output)
        traceback.print_exc()
        raise

    print 'dumping in_out_merge json'
    return json.dumps(in_out_merge)

def flatten_tasklets(tasklets):
    rt = []
    for t in tasklets:
        rt.append(t)
        rt[-1]['id'] = str(rt[-1]['id'])
        rt[-1]['timestamp'] = 'asdf'
    return rt

# for internal use only
@app.route('/internal/tasklets')
@flask_login.login_required
@admin_required
def showseedtasklets( ):
    db = get_db()
    tasklets = db.get_tasklets( )
    render_me = {}
    render_me['tasklets'] = urlescape( flatten_tasklets (tasklets))
    return do_render('templates/internal/tasklets.html', render_me)

@app.route('/internal/tasklet/<tid>')
@flask_login.login_required
@admin_required
def showinternaltasklet(tid):
    db = get_db()
    try:
        tasklet = db.get_full_tasklet (tid)
    except Exception as e:
        return 'Tasklet not found'

    render_me = {}
    if tasklet == None:
        return 'Tasklet not found'
    tasklet['id'] = str(tasklet['id'])
    render_me['tasklet'] = urlescape( tasklet )
    render_me['username'] = flask_login.current_user.name
    return do_render('templates/internal/tasklet.html', render_me)

@app.route('/internal/coverage_stats')
@flask_login.login_required
@admin_required
def showcoveragestats( ):
    db = get_db()
    coverage = db.get_coverage_stats()
    coverage['timestamp'] = str(coverage['timestamp'])
    coverage['coverage'] = json.loads((coverage['coverage']))
    render_me = {}
    render_me['coverage'] = urlescape(coverage)
    return do_render('templates/internal/coverage_stats.html', render_me)

@app.route('/internal/users')
@flask_login.login_required
@admin_required
def showusers( ):
    db = get_db()
    users = db.show_all_users()
    render_me = {}
    render_me['users'] = urlescape(users)
    return do_render('templates/internal/all_users.html', render_me)

@app.route('/internal/user/<uid>')
@flask_login.login_required
@admin_required
def showuser(uid ):
    db = get_db()
    username = db.get_username(uid)
    attempts = db.get_solving_history('internal_{}'.format(username))
    render_me = {}
    render_me['attempts'] = urlescape(attempts)
    pprint(attempts)
    return do_render('templates/internal/user.html', render_me)

@app.route('/internal/turker_infos')
@flask_login.login_required
@admin_required
def turkerinfos( ):
    db = get_db()
    render_me = {}
    tinfos = db.get_all_mturk_infos()
    render_me['turkinfos'] = urlescape(tinfos)

    return do_render('templates/internal/turker_infos.html', render_me)

@app.route('/internal/calculate_coverage', methods=['POST', 'GET'])
def calculatecoverage( ):
    db = get_db()
    tr = TurkerResults()
    taskid_earnings, prog_maxcoverage, seed_taskletid_solved= tr.get_solve_ratio()
    db.set_coverage_stats(prog_maxcoverage)
    return repr(json.dumps(prog_maxcoverage))

@app.route('/update_tasklet_status/', methods=['POST'])
def update_tasklet_status( ):
    db = get_db()
    tid = request.form['tid']
    workerid = request.form['worker_id']
    status = request.form['setstatus']
    if not status in ['ABORT', 'COMPLETE']:
        return "FAIL"
    db.update_mturk_assignment(tid, workerid, status)
    return "OK"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def xcatchall(path=None):
    return "{} ?\n".format(path)



if __name__ == "__main__":
    app.run(port=8383, debug=True)

