
import ConfigParser
import subprocess
import psycopg2
import glob
import pdb
import sys
import re
import os


class HaCRSUtil:

    @staticmethod
    def is_tasklet_type(typ):
        return typ in ['SEED']

    @staticmethod
    def get_config(conffile = 'config.ini'):
        try:
            config = ConfigParser.ConfigParser()
            config.readfp(open(conffile))
        except Exception as e:
            sys.stderr.write("Couldn't read config ({}): {}\n".format(conffile, e)) 
            sys.exit(1)
        assert config.get('general', 'runtype') in ['test', 'prod'], "Wrong runtype"
        return config

    @staticmethod
    def get_db(config):

        conn = psycopg2.connect ( user = config.get('db', 'username'),
            password = config.get('db', 'password'),
            host = config.get('db', 'host'),
            database = config.get('db', 'dbname'),
            port = config.get('db', 'port') )

        cur = conn.cursor()
        return conn, cur

    @staticmethod
    def get_nicer_program_name(pn):
        return pn.replace('_', ' ')

    @staticmethod
    def get_tasklet_name(tasklet):
        #pdb.set_trace()
        generic = "CRS Human Assistance"
        typedescr = {'SEED' : "Seeding"}
        return "{} - {} Task - {}".format(generic, 
                            typedescr[tasklet['type']], 
                            HaCRSUtil.get_nicer_program_name(tasklet['program']))

    @staticmethod
    def get_compositekey(taskid, assignmentid, workerid, hitid):
        k = "{}-{}-{}-{}".format(taskid, hitid, assignmentid, workerid)
        assert re.match('[a-z0-9-]',k) != None
        return k

    @staticmethod
    def find_result_file(config, program, key):
        tdir = "{}/{}/{}/*.json".format(config.get('general', 'resultsdir'), program, key)
        rc = sorted(glob.glob(tdir), key=os.path.getctime)
        if len(rc) == 0:
            return None
        else:
            return rc[-1]

    @staticmethod
    def get_bitmap(config, pname, tid):
        args = ['docker', 'run', '-it', '--rm', '-v', '/home/mturk/results:/home/angr/results', 'hal', 'update-bitmap', 'bins/{0}'.format(pname), 'empty_bitmap', '-d', 'default_seeds', 'results/{0}/all_seeds'.format(pname), '-o', 'results/{0}/{1}.bitmap'.format(pname, tid), '-r', 'results/{0}/{1}.json'.format(pname, tid)]
        px = subprocess.Popen(args, stdout = subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = px.communicate()
        if px.returncode != 0:
            sys.stderr.write("Error creating bitmap {} {}\n".format(pname, tid))
            sys.exit(1)
        return {
            'tcoverageinfo': '{0}/{1}/{2}.json'.format(config.get('docker', 'resultsdir'), pname, tid),
            'bitmap': '{0}/{1}/{2}.bitmap'.format(config.get('docker', 'resultsdir'), pname, tid)
            }

    @staticmethod
    def get_program_names_from_disk(config):
        tdir = "{}/*.desc".format(config.get('general', 'descriptiondir'))
        retfiles = []
        for f in glob.glob(tdir):
            retfiles.append(os.path.basename(f)[:-5])
        return retfiles

    class CoveredError(Exception): pass

    @staticmethod
    def hit_info(missing_transitions, total_transitions):
        coverage = 1 - float(missing_transitions) / float(total_transitions)
        if coverage < 0.2:
            rating = 'easy'
            base_pay = 100
        elif coverage < 0.4:
            rating = 'medium'
            base_pay = 115
        elif coverage < 0.6:
            rating = 'hard'
            base_pay = 130
        elif coverage <= 0.85:
            rating = 'very_hard'
            base_pay = 145
        else:
            raise CoveredError("Coverage already high enough.")
            
        base_goal = missing_transitions / 10
        payout_thresholds = {
            float(base_pay+5*i)/100: int(float(10+5*i)/100 * missing_transitions)
            for i in range(0, 19)
        }
        return rating, base_pay, payout_thresholds

    @staticmethod
    def get_payout_amount(xarr):
        # hash payout => transitions
        minpayout = min(xarr.keys())
        goaltransitions =xarr[minpayout]
        return minpayout, goaltransitions

    @staticmethod
    def get_next_payout_border(payout_arr, currtransition):
        res = sorted(filter(lambda x: x[1] > currtransition, payout_arr.items()))
        if res == None:
            # all set ! 
            return None
        # next_payment, next_#functions
        return res[0][0], res[0][1]

    @staticmethod
    def get_current_payout(payout_arr, currtransition):
        res = sorted(filter(lambda x: x[1] <= currtransition, payout_arr.items()))
        if res == None or len(res) == 0:
            # Payment extrapolated from minimum payout towards 0 transitions
            # This is not used anywhere
            # subpay = float(min(payout_arr.keys()))/float(min(payout_arr.values()))
            return 0
        return res[-1][0]

