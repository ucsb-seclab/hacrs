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
import json
import copy
import pdb
import sys
import os
from HaCRSUtil import HaCRSUtil
from HaCRSDB import HaCRSDB
from HaCRSTurker import HaCRSTurker


# Cutoff for old tasklets / hits
EXPERIMENT_START = '2017-05-'

class TurkerResults:


    # TODO: this should be moved to DB 
    def get_tasklet_from_hit(self, hitid):
        self.cur.execute("""
        select task_id 
        from tasklet_session_log 
        where assignment_id not like 'picked_%%' and 
        worker_id not like 'internal_%%' 
        and hit_id = %s; """,[hitid])
        return self.cur.fetchall()

    def get_tasklet_kw(self, tid):
        self.cur.execute("""
        select keywords
        from tasklets
        where tasklets.id = %s
        """, [tid])
        return self.cur.fetchone()[0]

    def __init__(self):
        self.config = HaCRSUtil.get_config('../config.ini')
        HOST = self.config.get('mturk','host')
        AWS_ACCESS_KEY_ID = self.config.get('mturk', 'access_key_id')
        AWS_SECRET_ACCESS_KEY = self.config.get('mturk', 'secret_access_key')
        self.MTconnection = MTurkConnection(aws_access_key_id=AWS_ACCESS_KEY_ID,
             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
             host=HOST)
        self.db = HaCRSDB()
        self.con, self.cur = HaCRSUtil.get_db(self.config)
        self.mt = HaCRSTurker()

    def assignment_payout(self, assignments, amount):
        paysum = 0
        for assignment in assignments:
            if assignment.AssignmentStatus == 'Approved':
                paysum += amount
            else:
                pdb.set_trace()
                pass
        return paysum

    def get_paid_bonus(self, bonuses, assignmentid, workerid):
        for bonus in bonuses:
            if bonus['aid'] == assignmentid and bonus['wid'] == workerid :
                return bonus['price']
        return 0

    def get_all_hits(self):
        all_hits = [hit for hit in self.MTconnection.get_all_hits()]
        totassignments = 0
        maxtotalspent = 0
        for hit in all_hits:
            assignments = self.MTconnection.get_assignments(hit.HITId)
            assignmentpay = self.assignment_payout(assignments, float(hit.Amount))
            maxtotalspent += assignmentpay
            print "{} - {} - {} - Expired: {} Keywords: {} #Assignments: {}".format(hit.CreationTime, hit.HITStatus, hit.HITReviewStatus, hit.expired, hit.Keywords, len(assignments))
            totassignments += len(assignments)
        print ''
        print "Total: #HIT: {}, #Assignments: {} TotalMaxSpent: {}".format(len(all_hits), totassignments, maxtotalspent)

    def log_worker(self, worker_base, worker_bonus, worker_solves, difficulty_solves, assignment, bonuses, hit):
        wid = assignment.WorkerId
        if wid not in worker_base.keys():
            worker_base[wid] = 0.0
            worker_solves[wid] = {}
        wbonus = self.get_paid_bonus(bonuses, assignment.AssignmentId, wid)
        worker_base[wid] += float(hit.Amount)

        if wbonus > 0:
            if wid not in worker_bonus.keys():
                worker_bonus[wid] = 0.0
            worker_bonus[wid] += wbonus
        if hit.Keywords not in worker_solves[wid].keys():
            worker_solves[wid][hit.Keywords] = 0
        worker_solves[wid][hit.Keywords] += 1

        if hit.Keywords not in difficulty_solves.keys():
            difficulty_solves[hit.Keywords] = 0
        difficulty_solves[hit.Keywords] += 1

    def get_all_spendings_by_worker(self):
        all_hits = [hit for hit in self.MTconnection.get_all_hits()]
        maxtotalspent = 0
        bonuses = json.load(open('bonus_paid.json'))
        worker_base = {}
        worker_bonus = {}
        worker_solves = {}
        difficulty_solves = {}
        for hit in all_hits:
            assignments = self.MTconnection.get_assignments(hit.HITId)
            for assignment in assignments:
                if assignment.AssignmentStatus == 'Approved':
                    self.log_worker(worker_base, worker_bonus, worker_solves, difficulty_solves, assignment, bonuses, hit)
        print "Worker Base:"
        print json.dumps(worker_base, sort_keys=True, indent=4, separators=(',', ': ') )
        print "Worker Bonus:"
        print json.dumps(worker_bonus, sort_keys=True, indent=4, separators=(',', ': ') )
        print "Worker Solves:"
        print json.dumps(worker_solves, sort_keys=True, indent=4, separators=(',', ': ') )
        print "By Difficulty:"
        print json.dumps(difficulty_solves, sort_keys=True, indent=4, separators=(',', ': ') )
        return



    def test_seek_tasklet(self, tid, program ):
        fseek = '{}/{}/{}-seek.json'.format(self.config.get('general', 'resultsfolder'), program, tid)
        if os.path.exists(fseek):
            return json.load(open(fseek))['triggered']
        else:
            return None

    def approve_reject(self, taskid_earnings):
        global EXPERIMENT_START
        all_hits = [hit for hit in self.MTconnection.get_all_hits()]
        worker_solvecount = {}
        worker_solvedifficulty = {}
        solved = 0

        tasklet_hit_done = set()
        empty = { 'easy': 0, 'medium': 0, 'hard': 0, 'very_hard': 0, 'priority': 0 }

        for hit in all_hits:
            if not hit.CreationTime.startswith(EXPERIMENT_START):
                print 'old hit!'
                continue
            if hit.NumberOfAssignmentsCompleted == 0:
                continue
            tasklet_ids = self.get_tasklet_from_hit(hit.HITId)
            if len(tasklet_ids) == 0:
                continue

            for line in tasklet_ids:
                tid = str(line[0])
                tasklet = self.db.get_full_tasklet(tid)
                assignments = self.MTconnection.get_assignments(hit.HITId)
                for assignment in assignments:

                    if assignment.WorkerId not in worker_solvecount.keys():
                        worker_solvecount[assignment.WorkerId] = 0
                        worker_solvedifficulty[assignment.WorkerId] = copy.deepcopy(empty)

                    if tasklet['type'] != 'SEED':
                        assert False, 'Wrong tasklet type!'

                    #print 'hit: {} {}'.format(hit.HITStatus, hit.HITReviewStatus)
                    if assignment.AssignmentStatus == 'Approved':
                        tkey = "{}/{}/{}".format(hit.HITId, assignment.AssignmentId, assignment.WorkerId)
                        if not tkey in tasklet_hit_done:
                            worker_solvedifficulty[assignment.WorkerId][tasklet['keywords']] += 1
                            tasklet_hit_done.add(tkey)
                            print 'Approved: {}'.format(tkey)

                    if hit.HITReviewStatus == 'NotReviewed':
                        if not assignment.AssignmentStatus == 'Submitted':
                            solved += 1
                            continue

                        try:
                            money = taskid_earnings[tid][assignment.WorkerId]
                        except Exception as e:
                            print '{} error'.format(tasklet['type'])
                            continue

                        if money['payout'] < money['amount']:
                            print 'Possible reject: {}'.format(money['payout'])
                            # TODO - uncomment this to actually reject a task
                            #self.MTconnection.reject_assignment(assignment.AssignmentId)
                        if money['payout'] >= money['amount']:
                            self.MTconnection.approve_assignment(assignment.AssignmentId, feedback = "Thanks for participating, more similar tasks coming soon")
                            pass
                    else:
                        print 'else: {}'.format(hit.HITReviewStatus)


                    worker_solvecount[assignment.WorkerId]+= float(hit.Amount)
        pprint (sorted(worker_solvecount.items(), key=operator.itemgetter(1)))
        print "worker_solvecount"
        print json.dumps(worker_solvecount, sort_keys=True, indent=4, separators=(',', ': ') )
        print "worker_solvedifficulty"
        print json.dumps(worker_solvedifficulty, sort_keys=True, indent=4, separators=(',', ': ') )
        print "Solved: {}, total payout: {}".format(solved, sum(worker_solvecount.values()))

    def split_composite_key(self, k):
        # "{}-{}-{}-{}".format(taskid, hitid, assignmentid, workerid)
        tid = k[:36]
        hitid, aid, workerid = k[37:].split('-')
        assert len(hitid) == 30
        assert len(aid) == 30
        assert len(workerid) in [11, 12, 13, 14]
        return {'tid': tid, 'hitid': hitid, 'aid': aid, 'workerid': workerid}

    def get_seed_stats(self, seed_taskletid_solved):
        global EXPERIMENT_START

        unique_seed_workers = set()
        worker_payouts_base = {}
        worker_payouts_bonus = {}
        worker_payouts_combined = {}
        worker_solves = {}
        tasklet_solved = set()

        total_payout_base = 0
        total_payout_bonus = 0

        tasklet_difficulty = {}

        program_solves = {}

        for program in json.load(open(self.config.get('general', 'programsjson'))):
            prog_maxcoverage[program] = 0
            if program not in program_solves:
                program_solves[program] = 0
        program = None

        total_payout = 0

        for tasklet in self.db.get_seed_tasklets():

            if not str(tasklet['timestamp']).startswith(EXPERIMENT_START):
                continue

            if tasklet['program'] in ['seed_training', 'A_Game_of_Chance']:
                continue

            if tasklet['id'] in seed_taskletid_solved.keys():
                program_solves[tasklet['program']] += 1

            for jfile in glob.glob('{}/{}/{}*/*.json'.format(self.config.get('general', 'resultsfolder'), tasklet['program'], str(tasklet['id']))):
                try:
                    metadata = self.split_composite_key(jfile.split(os.path.sep)[jfile.split(os.path.sep).index('result.json')-1])

                # fake keys
                except Exception as e:
                    continue
                # that's us
                if metadata['workerid'] == 'A2PRAI0ABXN99X':
                    continue

                results = json.loads(open(jfile).readlines()[-1])
                tasklet = self.db.get_full_tasklet(metadata['tid'])

                payout = HaCRSUtil.get_current_payout(tasklet['payout_arr'], results['new_transitions'])
                prog_maxcoverage[tasklet['program']] = max(prog_maxcoverage[tasklet['program']], results['coverage'])
                if payout > 0:
                    if metadata['workerid'] not in worker_solves.keys():
                        worker_solves[metadata['workerid']] = 0
                    worker_solves[metadata['workerid']] += 1
                    unique_seed_workers.add(metadata['workerid'])
                    if tasklet['keywords'] not in tasklet_difficulty:
                        tasklet_difficulty[tasklet['keywords']] = 0
                    tasklet_difficulty[tasklet['keywords']] += 1
                    tasklet_solved.add(tasklet['id'])
                    if metadata['workerid'] not in worker_payouts_base.keys():
                        worker_payouts_base[metadata['workerid']] = []
                        worker_payouts_bonus[metadata['workerid']] = []
                        worker_payouts_combined[metadata['workerid']] = []
                    worker_payouts_base[metadata['workerid']].append(tasklet['amount'])
                    total_payout_base += tasklet['amount']
                    if payout > tasklet['amount']:
                        total_payout_bonus += round(payout - tasklet['amount'], 2)
                        worker_payouts_bonus[metadata['workerid']].append(round(payout - tasklet['amount'], 2))
                        total_payout_bonus += round(payout - tasklet['amount'], 2)
                    worker_payouts_combined[metadata['workerid']].append(round(payout, 2))
                total_payout += payout

                pass

        print 'Total seed BASE payment: $ {}'.format(total_payout_base)
        print 'Total seed BONUS payment: $ {}'.format(total_payout_bonus)
        print 'Workers solving at least one SEED Task: {}'.format(len(unique_seed_workers))
        print 'Number of solved SEED tasks: {}'.format(len(tasklet_solved))
        print 'Number of tasklets by difficulty: {}'.format(tasklet_difficulty)
        print 'Busiest worker: {} solves'.format(max(worker_solves.values()))
        print 'Average worker throughput: {} solves'.format(round(sum(worker_solves.values())  / float(len(worker_solves.values())), 2))
        pdb.set_trace()

    def get_solve_ratio(self):
        global EXPERIMENT_START
        prog_maxcoverage = {}
        taskid_earnings = {}
        total_payout_with_bonus = 0

        goalreached = 0
        goalnotreached = 0
        for program in json.load(open(self.config.get('general', 'programsjson'))):
            prog_maxcoverage[program] = 0
        program = None

        seed_taskletid_solved = {}
        empty = { 'easy': 0, 'medium': 0, 'hard': 0, 'very_hard': 0, 'priority': 0 }

        for tasklet in self.db.get_seed_tasklets() + self.db.get_seek_tasklets():
            if not str(tasklet['timestamp']).startswith(EXPERIMENT_START):
                continue

            for jfile in glob.glob('{}/{}/{}*/*.json'.format(self.config.get('general', 'resultsfolder'), tasklet['program'], str(tasklet['id']))):
                try:
                    metadata = self.split_composite_key(jfile.split(os.path.sep)[jfile.split(os.path.sep).index('result.json')-1])
                # fake keys
                except Exception as e:
                    print e
                    continue
                # that's us
                if metadata['workerid'] == 'A2PRAI0ABXN99X':
                    continue
                results = json.loads(open(jfile).readlines()[-1])
                tasklet = self.db.get_full_tasklet(metadata['tid'])

                if tasklet == None:
                    print "No tasklet for program {}".format(tasklet['program'])
                    continue

                if tasklet['type'] == 'SEED':
                    payout = HaCRSUtil.get_current_payout(tasklet['payout_arr'], results['new_transitions'])
                    prog_maxcoverage[tasklet['program']] = max(prog_maxcoverage[tasklet['program']], results['coverage'])

                elif tasklet['type'] == 'SEEK':
                    payout = tasklet['amount']
                elif tasklet['type'] == 'DRILL':
                    payout = tasklet['amount']

                total_payout_with_bonus += payout

                # over-achieved
                if tasklet['amount'] <= payout:
                    goalreached += 1
                elif tasklet['amount'] > payout:
                    goalnotreached += 1

                if tasklet['amount'] <= payout and tasklet['type'] == 'SEED':
                    hitinfos = self.db.get_hit_for_tasklet(tasklet['id'])
                    for hit in hitinfos:
                        assignment = self.mt.get_assignment_from_hit(hit)
                        if assignment and assignment.WorkerId in ['A10O5YR01H865K', 'A1HRHFU7KTS0KW', 'A1PUHCEBSOWETV']:
                            pass
                        seed_taskletid_solved[tasklet['id']] = True

                if metadata['tid'] not in taskid_earnings.keys():
                    taskid_earnings[metadata['tid']] = {}
                if metadata['workerid'] not in taskid_earnings[metadata['tid']].keys():
                    taskid_earnings[metadata['tid']][metadata['workerid']] = {}

                taskid_earnings[metadata['tid']][metadata['workerid']] = {'payout': payout, 'amount': tasklet['amount']}
        print "Goal reached: {}, Goal not reached: {}". format(goalreached, goalnotreached)
        print "taskid_earnings"
        pprint(taskid_earnings)

        return taskid_earnings, prog_maxcoverage, seed_taskletid_solved

    def log_bonus(self, tid, wid, aid, price):
        self.bonuses.append({'tid': tid, 'wid': wid, 'aid': aid, 'price': price})
        json.dump(self.bonuses, open('bonus_paid.json', 'w'), sort_keys=True, indent=4, separators=(',', ': ') )

    def do_pay_bonus(self, tid, wid, aid, price):
        assert len(tid) > 5, 'tasklet id mismatch'
        reason = "We issued a bonus for reaching a stretch goal of our task - Thanks!"
        assert price < 5
        self.log_bonus(tid, wid, aid, price)
        try:
            self.MTconnection.grant_bonus(wid, aid, Price(price), reason)
            return True
        except Exception as e:
            print "Not issued for whatever reason: {}".format(e)
            return False

    def bonus_paid_before(self, tid, wid, aid):
        for bonus in self.bonuses:
            if bonus['tid'] == tid and bonus['aid'] == aid and bonus['wid'] == wid:
                return True
        return False

    def check_bonus(self, taskid_earnings):
        self.bonuses = json.load(open('bonus_paid.json'))
        total_bonus_issued = 0
        worker_bonus = {}

        for program in json.load(open(self.config.get('general', 'programsjson'))):
            for jfile in glob.glob('{}/{}/*/result.json'.format(self.config.get('general', 'resultsfolder'), program)):
                try:
                    xkey = jfile.split(os.path.sep)[jfile.split(os.path.sep).index('result.json')-1]
                    if xkey.endswith('-OLD') or xkey.endswith('-internal_zardus'):
                        continue
                    metadata = self.split_composite_key(xkey)
                except Exception as e:
                    #pdb.set_trace()
                    print 'Skipping {}'.format(e)
                    continue
                if metadata['workerid'] == 'A2PRAI0ABXN99X':
                    continue
                results = json.loads(open(jfile).readlines()[-1])
                tasklet = self.db.get_full_tasklet(metadata['tid'])
                try:
                    money = taskid_earnings[str(tasklet['id'])][metadata['workerid']]
                except Exception as e:
                    continue

                if tasklet['type'] != 'SEED':
                    print "We only pay a bonus for SEEDing"
                    continue

                if money['payout'] > money['amount']:
                    bonus = round(money['payout'] - money['amount'], 2)
                    if metadata['workerid'] not in worker_bonus:
                        worker_bonus[metadata['workerid']] = 0
                    worker_bonus[metadata['workerid']] += round( worker_bonus[metadata['workerid']] + bonus, 2)


                    if self.bonus_paid_before(str(tasklet['id']), metadata['workerid'], metadata['aid']):
                        print 'paid before - skip'
                    else:
                        print 'Bonus payout: {}'.format(bonus)
                        # TODO...
                        #if self.do_pay_bonus(str(tasklet['id']), metadata['workerid'], metadata['aid'], bonus):
                        #    total_bonus_issued += bonus
        print 'worker_bonus'
        print json.dumps(worker_bonus, sort_keys=True, indent=4, separators=(',', ': ') )
        print "Issued {} in bonuses".format(total_bonus_issued)

    def show_medium_hard(self, taskid_earnings):
        for tasklet in taskid_earnings:
            #tasklet = self.db.get_full_tasklet(tasklet)
            kw = self.get_tasklet_kw(tasklet)
            kwkey = ['easy', 'medium', 'hard', 'very_hard', 'priority'].index(kw)
            if len(filter(lambda x: x['payout'] >= x['amount'], taskid_earnings[tasklet].values())) > 0:
                pass
            print '{} [{}] {}: {}'.format(self.db.get_tasklet_program(tasklet), kwkey, kw, tasklet)
        sys.exit(1)

    def approve_single(self, hitid):
        xhit = self.MTconnection.get_hit(hitid)
        assignments = self.MTconnection.get_assignments(xhit[0].HITId)
        print 'Verify data before proceeding'
        pdb.set_trace()
        rc = self.MTconnection.approve_rejected_assignment(assignments[0].AssignmentId, feedback = "Thanks for participating, more similar tasks coming soon")


    def trace_hit(self, hitid):
        xhit = self.MTconnection.get_hit(hitid)
        pdb.set_trace()
        pass

def issue_single():
    tr = TurkerResults()
    tr.bonuses = json.load(open('bonus_paid.json'))
    tid = ''
    wid = ''
    aid = ''
    tr.do_pay_bonus(tid, wid, aid, 4)
    sys.exit(1)

if __name__ == "__main__":
    tr = TurkerResults()
    if len(sys.argv) == 1:
        sys.exit(1)

    if sys.argv[1] in [ 'payout-base', 'payout-bonus', 'medhard', 'stats', 'seedstats']:
        taskid_earnings, prog_maxcoverage, seed_taskletid_solved= tr.get_solve_ratio()
        if sys.argv[1] == 'payout-base':
            tr.approve_reject(taskid_earnings)
        elif sys.argv[1] == 'payout-bonus':
            tr.check_bonus(taskid_earnings)
        elif sys.argv[1] == 'medhard':
            tr.show_medium_hard(taskid_earnings)
        elif sys.argv[1] == 'stats':
            pprint (sorted(prog_maxcoverage.items(), key=operator.itemgetter(1)))
            print "Average Coverage: {}".format(sum(prog_maxcoverage.values()) / float(len(prog_maxcoverage.keys())))
        elif sys.argv[1] == 'seedstats':
            pprint(tr.get_seed_stats(seed_taskletid_solved))
    elif sys.argv[1] == 'showhit':
        tr.trace_hit(sys.argv[2])
    elif sys.argv[1] == 'showall':
        tr.get_all_hits()
    elif sys.argv[1] == 'approvesingle':
        tr.approve_single(sys.argv[2])
    elif sys.argv[1] == 'expireall':
        tr.mt.expire_all_hits()
    elif sys.argv[1] == 'workerstats':
        tr.get_all_spendings_by_worker()


