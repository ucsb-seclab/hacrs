from boto.mturk.connection import MTurkConnection
from boto.mturk.question import ExternalQuestion
from boto.mturk.price import Price
from pprint import pprint
import psycopg2
import boto3
import json
import pdb
import sys
import os
from HaCRSUtil import HaCRSUtil
from HaCRSDB import HaCRSDB

class HaCRSTurker:

    def __init__(self):
        self.config = HaCRSUtil.get_config('../config.ini')
        HOST = self.config.get('mturk','host')

        AWS_ACCESS_KEY_ID = self.config.get('mturk', 'access_key_id')
        AWS_SECRET_ACCESS_KEY = self.config.get('mturk', 'secret_access_key')

        self.MTconnection = MTurkConnection(aws_access_key_id=AWS_ACCESS_KEY_ID,
             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
             host=HOST)

        self.db = HaCRSDB()

    def get_balance(self):
        print self.MTconnection.get_account_balance()

    def expire_all_hits(self):
        all_hits = self.MTconnection.get_all_hits()
        for hit in all_hits:
            if hit.expired:
                continue
            try:
                self.MTconnection.expire_hit(hit.HITId)
                print 'Expired HIT'
            except Exception as e:
                print 'Could not expire: {}'.format(e)

    def delete_all_mturk_hits(self):
        all_hits = self.MTconnection.get_all_hits()
        for hit in all_hits:
            print 'expire/dispose'
            self.MTconnection.expire_hit(hit.HITId)
            self.MTconnection.dispose_hit(hit.HITId)

    def get_all_mturk_hits(self):
        all_hits = self.MTconnection.get_all_hits()
        return all_hits

    # TODO: HITs available via API, but not via Amazon Web Sandbox
    def push_tasklet_mturk(self, keywords):

        sdescription = self.config.get('mturk', 'shortdescr')
        frame_height = self.config.get('mturk', 'frameheight')
        #url = "https://cgcturk.hacked.jp/tasklet/{}/".format(tasklet['id'])
        url = "https://cgcturk.hacked.jp/pick_tasklet/{}/".format(keywords)
        #keywords = tasklet['keywords']
        #amount = tasklet['amount']
        if keywords == 'easy':
            amount = 1.00
        elif keywords in ['medium', 'hard', 'very_hard']:
            amount = 2.00
        elif keywords == 'priority':
            amount = 4.00
        else:
            print 'Error'
            sys.exit(1)

        questionform = ExternalQuestion(url, frame_height)


        
        title= 'HELP AN AI!!! We are students building an artificial intelligence to find bugs in programs to keep the internet safe'
        sdescription= 'We are students building an artificial intelligence system that finds bugs in programs and keeps the internet safe from malware. BUT IT NEEDS YOUR HELP! Play with programs to find functions that it missed, and get $$$!'

        hit_result = self.MTconnection.create_hit(
            title='[{}] {}'.format(keywords, title),
            description=sdescription,
            keywords=keywords,
            max_assignments=1,
            question=questionform,
            reward=Price(amount=amount),
            response_groups=('Minimal', 'HITDetail'),  # ?
        )
        assert len(hit_result) == 1
        mturkid = self.db.create_mturk_resource(hit_result[0].HITId, hit_result[0].HITGroupId)
        #self.db.add_mturk_tasklet_association(tasklet['id'], mturkid)
        #self.db.commit()
        return mturkid, hit_result


    def push_tasks_mturk(self):
        frame_height = self.config.get('mturk', 'frameheight')
        amount = 0.01
        tasklets = self.db.get_unassigned_tasklets()
        sdescription = self.config.get('mturk', 'shortdescr')

        for tasklet in tasklets:
            print 'pushing!'

            url = "https://cgcturk.hacked.jp/tasklet/{}/".format(tasklet['id'])
            keywords = ["easy"]
            questionform = ExternalQuestion(url, frame_height)

            hit_result = self.MTconnection.create_hit(
                title=HaCRSUtil.get_tasklet_name(tasklet),
                description=sdescription,
                keywords=keywords,
                max_assignments=1,
                question=questionform,
                reward=Price(amount=amount),
                response_groups=('Minimal', 'HITDetail'),  # ?
            )
            assert len(hit_result) == 1
            mturkid = self.db.create_mturk_resource(hit_result[0].HITId, hit_result[0].HITGroupId)
            self.db.add_mturk_tasklet_association(tasklet['id'], mturkid)
        self.db.commit()

    def show_seed_tasklets(self):
        pprint ( self.db.get_seed_tasklets() )


    def get_hit(self, hitid):
        try:
            hit = self.MTconnection.get_hit(hitid)
        except Exception as e:
            return None
        if hit != None:
            return hit[0]

    def get_assignment_from_hit(self, hitid):
        try:
            assignments = self.MTconnection.get_assignments(hitid)
            return assignments[0]
        except Exception as e:
            return None




    def get_approved_seeding_tasklets(self):

        for program in json.load(open(self.config.get('general', 'programsjson'))):
            pid = self.db.lookup_program(program)
        program = None

        approved = set()
        for tasklet in self.db.get_latest_seed_tasklets():
            turkinfos = self.db.get_mturk_infos(tasklet['id'])
            try:
                #hit = self.MTconnection.get_hit(turkinfos['hitid'])
                assignments = self.MTconnection.get_assignments(turkinfos['hitid'])
                if len(assignments) == 0:
                    continue
                if assignments[0].AssignmentStatus == 'Approved':
                    approved.add(self.db.get_tasklet_program(tasklet['id']))
            except Exception as e:
                #print e
                pass
        return list(approved)


def testing():
    mt = HaCRSTurker()

    mt.get_balance()

    mt.delete_all_mturk_hits()

    p1json = json.load(open('testdata/program1.json'))
    p1id = mt.db.lookup_program(p1json['name'])
    if not p1id:
        p1id = mt.db.create_program(p1json['name'])

    p2json = json.load(open('testdata/program2.json'))
    p2id = mt.db.lookup_program(p2json['name'])
    if not p2id:
        p2id = mt.db.create_program(p2json['name'])

    payment_arr = {"1.25": 739, "1.0": 211, "1.45": 1161, "1.35": 950, "1.1": 422, "1.6": 1478, "1.3": 844, "1.8": 1900, "1.2": 633, "1.55": 1372, "1.9": 2112, "1.05": 316, "1.7": 1689, "1.4": 1056, "1.15": 528, "1.65": 1584, "1.85": 2006, "1.75": 1795, "1.5": 1267}

    mt.db.create_seed_tasklet(p1id, 1, payment_arr, 'easy')
    mt.db.create_seed_tasklet(p2id, 1, payment_arr, 'medium')

    mt.show_seed_tasklets()
    mt.push_tasks_mturk()

if __name__ == "__main__":
    pass
    #testing()
    #mt = HaCRSTurker()
    #mt.get_approved_seeding_tasklets()

