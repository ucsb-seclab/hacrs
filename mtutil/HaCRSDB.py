from pprint import pprint
import psycopg2
import psycopg2.extras
import json
import pdb
import sys
import os
from HaCRSUtil import HaCRSUtil
import random
import hashlib
import binascii



class HaCRSDB:

    def __init__(self):
        self.config = HaCRSUtil.get_config('../config.ini')
        HOST = self.config.get('mturk','host')
        self.con, self.cur = HaCRSUtil.get_db(self.config)
        psycopg2.extras.register_uuid()

    def close(self):
        self.con.close()

    def commit(self):
        self.con.commit()

    
    # decodes array which has floats as strings for keys
    @staticmethod
    def fix_payout_arr(jloaded):
        loaded = json.loads(jloaded)
        assert len(loaded.keys()) == len(set(loaded.keys()))
        ret = {}
        for k in loaded.keys():
            ret[float(k)] = loaded[k]
        return ret 


    def get_unassigned_tasklets(self):

        self.cur.execute("""select tasklets.id, type, programs.name, tasklets.amount, count(tasklet_ref)
                          from tasklets left outer join programs on (tasklets.program = programs.id)
                                left outer join mturk_assoc on (tasklets.id = tasklet_ref)
                          group by 1, 2, 3, 4
                          having count(tasklet_ref) = 0
                          """)
        ret = []
        for line in self.cur.fetchall():
            ret.append( { 'id': line[0],
                          'type': line[1],
                          'program': line[2],
                          'amount': float(line[3])
                        })
        return ret

    def add_mturk_tasklet_association(self, tid, mturkid, commit = True):
        self.cur.execute('insert into mturk_assoc (tasklet_ref, mturk_ref) values (%s, %s)',
                            [tid, mturkid])
        if commit:
            self.con.commit()

    def create_mturk_resource(self, hit, hgid, commit = True):
        self.cur.execute('insert into mturk_resources (hit_id, hit_gid) values (%s, %s) returning id',
                            [hit, hgid])
        mturkid = self.cur.fetchone()[0]
        if commit:
            self.con.commit()
        return mturkid


    def create_program(self, name ):
        self.cur.execute('insert into programs (name) values (%s) returning id',
                            [name])
        programid = self.cur.fetchone()[0]
        self.con.commit()
        return programid


    # bitmap is results/$programname/$taskid
    def create_seed_tasklet(self, program, base_pay, payout_arr, keywords):
        tid = self.create_tasklet("SEED", program, base_pay, keywords)
        self.cur.execute('insert into seed_tasklets (task_id, payout_arr) values (%s, %s) returning id', [tid, json.dumps(payout_arr)])
        seedid = self.cur.fetchone()[0]
        self.con.commit()
        return tid

    def create_seek_tasklet(self, program, base_pay, keywords, task_spec, outputfile):
        tid = self.create_tasklet("SEEK", program, base_pay, keywords)
        self.cur.execute('insert into seek_tasklets (task_id, task_spec, outputfile) values (%s, %s, %s) returning id', [tid, "ignore task_spec", outputfile])
        seekid = self.cur.fetchone()[0]
        self.con.commit()
        return tid

    def create_drill_tasklet(self, program, base_pay, payout_array, keywords):
        tid = self.create_tasklet("DRILL", program, base_pay, keywords)
        self.cur.execute('insert into drill_tasklets (task_id, payout_arr) values (%s, %s) returning id', [tid, json.dumps(payout_array) ])
        drillid = self.cur.fetchone()[0]
        self.con.commit()
        return tid

    def create_tasklet(self, typ, program, base_pay_cents, keywords):

        # to be safe
        assert base_pay_cents < 2000
        assert HaCRSUtil.is_tasklet_type(typ)

        base_pay = round(float(base_pay_cents) / 100, 2)
        
        self.cur.execute('insert into tasklets (type, program, amount, keywords ) values (%s, %s, %s, %s) returning id', [typ, program, base_pay, keywords])
        taskletid = self.cur.fetchone()[0]
        self.con.commit()
        return taskletid

    #def seed_tasklet_update_target(self, tid, target):
    #    self.cur.execute("""select seed_tasklets.id 
    #                        from seed_tasklets
    #                            inner join tasklets on (tasklets.id = seed_tasklets.task_id)
    #                        where seed_tasklets.task_id = %s
    #                        """, [tid])
    #    res = self.cur.fetchone()
    #    if res == None:
    #        sys.stderr.write('error updating target!\n')
    #        return None
    #    seedid = res[0]
    #    self.cur.execute("""update seed_tasklets set mintransitinos = %s
    #                        where seed_tasklets.id = %s""", [target, seedid])
    #    self.con.commit()
    #    return True

    def seed_tasklet_update_payout_arr(self, tid, payout_arr):
        self.cur.execute("""select seed_tasklets.id 
                            from seed_tasklets
                                inner join tasklets on (tasklets.id = seed_tasklets.task_id)
                            where seed_tasklets.task_id = %s
                            """, [tid])
        res = self.cur.fetchone()
        if res == None:
            sys.stderr.write('error updating payout_arr!\n')
            return None
        seedid = res[0]
        self.cur.execute("""update seed_tasklets set payout_arr = %s
                            where seed_tasklets.id = %s""", [payout_arr, seedid])
        self.con.commit()
        return True

    def seed_tasklet_update_bitmap(self, tid, bitmap):
        self.cur.execute("""select seed_tasklets.id 
                            from seed_tasklets
                                inner join tasklets on (tasklets.id = seed_tasklets.task_id)
                            where seed_tasklets.task_id = %s
                            """, [tid])
        res = self.cur.fetchone()
        if res == None:
            sys.stderr.write('error updating bitmap!\n')
            return None
        seedid = res[0]
        self.cur.execute("""update seed_tasklets set bitmap = %s
                            where seed_tasklets.id = %s""", [bitmap, seedid])
        self.con.commit()
        return True

    def seek_tasklet_update_task_spec(self, tid, spec):
        self.cur.execute("""select seek_tasklets.id 
                            from seek_tasklets
                                inner join tasklets on (tasklets.id = seek_tasklets.task_id)
                            where seek_tasklets.task_id = %s
                            """, [tid])
        res = self.cur.fetchone()
        if res == None:
            sys.stderr.write('error updating spec!\n')
            return None
        seekid = res[0]
        self.cur.execute("""update seek_tasklets set task_spec = %s
                            where seek_tasklets.id = %s""", [spec, seekid])
        self.con.commit()
        return True

    def tasklet_update_amount(self, tid, amount):
        self.cur.execute("""update tasklets set amount = %s
                            where id = %s""", [amount, tid])
        self.con.commit()
        return True

    def tasklet_update_keywords(self, tid, kw):
        self.cur.execute("""update tasklets set keywords = %s
                            where id = %s""", [kw, tid])
        self.con.commit()
        return True


    def get_seed_tasklets(self):
        self.cur.execute("""select tasklets.id, programs.name, bitmap, payout_arr, timestamp, amount, keywords
                            from tasklets inner join seed_tasklets on (tasklets.id = seed_tasklets.task_id)
                                left outer join programs on (tasklets.program = programs.id)
                            order by tasklets.timestamp""")
        ret = []
        for line in self.cur.fetchall():
            ret.append({'id': line[0],
                        'program': line[1],
                        'bitmap': line[2],
                        'payout_arr': HaCRSDB.fix_payout_arr(line[3]),
                        'timestamp': line[4],
                        'amount': float(line[5]),
                        'keywords': line[6]
                       })
        return ret

    def get_seek_tasklets(self):
        self.cur.execute("""select tasklets.id, programs.name, amount, timestamp, outputfile
                            from tasklets inner join seek_tasklets on (tasklets.id = seek_tasklets.task_id)
                                left outer join programs on (tasklets.program = programs.id)
                            order by tasklets.timestamp""")
        ret = []
        for line in self.cur.fetchall():
            ret.append({'id': line[0],
                        'program': line[1],
                        'amount': line[2],
                        'timestamp': line[3],
                        'outputfile': line[4]
                       })
        return ret

    def get_drill_tasklets(self):
        self.cur.execute("""select tasklets.id, programs.name, amount, timestamp, payout_arr
                            from tasklets inner join drill_tasklets on (tasklets.id = drill_tasklets.task_id)
                                left outer join programs on (tasklets.program = programs.id)
                            order by tasklets.timestamp""")
        ret = []
        for line in self.cur.fetchall():
            ret.append({'id': line[0],
                        'program': line[1],
                        'amount': line[2],
                        'timestamp': line[3],
                        'payout_arr': HaCRSDB.fix_payout_arr(line[4])
                       })
        return ret

    def get_tasklets(self):
        self.cur.execute("""select tasklets.id, programs.name, timestamp, amount, keywords, type
                            from tasklets 
                            left outer join programs on (tasklets.program = programs.id)
                            order by tasklets.timestamp""")
        ret = []
        for line in self.cur.fetchall():
            ret.append({'id': line[0],
                        'program': line[1],
                        'timestamp': line[2],
                        'amount': float(line[3]),
                        'keywords': line[4],
                        'type': line[5]
                       })
        return ret

    def lookup_program(self, programname):
        self.cur.execute("""select id
                            from programs
                            where programs.name = %s """, [programname])
        res = self.cur.fetchone()
        if res == None:
            return None
        else:
            return res[0]

    def get_programs(self):
        self.cur.execute("""select id, name
                            from programs """)
        res = self.cur.fetchall()
        ret = []
        for line in res:
            ret.append( {
            'id': line[0],
            'name': line[1]
            })
        return ret

    def get_program_id(self, name):
        self.cur.execute("""select id
                            from programs 
                            where name = %s""", [name])
        res = self.cur.fetchone()
        if res == None:
            return None
        return res[0]

    def get_full_tasklet(self, tid):
        typ = self.get_tasklet_type(tid)
        if typ == None:
            return None
        if typ == 'SEED':
            return self.get_seed_tasklet(tid)
        elif typ == 'SEEK':
            return self.get_seek_tasklet(tid)
        elif typ == 'DRILL':
            return self.get_drill_tasklet(tid)
        else:
            assert False
            return None

    def get_solving_history(self, username):
        self.cur.execute("""select tasklets.id, programs.name, amount, keywords
                       from tasklet_session_log inner join tasklets on (tasklets.id = tasklet_session_log.task_id)
                       left join programs on (tasklets.program = programs.id)
                       where worker_id = %s
                       group by tasklets.id, programs.name, amount, keywords; """, [username])
        res = self.cur.fetchall()
        ret = []
        for line in res:
            ret.append( {
            'id': str(line[0]),
            'program': line[1],
            'amount': float(line[2]),
            'keywords': line[3]
            })
        return ret

    def get_mturk_assignment(self, mturkid):
        self.cur.execute("""select tasklet_ref
                            from mturk_tasklet_assignments
                            where status = 'WORKING' and 
                            worker_id = %s""", [mturkid])
        res = self.cur.fetchone()
        if res == None:
            return res
        else:
            return res[0]

    # Defaults to: WORKING
    def save_mturk_assignment(self, tid, mturkid):
        self.cur.execute("""insert into mturk_tasklet_assignments
                            (tasklet_ref, worker_id ) 
                            VALUES ( %s, %s)""", [tid, mturkid])
        self.con.commit()
        return

    # Update to ABORT or COMPLETE
    def update_mturk_assignment(self, tid, mturkid, newstatus):
        assert newstatus in ['ABORT', 'COMPLETE']
        self.cur.execute("""update mturk_tasklet_assignments
                            set status = %s
                            where tasklet_ref = %s and worker_id = %s""", [newstatus, tid, mturkid])
        self.con.commit()
        return

    def get_unassigned_seed_tasklet_for_mturkid(self, mturkid):

        self.cur.execute("""select tasklets.id, type, programs.name, tasklets.amount, count(tasklet_ref)
                          from tasklets left outer join programs on (tasklets.program = programs.id)
                                left outer join mturk_assoc on (tasklets.id = tasklet_ref)
                          group by 1, 2, 3, 4
                          having count(tasklet_ref) <= 2
                          """)
        ret = []
        for line in self.cur.fetchall():
            ret.append( { 'id': line[0],
                          'type': line[1],
                          'program': line[2],
                          'amount': float(line[3])
                        })
        return ret

    def pick_tasklet(self, ttype, difficulty, workerid):
        self.cur.execute("""select id from    
            tasklets where
            type = %s and 
            keywords = %s
            except
            select tasklet_ref 
            from mturk_tasklet_assignments 
            where worker_id = %s
            except
            (
            select tasklet_ref 
            from mturk_tasklet_assignments 
            inner join tasklets on mturk_tasklet_assignments.tasklet_ref = tasklets.id
            where status = 'COMPLETE'
            or issued = true
            );""", [ttype, difficulty, workerid])

        res = self.cur.fetchall()
        if res == None or len(res) == 0:
            return None
        pick_id = res[random.randint(0, len(res) - 1)][0]
        #return '1a00c606-3d63-4628-b260-ee63656e4bd2'
        return str(pick_id)

    def get_tasklet_type(self, tid):
        self.cur.execute("""select tasklets.type
                            from tasklets 
                            where tasklets.id = %s """, [tid])
        res = self.cur.fetchone()
        if res == None:
            return None
        else:
            return res[0]

    def get_hit_for_tasklet(self, tid):
        self.cur.execute("""select distinct(hit_id)
                            from tasklet_session_log 
                            where task_id = %s """, [tid])
        res = self.cur.fetchall()
        if res == None:
            return None
        else:
            hits = map(lambda x: x[0], res)
            return filter( lambda x: not x.startswith('picked_'), hits)

    def get_tasklet_program(self, tid):
        self.cur.execute("""select programs.name
                            from tasklets 
                            left outer join programs on (tasklets.program = programs.id)
                            where tasklets.id = %s """, [tid])
        res = self.cur.fetchone()
        if res == None:
            return None
        else:
            return res[0]

    def get_seed_tasklet(self, tid):
        self.cur.execute("""select tasklets.id, programs.name, bitmap, tasklets.type, payout_arr, amount, keywords
                            from tasklets inner join seed_tasklets on (tasklets.id = seed_tasklets.task_id)
                                left outer join programs on (tasklets.program = programs.id)
                            where tasklets.id = %s 
                            order by tasklets.timestamp""", [tid])
        lines = self.cur.fetchall()
        assert len(lines) <= 1

        if len(lines) == 0:
            return None
        else:
            ret = {'id': lines[0][0],
                        'program': lines[0][1],
                        'bitmap': lines[0][2],
                        'type': lines[0][3],
                        'payout_arr': HaCRSDB.fix_payout_arr(lines[0][4]),
                        'amount': float(lines[0][5]),
                        'keywords': lines[0][6]
                        }
            return ret


    def get_seek_tasklet(self, tid):
        self.cur.execute("""select tasklets.id, programs.name, tasklets.type, task_spec, amount, keywords, outputfile
                            from tasklets inner join seek_tasklets on (tasklets.id = seek_tasklets.task_id)
                                left outer join programs on (tasklets.program = programs.id)
                            where tasklets.id = %s 
                            order by tasklets.timestamp""", [tid])
        lines = self.cur.fetchall()
        assert len(lines) <= 1

        if len(lines) == 0:
            return None
        else:
            ret = {'id': lines[0][0],
                        'program': lines[0][1],
                        'type': lines[0][2],
                        'amount': float(lines[0][4]),
                        'keywords': lines[0][5],
                        'outputfile': lines[0][6]
                        }
            return ret

    def get_drill_tasklet(self, tid):
        self.cur.execute("""select tasklets.id, programs.name, tasklets.type, amount, keywords, payout_arr
                            from tasklets inner join drill_tasklets on (tasklets.id = drill_tasklets.task_id)
                                left outer join programs on (tasklets.program = programs.id)
                            where tasklets.id = %s 
                            order by tasklets.timestamp""", [tid])
        lines = self.cur.fetchall()
        assert len(lines) <= 1

        if len(lines) == 0:
            return None
        else:
            ret = {'id': lines[0][0],
                        'program': lines[0][1],
                        'type': lines[0][2],
                        'amount': float(lines[0][3]),
                        'keywords': lines[0][4],
                        'payout_arr': HaCRSDB.fix_payout_arr(lines[0][5])
                        }
            return ret


    def get_mturk_task(self, hit, gid):
        self.cur.execute('select * from mturk where hit_id = %s and hit_gid = %s',
                         [hit, gid])
        res = self.cur.fetchall()
        assert len(res) == 1
        # TODO: get task infos

    def get_mturk_task_from_tid(self, tid):
        pass
        self.cur.execute("""select hit_id, hit_gid 
                            from mturk_assoc, mturk_resources
                            where mturk_assoc.mturk_ref = mturk_resources.id and
                                 tasklet_ref = %s""", [tid])

        res = self.cur.fetchall()
        if res == None:
            return None
        return {'hitid': res[0][0] , 'hitgid': res[0][1]}

    def get_latest_seed_tasklets(self):
        self.cur.execute("""SELECT tasklets.id, timestamp, program, amount, keywords
            FROM tasklets WHERE (tasklets.program, timestamp) IN  
            ( SELECT tasklets.program, MAX(timestamp)
            FROM tasklets, mturk_assoc
            GROUP BY tasklets.program
            )
        order by tasklets.program""")

        ret = []
        for line in self.cur.fetchall():
            ret.append( { 'id': line[0],
                        'timestamp': line[1],
                        'program': line[2],
                        'amount': float(line[3]),
                        'keywords': line[4]
                        })
        return ret

    def get_mturk_infos(self, tid):
        self.cur.execute("""select hit_id, hit_gid
           from tasklets, mturk_assoc, mturk_resources
           where tasklets.id = mturk_assoc.tasklet_ref and
             mturk_assoc.mturk_ref = mturk_resources.id and
             tasklets.id = %s
             """, [tid])
        res = self.cur.fetchall()
        assert(len(res) <= 1)
        if len(res) == 0:
            return None
        return {'hitid': res[0][0], 'hitgid': res[0][1]}

    def get_all_mturk_infos(self):
        self.cur.execute("""select tasklets.id, hit_id, hit_gid, tasklets.type, tasklets.amount
           from tasklets, mturk_assoc, mturk_resources
           where tasklets.id = mturk_assoc.tasklet_ref and
             mturk_assoc.mturk_ref = mturk_resources.id 
             """)
        res = self.cur.fetchall()
        if len(res) == 0:
            return None
        ret = []
        for line in res:
            ret.append({'tid': str(line[0]),
                        'hitid': line[1],
                        'hitgid': line[2],
                        'type': line[3],
                        'amount': float(line[4])
                        })
        return ret

    # TODO
    def get_coverage_stats(self):
        self.cur.execute("""select timestamp, programs_coverage
                            from coverage_cache
                            where timestamp in ( select max(timestamp) from coverage_cache)""")
        res = self.cur.fetchone()
        return {'timestamp': res[0],
                'coverage': res[1]
                }

    def set_coverage_stats(self, stats):
        self.cur.execute("""insert into coverage_cache
                        (programs_coverage) VALUES ( %s ) """, [ json.dumps(stats)] )
        self.con.commit()
        return

    def add_user(self, uname, password, utype, permissions):
        pwsalt = random.randint(0, 100000)
        pwhash = binascii.hexlify( hashlib.pbkdf2_hmac('sha256', password, 'salt', pwsalt))
        permissions = 'standard'
        try:
            self.cur.execute("""insert into users
                                (name, permissions, utype, pwsalt, pwhash) 
                                VALUES (%s, %s, %s, %s, %s)
                                returning id""", [ uname, permissions, utype, pwsalt, pwhash ] )
            self.con.commit()
            return self.cur.fetchone()[0]
        except Exception as e:
            return None

    def load_user(self, uname):
        self.cur.execute("""select permissions, utype, id
                            from users where name = %s; """, [ uname ] )
        res = self.cur.fetchone()
        if res == None:
            return None
        permissions, utype, xid = res
        return {'permissions': permissions, 'utype': utype, 'uname': uname, 'id': xid}

    def get_username(self, uid):
        self.cur.execute("""select name
                            from users where id = %s; """, [ uid ] )
        res = self.cur.fetchone()
        if res == None:
            return None
        return res[0]

    def show_all_users(self):
        self.cur.execute("""select name, permissions, utype, id
                            from users; """ )
        res = self.cur.fetchall()
        if res == None:
            return None

        ret = []
        for line in res:
            ret.append( { 'name': line[0],
                          'permissions': line[1],
                          'utype': line[2],
                          'id': line[3]
                        })
        return ret


        return {'permissions': permissions, 'utype': utype, 'uname': uname}


    def authenticate_user(self, uname, password):
        self.cur.execute("""select permissions, utype, pwsalt, pwhash 
                            from users where name = %s; """, [ uname ] )
        res = self.cur.fetchone()
        if res == None:
            return None
        permissions, utype, pwsalt, pwhash = res

        hashedinput = binascii.hexlify( hashlib.pbkdf2_hmac('sha256', password, 'salt', int(pwsalt)))

        if hashedinput == pwhash:
            return True

        return None


    def log_session_start(self, tid, hitId, workerId, assignmentId, execution_id, user_agent, remote_addr):
        self.cur.execute("""insert into tasklet_session_log
                            ( task_id, hit_id, worker_id, assignment_id, execution_id, user_agent, remote_add )
                            values (%s, %s, %s, %s, %s, %s, cidr %s)""", 
        [ psycopg2.extensions.adapt( tid), hitId, workerId, assignmentId, psycopg2.extensions.adapt( execution_id), user_agent[:300], remote_addr ])
        self.con.commit()

    def add_note (self, userid, program, note ):
        self.cur.execute("""insert into notes
                            ( user_id, program_id, text) VALUES
                            ( %s, %s, %s ) returning id;""", [userid, program, note])
        res = self.cur.fetchone()
        if res == None:
            return None
        self.commit()
        return res[0]

    def get_notes_for_tasklet(self, tid):
        self.cur.execute("""select users.name, notes.text, notes.timestamp
                            from notes left join users on (notes.user_id = users.id)
                            inner join tasklets on (notes.program_id = tasklets.program)  and tasklets.id = %s """, [tid])
        ret = []
        res = self.cur.fetchall()
        for line in res:
            ret.append( { 'name': line[0],
                          'note': line[1],
                          'timestamp': line[2]
                        })
        return ret


if __name__ == "__main__":
    pass

