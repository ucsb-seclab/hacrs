import os
import sys

mtutil_path = os.path.abspath(os.path.join(__file__, '../../../mtutil'))
sys.path.append(mtutil_path)

from HaCRSDB import HaCRSDB

db = HaCRSDB()
seek_tasklets = db.get_seek_tasklets()
for tasklet in seek_tasklets:
    print str(tasklet['id']), tasklet['program'], tasklet['outputfile']