#!/usr/bin/python -O

import sys
import re

EPOCH = 1000000

benchmark = sys.argv[1] # e.g., canneal
tech = sys.argv[2] # e.g., sram_32nm_32MB_mix

flog = open('../'+benchmark + '_' + tech + '/' + benchmark + '.log', 'r')
ftrace = open('../'+benchmark + '_' + tech + '/llc_access_trace.log', 'r')
#fout = open('access_pattern_block reuse.dat', 'w')

time = re.compile("Stopped after ([0-9]+) cycles, ([0-9]+) instructions(.*)")

for line in flog:
    t = time.match(line)
    if t is not None:
        exe_time = int(t.group(1))

with open('../'+benchmark + '_' + tech + '/llc_access_trace.log', 'rb') as fh:
    first = next(fh)
    offs = -100
    while True:
        fh.seek(offs, 2)
        lines = fh.readlines()
        if len(lines)>1:
            last = lines[-1]
            break
        offs *= 2
    last_line = int(last.split()[0])


#########################  1st part ##############################
# RR ==> pre_state = 0, cur_state = 0   , SEU
# WR ==> pre_state = 2, cur_state = 0   , SEU
# WE ==> pre_state = 2, cur_state = 3   , SEU
# RE ==> pre_state = 0, cur_state = 3   , SEU
# RW ==> pre_state = 0, cur_state = 2
# WW ==> pre_state = 2, cur_state = 2
#LRR: Long RR
#MRR: Medium RR
#SRR: Short RR

#LWR: Long WR
#MWR: Medium WR
#SWR: Short WR

#LWE: Long WE
#MWE: Medium WE
#SWE: Short WE

#LRE: Long RE
#MRE: Medium RE
#SRE: Short RE

LRR_cycle = 0
MRR_cycle = 0
SRR_cycle = 0
LWR_cycle = 0
MWR_cycle = 0
SWR_cycle = 0
LWE_cycle = 0
MWE_cycle = 0
SWE_cycle = 0
LRE_cycle = 0
MRE_cycle = 0
SRE_cycle = 0
nonvulnerable =0

num_line = [0] * 1000000
cycle = 0
i = 0
exec_time = 0 # the total execution time for those cacheline selected here
SRR= 0
MRR= 0
LRR= 0
SWR= 0
MWR= 0
LWR= 0
SWE= 0
MWE= 0
LWE= 0
SRE= 0
MRE= 0
LRE= 0
nonvul_line = 0
total_line = 0
j = 4 
num_0rows = 0

sim_cycle = int(last_line / 10000)
iter = 1
for y in xrange(0, iter):
    for line in ftrace:
        pre_state = -1
        row_exist = 0
        pre_row_sim = 0
        row = int(line.split()[2])
        pre_state = int(line.split()[1])
        pre_row_sim = int(line.split()[0])
        if row == 0:
            num_0rows += 1
        if num_line.count(row) == 1: #if the line has been already counted, change flag to 1 and avoid to count it again
            row_exist = 1
        if row == 0 and num_0rows > 1:
            ftrace.seek(0)
            i += 1
            for y in xrange(0, i):
                line = ftrace.next()
        elif  int(line.split()[0]) > (j*sim_cycle):
            j += 1
            ftrace.seek(0)
            for y in xrange(0, i):
                line = ftrace.next()
            break
        elif row_exist == 0 and int(line.split()[0]) <= last_line:
            while int(line.split()[0]) < last_line:
                if int(line.split()[2]) == row:
                    if int(line.split()[1]) == 0 and pre_state == 0:
                        if (int(line.split()[0]) - pre_row_sim) < 1000000:
                            SRR+= 1 #Count number of lines which are accessed less than 0.5% of program execution
			    total_line += 1
		    	    SRR_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        elif (int(line.split()[0]) - pre_row_sim) < 50000000:
                            MRR += 1
			    total_line += 1
			    MRR_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim=int(line.split()[0])
                            line = ftrace.next()
                        else:
                            LRR += 1
			    total_line += 1
			    LRR_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                    elif int(line.split()[1]) == 2 and pre_state == 0:
                        if (int(line.split()[0])- pre_row_sim) < 1000000:
                            SWR += 1
			    total_line += 1
			    SWR_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        elif (int(line.split()[0])- pre_row_sim) < 50000000:
                            MWR += 1
			    total_line += 1
			    MWR_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        else:
                            LWR += 1
			    total_line += 1
			    LWR_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                    elif int(line.split()[1]) == 2 and pre_state == 3:
                        if (int(line.split()[0])- pre_row_sim) < 1000000:
                            SWE += 1
			    total_line += 1
			    SWE_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        elif (int(line.split()[0])- pre_row_sim) < 50000000:
                            MWE += 1
			    total_line += 1
			    MWE_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        else:
                            LWE += 1
			    total_line += 1
			    LWE_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                    elif int(line.split()[1]) == 0 and pre_state == 3:
                        if (int(line.split()[0])- pre_row_sim) < 1000000:
                            SRE += 1
			    total_line += 1
			    SRE_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        elif (int(line.split()[0])- pre_row_sim) < 50000000:
                            MRE += 1
			    total_line += 1
			    MRE_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                        else:
                            LRE += 1
			    total_line += 1
			    LRE_cycle += int(line.split()[0]) - pre_row_sim
			    exec_time += int(line.split()[0]) - pre_row_sim
                            pre_row_sim = int(line.split()[0])
                            line = ftrace.next()
                    else:
			nonvulnerable += int(line.split()[0]) - pre_row_sim
			nonvul_line += 1
			total_line += 1
			exec_time += int(line.split()[0]) - pre_row_sim
                        line = ftrace.next()
                else:
                    line = ftrace.next()
            num_line[i] = row
            ftrace.seek(0)
            i += 1
            for y in xrange(0, i):
                line = ftrace.next()
        elif row_exist != 0 and int(line.split()[0]) <= last_line:
            i += 1
            ftrace.seek(0)
            for y in xrange(0, i):
                line = ftrace.next()
        else:
            break

    fout = open("phase_dist_cycle_"+benchmark+".dat","w")
    # access type = 4 = prefetch
    # access type = 5 = insert (MEM writes LLC)
    # access type = MEMORY_OP_READ or MEMORY_OP_WRITE or MEMORY_OP_UPDATE or MEMORY_OP_EVICT
    # access type = 6 = writeback (LLC writes MEM)
print >>fout, "SRR_cyc,      MRR_cyc,  LRR_cyc,     SWR_cyc,   MWR_cyc,  LWR_cyc,  SWE_cyc,     MWE_cyc,     LWE_cyc,        SRE_cyc,      MRE_cyc,      LRE_cyc,        nonvulnerable, total execution time"
print >>fout, "%-5s %-5s %-5s %-5s %-5s %-5s   %-5s        %-5s         %-5s          %-5s         %-5s         %-5s        %-5s    %-5s" % (SRR_cycle,MRR_cycle,LRR_cycle,SWR_cycle,MWR_cycle,LWR_cycle,SWE_cycle,MWE_cycle,LWE_cycle, SRE_cycle,MRE_cycle,LRE_cycle,nonvulnerable, exec_time)
fout.close()

fout = open("phase_line_num_"+benchmark+".dat","w")
print >>fout, "Line num,SRR,  MRR,  LRR, SWR,   MWR,  LWR,  SWE,  MWE,  LWE,  SRE,  MRE,  LRE, nonvulnerable lines"
#for c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13  in zip(total_line,SRR,MRR,LRR,SWR,MWR,LWR,SWE,MWE,LWE, SRE,MRE,LRE, nonvul_line):
print >>fout, "%-9s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s" % (total_line,SRR,MRR,LRR,SWR,MWR,LWR,SWE,MWE,LWE, SRE,MRE,LRE, nonvul_line)
fout.close()

flog.close()
ftrace.close()

