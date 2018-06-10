#!/usr/bin/python2.7

# make the python magic happen!
# example log line for reference
# 127.0.0.1 - james [09/May/2018:16:00:39 +0000] "GET /report HTTP/1.0" 200 1234

import os
import sys
import argparse
from collections import deque, Counter
import datetime
import re
import time
import pprint


def parseArgs (args):
    parser = argparse.ArgumentParser();
    parser.add_argument('--logfile', help="Log File to Patrol", default="/var/log/access.log")
    parser.add_argument('--stats_interval', help="Intervals for Stats in seconds", default=10)
    parser.add_argument('--high_water_hits', help="High Water Mark for Hits", default=10)
    parser.add_argument('--alert_interval', help="Intervals for Alerting in seconds", default=120)
    return parser.parse_args()

def read_log_file(logfile):
    try:
        current = open (logfile, "r")
        curino = os.fstat(current.fileno()).st_ino
        while True:
            while True:
                line = current.readline()
                if not line:
                    break
                yield line

            try:
                if os.stat(logfile).st_ino != curino:
                    new = open(logfile, "r")
                    current.close()
                    current = new
                    curino = os.fstat(current.fileno()).st_ino
                    continue
            except IOError:
                pass
            time.sleep(1)
    except IOError:
        print "Cannot open file {} for reading".format(logfile)     

def parse_log_line (line):
    # first parse the whole line
    lp = [
        r'(?P<host>\S+)',                  # host %h
        r'\S+',                            # indent %l (unused)
        r'(?P<user>\S+)',                  # user %u
        r'\[(?P<time>.+)\]',               # time %t
        r'"(?P<request>.*)"',              # request "%r"
        r'(?P<status>[0-9]+)',             # status %>s
        r'(?P<size>\S+)'                   # size %b (careful, can be '-')
    ]
    pattern = re.compile(r'\s+'.join(lp)+r'\s*\Z')
    l = pattern.match(line)
    # we didn't match for some reason
    if l == None:
        print "No match"
        return None
    
    logtoks = l.groupdict()  

    # Now make a date time object from the string
    (t, zone_offset) = logtoks['time'].split()
    offset = int(zone_offset[-4:-2])*60 + int(zone_offset[-2:])
    if zone_offset[0] == "-":
        offset = -offset
    logtoks['time'] = datetime.datetime.strptime(t, "%d/%b/%Y:%H:%M:%S") + datetime.timedelta(minutes=offset)
    # Now break up the request
    rp = [
        r'(?P<action>\S+)',        
        r'(?P<path>\S+)',
        r'(?P<http_vers>\S+)',
    ]
    pattern = re.compile(r'\s+'.join(rp)+r'\s*\Z')
    r = pattern.match(logtoks['request'])
    reqtoks = r.groupdict()
    sectoks = reqtoks['path'].split("/")
    logtoks['section'] = "/{}".format(sectoks[1])    
    logtoks.update(reqtoks)
    return (logtoks)

# todo: screen out data that are too old
def display_counters (data, start, end):
    high_score = Counter()
    for ticks in data:
        for tick in data[ticks]:
            if tick['time'] >= start and tick['time'] < end:
                high_score[tick['section']] += 1
    print high_score.most_common(1)

if __name__ == '__main__':

    options = parseArgs(sys.argv)

	# let's create a deque with a max retention of either our
    # alerting or our stats interval, whichever is greater
    counters_stats = {}
    alerts_stats = {}

    # now something in which to hold our alerts
    alerts = {}

    counter_start = datetime.datetime.utcnow()
    alert_start = datetime.datetime.utcnow()

    # pp = pprint.PrettyPrinter(indent=4)  
    for line in read_log_file(options.logfile):
        now = datetime.datetime.utcnow()
        tokens = parse_log_line(line.rstrip("\n\r"))
        if tokens == None:
            pass
        # makes it a lot easier to read debug
        tok_time = int(time.mktime(tokens['time'].timetuple()))
        if tok_time in counters_stats:
            counters_stats[tok_time].append(tokens)
        else:
            counters_stats[tok_time] = [ tokens ]
        if tok_time in alerts_stats:
            alerts_stats[tok_time].append(tokens)
        else:
            alerts_stats[tok_time] = [ tokens ] 
        if (now - datetime.timedelta(seconds=options.stats_interval)) >= counter_start:
            display_counters(counters_stats, counter_start, now)
            counters_stats = {}
            counter_start = now
