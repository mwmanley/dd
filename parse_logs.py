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
import math

def parseArgs (args):
    parser = argparse.ArgumentParser();
    parser.add_argument('--logfile', help="Log File to Patrol", default="/var/log/access.log")
    parser.add_argument('--stats_interval', help="Intervals for Stats in seconds", default=10)
    parser.add_argument('--alert_threshold', help="High Water Mark for Hits", default=10)
    parser.add_argument('--alert_interval', help="Intervals for Alerting in seconds", default=120)
    parser.add_argument('--debug', help="Do not run in an infinite loop for debugging", default=0)
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
            yield None
            time.sleep(.1)
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

def group_http_codes (code):
    code_class = int(math.floor(int(code) / 100))
    code_type = "ERROR"
    if code_class == 2:
        code_type = "OK"
    elif code_class == 3:
        code_type = "REDIRECT"
    elif code_class == 4:
        code_type = "BAD"
    return ("{}xx - {}".format(code_class, code_type))

def display_counters (data, start, end):
    high_score = Counter()
    status_codes = {}
    total_traffic = 0
    ips = Counter()
    for ticks in data:
        for tick in data[ticks]:
            if tick['time'] >= start and tick['time'] < end:
                high_score[tick['section']] += 1
                total_traffic += int(tick['size'])
                ips[tick['host']] += 1
                http_code = group_http_codes(tick['status'])
                if http_code in status_codes:
                    status_codes[http_code] += 1
                else:
                    status_codes[http_code] = 1
    print "\n---"
    print "Traffic breakdown at {}".format(end)
    if total_traffic == 0:
        print "No traffic recorded"
        return end
    for high_scorers in high_score.most_common(1):
        if (len(high_scorers)) > 2:
            print "Warning: There are multiple sections with equal hits"
        (section, count) = high_scorers
        print "Most active section is {} with {} hits".format(section,count)

    print "Total HTTP traffic: {} bytes".format(total_traffic)
    print "Total hits: {}".format(sum(high_score.values()))
    print "The five most active hosts: "
    for k, v in ips.most_common(5):
        print "%20s:%7d" % (k,v)

    print "HTTP status breakdown:"
    for k, v in sorted(status_codes.iteritems()):
        print "%20s:%7d" % (k,v)
    return end


def alert_on_moving_average(data, alert_interval, alert_threshold, alerts):
    start = datetime.datetime.utcnow() - datetime.timedelta(seconds=int(alert_interval))
    end = datetime.datetime.utcnow()
    activity = Counter()
    label = 'activity'
    for ticks in data:
        for tick in data[ticks]:
            if tick['time'] >= start and tick['time'] < end:
                activity[tick['time']] += 1
    totals = sum(activity.values())
    avg = totals/float(alert_interval)
    if avg > alert_threshold:
        # we've already alerted
        if label not in alerts:
            # record for later, if needed
            alerts[label] = {'time': end, 'value': avg, 'threshold': alert_threshold}
            print "High traffic generated an alert - hits = {}, triggered at {}".format(avg,end)
    else:
        if label in alerts:
            print "Cleared high traffic generated alert - hits = {} below {}, okay at {}".format(avg,alert_threshold,end)
            del(alerts[label])
    return end

def start_parsing (stats_interval,alert_interval,logfile,alert_threshold,debug):    
    stats = {}

    # now something in which to hold our alerts
    alerts = {}

    # this is arbitrary, but keep the stats hash from getting 
    # unmanagably large
    interval = int(stats_interval) * int(alert_interval)

    now = datetime.datetime.utcnow()
    counter_start = now
    stats_start = now

    # create an alarm so that if we are blocked for 
    # more than the stats interval we can just say
    # that nothing happened 
    for line in read_log_file(logfile):
        now = datetime.datetime.utcnow()
        if line != None:
            tokens = parse_log_line(line.rstrip("\n\r"))
            if tokens == None:
                pass
            # makes it a lot easier to read debug
            tok_time = int(time.mktime(tokens['time'].timetuple()))
            if tok_time in stats:
                stats[tok_time].append(tokens)
            else:
                stats[tok_time] = [ tokens ]
        if (now - datetime.timedelta(seconds=int(stats_interval))) >= counter_start:
            counter_start = display_counters(stats, counter_start, now)
        alert_on_moving_average(stats, alert_interval, alert_threshold, alerts)
        if (now - (datetime.timedelta(seconds=interval))) >= stats_start:
            stats.clear()
            stats_start = now
            if debug > 0:
                break

if __name__ == '__main__':

    options = parseArgs(sys.argv)
    start_parsing(options.stats_interval,options.alert_interval,
                  options.logfile,options.alert_threshold,options.debug)
