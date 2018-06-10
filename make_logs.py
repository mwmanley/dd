#!/usr/bin/python2.7

import logging
import time
from logging.handlers import RotatingFileHandler
import os
import sys
import argparse
import random
import datetime

# 127.0.0.1 - james [09/May/2018:16:00:39 +0000] "GET /report HTTP/1.0" 200 1234

def parseArgs (args):
    parser = argparse.ArgumentParser();
    parser.add_argument('--logfile', help="Log File to Patrol", default="/var/log/access.log")
    parser.add_argument('--max_size', help="Number of bytes before we rotate", default=10000000)
    return parser.parse_args()

def give_a_name():
    names = ['james', 'wendy', 'sally', 'mary', 'ben', 'leo']
    return(random.choice(names))

def give_an_ip():
    num_array_1 = [2, 6, 98, 14]
    num_array_2 = [56, 198, 23, 214]
    a_octet = random.choice(num_array_1)
    b_octet = random.choice(num_array_2)
    c_octet = random.choice(num_array_2)
    d_octet = random.choice(num_array_1)
    ip_string = "{}.{}.{}.{}".format(a_octet,b_octet,c_octet,d_octet)
    return(ip_string)

def give_a_path():
    a_path = ['/api', '/user', '/www']
    b_path = ['/awesome', '/baking', '/julia', '/child', '/eating', '/weightgain']
    path_string = "{}{}".format((random.choice(a_path)),(random.choice(b_path)))
    return(path_string)

def give_a_return():
    code_array = [200,400,301,201,500]
    return (random.choice(code_array))

def give_a_size():
    return (random.randint(1,100000))   

def create_rotating_log(path, max_size):
    """
    Creates a rotating log
    """
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.INFO)
 
    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=max_size,
                                  backupCount=1)
    logger.addHandler(handler)
    for i in range(30000):
        now = datetime.datetime.utcnow()
        timestamp = now.strftime("%d/%b/%Y:%H:%M:%S")
 
        message = "{} - {} [{} +0000] \"GET {} HTTP/1.0\" {} {}".format(give_an_ip(),
                                                                    give_a_name(),
                                                                    timestamp,
                                                                    give_a_path(),
                                                                    give_a_return(),
                                                                    give_a_size())
        logger.info(message)
        sleeptime = (random.randint(0,500) / float(100))
        time.sleep(sleeptime)


if __name__ == '__main__':
    options = parseArgs(sys.argv)
    if os.path.isfile(options.logfile):
        os.unlink(options.logfile)
    create_rotating_log(options.logfile,options.max_size)


