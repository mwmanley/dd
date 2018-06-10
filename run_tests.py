#!/usr/bin/python2.7

# run unit testing

import unittest
from subprocess import call
import os
from make_logs import *
from parse_logs import *

log_options={
    'logfile': '/tmp/access.log',
    'max_size': '3000',
    'seed': '20',
    'lines': '3000'
}

parse_options={
    'logfile': '/tmp/access.log',
    'stats_interval': '10',
    'alert_interval': '120',
    'alert_threshold': '10'
}

class BasicFunctionTest(unittest.TestCase):

    def setUp(self):
        parse_logs.main(parse_options)
        make_logs.main(log_options)
       

    
    def test_access_log(self):
        assert os.path.isfile('/tmp/access.log')


if __name__ == '__main__':
    unittest.main(buffer=True)