#!/usr/bin/python2.7

# run unit testing

import unittest
import make_logs 
import parse_logs 
import os
import sys


class BasicFunctionTest(unittest.TestCase):

    def setUp(self):
        make_logs.create_rotating_log('/tmp/access.log', 3000, 20, 30)
        parse_logs.start_parsing (10,4,'/tmp/access.log',3,1)

    
    def test_access_log(self):
        assert os.path.isfile('/tmp/access.log')
    
    def test_high_traffic(self):
        output = sys.stdout.getvalue().strip()
        self.assertRegexpMatches(output,'High traffic generated an alert')

    def test_high_traffic_clear(self):
        output = sys.stdout.getvalue().strip()
        self.assertRegexpMatches(output,'Cleared high traffic generated alert')        


if __name__ == '__main__':
    unittest.main(buffer=False)