#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" A pure Python GlobalConfig implementation.  Copyright (c) 2010, flk3y """
__version__ = '0.1'

import os
import sys
GlobalConfig = {'xmlfilename':"test.xml",
                'pcapfilename':"test.pcap",
                'outputpathname':"outputdir", 
                'appname':"default_app",
                'tmp_arff_filename':"/tmp/testdata.log",
		'tmp_netdude_path':"/tmp/netdude_demux",
		'isALL':False,
                'isSplit':False,
                'isMerge':False,
                'isFeature':False,
                'isVerbose':False,
                'ismergearff':False,
		'isNetdude':False,
                }
xmlbuffer=[]
def mkdir_p(newdir):
    """works the way a good mkdir should :)
        - already exists, silently complete
        - regular file in the way, raise an exception
        - parent directory(ies) does not exist, make them as well
    """
    if os.path.isdir(newdir):
        pass
    elif os.path.isfile(newdir):
        raise OSError("a file with the same name as the desired " \
                      "dir, '%s', already exists." % newdir)
    else:
        head, tail = os.path.split(newdir)
        if head and not os.path.isdir(head):
           os.mkdir(head)
        #print "_mkdir %s" % repr(newdir)
        if tail:
            os.mkdir(newdir)
