#!/usr/bin/env python
import os,sys,  logging, socket
import subprocess
import string
from exceptions import Exception
from threading import Thread
from optparse import OptionParser
from subprocess import Popen, PIPE, STDOUT
import re
import glob

sys.stderr=sys.stdout


arff_head_s=('''@RELATION <netmate>

@ATTRIBUTE srcip STRING
@ATTRIBUTE srcport NUMERIC
@ATTRIBUTE dstip STRING
@ATTRIBUTE dstport NUMERIC
@ATTRIBUTE proto NUMERIC
@ATTRIBUTE total_fpackets NUMERIC
@ATTRIBUTE total_fvolume NUMERIC
@ATTRIBUTE total_bpackets NUMERIC
@ATTRIBUTE total_bvolume NUMERIC
@ATTRIBUTE min_fpktl NUMERIC
@ATTRIBUTE mean_fpktl NUMERIC
@ATTRIBUTE max_fpktl NUMERIC
@ATTRIBUTE std_fpktl NUMERIC
@ATTRIBUTE min_bpktl NUMERIC
@ATTRIBUTE mean_bpktl NUMERIC
@ATTRIBUTE max_bpktl NUMERIC
@ATTRIBUTE std_bpktl NUMERIC
@ATTRIBUTE min_fiat NUMERIC
@ATTRIBUTE mean_fiat NUMERIC
@ATTRIBUTE max_fiat NUMERIC
@ATTRIBUTE std_fiat NUMERIC
@ATTRIBUTE min_biat NUMERIC
@ATTRIBUTE mean_biat NUMERIC
@ATTRIBUTE max_biat NUMERIC
@ATTRIBUTE std_biat NUMERIC
@ATTRIBUTE duration NUMERIC
@ATTRIBUTE min_active NUMERIC
@ATTRIBUTE mean_active NUMERIC
@ATTRIBUTE max_active NUMERIC
@ATTRIBUTE std_active NUMERIC
@ATTRIBUTE min_idle NUMERIC
@ATTRIBUTE mean_idle NUMERIC
@ATTRIBUTE max_idle NUMERIC
@ATTRIBUTE std_idle NUMERIC
@ATTRIBUTE sflow_fpackets NUMERIC
@ATTRIBUTE sflow_fbytes NUMERIC
@ATTRIBUTE sflow_bpackets NUMERIC
@ATTRIBUTE sflow_bbytes NUMERIC
@ATTRIBUTE fpsh_cnt NUMERIC
@ATTRIBUTE bpsh_cnt NUMERIC
@ATTRIBUTE furg_cnt NUMERIC
@ATTRIBUTE burg_cnt NUMERIC
@ATTRIBUTE opendpi_class {''' , '''}

% you need to add a nominal class attribute!
% @ATTRIBUTE class {class0,class1}

@DATA

''')

if __name__ == '__main__':
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="make lots of noise")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose",
                      help="be very quiet")
    parser.add_option("-f", "--from_path",dest="from_path",
                      metavar="INPUT_PATH", help="read from INPUT_PATH")
    parser.add_option("-o", "--output",dest="output_arff_file_name",
                      metavar="OUTPUT_FILES", help="write output OUTPUT_FILES")
    (options, args) = parser.parse_args()
    
    output_real_arff_file_name=""
    
    items = set()
  
    
    if os.path.isdir(options.output_arff_file_name):
        output_real_arff_file_name= os.path.join(output_arff_file_name,'default.arff' )
    elif options.output_arff_file_name:
        output_real_arff_file_name=options.output_arff_file_name
    else:
        output_real_arff_file_name="./default.arff"
    
    if options.from_path:
        if os.path.isdir(options.from_path):
            for f in glob.glob(os.path.join(options.from_path, '*.merged.arff')):
                if os.path.isfile(f):
                    items.add(os.path.abspath(f))
        elif '*' in options.from_path:
            for n in glob.glob(options.from_path):
                items.add(os.path.abspath(f))
        else:
            print "not set input file/path"
            #exit()
    
    for arg in args: 
    #    if os.path.isdir(arg):
    #        for f in glob.glob(os.path.join(arg, '*.merged.arff')):
    #            if os.path.isfile(f):
    #                items.add(os.path.abspath(f))
        #print arg 
        if '*' in arg:
            for n in glob.glob(arg):
                items.add(os.path.abspath(n))
        elif os.path.isfile(arg):
            items.add(os.path.abspath(arg))
        else:
            pass
    #add arff header into output_real_arff_file_name
    if os.path.isfile(output_real_arff_file_name):
        os.remove(output_real_arff_file_name)
    output_file = open(output_real_arff_file_name,'a')
    #output_file.write(arff_head_s[0])
    
    #output_file.write(arff_head_s[1])

    #from collections import deque
    
    applist=[]
    #writelines_header=[]
    writelines_data=[]
    for input_arff_filename in items:
        foundData = False
        p = open(input_arff_filename,'r')
        for line in p.readlines():
            prog=re.compile("^@DATA")
            m = prog.match(line)
            if m:
                foundData = True
                continue
            if ( foundData==True and ( not line.isspace() ) and (not re.match('^@',line))  and (not re.match('^%',line)) ):
                appname = input_arff_filename.split('@')[0].split('/')[-1]
                print appname
                writline=line.strip()+appname+"\n"
                opendpi_class = writline.split(',')[-1].strip()
                if opendpi_class not in applist:
                    applist.append(opendpi_class)
                writelines_data.append( writline )
        p.close()     
    #write output arff file
    output_file.write(arff_head_s[0])
    for i in applist:
        output_file.write( "%s," % i )
    output_file.write(arff_head_s[1])
    for ii in writelines_data:
        output_file.write(ii)
    output_file.close()
    exit()

