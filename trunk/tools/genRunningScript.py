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
import appconfig as APPCONFIG


sys.stderr=sys.stdout



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
    parser.add_option("-o", "--output",dest="output_arff_path_name",
                      metavar="OUTPUT_PATH", help="write output OUTPUT_PATH")
    parser.add_option('-w',"--script",dest="outputScript",
                      default="runall.sh",
                      help="generate run.sh, default is ./runall.sh")
    (options, args) = parser.parse_args()
    
    output_real_arff_file_name=""
    
    arguments_list=[]
    items = set()
    
    if options.output_arff_path_name:
        if os.path.isdir(options.output_arff_path_name):
            output_real_path_file_name= os.path.abspath(options.output_arff_path_name)
        elif os.path.isfile(options.output_arff_path_name):
            print ("error, file exists, plz specify a director")
            exit()
        else:
            APPCONFIG.mkdir_p(options.output_arff_path_name)
            output_real_path_file_name=options.output_arff_path_name
    patern=re.compile('[a-zA-Z]')    
    if options.from_path:
        if os.path.isdir(options.from_path):
            #for f in glob.glob(os.path.join(options.from_path, '*.pcap')):
            #    if os.path.isfile(f):
            #        items.add(os.path.abspath(f))
            for (thisDir, subsHere, filesHere) in os.walk(options.from_path):
                for filename in filesHere:
                    (shortname, extension) = os.path.splitext(filename)
                    pcapfullname = os.path.join(thisDir,filename)
                    if( os.path.isfile(pcapfullname) and (extension==".pcap" or extension == ".PCAP" ) ):
                        m = shortname.split('.')[-1]
                        #print (m)
                        if   patern.search(m):  # in shortname.split('.')[-1]: 
                            items.add(pcapfullname)
                            #print (shortname)
                            gg_path = os.path.join(thisDir,'*.xml')
                            gg = glob.glob(gg_path)
                            xmlfilename= shortname+'.xml'
                            realxml=''
                            r=os.path.join(thisDir,xmlfilename)
                            if os.path.isfile(r ):
                                print ("found xml: %s " % (r))
                                realxml=r
                            elif gg :
                                i = 0
                                for f in gg:
                                    i+=1
                                    print ("cannot found an exact xml file, use %d:  %s instead" %(i,f))
                                    realxml=f
                            else:
                                print("no xml found in %s" %(thisDir))
                                continue
                            outputpath=''
                            if options.output_arff_path_name:
                                outputpath=output_real_path_file_name
                            else:
                                outputpath=os.path.join(thisDir,( shortname+'.pcap.demux' ) )
                            a = (pcapfullname,realxml,outputpath)
                            arguments_list.append(a)
                        else:
                            continue
        elif os.path.isfile(options.from_path):
            items.add(options.from_path)
        else:
            print "not set input file/path"
            exit()
    
    for arg in args: 
        if '*' in arg:
            for n in glob.glob(arg):
                items.add(os.path.abspath(n))
        elif os.path.isfile(arg):
            items.add(os.path.abspath(arg))
        else:
            pass
    realpath=os.path.realpath(options.outputScript)
    runfile=open(options.outputScript,'w')
    writelines=[]
    writeline=''
    mergedarff_list=[]
    for i in arguments_list:
        print (i)
        #for ii in i:
        #    runfile.write(ii)
        writeline=( "flowsing.py -f %s -x %s -o %s -n\n" % (i[0], i[1], i[2]) )
        writelines.append(writeline) 
        writeline=( "flowsing.py -f %s -x %s -o %s -c\n" % (i[0], i[1], i[2]) )
        writelines.append(writeline) 
        writeline=( "flowsing.py -f %s -x %s -o %s -m\n" % (i[0], i[1], i[2]) )
        writelines.append(writeline) 
        writeline=( "flowsing.py -f %s -x %s -o %s -g\n" % (i[0], i[1], i[2]) )
        writelines.append(writeline) 
        mergearff=i[0]+".merged.arff"
        mergedarff_list.append(mergearff)
        writeline=( "arffmerge.py -f %s -o %s \n\n"%( i[2], mergearff ) )
        writelines.append(writeline) 
    computed_arff_list=[]
    yamlconf="catalogue.details.yaml" 
    for m in mergedarff_list:
        outputarff = m+".ARFF"
        computed_arff_list.append(outputarff)
        #yamlconf="catalogue.details.yaml"
        writeline= ( "catalogue.py -d -c %s -o %s -f %s\n\n\n" % (yamlconf,outputarff,m) )
        writelines.append(writeline)
    computed_arff_s=''
    for n in computed_arff_list:
        #print (n)
        computed_arff_s+=n+" "
    final_arff='ALLinONE.ARFF'
    writeline= ( "topmerger2.py  -q -p -n 3000 -s opendpi  -o %s -f %s\n\n" % ( final_arff, computed_arff_s ) )
    writelines.append(writeline)
    
    writelines_s=''    
    for w in writelines:
        writelines_s+=w
    runfile.write(writelines_s)
    runfile.close()
    os.system("chmod +x %s" %(realpath) )
    exit()
