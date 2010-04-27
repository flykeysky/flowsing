#!/usr/bin/env python
import os,sys,logging
import string
from exceptions import Exception
from optparse import OptionParser
import re
import glob
import yaml


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
@ATTRIBUTE open_class {''' ,
'}',
'\n@ATTRIBUTE app_class {',
'}',
'\n@ATTRIBUTE cata_class {',
'}',
'''
% you need to add a nominal class attribute!
% @ATTRIBUTE class {class0,class1}

@DATA

''')



def LoadStream(FileName_s='default.yaml'):
    f = file(FileName_s,'r')
    stream=yaml.load(f)
    return stream
def SaveStream(stream,FileName_s='default.yaml'):
    f = file(FileName_s,'w')
    yaml.dump(stream,f)
    f.close()

def FindCataFromYAML(realapp_name,fromyaml):
    #print ("looking for %s in %s"%(realapp_name,yamlfile))
    #f=LoadStream(yamlfile)
    for i in fromyaml:
        for j in i['Applications']:
            for k in i['Applications'][j]:
                #print (k)
                if k.lower() == realapp_name.lower():
                    return i['CatalogueName']
    return "Others"

if __name__ == '__main__':
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="make lots of noise")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose",default=True,
                      help="be very quiet")
    parser.add_option("-f", "--from_arff",dest="from_arff",
                      metavar="INPUT_ARFF", help="read from INPUT_ARFF")
    parser.add_option("-o", "--output_arff",dest="output_arff_file_name",
                      metavar="OUTPUT_FILES", help="write output OUTPUT_FILES")
    parser.add_option("-c","--catalogue",dest="cataloguefile",
                      metavar="catalogue", help="read from catalogue.yaml",)
    parser.add_option("-d","--details",dest="isdetails",default=True,
                      action="store_true",
                      help="parser ")
    (options, args) = parser.parse_args()
    
    output_real_arff_file_name=""
    
    items = set()
  
    
    if os.path.isdir(options.output_arff_file_name):
        output_real_arff_file_name= os.path.join(output_arff_file_name,'catalogue.arff' )
    elif options.output_arff_file_name:
        output_real_arff_file_name=options.output_arff_file_name
    else:
        output_real_arff_file_name="./catalogue.arff"
    if options.cataloguefile:
        catalogue_yaml_file=options.cataloguefile
    else:
        catalogue_yaml_file="catalogue.yaml"
    if options.from_arff:
        if os.path.isdir(options.from_arff):
            for f in glob.glob(os.path.join(options.from_path, '*.arff')):
                if os.path.isfile(f):
                    items.add(os.path.abspath(f))
        if os.path.isfile(options.from_arff):
            items.add(options.from_arff)
        elif '*' in options.from_arff:
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
    #output_file = open(output_real_arff_file_name,'a')
    #output_file.write(arff_head_s[0])
    #output_file.write(arff_head_s[1])

    #from collections import deque
    
    applist=[]
    opendpi_class_list=[]
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
                #appname = input_arff_filename.split('@')[0].split('/')[-1]
                #print appname
                writline=line
                opendpi_class=''
                
                pp_line = writline.split(',')[-1].strip()
                p_line=pp_line.split('_')[-3:]
                if not p_line[0] == 'notfound' :
                    #print p_line[-1]
                    opendpi_class=p_line[-1]
                else:
                    #print ("ignore notfound apps")
                    continue
                #a=re.compile('^[ \t]*\r?\n?$')
                a=re.compile('^[ \t]*\r?\n?$')
                if not a.match(opendpi_class):
                    if opendpi_class not in applist:
                        applist.append(opendpi_class)
                    if pp_line not in opendpi_class_list:
                        opendpi_class_list.append(pp_line)
                        #print (opendpi_class)
                    #for i in writline.split(',')[:-1]:
                    #    writelines_data.append( i+"," )
                    writelines_data.append(writline.strip()+","+opendpi_class+"\n")
                else:
                    print ("ignore blank apps:"),
                    print (opendpi_class)
                    continue
        p.close()     
    #write output arff file
    f_yaml=LoadStream(catalogue_yaml_file)
    realapp_list=[]
    cata_list=[]
    final_data_to_write=[]
    for write_item in writelines_data:
        splited=write_item.strip().split(',')
        realapp=splited[-1]
        if options.isdetails:
            cata=FindCataFromYAML(splited[-2],f_yaml)
        else:
            cata=FindCataFromYAML(splited[-1],f_yaml)
        if cata not in cata_list:
            cata_list.append(cata)
        if realapp not in realapp_list:
            realapp_list.append(realapp)
        final_data_to_write.append(write_item.strip()+","+cata+"\n")
    output_file = open(output_real_arff_file_name,'a')
    #opendpi_class_list=[]
    output_file.write(arff_head_s[0])
    print("opendpi_class:")
    for i in opendpi_class_list:
        output_file.write( "%s," % i )
        print("\t%s"%i)
    output_file.write(arff_head_s[1])
    output_file.write(arff_head_s[2])
    print ("realapp_class:")
    for i in realapp_list:
        output_file.write( "%s,"% i )
        print ("\t%s"%i)
    output_file.write(arff_head_s[3])
    output_file.write(arff_head_s[4])
    print ("catalogue_class:")
    for i in cata_list:
        output_file.write("%s,"%i)
        print ("\t%s"%i)
    output_file.write(arff_head_s[5])
    output_file.write(arff_head_s[6])
    for ii in final_data_to_write:
        output_file.write(ii)
    output_file.close()
    exit()

