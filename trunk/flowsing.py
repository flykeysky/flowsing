#!/usr/bin/python
# Copyright (c) 
#
#  pcapy: open_offline, pcapdumper.
#  ImpactDecoder.

import os,sys,  logging, socket
import subprocess
import string
from exceptions import Exception
from threading import Thread
from optparse import OptionParser
from subprocess import Popen, PIPE, STDOUT
import re
import glob

import pcapy
from pcapy import open_offline
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import appconfig as APPCONFIG
import ipdef as  IPDEF
sys.stderr=sys.stdout
try:
    from lxml import etree
    if APPCONFIG.GlobalConfig['isVerbose']==True:
        logging.info("running with lxml.etree")
except ImportError:
    try:
        # Python 2.5
        import xml.etree.cElementTree as etree
        if APPCONFIG.GlobalConfig['isVerbose']==True:
            logging.info("running with cElementTree on Python 2.5+")
    except ImportError:
        try:
            # Python 2.5
            import xml.etree.ElementTree as etree
            if APPCONFIG.GlobalConfig['isVerbose']==True:
                logging.info("running with ElementTree on Python 2.5+")
        except ImportError:
            try:
                # normal cElementTree install
                import cElementTree as etree
                if APPCONFIG.GlobalConfig['isVerbose']==True:
                    logging.info("running with cElementTree")
            except ImportError:
                try:
                    # normal ElementTree install
                    import elementtree.ElementTree as etree
                    if APPCONFIG.GlobalConfig['isVerbose']==True:
                        logging.info("running with ElementTree")
                except ImportError:
                    logging.info("Failed to import ElementTree from any known place")
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir) # needed for Py3

#from common_imports import etree, StringIO, BytesIO, HelperTestCase, fileInTestDir
#from common_imports import SillyFileLike, LargeFileLikeUnicode, doctest, make_doctest
#from common_imports import canonicalize, sorted, _str, _bytes

try:
    _unicode = unicode
except NameError:
    # Python 3
    _unicode = str


ETHERNET_MAX_FRAME_SIZE = 1518
PROMISC_MODE = 0


class Connection:
    """This class can be used as a key in a dictionary to select a connection
    given a pair of peers. Two connections are considered the same if both
    peers are equal, despite the order in which they were passed to the
    class constructor.
    """

    def __init__(self, p1, p2, p3):
        """This constructor takes two tuples, one for each peer. The first
        element in each tuple is the IP address as a string, and the
        second is the port as an integer.
        """

        self.p1 = p1
        self.p2 = p2
        #self.p3 = p3
        self.proto_id=int(p3)
        self.protocol = "unknown"
        self.curpath= "."
    def getFilename(self):
        """Utility function that returns a filename composed by the IP
        addresses and ports of both peers.
        """
        try:
            if self.proto_id:
                if self.proto_id == socket.IPPROTO_TCP:
                    self.protocol = "TCP"
                elif self.proto_id == socket.IPPROTO_UDP:
                    self.protocol = "UDP"
                else:
                    self.protocol = IPDEF.ip_protocols[self.proto_id]
        except Exception, e:
            logging.error("failed setting protocol. Error: %s" % str(e))
        #APPCONFIG.GlobalConfig["appname"] = self.FindNameFromXML(self.p1, self.p2, self.protocol)
        appname_s= self.FindNameFromXML(self.p1, self.p2, self.protocol)
        #global this_dir
        self.curpath=APPCONFIG.GlobalConfig["outputpathname"]+os.path.sep+appname_s+os.path.sep
        #self.curpath=os.path.join(APPCONFIG.GlobalConfig["outputpathname"],APPCONFIG.GlobalConfig["appname"])
        APPCONFIG.mkdir_p(self.curpath)
        #print (self.curpath, self.p1[0],self.p1[1],self.protocol, self.p2[0],self.p2[1])
        m ='%s%s-%s-%s-%s-%s.pcap' % (self.curpath, self.p1[0], str(self.p1[1] ),self.protocol, str(self.p2[0] ),self.p2[1])
        return m
    def FindNameFromXML(self, src, dst, protocol):
        for line in APPCONFIG.xmlbuffer:
            if (line[2][1] == src[0]  and line[3][1] ==str(src[1]) and line[4][1] == dst[0] and line[5][1] == str(dst[1]) and line[6][1] == protocol ):
                if APPCONFIG.GlobalConfig['isVerbose']==True:
                    logging.info ( "found!: application %s, PID %s"% (line[0][1] , line[1][1] ))
                app_str= line[0][1] +"@"+line[1][1]
                app_str_limited=''
                p = re.compile('[a-zA-Z0-9,.@]')
                for i in app_str:
                    if p.match(i):
                        app_str_limited+=i
                    else:
                        app_str_limited+='-'
                return app_str_limited
        if APPCONFIG.GlobalConfig['isVerbose']==True:
            logging.info ("missed!....")
        return "notfound_in_XML@0"
    def getNetdudeFileName(self):
        netdude_output_path=APPCONFIG.GlobalConfig['tmp_netdude_path']
        proto_number = self.proto_id
        s_ip=self.p1[0]
        s_port=self.p1[1]
        d_ip=self.p2[0]
        d_port=self.p2[1]
        fullpath1 = "%s%s%d%s%s%s%s"%(netdude_output_path,
                                  os.path.sep,
                                  proto_number,
                                  os.path.sep,
                                  s_ip,
                                  os.path.sep,
                                  d_ip)
        fullpath2 = "%s%s%d%s%s%s%s"% (netdude_output_path,
                                   os.path.sep,
                                   proto_number,
                                   os.path.sep,
                                   d_ip,
                                   os.path.sep,
                                   s_ip)
        fullpath=[fullpath1,fullpath2]
        ports1="*-%s-%s.trace" % (s_port,d_port)
        ports2="*-%s-%s.trace" % (d_port,s_port)
        port_pair = [ports1,ports2]
        tracename_list=[]
        #print ports2
        for i_path in fullpath:
            #print (i_path),
            if os.path.isdir(i_path):
                for i_port in port_pair:
                    #print (i_port)
                    fullfilename=i_path+os.path.sep+i_port
                    #print (fullfilename)
                    for f in  glob.glob(fullfilename):
                        #print (f)
                        if os.path.isfile(f):
                            tracename_list.append(f)
        return tracename_list

    def __cmp__(self, other):
        if ((self.p1 == other.p1 and self.p2 == other.p2)
            or (self.p1 == other.p2 and self.p2 == other.p1)):
            return 0
        else:
            return -1

    def __hash__(self):
        return (hash(self.p1[0]) ^ hash(self.p1[1])^ hash(self.proto_id)
                ^ hash(self.p2[0]) ^ hash(self.p2[1]))


class Decoder:
    def __init__(self, pcapObj):
        # Query the type of the link and instantiate a decoder accordingly.
        self.proto_id = None
        self.src_ip = None
        self.tgt_ip = None
        self.src_port = None
        self.tgt_port = None
        self.msgs = [] # error msgs
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        self.connections = []

    def start(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        """Handles an incoming pcap packet. This method only knows how
        to recognize TCP/IP connections.
        Be sure that only TCP packets are passed onto this handler (or
        fix the code to ignore the others).

        Setting r"ip proto \tcp" as part of the pcap filter expression
        suffices, and there shouldn't be any problem combining that with
        other expressions.
        """

        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        try:
            p = self.decoder.decode(data)
            logging.debug("start decoding" )
        except Exception, e:
            logging.error("p = self.decoder.decode(data) failed for device" )
            msgs.append(str(e))
        # get the details from the decoded packet data
        if p:
            try:
                self.src_ip  = p.child().get_ip_src()
                self.tgt_ip = p.child().get_ip_dst()
                self.proto_id = p.child().child().protocol
            except Exception, e:
                logging.error("exception while parsing ip packet: %s" % str(e))
                self.msgs.append(str(e))
        if self.proto_id:
            try:
                if self.proto_id == socket.IPPROTO_TCP:
                    self.tgt_port = p.child().child().get_th_dport()
                    self.src_port = p.child().child().get_th_sport()
                elif self.proto_id == socket.IPPROTO_UDP:
                    self.tgt_port = p.child().child().get_uh_dport()
                    self.src_port = p.child().child().get_uh_sport()
            except Exception, e:
                logging.error("exception while parsing tcp/udp packet: %s" % str(e))
                self.msgs.append(str(e))
        #ip = p.child()
        #tcp = ip.child()

        # Build a distinctive key for this pair of peers.
        src = (self.src_ip, self.src_port)
        dst = (self.tgt_ip, self.tgt_port )
        con = Connection(src,dst, self.proto_id)
        outputPCAPFileName=con.getFilename()
        tmpPCAPFileName="/tmp/appending.pcap"
        appendpcap_cmd_1=''

        #dumper = self.pcap.dump_open(tmpPCAPFileName)
        #os.remove(tmpPCAPFileName)
        #open(tmpPCAPFileName, 'w').close() 
        #dumper = self.pcap.dump_open(tmpPCAPFileName)
        #if not self.connections.has_key(con):

        if con not in self.connections:
            logging.info("found flow for the first time: saving to %s" % outputPCAPFileName)
            #self.connections[con]=1            
            self.connections.append(con)
            try:
                open(outputPCAPFileName, 'w').close()                
                dumper = self.pcap.dump_open(outputPCAPFileName)
                dumper.dump(hdr,data)
            except pcapy.PcapError, e:
                logging.error( "Can't write packet to :%s\n---%s", outputPCAPFileName, str(e) )
            del dumper
        else:
            logging.info( "found duplicated flows, creating a tempfile: %s to append to %s" % (tmpPCAPFileName,outputPCAPFileName) )
            try:
                open(tmpPCAPFileName, 'w').close()                 
                dumper = self.pcap.dump_open(tmpPCAPFileName)
                dumper.dump(hdr,data)
            except pcapy.PcapError, e:
                logging.error("Can't write packet to:\n---%s ", tmpPCAPFileName,str(e) )
            ##Write the packet to the corresponding file.
            del dumper
            tmpPCAPFileName2 = "/tmp/append2.pcap"
            if os.path.isfile(outputPCAPFileName):
                #os.rename( outputPCAPFileName , tmpPCAPFileName2 )
                os.system("mv %s %s"%( outputPCAPFileName, tmpPCAPFileName2 ))
                appendpcap_cmd_1 = "mergecap -w %s %s %s " % (outputPCAPFileName,tmpPCAPFileName2,tmpPCAPFileName)
                #appendpcap_cmd_1="pcapnav-concat %s %s"%(outputPCAPFileName, tmpPCAPFileName)
                os.system(appendpcap_cmd_1)
                #self.connections[con] += 1
                os.remove(tmpPCAPFileName2)
                #os.rename(tmpPCAPFileName2,outputPCAPFileName)
                #logging.info ( self.connections[con] )
            else:
                logging.error( "did nothing" )
                logging.error("%s is in %s\ntry again!!!" % (outputPCAPFileName, str(con in self.connections) ))
                try:
                    dumper = self.pcap.dump_open(outputPCAPFileName)
                    dumper.dump(hdr,data)
                except pcapy.PcapError, e:
                    logging.error( "Can't write packet to :%s\n---%s", outputPCAPFileName, str(e) )
                del dumper
                logging.error("succeded =%s" % str(os.path.isfile(outputPCAPFileName)))

class NetdudeDecoder(Decoder):
    """
    """
    
    def __init__(self,pcapObj ):
        """
        """
        self.proto_id = None
        self.src_ip = None
        self.tgt_ip = None
        self.src_port = None
        self.tgt_port = None
        self.msgs = [] # error msgs
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        self.connections = []
        
    def packetHandler(self, hdr, data):
        try:
            p = self.decoder.decode(data)
            logging.debug("start decoding" )
        except Exception, e:
            logging.error("p = self.decoder.decode(data) failed for device" )
            msgs.append(str(e))
        # get the details from the decoded packet data
        if p:
            try:
                self.src_ip  = p.child().get_ip_src()
                self.tgt_ip = p.child().get_ip_dst()
                self.proto_id = p.child().child().protocol
            except Exception, e:
                logging.error("exception while parsing ip packet: %s" % str(e))
                self.msgs.append(str(e))
        if self.proto_id:
            try:
                if self.proto_id == socket.IPPROTO_TCP:
                    self.tgt_port = p.child().child().get_th_dport()
                    self.src_port = p.child().child().get_th_sport()
                elif self.proto_id == socket.IPPROTO_UDP:
                    self.tgt_port = p.child().child().get_uh_dport()
                    self.src_port = p.child().child().get_uh_sport()
            except Exception, e:
                logging.error("exception while parsing tcp/udp packet: %s" % str(e))
                self.msgs.append(str(e))

        src = (self.src_ip, self.src_port)
        dst = (self.tgt_ip, self.tgt_port )
        con = Connection(src,dst, self.proto_id)
        outputPCAPFileName=con.getFilename()

        merge_cmd1="mergecap -w %s" % (outputPCAPFileName)
        merge_cmd_readtrace_filename=' '
        
        readPCAPFileNameFromNetdude=con.getNetdudeFileName()
        
        for rr in readPCAPFileNameFromNetdude:
            merge_cmd_readtrace_filename += ( "%s " % (rr) )
        merge_cmd = ("%s%s" % (merge_cmd1, merge_cmd_readtrace_filename) )
        print (merge_cmd)
        os.system(merge_cmd)
        print ("------")
        tmpPCAPFileName="/tmp/appending.pcap"
        appendpcap_cmd_1=''
        
 


import shutil

def SplitPcapByNetdude():
    shutil.rmtree(APPCONFIG.GlobalConfig["tmp_netdude_path"],ignore_errors=True)
    netdude_cmd1=( "lndtool -r Demux -o %s %s" % (APPCONFIG.GlobalConfig["tmp_netdude_path"], APPCONFIG.GlobalConfig["pcapfilename"]) )
    os.system(netdude_cmd1)
    # Open file
    filename=APPCONFIG.GlobalConfig["pcapfilename"]
    #print filename
    p = open_offline(filename)
    # At the moment the callback only accepts TCP/IP packets.
    #p.setfilter(r'ip proto \tcp')
    p.setfilter(r'ip')
    print "Reading from %s: linktype=%d" % (filename, p.datalink())
    # Start decoding process.
    NetdudeDecoder(p).start()
    
    os.system('ls %s' % (APPCONFIG.GlobalConfig["tmp_netdude_path"] ))
    os.system("rm -rf %s"% (APPCONFIG.GlobalConfig["tmp_netdude_path"] ) )
def getFiveTupleListFromDemuxedPath(demuxedpath):
    #print ("in getFiveTupleFromDemuxedPath")
    fivetuplelist=[]
    for (thisDir, subsHere, filesHere) in os.walk(demuxedpath):
        for filename in filesHere:
            (shortname, extension) = os.path.splitext(filename)
            pcapfullname = os.path.join(thisDir,filename)
            if( os.path.isfile(pcapfullname) and (extension==".trace" or extension == ".TRACE" ) ):
                ipprotocol_pair=thisDir.split(os.path.sep)[-3:]
                pro_num=ipprotocol_pair[0]
                ip_pair=ipprotocol_pair[-2:]
                if ipprotocol_pair[0]  in ['6','17']:
                    port_pair=shortname.split('-')[-2:]
                    a = ((ip_pair[0],port_pair[0]),(ip_pair[1],port_pair[1]),pro_num)
                    fivetuplelist.append(a)
                else:
                    logging.info ("no ip protocol %s "%(ipprotocol_pair[0]))
    return fivetuplelist
def SplitPcapByTraverseNetdudeDir():
    shutil.rmtree(APPCONFIG.GlobalConfig["tmp_netdude_path"],ignore_errors=True)
    netdude_cmd1=( "lndtool -r Demux -o %s %s" % (APPCONFIG.GlobalConfig["tmp_netdude_path"], APPCONFIG.GlobalConfig["pcapfilename"]) )
    os.system(netdude_cmd1)
    # Start decoding process.
    #print ("%s\n%s\n%s"% (APPCONFIG.GlobalConfig["xmlfilename"], APPCONFIG.GlobalConfig["tmp_netdude_path"], APPCONFIG.GlobalConfig["outputpathname"]) )
    xmlFilename =APPCONFIG.GlobalConfig['xmlfilename']
    tmpNetdudeDir = APPCONFIG.GlobalConfig['tmp_netdude_path']
    outputDir = APPCONFIG.GlobalConfig['outputpathname']
    
    fivetupleList=getFiveTupleListFromDemuxedPath(tmpNetdudeDir)
    connections = []
    merge_cmd=''
    for i in fivetupleList:
        #print (i)
        con = Connection(i[0],i[1],i[2])
        if con not in connections:
            connections.append(con)
            outputPCAPFileName=con.getFilename()
            inputPCAPFileNameList=con.getNetdudeFileName()
            #print (outputPCAPFileName)
            #print (inputPCAPFileNameList)
            merge_cmd1="mergecap -w %s" % (outputPCAPFileName)
            merge_cmd_readtrace_filename=' '
            for rr in inputPCAPFileNameList:
                merge_cmd_readtrace_filename += ( "%s " % (rr) )
            merge_cmd = ("%s%s" % (merge_cmd1, merge_cmd_readtrace_filename) )
            print (merge_cmd)
            os.system(merge_cmd)
        else:
            print ("duplicated! in SplitPcapByTraverseNetdudeDir")
            print i
    
    os.system('ls %s' % (APPCONFIG.GlobalConfig["tmp_netdude_path"] ))
    #os.system("rm -rf %s"% (APPCONFIG.GlobalConfig["tmp_netdude_path"] ) )
    #os.system(merge_cmd)

def main():
    #mkdir output_path
    APPCONFIG.mkdir_p(APPCONFIG.GlobalConfig["outputpathname"])
    xmlfile=open(APPCONFIG.GlobalConfig["xmlfilename"], 'r')
    root = etree.parse(xmlfile)
    for element in root.iter("session"):
    	line=element.attrib.items()
	APPCONFIG.xmlbuffer.append(line)
    if APPCONFIG.GlobalConfig["isNetdude"] == True:
        logging.info("splitting pcap trace into flows by netdude")
        #SplitPcapByNetdude()
        SplitPcapByTraverseNetdudeDir()
    if APPCONFIG.GlobalConfig["isSplit"]==True:
        logging.info("splitting pcap trace into flows")
        SplitPcap()
    if APPCONFIG.GlobalConfig["isMerge"]==True:
        logging.info("Merging flows into applications")
        MergepcapInDir(APPCONFIG.GlobalConfig["outputpathname"])
    if APPCONFIG.GlobalConfig["isFeature"]==True:
        logging.info("computing flow features")
        FeatureCompute(APPCONFIG.GlobalConfig["outputpathname"])
    if APPCONFIG.GlobalConfig['ismergearff']==True:
        logging.info ("merging arff filenames")
        MergeARFF(APPCONFIG.GlobalConfig["outputpathname"])
    logging.info("---done---")
def SplitPcap():
    # Open file
    filename=APPCONFIG.GlobalConfig["pcapfilename"]
    #logging.info (filename )
    p = open_offline(filename)
    # At the moment the callback only accepts TCP/IP packets.
    #p.setfilter(r'ip proto \tcp')
    p.setfilter(r'ip')
    logging.info ("Reading from %s: linktype=%d" % (filename, p.datalink()) )
    # Start decoding process.
    Decoder(p).start()
    #p.close() #flk3y: avoid p.close() error, after GC?
def FeatureCompute(currentdirname):
    for (thisDir, subsHere, filesHere) in os.walk(currentdirname):
        for filename in filesHere:
            (shortname, extension) = os.path.splitext(filename)
            pcapfullname = os.path.join(thisDir,filename)
            #featurefilename = 
            if( os.path.isfile(pcapfullname) and (extension==".pcap" or extension == ".PCAP" ) ):
                #fullfeaturefilename=pcapfullname+".arff"
                #cmd1_s= "rm %s" % (APPCONFIG.GlobalConfig['tmp_arff_filename'])
                if os.path.isfile(APPCONFIG.GlobalConfig['tmp_arff_filename']):
                    os.remove(APPCONFIG.GlobalConfig['tmp_arff_filename'])
                cmd1_s='OpenDPI_demo -f %s' % pcapfullname
                p = Popen(cmd1_s, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT,close_fds=True)
                output = p.stdout.read()
                prog=re.compile("###.*###")
                m = prog.search(output)
                p = re.compile('[a-zA-Z0-9,.@#_]')
                app_str_limited=''
                for i in m.group(0):
                    if p.match(i):
                        app_str_limited+=i
                    else:
                        app_str_limited+='='
                appfilename=pcapfullname+"."+app_str_limited+".arff"
                logging.info ("computing feature to: %s" % appfilename)
                cmd2_s= "netmate -f %s" % (pcapfullname )
                cmd3_s= "mv %s %s"%(APPCONFIG.GlobalConfig['tmp_arff_filename'],appfilename)
                #os.system(cmd1_s)
                #os.system(cmd2_s)
                #os.system(cmd3_s)
                allcmd_s=("%s && %s"%(cmd2_s,cmd3_s))
                os.system(allcmd_s)
            else:
                logging.info ("%s is not a directory" % pcapfullname )
                pass
def MergepcapInDir(currentdirname):#TODO: add mergecap files into a list, then pop up when merging
    all_cmd_s=[] 
    BATCH_NUM=50
    tmp_pcap="/tmp/tmp_pcap"
    os.system(("rm -f %s%s*.pcap ")%(currentdirname,os.sep))
    for (thisDir, subsHere, filesHere) in os.walk(currentdirname):
        for filename in subsHere:
            #print ("==%s" % filename)
            fullname = os.path.join(thisDir,filename)
            if(os.path.isdir(fullname) ):
                pcapname=fullname+".pcap"
                print ("==%s" % filename)
                os.system(("rm -f %s ")%(tmp_pcap))
                pcap_list=[]
                #if os.path.isfile(pcapname):
                #    os.remove(pcapname)
                for (f_dir,f_subs,f_files) in os.walk(fullname):
                    pcap_f=[]
                    for f in f_files:
                        if (f[-5:] == '.pcap'):
                            pcap_f.append(f_dir+os.sep+f)
                    #print (pcap_f)
                    while (len(pcap_f) != 0):
                        tmp_s=""
                        pcap_f_length=len(pcap_f)
                        if (pcap_f_length >=BATCH_NUM):
                            for i in range(BATCH_NUM) :
                                tmp_s =tmp_s+" "+pcap_f.pop()+" "
                            pcap_list.append(tmp_s)
                        else:
                            for i in range(pcap_f_length):
                                tmp_s=tmp_s+" "+pcap_f.pop()+" "
                                #print (tmp_s)
                            pcap_list.append(tmp_s)
                        print ("remaining pcap %d files to read" % pcap_f_length)
                    #print (pcap_list)
                    #for i in pcap_list:
                    #    #cmd_s='mergecap -w  %s %s' % (pcapname,i)
                    #    all_cmd_s.append(i)
                        #print (cmd_s)
                    #print (all_cmd_s)
                print ("----- %s ------\ntmp_pcap   output_pcap" % pcapname)
                logging.info ("%s is a directory, merging all pcap files in it" % fullname )
                for i in pcap_list:
                    if ( os.path.isfile(tmp_pcap) and os.path.isfile(pcapname) ):
                        print ("  Y         Y  :You'd better not be here, but it OK")
                        os.remove(tmp_pcap)
                        #os.rename(pcapname,tmp_pcap)
                        os.system( "mv %s %s"% ( pcapname , tmp_pcap) )
                        cmd="mergecap -w %s  %s %s" % (pcapname,tmp_pcap,i)
                        os.system(cmd)
                        os.remove(tmp_pcap)
                    elif ( os.path.isfile(tmp_pcap) and (not os.path.isfile(pcapname)) ):
                        print ("  Y         N  :You should not be here! there may errors happened ") 
                        cmd="mergecap -w %s  %s %s" % (pcapname,tmp_pcap,i)
                        os.system(cmd)
                    elif ((not os.path.isfile(tmp_pcap)) and (os.path.isfile(pcapname)) ) :
                        print ("  N         Y") 
                        #os.rename(pcapname,tmp_pcap)
                        os.system( "mv %s %s" % ( pcapname,tmp_pcap ) )
                        cmd="mergecap -w %s  %s %s" % (pcapname,tmp_pcap,i)
                        os.system(cmd)
                        os.remove(tmp_pcap)
                    else:
                        print ("creating...\n  N         N")
                        cmd="mergecap -w %s  %s" % (pcapname,i)
                        #print (cmd)
                        os.system(cmd)
            else:
                logging.info ("%s is not a directory" % fullname )

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
@ATTRIBUTE opendpiclass  {''',
'''}

% you need to add a nominal class attribute!
% @ATTRIBUTE class {class0,class1}

@DATA

''')
def MergeARFF(currentdirname):
    global arff_head_s
    for (thisDir, subsHere, filesHere) in os.walk(currentdirname):
        for dirname in subsHere:
            fullsubdirname = os.path.join(thisDir,dirname)
            if(os.path.isdir(fullsubdirname) ):
                #appendable=False
                arff_big_name=fullsubdirname+".merged.arff"
                opendpiclass_list=[]
                writelines_data=[]
                if (os.path.isfile(arff_big_name)) :
                    os.remove(arff_big_name)
                appendable = True
                #q_arff_big = open(arff_big_name,'a')
                #q_arff_big.write(arff_head_s[0])
                #q_arff_big.write("test")
                #q_arff_big.write(arff_head_s[1])
                logging.info ("%s is a directory, merging all arff files in it" % fullsubdirname )
                for (sub_thisdir,sub_subshere,sub_filesHere ) in os.walk(fullsubdirname):
                    for filename in sub_filesHere:
                        (shortname, extension) = os.path.splitext(filename)
                        foundData=False
                        #appendable=False
                        #logging.info ("merging %s" % filename)
                        if( (extension==".arff" or extension == ".ARFF" )  and (shortname[-3:]=='###' ) ):
                            logging.info ("merging %s" % filename)
                            opendpi_apptype=shortname.split('.')[-1][3:-3] # for example: blah.blah.blah.###type1_type2_###
                            logging.error (opendpi_apptype)
                            if opendpi_apptype not in opendpiclass_list:
                                opendpiclass_list.append(opendpi_apptype)
                            full_arff_name = os.path.join(sub_thisdir,filename)
                            if appendable == True:
                                p = open(full_arff_name,'r')
                                for line in p.readlines():
                                    prog=re.compile("^@DATA")
                                    m = prog.match(line)
                                    if m:
                                        foundData=True
                                        continue
                                    if ( foundData==True and ( not line.isspace() ) and (not re.match('^@',line))  and (not re.match('^%',line))  ):
                                        #q_arff_big.write
                                        writelines_data.append( (line.strip()+","+opendpi_apptype+"\n") )
                q_arff_big = open(arff_big_name,'a')
                q_arff_big.write(arff_head_s[0]) 
                for i in opendpiclass_list:
                    q_arff_big.write( "%s," % i )
                q_arff_big.write(arff_head_s[1])
                for ii in writelines_data:
                    q_arff_big.write(ii)
                q_arff_big.close()                
            else:
                logging.info ("%s is not a directory" % fullname )
                pass
def ParseCMD():
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="make lots of noise")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose",
                      help="be very quiet")
    parser.add_option("-x","--xmlfilename",dest="xmlfilename",
                      metavar="XML", help= "read XML, which was generated by network bandwith monitor")
    parser.add_option("-f", "--pcapfilename",dest="pcapfilename",
                      metavar="FILE", help="write output to FILE")
    parser.add_option("-o", "--output_path",dest="output_path",
                      metavar="OUTPUT_PATH", help="write output OUTPUT_PATH/FILE.demux")
    #parser.add_option('-M', '--MODE',
    #                  type='choice',
    #                  action='store',
    #                  dest='modechoice',
    #                  choices=['all','split_only', 'merge_only', 'feature_only',],
    #                  default='all',
    #                  help='mode to run on: all, split_only, merge_only, feature_only',)
    parser.add_option("-a", "--all",
                      default=False,
                      dest='isall',
                      action='store_true',
                      help="enable all: split->merge->calculate features ",)
    parser.add_option("-s","--split",
                      default=False,
                      dest='issplit',
                      action='store_true',
                      help="split pcap trace into flows",)
    parser.add_option("-m","--merge",
                      default=False,
                      dest='ismerge',
                      action='store_true',
                      help="merge flows from the same application into one pcap trace",)
    parser.add_option("-g","--mergearff",
                      default=False,
                      dest='ismergearff',
                      action='store_true',
                      help="merge .arff files from the same application into one",)
    parser.add_option("-c","--computefeatures",
                      default=False,
                      dest='isfeature',
                      action='store_true',
                      help="compute features for every pcap file in OUTPUT_PATH",)
    parser.add_option("-n","--netdude",
                      default=False,
                      dest='isNetdude',
                      action='store_true',
                      help="enable libnetdude's demuxer")
    (options, args) = parser.parse_args()
    #if len(args) != 1:
    #    parser.error("incorrect number of arguments")
    if options.pcapfilename:
        APPCONFIG.GlobalConfig["pcapfilename"] = options.pcapfilename
    if options.output_path:
        APPCONFIG.GlobalConfig["outputpathname"] = options.output_path
    else:
        APPCONFIG.GlobalConfig["outputpathname"] = options.pcapfilename+".demux"
    if options.xmlfilename:
        APPCONFIG.GlobalConfig["xmlfilename"]= options.xmlfilename
    if options.isall:
        APPCONFIG.GlobalConfig['isAll']=True
        options.issplit=True
        APPCONFIG.GlobalConfig['isSplit']=True
        options.ismerge=True
        APPCONFIG.GlobalConfig['isMerge']=True
        options.isfeature=True
        APPCONFIG.GlobalConfig['isFeature']=True        
    if options.isNetdude:
        options.isNetdude=True
        options.issplit=False
        APPCONFIG.GlobalConfig['isSplit']=False
        APPCONFIG.GlobalConfig['isNetdude']=True    
    if options.issplit:
        options.issplit=True
        APPCONFIG.GlobalConfig['isSplit']=True
    if options.ismerge:
        options.ismerge=True
        APPCONFIG.GlobalConfig['isMerge']=True
    if options.ismergearff:
        options.ismergearff=True
        APPCONFIG.GlobalConfig['ismergearff']=True
    if options.isfeature:
        options.isfeature=True
        APPCONFIG.GlobalConfig['isFeature']=True        
    if options.verbose:
        APPCONFIG.GlobalConfig['isVerbose']=True
        logging.info ("------running info.---------")
        logging.info ("Reading xmlfile  %s..." % options.xmlfilename)
        logging.info ("Reading pcapfile %s..." % options.pcapfilename)
        if options.output_path:
            logging.info ("demux to path: %s"%options.output_path)
        else:
            logging.info ("have not assigned, output to %s.demux by default"%options.pcapfilename)
        logging.info ( "Split pcap trace: %s" % str(APPCONFIG.GlobalConfig['isSplit']) )
        logging.info ( "Merge flows into applications: %s"% str(APPCONFIG.GlobalConfig['isMerge']) )
        logging.info ( "compute features: %s"% str(APPCONFIG.GlobalConfig['isFeature']) )
        logging.info ("------------end info.------------")

# Process command-line arguments.
if __name__ == '__main__':
    ParseCMD()
    main()
    exit()
