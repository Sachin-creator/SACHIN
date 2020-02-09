import struct
import os
import math
import sys
import numpy as np
import Tkinter
import tkFileDialog
import matplotlib.pyplot as plt
from optparse import OptionParser

prgms = 1

class SystemClock:
    def __init__(self):
        self.PCR_base_hi = 0x0
        self.PCR_base_lo = 0x0
        self.PCR_extension = 0x0
    def setPCR(self, PCR_base_hi, PCR_base_lo, PCR_extension):
        self.PCR_base_hi = PCR_base_hi
        self.PCR_base_lo = PCR_base_lo
        self.PCR_extension = PCR_extension
    def getPCR(self):
        return self.PCR_base_hi, self.PCR_base_lo, self.PCR_extension

class PESPacketInfo:
    def __init__(self):
        self.PTS_hi = 0
        self.PTS_lo = 0
        self.streamID = 0
        self.AUType = ""
    def setPTS(self, PTS_hi, PTS_lo):
        self.PTS_hi = PTS_hi
        self.PTS_lo = PTS_lo
    def getPTS(self):
        return self.PTS_hi, self.PTS_lo
    def setStreamID(self, streamID):
        self.streamID = streamID
    def setAUType(self, auType):
        self.AUType = auType
    def getStreamID(self):
        return self.streamID
    def getAUType(self):
        return self.AUType

import struct
import os
def getNextBuffer(packetS, file):
    buf = file.read(packetS * CHUNK())
    return buf

def getNextPck(buffer,pckSize,index):
    return buffer[index*pckSize:pckSize*(index+1)]

def getPCRValue(buffer):
    base =(struct.unpack(">Q", buffer[6:14])[0] & 0xFFFFFFFF80000000) >> 31 #pcr base
    ext = (struct.unpack(">Q", buffer[6:14])[0] & 0x0000000001FF0000) >> 16 #pcr ext (there is 6 reserved bits between base and ext)
    pcr = base*300 + ext
    if pcr==0:
       print pcr
       exit
    return pcr

def CHUNK():
    return 10000 

def getTSPacketSize(bufferTest):
    i=0
    j=0
    pckSize=188
    Sizefound=False
    while (not Sizefound): #and (i < bufferTest.len):
        char = hex(struct.unpack("B",bufferTest[i])[0])
        if char==hex(71):
            i=i+pckSize
            j=j+1
        else:
            if j==0:
                i=i+1
            else:
                if j==1:
                    i=i+16 #188+16=204
                    pckSize=204
                else:
                    pckSize=-1
        if j>3:
            Sizefound=True
            offset = i - 4*pckSize    #remove 4 packets from initial position, since 4 * pckSizes was needed to establish packet size
       
    return (pckSize,offset)

def isPCRPid(buffer):
    
    adaptFieldControl =(struct.unpack(">B", buffer[3:4])[0] & 0x30)>>4
    if (adaptFieldControl == 2 or adaptFieldControl == 3):
        if ((struct.unpack(">B", buffer[5:6])[0] & 0x10)> 0x0):
            return struct.unpack(">H", buffer[1:3])[0] & 0x01FFF
    else:
        return -1


def TSBitrate(infile, PcrPid):
    filename = open(infile, 'rb')
    bufferTest = filename.read(CHUNK())
    (packetL,offset)=getTSPacketSize(bufferTest)
    fourPcrs = 0
    filename.seek(offset)
    PcrArray = []
    PckArray = []
    Rate =[]
    i=0
    
    while fourPcrs <1000:
        wBuffer=getNextBuffer(packetL,filename)
        #print packetL
        here = False
        j=0
        while j<CHUNK() and not here:
            wPacket=getNextPck(wBuffer,packetL,j)
            Pid=isPCRPid(wPacket)
            #print PcrPid,Pid
            if  Pid > 0 and (PcrPid == Pid or fourPcrs ==0):
                #pcr_count +=1
                PcrPid =Pid
                PckArray.append(i+j+1)
                PcrArray.append(getPCRValue(wPacket))
                fourPcrs = fourPcrs + 1
                if fourPcrs == 1000:
                    here = True
                
            j=j+1
        i=i+CHUNK()
    tsRate=0
    tsRate= ((PckArray[-1]-PckArray[0])*packetL*8*(27000000))/(PcrArray[-1]-PcrArray[0])
    print "TSBitrate=", tsRate
    filename.close()
    del bufferTest
    del wBuffer
    del wPacket
    return tsRate

def PTS_PCR_Diff(infile, PCR_pid, PTS_pid):
    found= False
    sync_pointer=0
    continuity_counter = 0
    previous_CC=0
    loop_breaker = 1
    adaptation_field_length=0
    j = 0
    pts = 0
    k = 0
    prev_pcr =0
    num_TS_Pkts = 0
    prev_j = 0
    TS_rate = 0
    cc_error = 0
    filename = open(infile, 'rb')
    large_file = False
    size = os.path.getsize(infile)
    readTS = filename.read(1024)
    (TSPacketSize,offFirst)= getTSPacketSize(readTS)
    filename.seek(offFirst)
    num_TS_Pkts = size/TSPacketSize
    pcr_accuracy=0.0
    pcr_repetition = 0.0
    pcr_interval = 0.0
    last_pcr = 0
    npcr=0
    npts=0
    pcr = 0
    pcr_flag = 0
    prev_TSpkt = 0
    pcr_rep = 0.0
    num_of_TS_pkts_since_last_PCR = 0
    time_since_last_PCR = 0
    current_pcr = 0
    PTS=0
    PTSPCRDiff=0
    PTSPCRDiff_mseconds = 0
    prev_PTS_pkt =0
    stream_ID=0
    x_TS =[]
    y_PTS_PCR =[]
    Y_pcr = []
    y_PTS = []
    y_PCR_repetition= []
    j2k=0
    pcr_rep=0
    y_PCR_acc = []
    y_PTS_interval=[]
    PTS_Interval=0
    PTS_prev =0
    PTSPIDFound= False
    TS_bitrate = TSBitrate(infile,PCR_pid)
    next_chunk =0
    exp_pcr = 0.0
    print 'PCR PID = %d, PTS PID = %d are being analysed' %(PCR_pid, PTS_pid)
    while loop_breaker < num_TS_Pkts :
        wBuffer=getNextBuffer(TSPacketSize,filename)
        j = 0
        while j<CHUNK()and loop_breaker < num_TS_Pkts:
              readTS=getNextPck(wBuffer,TSPacketSize,j)
              sync_pointer = 0
              sync_byte = hex(struct.unpack("B",readTS[sync_pointer])[0])
              if sync_byte==hex(71) :

                 TEI= struct.unpack("B",readTS[sync_pointer+1])[0] & 0x80
                 if TEI != 0:
                    print "TRANSPORT ERROR INDICATOR is SET"
                    break
                 Payload_unit_start_indicator= (struct.unpack("B",readTS[sync_pointer+1])[0] & 0b01000000 ) >> 6
                 pid = (struct.unpack(">H", readTS[sync_pointer+1: sync_pointer+3])[0] & 0x1FFF)
                 if pid == PTS_pid:
                    PTSPIDFound = True
                    #print pid
                 scrambling_control = struct.unpack("B",readTS[sync_pointer+3])[0] & 0xC0
                 if scrambling_control != 0:
                    print "TS SCRAMBLING ENABLED!!!!"
                    #Can go further to see if it is even key or odd key- left for future implementation.

                 adaptation_field = struct.unpack("B",readTS[sync_pointer+3])[0] & 0x30
                 adaptation_field = adaptation_field >> 4
                 if (adaptation_field == 2 or adaptation_field == 3) :
                    adaptation_field_length = struct.unpack("B",readTS[sync_pointer+4])[0] & 0xFF
                    if adaptation_field_length > 0 :
                       pcr_flag= (struct.unpack("B",readTS[sync_pointer+5])[0] & 0x10) >> 4
                       #print "PCR_Flag=",pcr_flag
                       opcr_flag=(struct.unpack("B",readTS[sync_pointer+5])[0] & 0x8) >> 3

                       if pid == PCR_pid and pcr_flag==1: 
                          base =((struct.unpack(">Q", readTS[sync_pointer+6 : sync_pointer+14])[0] & 0xFFFFFFFF80000000) >> 31 ) % (2**33) #pcr base
                          ext = ((struct.unpack(">Q", readTS[sync_pointer+6 : sync_pointer+14])[0] & 0x0000000001FF0000) >> 16 ) % 300 #pcr ext (there is 6 reserved bits between base and ext)
                          pcr = (base*300 + ext)
                          npcr += 1
                          if npcr > 1 and prev_TSpkt!= loop_breaker:
                             #TS_bitrate = TSBitrate(infile,PCR_pid)
                          #if npcr > 1 :
                             if TS_bitrate !=0 :
                                #print TS_bitrate 
                                (pcr_interval) = (((float(loop_breaker) - float(prev_TSpkt) ) * float(TSPacketSize)*8))/ float(TS_bitrate) 
                                (pcr_rep) = float(pcr_interval)*1000
                                (exp_pcr) = float(prev_pcr) + (float(pcr_interval) * float(27000000))
                                (pcr_accuracy) = (((float(pcr) - float(exp_pcr)))/(float(27000000))) 
                                pcr_accuracy = float(pcr_accuracy) *float(1000000000)
                             else:
                                print "TS Bitrate found to be 0"
                                exit(10)
                          prev_TSpkt = loop_breaker
                          prev_pcr =pcr
                          



                 if Payload_unit_start_indicator == 1  and pid == PTS_pid and pid != 8191 and pid!=7999 and (adaptation_field == 1 or adaptation_field == 3) :

                    adaptation_field_length = struct.unpack("B",readTS[sync_pointer+4])[0]
                    #Expecting 0xFF64000E4D4D for J2K
                    if ( 0xFF64000E4D4D == (struct.unpack(">Q", readTS[sync_pointer+4:sync_pointer+12])[0] >> 16)):
                       j2k=1
                       npts += 1
                       PTS = (struct.unpack(">Q", readTS[sync_pointer+12:sync_pointer+20])[0] >> 32) + (((struct.unpack(">B", readTS[sync_pointer+19:sync_pointer+20])[0]) & 0x01) << 32)
                       num_of_TS_pkts_since_last_PCR = loop_breaker - prev_TSpkt
                       num_of_TS_pkts_since_last_PTS = loop_breaker - prev_PTS_pkt
                       if TS_bitrate != 0 :
                          time_since_last_PCR = ( num_of_TS_pkts_since_last_PCR *TSPacketSize*8)/float(TS_bitrate)
                          PTS_Interval = ( num_of_TS_pkts_since_last_PTS *TSPacketSize*8*1000)/float(TS_bitrate)
                       current_pcr = prev_pcr + (time_since_last_PCR*27000000)
                    if adaptation_field == 3:
                       PTS_DTS_Flag = (struct.unpack("B",readTS[sync_pointer+4+adaptation_field_length+1+7])[0] & 0b11000000 )>> 6
                    if adaptation_field == 1:
                       PTS_DTS_Flag = (struct.unpack("B",readTS[sync_pointer+4+7])[0] & 0b11000000 )>> 6

                    if adaptation_field == 1 and (PTS_DTS_Flag == 2 or PTS_DTS_Flag == 3) and j2k !=1 :
                          npts += 1
                          num_of_TS_pkts_since_last_PCR = loop_breaker - prev_TSpkt
                          num_of_TS_pkts_since_last_PTS = loop_breaker - prev_PTS_pkt
                          if TS_bitrate != 0:
                             time_since_last_PCR = ( num_of_TS_pkts_since_last_PCR *TSPacketSize*8)/float(TS_bitrate)
                             PTS_Interval = ( num_of_TS_pkts_since_last_PTS *TSPacketSize*8*1000)/float(TS_bitrate)
                             current_pcr = prev_pcr + (time_since_last_PCR*27000000)
                             stream_ID= struct.unpack("B",readTS[sync_pointer+7])[0]

                             PTS_32_30= (struct.unpack(">Q",readTS[sync_pointer+10 : sync_pointer+18 ])[0] & 0x0000000E00000000) >> 3
                             PTS_29_15= (struct.unpack(">Q",readTS[sync_pointer+10 : sync_pointer+18 ])[0] & 0x00000000FFFE0000) >> 2
                             PTS_14_0=  (struct.unpack(">Q",readTS[sync_pointer+10 : sync_pointer+18 ])[0] & 0x000000000000FFFE) >> 1
                             PTS= PTS_32_30 + PTS_29_15 + PTS_14_0

                    if adaptation_field == 3 and (PTS_DTS_Flag == 2 or PTS_DTS_Flag == 3) and j2k !=1: ##loop_breaker > 6000 to ignore first couple of frames
                          npts += 1
                          num_of_TS_pkts_since_last_PCR = loop_breaker - prev_TSpkt
                          num_of_TS_pkts_since_last_PTS = loop_breaker - prev_PTS_pkt
                          if TS_bitrate != 0:
                             time_since_last_PCR = ( num_of_TS_pkts_since_last_PCR *TSPacketSize*8)/float(TS_bitrate)
                             PTS_Interval = ( num_of_TS_pkts_since_last_PTS *TSPacketSize*8*1000)/float(TS_bitrate)
                             current_pcr = prev_pcr + (time_since_last_PCR*27000000)
                             stream_ID= struct.unpack("B",readTS[sync_pointer+adaptation_field_length+1+7])[0]

                             PTS_32_30= (struct.unpack(">Q",readTS[sync_pointer+adaptation_field_length+11 : sync_pointer+adaptation_field_length+19 ])[0] & 0x0000000E00000000) >> 3
                             PTS_29_15= (struct.unpack(">Q",readTS[sync_pointer+adaptation_field_length+11 : sync_pointer+adaptation_field_length+19 ])[0] & 0x00000000FFFE0000) >> 2
                             PTS_14_0=  (struct.unpack(">Q",readTS[sync_pointer+adaptation_field_length+11: sync_pointer+adaptation_field_length+19 ])[0] & 0x000000000000FFFE) >> 1
                             PTS= PTS_32_30 + PTS_29_15 + PTS_14_0
                    PTS_diff = PTS- PTS_prev
                    PTS_prev= PTS

                    if current_pcr > 0 and npcr> 1 and npts > 1:

                       PTSPCRDiff = PTS - (current_pcr/300)
                       PTSPCRDiff_mseconds = PTSPCRDiff*1000/float(90000)
                       y_PTS_PCR.append(PTSPCRDiff_mseconds)
                       x_TS.append(loop_breaker)
                       Y_pcr.append(pcr)
                       y_PTS.append(PTS*300)
                       y_PCR_repetition.append(pcr_rep)
                       y_PCR_acc.append(pcr_accuracy)
                       y_PTS_interval.append(PTS_Interval)

                    if PTSPCRDiff < 0 and current_pcr > 0 and npcr > 1 and npts > 1:
                       found= 1
                       if (stream_ID == 224  and current_pcr != last_pcr) :
                           print "PTS stamped before Video Access Unit arrived into buffer and the PID is",pid
                           print "PID PTS-PCR difference(msec)\n",pid, PTSPCRDiff_mseconds
                       if j2k == 1 :
                           found=3
                           print "PTS stamped before J2K video Access Unit arrived into buffer and the PID is",pid
                           print "PID PTS-PCR difference(msec)\n",pid, PTSPCRDiff_mseconds
                       if current_pcr!=last_pcr and stream_ID != 224 and j2k != 1:
                          print "PTS stamped before Audio Access Unit arrived into buffer and the PID is",pid
                          print "PID PTS-PCR difference(msec)\n",pid, PTSPCRDiff_mseconds
                    if PTSPCRDiff_mseconds > 3000 and current_pcr > 0 :
                       found =2
                       if (stream_ID == 224 or j2k==1) :
                          print "PTS stamped greater than 3s after Video Access Unit arrived into buffer and the PID is",pid
                          print "PID PTS-PCR difference(msec)\n",pid, PTSPCRDiff_mseconds
                       if j2k == 1 :
                          found = 4
                          print "PTS stamped greater than 3s after J2K video Access Unit arrived into buffer and the PID is",pid
                          print "PID PTS-PCR difference(msec)\n",pid, PTSPCRDiff_mseconds
                       if current_pcr!=last_pcr and stream_ID != 224 and j2k != 1:
                          found = 5
                          print "WARNING:PTS stamped greater than 3s after  Audio Access Unit arrived into buffer and the PID is",pid
                          print "PID PTS-PCR difference(msec)\n",pid, PTSPCRDiff_mseconds
                    if PTS_Interval > 700 and npcr> 1 and npts > 1:
                       found = 6
                       #print "WARNING:PTS Interval is greater than 700ms", PTS_Interval
                    if pcr_rep > 40 and pcr_rep < 100 and npcr > 1 and npts > 1:
                       found = 9
                       #print "WARNING:PCR repetition is greater than 40ms, but less than 100ms.PCR Repetition=", pcr_rep
                    if pcr_rep > 100 and  npcr > 1 and npts > 1:
                       found=7
                       #print "ERROR:PCR repetition is greater than 100ms,PCR Repetition=", pcr_rep
                    if pcr_accuracy > 500 or pcr_accuracy < -500 and npcr > 1 and npts > 1:
                       found =8
                       #print "ERROR:PCR Inaccuracy is outside the range [-500,500]ns", pcr_accuracy
                    prev_PTS_pkt = loop_breaker
              loop_breaker+= 1
              j = j + 1
    del readTS          
    if PTSPIDFound == False:
       print "Elementary PID defined in PMT, however not present in the Transport Stream."
    if found == 0 and PTSPIDFound == True and PTS_pid != 7999:
       print "PTS-PCR difference test-->PASS"
       print "PCR Repetition test-->PASS"
       print "PCR Accuracy Test-->PASS"
       print "PTS Interval Test-->PASS"

    if found == 2 or found == 5 or found == 4:
       print "PTS-PCR difference test is larger than 3s-->FAIL"
    if found == 1 or found == 3:
       print "PTS-PCR difference is negative --> FAIL"
    if found == 7:
       print "PCR Repetition interval is > 100ms --> FAIL"
    if found == 8:
       print "PCR  Inaccuracy is outside the range[-500ns,500ns]--> FAIL"
    if found == 9:
       print "PCR Repetition Interval is greater than 40ms, but less than 100ms- FAIL"
    if found == 6:
       print "PTS Repetition is greater than 700ms. PTS repetition test-FAIL"

    if PTSPCRDiff != 0:
        #print "Inside Plotting"
        fig = plt.figure(figsize=(12, 12))
        fig_title = infile + 'PID=' + str(PTS_pid)
        fig.canvas.set_window_title(infile+ '(PID='+ str(PTS_pid)+')' )

        ax1 = fig.add_subplot(511, axisbg='linen')
        ax1.set_ylabel('PCR/PTS(27MHz)', fontweight="bold")
        ax1.set_title('PCR/PTS ANALYSIS', fontweight="bold")
        ax1.plot(x_TS, Y_pcr, 'r-', label='PCR')
        ax1.plot(x_TS, y_PTS, 'g-', label='PTS')
        leg = ax1.legend(loc='upper left')

        bx1 = fig.add_subplot(512, axisbg='azure')
        bx1.set_ylabel('PTS-PCR(ms)', fontweight="bold")
        bx1.plot(x_TS, y_PTS_PCR, 'b-')

        cx1 = fig.add_subplot(513, axisbg='lavender')
        cx1.set_ylabel('PCR Repetition(ms)', fontweight="bold")
        cx1.plot(x_TS, y_PCR_repetition, 'b-')

        dx1 = fig.add_subplot(514, axisbg='lemonchiffon')
        dx1.set_ylabel('PCR Accuracy(ns)', fontweight="bold")
        dx1.plot(x_TS, y_PCR_acc, 'b-')

        ex1 = fig.add_subplot(515, axisbg='palegreen')
        ex1.set_xlabel('TS PACKET#', fontweight="bold")
        ex1.set_ylabel('PTS Interval(ms)', fontweight="bold")
        ex1.plot(x_TS, y_PTS_interval, 'b-')
        kurs = "C:\\Users\\sachi\\Desktop\\Myscripts\\PTSPCR_ANALYSIS_PID%d.pdf" % PTS_pid
        plt.savefig(kurs, format='pdf')

        plt.show()
        plt.close(fig)
    del y_PTS_PCR
    del x_TS
    del Y_pcr
    del y_PTS
    del y_PCR_repetition
    del y_PCR_acc
    del y_PTS_interval
    del wBuffer
    filename.close()


def readFile(filehandle, startPos, width):
    filehandle.seek(startPos, 0)
    if width == 4:
        string = filehandle.read(4)
        if string == '':
            raise IOError
        return struct.unpack('>L', string[:4])[0]
    elif width == 2:
        string = filehandle.read(2)
        if string == '':
            raise IOError
        return struct.unpack('>H', string[:2])[0]
    elif width == 1:
        string = filehandle.read(1)
        if string == '':
            raise IOError
        return struct.unpack('>B', string[:1])[0]
    elif width == 188:
         string = filehandle.read(188)
         if string == '':
            raise IOError
         return struct.unpack('>B', string[:188])[0]
    filehandle.close()


def parseAdaptation_Field(filehandle, startPos, PCR):
    n = startPos
    flags = 0
    adaptation_field_length = readFile(filehandle, n, 1)
    if adaptation_field_length > 0:
        flags = readFile(filehandle, n + 1, 1)
        PCR_flag = (flags >> 4) & 0x1
        if PCR_flag == 1:
            PCR1 = readFile(filehandle, n + 2, 4)
            PCR2 = readFile(filehandle, n + 6, 2)
            PCR_base_hi = (PCR1 >> 31) & 0x1
            PCR_base_lo = (PCR1 << 1) + ((PCR2 >> 15) & 0x1)
            PCR_ext = PCR2 & 0x1FF
            PCR.setPCR(PCR_base_hi, PCR_base_lo, PCR_ext)
    return [adaptation_field_length + 1, flags]


def parsePATSection(filehandle, k):
    pmap = []
    num_programs = 0
    local = readFile(filehandle, k, 4)
    table_id = (local >> 24)
    if (table_id != 0x0):
        print 'Ooops! error in parsePATSection()!'
        return

    section_length = (local >> 8) & 0xFFF

    transport_stream_id = (local & 0xFF) << 8;
    local = readFile(filehandle, k + 4, 4)
    transport_stream_id += (local >> 24) & 0xFF
    transport_stream_id = (local >> 16)
    version_number = (local >> 17) & 0x1F
    current_next_indicator = (local >> 16) & 0x1
    section_number = (local >> 8) & 0xFF
    last_section_number = local & 0xFF;
    length = section_length - 4 - 5
    j = k + 8
    i = 0
    while (length > 0):
        local = readFile(filehandle, j, 4)
        program_number = (local >> 16)
        program_map_PID = local & 0x1FFF
        if (program_number == 0):
            print 'network_PID = %d' % program_map_PID
        else:
            pmap = program_map_PID

            num_programs += 1

        length = length - 4;
        j += 4
        i += 1

        # print ''
    return num_programs


def parsePMTSection(filehandle, filename, k):
    l = 0
    local = readFile(filehandle, k, 4)

    table_id = (local >> 24)
    if (table_id != 0x2):
        print 'Ooops! error in parsePMTSection()!'
        return


    section_length = (local >> 8) & 0xFFF
    print "Section_Length=", section_length

    program_number = (local & 0xFF) << 8;

    local = readFile(filehandle, k + 4, 4)

    program_number += (local >> 24) & 0xFF
    print "\n===============================================================================\n" 
    print 'program_number#%d' % program_number

    version_number = (local >> 17) & 0x1F
    current_next_indicator = (local >> 16) & 0x1
    section_number = (local >> 8) & 0xFF; 
    last_section_number = local & 0xFF;

    local = readFile(filehandle, k + 8, 4)
    PCR_PID = (local >> 16) & 0x1FFF
    program_info_length = (local & 0xFFF)
    
    n = program_info_length
    m = k + 12;
    descriptor_tag =0 
    while (n > 0):
        descriptor_tag = readFile(filehandle, m, 1)
        descriptor_length = readFile(filehandle, m + 1, 1)
        n -= descriptor_length + 2
        m += descriptor_length + 2

    j = k + 12 + program_info_length
    last_length =0
    length = section_length - 4 - 9 - program_info_length


    while (length > 0):
        print "Length=", length
        local1 = readFile(filehandle, j, 1)
        local2 = readFile(filehandle, j + 1, 4)
        l += 1
        stream_type = local1;
        if stream_type == 0x02:
            PID_type = "MPEG2 Video"
        if stream_type == 33:
            PID_type = "JPEG2000"
        if stream_type == 27:
            PID_type = "H.264/AVC"
        if stream_type == 36:
            PID_type = "HEVC"
        if stream_type == 0x03:
            PID_type = "MPEG1 Audio"
        if stream_type == 0x04:
            PID_type = "MPEG2 Audio"
        if stream_type == 0x06:
            PID_type = "PCM Audio/DVB AC-3/PES Private Data"
        if stream_type >= 0x80 and stream_type <= 0xFF:
            if stream_type == 0x81:
                PID_type = "ATSC AC-3/DVB User Private "
            else:
                PID_type = "User Private"
        if stream_type == 0x0F:
            PID_type = "MPEG4 Audio with ADTS transport"
        if stream_type == 0x11:
            PID_type = "MPEG4 Audio with LATM transport"
        if stream_type == 134:
            PID_type = "SCTE35"
            print "SCTE PID present"

        elementary_PID = (local2 >> 16) & 0x1FFF
        ES_info_length = local2 & 0xFFF
##        print "\nstream_type = %d(%s), Elementary PID = %d, PCR PID= %d" % (
##        stream_type, PID_type, elementary_PID, PCR_PID)
        PTS_PCR_Diff(filename, PCR_PID, elementary_PID)
        n = ES_info_length
        m = j + 5;
        while (n > 0):
            descriptor_tag = readFile(filehandle, m, 1)
            descriptor_length = readFile(filehandle, m + 1, 1)

            n -= descriptor_length + 2
            m += descriptor_length + 2
        last_length = 0 
        last_length = int(length)
        j += 5 + ES_info_length
        length -= 5 + ES_info_length
        #### Need to take care if PMT spans over multiple TS
##        if length < 0 and last_length > 188 and last_length != None:
##           local3 = readFile(filehandle, j + 1+last_length, 4)
##           ES_info_length = local3 & 0xFFF
##           length = int(last_length) - (5 + int(ES_info_length))
  
    return



def parseTSMain(filehandle, filename, packet_size, mode, pid, psi_mode, searchItem):
    PCR = SystemClock()
    PESPktInfo = PESPacketInfo()

    if (packet_size != 192):
        n = 0
    else:
        n = 4

    packetCount = 0
    rdi_count = 0

    EntryPESPacketNumList = []
    TPIList = []
    PTSList = []
    PIDList = []

    idr_flag = False
    last_SameES_packetNo = 0
    last_EntryTPI = 0
    found = 0
    loop = 0
    message_loop=0
    global prgms

    try:
        while (loop < prgms):

            PacketHeader = readFile(filehandle, n, 4)

            syncByte = (PacketHeader >> 24)
            if (syncByte != 0x47):
                print 'Ooops! Can NOT found Sync_Byte! maybe something wrong with the file'
                break

            payload_unit_start_indicator = (PacketHeader >> 22) & 0x1

            PID = ((PacketHeader >> 8) & 0x1FFF)

            adaptation_fieldc_trl = ((PacketHeader >> 4) & 0x3)
            Adaptation_Field_Length = 0

            if (adaptation_fieldc_trl == 0x2) | (adaptation_fieldc_trl == 0x3):
                [Adaptation_Field_Length, flags] = parseAdaptation_Field(filehandle, n + 4, PCR)

                if ((searchItem == "PCR") & ((flags >> 4) & 0x1)):
                    discontinuity = 'discontinuity: false'
                    if (((flags >> 7) & 0x1)):
                        discontinuity = 'discontinuity: true'
                        print "discontinuity flag is Set"
                    print 'PCR packet, packet No. %d, PID = 0x%x, PCR_base = hi:0x%X lo:0x%X PCR_ext = 0x%X %s' \
                          % (packetCount, PID, PCR.PCR_base_hi, PCR.PCR_base_lo, PCR.PCR_extension, discontinuity)

            if (adaptation_fieldc_trl == 0x1) | (adaptation_fieldc_trl == 0x3):

                PESstartCode = readFile(filehandle, n + Adaptation_Field_Length + 4, 4)

                if ((PESstartCode & 0xFFFFFF00) == 0x00000100) & \
                        (PID == pid) & (payload_unit_start_indicator == 1):

                    parsePESHeader(filehandle, n + Adaptation_Field_Length + 4, PESPktInfo)
                    PTS_MSB24 = ((PESPktInfo.PTS_hi & 0x1) << 23) | ((PESPktInfo.PTS_lo >> 9) & 0x7FFFFF)
                    print 'PES start, packet No. %d, PID = 0x%x, PTS_MSB24 = 0x%x PTS_hi = 0x%X, PTS_low = 0x%X' \
                          % (packetCount, PID, PTS_MSB24, PESPktInfo.PTS_hi, PESPktInfo.PTS_lo)
                    print 'packet No. %d,  ES PID = 0x%X,  Steam_ID = 0x%X,  AU_Type = %s' \
                          % (packetCount, PID, PESPktInfo.getStreamID(), PESPktInfo.getAUType())
                    if (mode == 'ES'):
                        print 'packet No. %d,  ES PID = 0x%X,  Steam_ID = 0x%X,  AU_Type = %s' \
                              % (packetCount, PID, PESPktInfo.getStreamID(), PESPktInfo.getAUType())

                        if (idr_flag == True):
                            EntryPESPacketNumList.append(last_SameES_packetNo - last_EntryTPI + 1)
                            print 'packet No. %d, ES PID = 0x%X, Steam_ID = 0x%X, AU_Type = %s' \
                                  % (packetCount, PID, PESPktInfo.getStreamID(), PESPktInfo.getAUType())

                        if (PESPktInfo.getAUType() == "IDR_picture"):
                            idr_flag = True
                            last_EntryTPI = packetCount
                            print 'packet No. %d, ES PID = 0x%X, Steam_ID = 0x%X, AU_Type = %s' \
                                  % (packetCount, PID, PESPktInfo.getStreamID(), PESPktInfo.getAUType())
                            TPIList.append(packetCount)
                            PTSList.append(PTS_MSB24)
                        else:
                            idr_flag = False

                elif (((PESstartCode & 0xFFFFFF00) != 0x00000100) & \
                              (payload_unit_start_indicator == 1)):

                    pointer_field = (PESstartCode >> 24)
                    table_id = readFile(filehandle, n + Adaptation_Field_Length + 4 + 1 + pointer_field, 1)

                    if ((table_id == 0x0) & (PID != 0x0)):
                        print 'Ooops!, Something wrong in packet No. %d' % packetCount

                    k = n + Adaptation_Field_Length + 4 + 1 + pointer_field

                    if (table_id == 0x0):
##                        if (((searchItem == "FFF") & (mode == 'PAT')) | (searchItem == "PAT")):
##                            if ((psi_mode == 2) & (searchItem == "PAT")):
##                                isUnique = True
##                                for i in PIDList:
##                                    if (i == PID):
##                                        isUnique = False
##
##                                if isUnique:
##                                    PIDList.append(PID)
##                                else:
##                                    n += packet_size
##                                    packetCount += 1
##                                continue

                        prgms = parsePATSection(filehandle, k)
                        print "number of programs=",prgms
                        found = 1
                        
                        if prgms > 1:
                            message_loop += 1
                            if message_loop == 1:
                               print "This is a Multiple Program Transport Stream(MPTS) file. Number of Programs=", prgms
                        else:
                            print "This is a Single Program Transport Stream(SPTS) file."

                    elif (table_id == 0x2):
##                        if (((searchItem == "FFF") & (mode == 'PMT') & (PID == pid)) | (searchItem == "PMT")):
##                            if ((psi_mode == 2) & (searchItem == "PMT")):
##                                isUnique = True
##                                for i in PIDList:
##                                    if (i == PID):
##                                        isUnique = False
##
##                                if isUnique:
##                                    PIDList.append(PID)
##                                else:
##                                    n += packet_size
##                                    packetCount += 1
##                                    continue
                        if loop < prgms:
                            parsePMTSection(filehandle, filename, k)
                            loop += 1


                if (PID == pid):
                    last_SameES_packetNo = packetCount

            n += packet_size

            packetCount += 1

            if (packetCount > 1450000):
                break

    except IOError:
        print 'IO error! maybe reached EOF'
    else:
        filehandle.close()

    for i in range(len(EntryPESPacketNumList)):
        print 'TPI = 0x%x, PTS = 0x%x, EntryPESPacketNum = 0x%x' % (TPIList[i], PTSList[i], EntryPESPacketNumList[i])


def getFilename():
    root=Tkinter.Tk()
    root.withdraw()
    fTyp=[('.ts File','*.ts'),('.TOD File','*.TOD'),('.trp File','*.trp'),('All Files','*.*')]
    iDir='~/'
    filename=tkFileDialog.askopenfilename(filetypes=fTyp,initialdir=iDir)
    #filename= "C:\Users\schandrashekar\Desktop\J2K_input_Output\j2k_Mux_input_bars_5min.ts"
    root.destroy()
    return filename;


def Main():
    description = "This is a python script for parsing MPEG-2 TS stream"
    usage = "\n\t%prog -t <188|192|204> -m PAT\
    \n\t%prog -t <188|192|204> -m <PMT|ES|SIT> PID\
    \n\t%prog -s PCR \
    \n\t%prog -s <PAT|PMT|SIT> --all \
    \n\t%prog -s <PAT|PMT|SIT> --unique\n\n \
    Example: TSParser.py -t 188 -m PMT 1fc8"

    cml_parser = OptionParser(description=description, usage=usage)
    cml_parser.add_option("-f", "--file", action="store", type="string", dest="filename", default="",
                          help="specify file name, if not specified, a file open dialogbox will be shown.")

    cml_parser.add_option("-t", "--type", action="store", type="int", dest="packet_size", default="188",
                          help="specify TS packet size[188, 192, 204], default = 188")

    cml_parser.add_option("-m", "--mode", action="store", type="string", dest="mode", default="PAT",
                          help="specify parsing mode[PAT, PMT, SIT, ES], default = PAT")

    cml_parser.add_option("-s", "--search", action="store", type="string", dest="searchItem", default="FFF",
                          help="search PAT/PMT/PCR/SIT packets and output Information.")

    cml_parser.add_option("--all", action="store_const", const=1, dest="psi_mode", default=0,
                          help="Output all PAT/PMT/SIT packets Information. default, only the first one is output.")

    cml_parser.add_option("--unique", action="store_const", const=2, dest="psi_mode", default=0,
                          help="Output unique PAT/PMT/SIT packets Information. default, only the first one is output.")

    (opts, args) = cml_parser.parse_args(sys.argv)

    if ((opts.searchItem == "FFF") & (opts.mode != "PAT") & (len(args) < 2)):
        cml_parser.print_help()
        return

    if ((opts.searchItem == "FFF") & (opts.mode != "PAT")):
        pid = int(args[1], 16)
    else:
        pid = 0;

    if ((opts.searchItem != "FFF") & (opts.searchItem != "PAT") & \
                (opts.searchItem != "PMT") & (opts.searchItem != "PCR") &
            (opts.searchItem != "SIT")):
        cml_parser.print_help()
        return

    psi_mode = 0
    if (opts.searchItem != "FFF"):
        psi_mode = opts.psi_mode

    if (opts.filename == ""):
        filename = getFilename()
    else:
        filename = opts.filename

    if (filename == ""):
        return

    print "FILE being analysed:", filename
    filehandle = open(filename, 'rb')

    parseTSMain(filehandle, filename, opts.packet_size, opts.mode, pid, psi_mode, opts.searchItem)

    #filehandle.close()


if __name__ == "__main__":
    Main()





