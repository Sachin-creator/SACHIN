# encoding=utf8
#Author:Sachin Chandrashekar
# Usage:
#TransportStreamSCTEAnalyser.py  <multicast IPv4> <udpport> <Inerface IP>

import time
import struct
import socket
import sys
import win_inet_pton
#from multiprocessing import Process, Pipe
print "##############################################################################################################################################"
print "TRANSPORT STREAM SCTE35 ANALYZER(Designed & Developed by Sachin Chandrashekar):\n"
print "Transport Stream SCTE35 Analyser tunes to a udp multicast stream and prints the SCTE35 message as it finds in the input.\nIt also performs basic check of the messages and reports errors, if any."
print "In addition to the SCTE35 validation,the tool also performs PTS-PCR difference, PTS interval on elementary PIDs, PCR accuracy check and PCR interval check."
print "IMPORTANT:PCR related errors are to be ignored for a variable transport bitrate input."
print "\nFor more features and support or any issues with the tool reach out through email-sachinhc@hotmail.com\n"
print "##############################################################################################################################################"

if len(sys.argv) < 4:
    print "ERROR:Incorrect Arguments provided."
    print "Usage:TransportStreamSCTE35AnalyserGUI.exe <multicast_address> <udp_port> <Interface_IP_address>"
    sys.exit()
else:
  MYPORT = int(sys.argv[2])
  MYGROUP_IPv4 = sys.argv[1]
  SYSTEM_IF = sys.argv[3]


# MYPORT = 1234
# MYGROUP_IPv4 = '239.1.1.1'
# SYSTEM_IF = '192.168.0.61'
packetL = 188
RECORD=1
            
def crc32(hexstring,CRC_32,encrypted_flag):
    from crccheck.crc import Crc32, CrcXmodem,Crc32Mpeg2
    from crccheck.checksum import Checksum32
    bytearraydata = bytearray.fromhex(hexstring)
    if not encrypted_flag:
        crc = Crc32Mpeg2.calc(bytearraydata)
        if hex(crc) != CRC_32:
           print "\nERROR:Incorrect CRC_32. Expected CRC_32(MPEG2) is",hex(crc)
        else:
           print "(Valid CRC value)"
    else:
        ecrc = Crc32Mpeg2.calc(bytearraydata)
        if hex(ecrc) != CRC_32:
           print "\nERROR:Incorrect ECRC_32. Expected ECRC_32(MPEG2) is",hex(crc)
        else:
           print "(Valid ECRC value)"

def formatUTC(UTC):
    import datetime
    x = datetime.datetime(1980,1,6)
    y=x + datetime.timedelta(0,UTC)
    UTC2time='{:%Y-%m-%d %H:%M:%S}'.format(y)
    return UTC2time

def toHex(string):
    lst = []
    for ch in string:
        hv = (ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return reduce(lambda x,y:x+y, lst)

def listConcatenator(list):
    ConcatedList= ''
    for element in list:
        ConcatedList += str(element) + " "
    return ConcatedList


def isPCRPid(buffer):
    adaptFieldControl =(struct.unpack(">B", buffer[3:4])[0] & 0x30)>>4
    if (adaptFieldControl == 2 or adaptFieldControl == 3):
        if ((struct.unpack(">B", buffer[5:6])[0] & 0x10)> 0x0):
            return struct.unpack(">H", buffer[1:3])[0] & 0x01FFF
    else:
        return -1
####################Decode RTP Packet-- to be implemented##################################################
def decodeRTPpacket(packet_bytes):
    packet_vars = {}
    byte1 = packet_bytes[0:2]           #Byte1 as Hex
    byte1 = int(byte1,16)              #Convert to Int
    byte1 = format(byte1, 'b')          #Convert to Binary
    packet_vars['version'] = int(byte1[0:2], 2)     #Get RTP Version
    packet_vars['padding'] = int(byte1[2:3])        #Get padding bit
    packet_vars['extension'] = int(byte1[3:4])        #Get extension bit
    packet_vars['csi_count'] = int(byte1[4:8], 2)     #Get RTP Version

    byte2 = packet_bytes[2:4]

    byte2 = int(byte2, 16)              #Convert to Int
    byte2 = format(byte2, 'b').zfill(8) #Convert to Binary
    packet_vars['marker'] = int(byte2[0:1])
    packet_vars['payload_type'] = int(byte2[1:8], 2)

    packet_vars['sequence_number'] = int(str(packet_bytes[4:8]), 16)

    packet_vars['timestamp'] = int(str(packet_bytes[8:16]), 16)

    packet_vars['ssrc'] = int(str(packet_bytes[16:24]), 16)

    packet_vars['payload'] = str(packet_bytes[24:])
    return packet_vars

#######################index of duplicate items#############################################################

def list_duplicates_of(seq,item):
    start_at = -1
    locs = []
    while True:
        try:
            loc = seq.index(item,start_at+1)
        except ValueError:
            break
        else:
            locs.append(loc)
            start_at = loc
    return locs


#########################SpliceInsert#########################################################################

def spliceInsert(buffer,curr_PCR,pts_adjustment):
      tracker=0
      print "(Splice Insert)"
      splice_event_id= ((struct.unpack(">Q", buffer[15:23])[0])&0x0000FFFF)
      splice_event_cancel_indicator=((struct.unpack("B",buffer[23])[0] & 0xF0) >> 7)
      reserved2=(struct.unpack("B",buffer[23])[0] & 0x7F) 
      print "    splice_event_id=",(splice_event_id)
      print "    splice_event_cancel_indicator=",(splice_event_cancel_indicator)
      print "    reserved2=",(reserved2)
      if splice_event_cancel_indicator == 0:
         out_of_network_indicator=((struct.unpack("B",buffer[24])[0] & 0x80) >> 7)
         program_splice_flag=((struct.unpack("B",buffer[24])[0] & 0x40) >> 6)
         duration_flag=((struct.unpack("B",buffer[24])[0] & 0x20) >> 5)
         splice_immediate_flag=((struct.unpack("B",buffer[24])[0] & 0x10) >> 4)
         reserved3=((struct.unpack("B",buffer[24])[0] & 0x0F))

         print "    out_of_network_indicator=",out_of_network_indicator,
         if out_of_network_indicator == 0:
            print "(Splice Point is an opportunity to return to the network feed and exit the spliced ad)"
         else:
            print "(Splice Point is an opportunity to exit the network feed and start the ad-splice)"
         print "    program_splice_flag=",program_splice_flag
         print "    duration_flag=",duration_flag
         print "    splice_immediate_flag=",splice_immediate_flag
         print "    reserved3=",reserved3
         if program_splice_flag  and not splice_immediate_flag :
            time_specified_flag=((struct.unpack("B",buffer[25])[0] & 0x80) >> 7)
            if time_specified_flag:
               reserved4=((struct.unpack("B",buffer[25])[0] & 0x7E) >> 1)
               pts_time= (((struct.unpack(">Q", buffer[25:33])[0] )& 0x01ffffffff000000)>> 24) 
               print "    reserved4=", reserved4
               print "    pts_time=",pts_time
               print "    effective pts(pts_time+pts_adjustment)=",pts_time+pts_adjustment
               tracker = tracker+5
            else:
               reserved4=(struct.unpack("B",buffer[25])[0] & 0x7F)
               print "    reserved4=",reserved4
               tracker +=1
         if not program_splice_flag:
            component_count=struct.unpack("B",buffer[25])[0]
            while i<component_count:
                 component_tag=struct.unpack("B",buffer[25+i+1])[0]
                 print "component_tag=",component_tag
                 i +=1
                 if not splice_immediate_flag:
                    time_specified_flag=((struct.unpack("B",buffer[25+i+1])[0] & 0x80) >> 7)
                    if time_specified_flag:
                       reserved4=((struct.unpack("B",buffer[25+i+1])[0] & 0x7E) >> 1)
                       pts_time= (((struct.unpack(">Q", buffer[25+i+1:33+i+1])[0] )& 0x01ffffffff000000)>> 24) 
                       print "    reserved4=", reserved4
                       print "    pts_time=",pts_time
                       print "    effective pts(pts_time+pts_adjustment)=",pts_time+pts_adjustment
                    else:
                       reserved4=(struct.unpack("B",buffer[25+i+1])[0] & 0x7F)
                       print "    reserved4=",reserved4
            tracker=i

         if duration_flag:
            print "    duration_flag=", duration_flag
            auto_return=((struct.unpack("B",buffer[25+tracker])[0] & 0x80) >> 7)
            reserved5=((struct.unpack("B",buffer[25+tracker])[0] & 0x7E) >> 1)
            duration= (((struct.unpack(">Q", buffer[25+tracker:33+tracker])[0] )& 0x01ffffffff000000)>> 24)
            print "    auto_return=",auto_return
            print "    reserved5=",reserved5
            print "    duration=",duration,
            dur_sec= float(duration)/90000.0
            print "(%d seconds)" %(dur_sec)
            tracker +=5
         unique_program_id=(struct.unpack(">H", buffer[25+tracker:27+tracker])[0])
         tracker +=2
         avail_num=(struct.unpack("B",buffer[25+tracker])[0])
         tracker +=1
         avails_expected=(struct.unpack("B",buffer[25+tracker])[0])
         tracker +=1
         print "    unique_program_id=", unique_program_id
         print "    avail_num=",avail_num
         print "    avails_expected=",avails_expected
         tracker=tracker+25
         
         sctePos=(((pts_time+pts_adjustment-curr_PCR)*1000)/90000)

         if not sctePos:
                print "ERROR:scte35 packet received after the effective pts time indicated in the splice command!",
                print "Splice Point:",sctePos,
                print "ms in the past"
         elif sctePos < 4000:
                print "ERROR: Splice Point occurs in less than 4s(i.e., preroll<4s)"
                print "Splice Point:",sctePos,
                print "ms in future"
         else:
                print "Splice Point:",sctePos,
                print "ms in future"  
      if splice_event_cancel_indicator:
         tracker=23             
      return (tracker)


########################SpliceNull################################################################################################

def spliceNull(buffer,tracker):
    print "(Splice Null Message)"
    return tracker

######################SpliceSchedule##############################################################################################

def spliceSchedule(buffer,tracker):
    i=0
    j=0
    print "(Splice Schedule Message)"
    splice_count=struct("B",buffer[tracker])[0]
    while i<splice_count:
          splice_event_id=(((struct.unpack(">Q", buffer[tracker+i+1:tracker+i+9])[0] )& 0xffffffff00000000)>> 32)
          splice_event_cancel_indicator=((struct.unpack("B",buffer[tracker+i+5])[0] & 0x80) >> 7)
          reserved11=(struct.unpack("B",buffer[tracker+i+5])[0] & 0x7F)
          print "    splice_event_id=",splice_event_id
          print "    splice_event_cancel_indicator=",splice_event_cancel_indicator
          print "    reserved11=",reserved11

          if not splice_event_cancel_indicator:
             out_of_network_indicator=((struct.unpack("B",buffer[tracker+i+6])[0] & 0x80) >> 7)
             program_splice_flag=((struct.unpack("B",buffer[tracker+i+6])[0] & 0x40) >> 6)
             duration_flag=((struct.unpack("B",buffer[tracker+i+6])[0] & 0x20) >> 5)
             reserved12=(struct.unpack("B",buffer[tracker+i+6])[0] & 0x1F)
             print "    out_of_network_indicator=",out_of_network_indicator
             print "    program_splice_flag=",program_splice_flag
             print "    duration_flag=",duration_flag
             print "    reserved12=",reserved12
             if program_splice_flag:
                utc_splice_time=(((struct.unpack(">Q", buffer[tracker+i+7:tracker+i+15])[0] )& 0xffffffff00000000)>> 32)
                print "    utc_splice_time=",utc_splice_time, 
                print(formatUTC(utc_splice_time))
             else:
                component_count=struct.unpack("B",buffer[tracker+i+7])[0]
                print "    component_count=",component_count
                while j<component_count:
                      component_tag=struct.unpack("B",buffer[tracker+j+8])[0]
                      utc_splice_time=(((struct.unpack(">Q", buffer[tracker+j+9:tracker+j+17])[0] )& 0xffffffff00000000)>> 32)
                      print "    component_tag=",component_tag
                      print "    utc_splice_time=",utc_splice_time
                      j +=1
             if program_splice_flag:
                if duration_flag:
                    print "    duration_flag=", duration_flag
                    auto_return=((struct.unpack("B",buffer[tracker+11+i])[0] & 0x80) >> 7)
                    reserved5=((struct.unpack("B",buffer[tracker+11+i])[0] & 0x7E) >> 1)
                    duration= (((struct.unpack(">Q", buffer[tracker+11+i:tracker+19+i])[0] )& 0x01ffffffff000000)>> 24)
                    print "    auto_return=",auto_return
                    print "    reserved5=",reserved5
                    print "    duration=",duration,
                    dur_sec= duration/90000
                    print "(%d seconds)" %(dur_sec)
                    unique_program_id=struct.unpack(">H", buffer[traker+16+i:traker+18+i])[0]
                    avail_num=struct.unpack("B",buffer[tracker+19+i])[0]
                    avails_expected=struct.unpack("B",buffer[tracker+20+i])[0]
                else:
                    unique_program_id=struct.unpack(">H", buffer[traker+11+i:traker+13+i])[0]
                    avail_num=struct.unpack("B",buffer[tracker+14+i])[0]
                    avails_expected=struct.unpack("B",buffer[tracker+15+i])[0]                    
                
             if not program_splice_flag:
                if duration_flag:
                    print "    duration_flag=", duration_flag
                    auto_return=((struct.unpack("B",buffer[tracker+13+j])[0] & 0x80) >> 7)
                    reserved5=((struct.unpack("B",buffer[tracker+13+j])[0] & 0x7E) >> 1)
                    duration= (((struct.unpack(">Q", buffer[tracker+13+j:tracker+21+j])[0] )& 0x01ffffffff000000)>> 24)
                    print "    auto_return=",auto_return
                    print "    reserved5=",reserved5
                    print "    duration=",duration,
                    dur_sec= duration/90000
                    print "(%d seconds)" %(dur_sec)  
                    unique_program_id=struct.unpack(">H", buffer[traker+18+j:traker+20+j])[0]
                    avail_num=struct.unpack("B",buffer[tracker+21+j])[0]
                    avails_expected=struct.unpack("B",buffer[tracker+21+j])[0]  
                else:
                    unique_program_id=struct.unpack(">H", buffer[traker+13+j:traker+15+j])[0]
                    avail_num=struct.unpack("B",buffer[tracker+16+j])[0]
                    avails_expected=struct.unpack("B",buffer[tracker+17+j])[0]
          i +=1
    if splice_event_cancel_indicator:
       return tracker+i+5 

    if not splice_event_cancel_indicator and program_splice_flag:
        if duration_flag:
           return tracker+20+i
        else:
           return tracker+15+i
    if not splice_event_cancel_indicator and not  program_splice_flag:
        if duration_flag:
           return tracker+21+j
        else:
           return tracker+17+j                  
    
################TimeSignal############################################################################

def time_signal(buffer,curr_PCR,pts_adjustment,tracker):
    print "(time_signal splice message)"
    time_specified_flag=((struct.unpack("B",buffer[tracker])[0] & 0x80) >> 7)
    if time_specified_flag:
       reserved4=((struct.unpack("B",buffer[tracker])[0] & 0x7E) >> 1)
       pts_time= (((struct.unpack(">Q", buffer[tracker:tracker+8])[0] )& 0x01ffffffff000000)>> 24) 
       print "    reserved4=", reserved4
       print "    pts_time=",pts_time

       sctePos=float(((pts_time+pts_adjustment)- curr_PCR)*1000/90000)

       if not sctePos:
              print "ERROR:scte35 packet received after the effective pts time indicated in the splice command!",
              print "Splice Point:",sctePos,
              print "ms in the past"
       elif sctePos < 4000:
              print "ERROR: Splice Point occurs in less than 4s(i.e., preroll<4s)"
              print "Splice Point:",sctePos,
              print "ms in future"
       else:
              print "Splice Point:",sctePos,
              print "ms in future"

       tracker = tracker+5    
    else:
       reserved4=(struct.unpack("B",buffer[tracker])[0] & 0x7F)
       print "    reserved4=",reserved4
       tracker +=1
    return tracker

################bandwidth_reservation############################################################################

def bandwidth_reservation(buffer,tracker):
    print "(bandwidth reservation Splice Message)"
    return tracker

################private_command############################################################################
def private_command(buffer):
    return 4##to be implemented!!

#######################Splice_Descriptor#################################################################

def splice_descriptor(buffer,tracker):
    i=0
    m=0
    k=0
    length=tracker
    private_data=[]
    splice_descriptor_tag=(struct.unpack("B",buffer[tracker])[0])
    print "splice_descriptor_tag=" ,splice_descriptor_tag,

    descriptor_length=(struct.unpack("B",buffer[tracker+1])[0])
    identifier=(((struct.unpack(">Q", buffer[tracker+2:tracker+10])[0] )& 0xffffffff00000000)>>32)
    while i < descriptor_length:
          private_data.append(chr(struct.unpack("B",buffer[tracker+2+i])[0]))
          i +=1
 
    if splice_descriptor_tag  == 0:
       print "(AvailDescriptor)"
    if splice_descriptor_tag  == 1:
       print "(DTMFDescriptor)"
    if splice_descriptor_tag  == 2:
       print "(SegmentationDescriptor)"
    if splice_descriptor_tag  == 3:
       print "(TimeDescriptor)"
    if splice_descriptor_tag  == 4:
       print "(AudioDescriptor)"    
    print "descriptor_length=",descriptor_length
    print "identifier=",identifier,
    if str(identifier) == "1129661769":
        print "(CUEI)"
    else:
        print "ERROR:Incorrect identifier!"
    #print "descriptor_data=",listConcatenator(private_data)

    ####Avail Descriptor#####################################################################################
    if splice_descriptor_tag == 0:
       provider_avail_id= (((struct.unpack(">Q", buffer[tracker+6:tracker+14])[0] )& 0xffffffff00000000)>>32)
       print "provider_avail_id=",provider_avail_id


    ####DTMF Descriptor#####################################################################################
    if splice_descriptor_tag == 1:
       
       DTMF_char=[]
       preroll= (struct.unpack("B",buffer[tracker+6])[0])
       dtmf_count=(((struct.unpack("B",buffer[tracker+7])[0])&0XE0)>>5)
       reserved6=((struct.unpack("B",buffer[tracker+7])[0])&0X1F)
       while k<dtmf_count:
            DTMF_char.append(chr(struct.unpack("B",buffer[tracker+8+k])[0]))
            k +=1
       print "preroll=",preroll
       print "dtmf_count=",dtmf_count
       print "reserved6=",reserved6
       print "DTMF_char=", listConcatenator(DTMF_char)

    ####Segmentation Descriptor#####################################################################################
    segmentation_upid=[]
    if splice_descriptor_tag  == 2:
       segmentation_event_id=((struct.unpack(">Q", buffer[tracker+2:tracker+10])[0] )& 0x00000000ffffffff)
       segmentation_event_cancel_indicator=(((struct.unpack("B",buffer[tracker+10])[0])&0x80)>>7)
       reserved7=(struct.unpack("B",buffer[tracker+10])[0])&0x7F
       print "segmentation_event_id=",segmentation_event_id
       print "segmentation_event_cancel_indicator=",segmentation_event_cancel_indicator
       print "reserved7=",reserved7

       if not segmentation_event_cancel_indicator :
          program_segmentation_flag=(((struct.unpack("B",buffer[tracker+11])[0])&0x80)>>7)
          segmentation_duration_flag=(((struct.unpack("B",buffer[tracker+11])[0])&0x40)>>6)
          delivery_not_restricted_flag=(((struct.unpack("B",buffer[tracker+11])[0])&0x20)>>5)
          print "program_segmentation_flag=",program_segmentation_flag
          print "segmentation_duration_flag=",segmentation_duration_flag
          print "delivery_not_restricted_flag=",delivery_not_restricted_flag

          if not delivery_not_restricted_flag:
             web_delivery_allowed_flag=(((struct.unpack("B",buffer[tracker+11])[0])&0x10)>>4)
             no_regional_blackout_flag=(((struct.unpack("B",buffer[tracker+11])[0])&0x08)>>3)
             archive_allowed_flag=(((struct.unpack("B",buffer[tracker+11])[0])&0x04)>>2)
             device_restrictions=((struct.unpack("B",buffer[tracker+11])[0])&0x03)
             print "web_delivery_allowed_flag=",web_delivery_allowed_flag
             print "no_regional_blackout_flag=",no_regional_blackout_flag
             print "archive_allowed_flag=",archive_allowed_flag
             print "device_restrictions=",device_restrictions
          else:
             reserved8=((struct.unpack("B",buffer[tracker+11])[0])&0x1F)
             print "reserved8=",reserved8

          if not program_segmentation_flag:
             component_count=(struct.unpack("B",buffer[tracker+12])[0])
             print "component_count=",component_count
             while m < component_count:
                   component_tag=(struct.unpack("B",buffer[tracker+13+m])[0])
                   reserved9=((struct.unpack("B",buffer[tracker+13+m])[0])&0xFE)
                   pts_offset=((struct.unpack(">Q", buffer[tracker+13+m:tracker+21+m])[0]& 0x1FFFFFFFF000000)>> 24)
                   print "component_tag=",component_tag
                   print "reserved9=",reserved9
                   print "pts_offset=",pts_offset

          if not program_segmentation_flag  and segmentation_duration_flag :
             segmentation_duration=((struct.unpack(">Q", buffer[tracker+18+m:tracker+26+m])[0]& 0xFFFFFFFFFF000000)>> 24)
             print "segmentation_duration=",segmentation_duration

             segmentation_upid_byte=0
             segmentation_upid_type=(struct.unpack("B",buffer[tracker+23+m])[0])
             segmentation_upid_length=(struct.unpack("B",buffer[tracker+24+m])[0])
             print "segmentation_upid_type=",segmentation_upid_type,
             if segmentation_upid_type==0:
                print "(The segmentation_upid is not defined and is not present in the descriptor.)"
             if segmentation_upid_type==1:
                print "(Deprecated: use type 0x0C; The segmentation_upid does not follow a standard naming scheme.)" 
             if segmentation_upid_type==2:
                print "(Deprecated: use type 0x03, 8 characters; 4 alpha characters followed by 4 numbers.)" 
             if segmentation_upid_type==3:
                print "(Defined by the Advertising Digital Identification, LLC group. 12 characters; 4 alpha characters (company identification prefix) followed by 8 alphanumeric characters. (See [Ad-ID]).)" 
             if segmentation_upid_type==4:
                print "(UMID-See SMPTE 330)" 
             if segmentation_upid_type==5:
                print "(Deprecated: use type 0x06, ISO 15706 binary encoding.)"   
             if segmentation_upid_type==6:
                print "(Formerly known as V-ISAN. ISO 15706-2 binary encoding (\“versioned\” ISAN). See [ISO 15706-2].)"
             if segmentation_upid_type==7:
                print "(Tribune Media Systems Program identifier. 12 characters; 2 alpha characters followed by 10 numbers.)" 
             if segmentation_upid_type==8:
                print "(AiringID (Formerly Turner ID), used to indicate a specific airing of a program that is unique within a network.)" 
             if segmentation_upid_type==9:
                print "ADI-CableLabs metadata identifier)" 
             if segmentation_upid_type==10:
                print "(EIDR represented in Compact Binary encoding)" 
             if segmentation_upid_type==11:
                print "(ATSC_content_identifier() structure as defined in [ATSC A/57B].)"  
             if segmentation_upid_type==12:
                print "(Managed Private UPID structure.)"
             if segmentation_upid_type==13:
                print "(Multiple UPID types structure.)" 
             if segmentation_upid_type==14:
                print "(Advertising information.)" 
             if segmentation_upid_type==15:
                print "(UR-Universal Resource Identifier)" 
             if segmentation_upid_type > 15 and segmentation_upid_type  < 256:
                print "(Reserved)" 
           
             print "segmentation_upid_length=",segmentation_upid_length

             while segmentation_upid_byte < segmentation_upid_length:
                   segmentation_upid.append(hex(struct.unpack("B",buffer[tracker+25+segmentation_upid_byte+m])[0]))
                   segmentation_upid_byte +=1
             print "segmentation_upid=",listConcatenator(segmentation_upid)

             segmentation_type_id= struct.unpack("B",buffer[tracker+26+segmentation_upid_length-1+m])[0] 
             segment_num= struct.unpack("B",buffer[tracker+27+segmentation_upid_length-1+m])[0]
             segments_expected= struct.unpack("B",buffer[tracker+28+segmentation_upid_length-1+m])[0]

             print "segmentation_type_id=",segmentation_type_id,
             if segmentation_type_id == 0:
                print "(Not Indicated)"
             if segmentation_type_id == 1:
                print "(Content Identification)"
             if (segmentation_type_id > 1 and segmentation_type_id < 16) or (segmentation_type_id > 25 and segmentation_type_id < 32) or (segmentation_type_id > 39 and segmentation_type_id < 48) or (segmentation_type_id > 59 and segmentation_type_id < 64) or (segmentation_type_id > 65 and segmentation_type_id < 80):
                print "segmentation_type_id is not defined in SCTE35 2019 specification"
             if segmentation_type_id == 16:
                print "(Program Start)"
             if segmentation_type_id == 17:
                print "(Program End)"
             if segmentation_type_id == 18:
                print "(Program Early Termination)"   
             if segmentation_type_id == 19:
                print "(Program Breakaway)"
             if segmentation_type_id == 20:
                print "(Program Resumption)"
             if segmentation_type_id == 21:
                print "(Program Runover Planned)"
             if segmentation_type_id == 22:
                print "(Program Runover Unplanned)"
             if segmentation_type_id == 23:
                print "(Program Overlap Start)" 
             if segmentation_type_id == 24:
                print "(Program Blackout Override)"
             if segmentation_type_id == 25:
                print "(Program Start – In Progress)"
             if segmentation_type_id == 32:
                print "(Chapter Start)"   
             if segmentation_type_id == 33:
                print "(Chapter End)"
             if segmentation_type_id == 34:
                print "(Break Start)"
             if segmentation_type_id == 35:
                print "(Break End)"
             if segmentation_type_id == 36:
                print "(Opening Credit Start)"
             if segmentation_type_id == 37:
                print "(Opening Credit End)"
             if segmentation_type_id == 38:
                print "(Closing Credit Start)"
             if segmentation_type_id == 39:
                print "(Closing Credit End)"
             if segmentation_type_id == 48:
                print "(Provider Advertisement Start)"   
             if segmentation_type_id == 49:
                print "(Provider Advertisement End)"
             if segmentation_type_id == 50:
                print "(Distributor Advertisement Start)"
             if segmentation_type_id == 51:
                print "(Distributor Advertisement End)"
             if segmentation_type_id == 52:
                print "(Provider Placement Opportunity Start)"
             if segmentation_type_id == 53:
                print "(Provider Placement Opportunity End)" 
             if segmentation_type_id == 54:
                print "(Distributor Placement Opportunity Start)"
             if segmentation_type_id == 55:
                print "(Distributor Placement Opportunity End)"
             if segmentation_type_id == 56:
                print "(Provider Overlay Placement Opportunity Start)"   
             if segmentation_type_id == 57:
                print "(Provider Overlay Placement Opportunity End)"
             if segmentation_type_id == 58:
                print "(Distributor Overlay Placement Opportunity Start)"
             if segmentation_type_id == 59:
                print "(Distributor Overlay Placement Opportunity End)"
             if segmentation_type_id == 64:
                print "(Unscheduled Event Start)"
             if segmentation_type_id == 65:
                print "(Unscheduled Event End)"  
             if segmentation_type_id == 80:
                print "(Network Start)"
             if segmentation_type_id == 81:
                print "(Network End)"         
             print "segment_num=",segment_num
             print "segments_expected=",segments_expected
             if segmentation_type_id== 0X34 or segmentation_type_id == 0X36:
                sub_segment_num= struct.unpack("B",buffer[tracker+29+segmentation_upid_length-1+m])[0]
                sub_segments_expected= struct.unpack("B",buffer[tracker+30+segmentation_upid_length-1+m])[0] 
                print "sub_segment_num=",sub_segment_num
                print "sub_segments_expected=",sub_segments_expected

          if segmentation_duration_flag and program_segmentation_flag :
             segmentation_duration=((struct.unpack(">Q", buffer[tracker+12+m:tracker+20+m])[0]& 0xFFFFFFFFFF000000)>> 24)

             segmentation_upid_byte=0
             segmentation_upid_type=(struct.unpack("B",buffer[tracker+17+m])[0])
             segmentation_upid_length=(struct.unpack("B",buffer[tracker+18+m])[0])
             print "segmentation_duration=",hex(segmentation_duration)
             print "segmentation_upid_type=",segmentation_upid_type,
             #print "segmentation_upid_type=",segmentation_upid_type,
             if segmentation_upid_type==0:
                print "(The segmentation_upid is not defined and is not present in the descriptor.)"
             if segmentation_upid_type==1:
                print "(Deprecated: use type 0x0C; The segmentation_upid does not follow a standard naming scheme.)" 
             if segmentation_upid_type==2:
                print "(Deprecated: use type 0x03, 8 characters; 4 alpha characters followed by 4 numbers.)" 
             if segmentation_upid_type==3:
                print "(Defined by the Advertising Digital Identification, LLC group. 12 characters; 4 alpha characters (company identification prefix) followed by 8 alphanumeric characters. (See [Ad-ID]).)" 
             if segmentation_upid_type==4:
                print "(UMID-See SMPTE 330)" 
             if segmentation_upid_type==5:
                print "(Deprecated: use type 0x06, ISO 15706 binary encoding.)"   
             if segmentation_upid_type==6:
                print "(Formerly known as V-ISAN. ISO 15706-2 binary encoding (\“versioned\” ISAN). See [ISO 15706-2].)"
             if segmentation_upid_type==7:
                print "(Tribune Media Systems Program identifier. 12 characters; 2 alpha characters followed by 10 numbers.)" 
             if segmentation_upid_type==8:
                print "(AiringID (Formerly Turner ID), used to indicate a specific airing of a program that is unique within a network.)" 
             if segmentation_upid_type==9:
                print "ADI-CableLabs metadata identifier)" 
             if segmentation_upid_type==10:
                print "(EIDR represented in Compact Binary encoding)" 
             if segmentation_upid_type==11:
                print "(ATSC_content_identifier() structure as defined in [ATSC A/57B].)"  
             if segmentation_upid_type==12:
                print "(Managed Private UPID structure.)"
             if segmentation_upid_type==13:
                print "(Multiple UPID types structure.)" 
             if segmentation_upid_type==14:
                print "(Advertising information.)" 
             if segmentation_upid_type==15:
                print "(UR-Universal Resource Identifier)" 
             if segmentation_upid_type > 15 and segmentation_upid_type  < 256:
                print "(Reserved)" 
             print "segmentation_upid_length=",segmentation_upid_length

             while segmentation_upid_byte < segmentation_upid_length:
                   segmentation_upid.append(hex(struct.unpack("B",buffer[tracker+19+segmentation_upid_byte+m])[0]))
                   segmentation_upid_byte +=1
             print "segmentation_upid=",listConcatenator(segmentation_upid)                   
             segmentation_type_id= struct.unpack("B",buffer[tracker+20+segmentation_upid_length-1+m])[0] 
             segment_num= struct.unpack("B",buffer[tracker+21+segmentation_upid_length-1+m])[0]
             segments_expected= struct.unpack("B",buffer[tracker+22+segmentation_upid_length-1+m])[0]
             print "segmentation_type_id=",segmentation_type_id,
             if segmentation_type_id == 0:
                print "(Not Indicated)"
             if segmentation_type_id == 1:
                print "(Content Identification)"
             if (segmentation_type_id > 1 and segmentation_type_id < 16) or (segmentation_type_id > 25 and segmentation_type_id < 32) or (segmentation_type_id > 39 and segmentation_type_id < 48) or (segmentation_type_id > 59 and segmentation_type_id < 64) or (segmentation_type_id > 65 and segmentation_type_id < 80):
                print "segmentation_type_id is not defined in SCTE35 2019 specification"
             if segmentation_type_id == 16:
                print "(Program Start)"
             if segmentation_type_id == 17:
                print "(Program End)"
             if segmentation_type_id == 18:
                print "(Program Early Termination)"   
             if segmentation_type_id == 19:
                print "(Program Breakaway)"
             if segmentation_type_id == 20:
                print "(Program Resumption)"
             if segmentation_type_id == 21:
                print "(Program Runover Planned)"
             if segmentation_type_id == 22:
                print "(Program Runover Unplanned)"
             if segmentation_type_id == 23:
                print "(Program Overlap Start)" 
             if segmentation_type_id == 24:
                print "(Program Blackout Override)"
             if segmentation_type_id == 25:
                print "(Program Start – In Progress)"
             if segmentation_type_id == 32:
                print "(Chapter Start)"   
             if segmentation_type_id == 33:
                print "(Chapter End)"
             if segmentation_type_id == 34:
                print "(Break Start)"
             if segmentation_type_id == 35:
                print "(Break End)"
             if segmentation_type_id == 36:
                print "(Opening Credit Start)"
             if segmentation_type_id == 37:
                print "(Opening Credit End)"
             if segmentation_type_id == 38:
                print "(Closing Credit Start)"
             if segmentation_type_id == 39:
                print "(Closing Credit End)"
             if segmentation_type_id == 48:
                print "(Provider Advertisement Start)"   
             if segmentation_type_id == 49:
                print "(Provider Advertisement End)"
             if segmentation_type_id == 50:
                print "(Distributor Advertisement Start)"
             if segmentation_type_id == 51:
                print "(Distributor Advertisement End)"
             if segmentation_type_id == 52:
                print "(Provider Placement Opportunity Start)"
             if segmentation_type_id == 53:
                print "(Provider Placement Opportunity End)" 
             if segmentation_type_id == 54:
                print "(Distributor Placement Opportunity Start)"
             if segmentation_type_id == 55:
                print "(Distributor Placement Opportunity End)"
             if segmentation_type_id == 56:
                print "(Provider Overlay Placement Opportunity Start)"   
             if segmentation_type_id == 57:
                print "(Provider Overlay Placement Opportunity End)"
             if segmentation_type_id == 58:
                print "(Distributor Overlay Placement Opportunity Start)"
             if segmentation_type_id == 59:
                print "(Distributor Overlay Placement Opportunity End)"
             if segmentation_type_id == 64:
                print "(Unscheduled Event Start)"
             if segmentation_type_id == 65:
                print "(Unscheduled Event End)"  
             if segmentation_type_id == 80:
                print "(Network Start)"
             if segmentation_type_id == 81:
                print "(Network End)"             
             print "segment_num=",segment_num
             print "segments_expected=",segments_expected
             if segmentation_type_id== 0X34 or segmentation_type_id == 0X36:
                sub_segment_num= struct.unpack("B",buffer[tracker+23+segmentation_upid_length-1+m])[0]
                sub_segments_expected= struct.unpack("B",buffer[tracker+24+segmentation_upid_length-1+m])[0]
                print "sub_segment_num=",sub_segment_num
                print "sub_segments_expected=",sub_segments_expected

          if not segmentation_duration_flag and program_segmentation_flag :
             segmentation_upid_byte=0
             segmentation_upid_type=(struct.unpack("B",buffer[tracker+12+m])[0])
             segmentation_upid_length=(struct.unpack("B",buffer[tracker+13+m])[0])
             print "segmentation_upid_type=",segmentation_upid_type,
             #print "segmentation_upid_type=",segmentation_upid_type,
             if segmentation_upid_type==0:
                print "(The segmentation_upid is not defined and is not present in the descriptor.)"
             if segmentation_upid_type==1:
                print "(Deprecated: use type 0x0C; The segmentation_upid does not follow a standard naming scheme.)" 
             if segmentation_upid_type==2:
                print "(Deprecated: use type 0x03, 8 characters; 4 alpha characters followed by 4 numbers.)" 
             if segmentation_upid_type==3:
                print "(Defined by the Advertising Digital Identification, LLC group. 12 characters; 4 alpha characters (company identification prefix) followed by 8 alphanumeric characters. (See [Ad-ID]).)" 
             if segmentation_upid_type==4:
                print "(UMID-See SMPTE 330)" 
             if segmentation_upid_type==5:
                print "(Deprecated: use type 0x06, ISO 15706 binary encoding.)"   
             if segmentation_upid_type==6:
                print "(Formerly known as V-ISAN. ISO 15706-2 binary encoding (\“versioned\” ISAN). See [ISO 15706-2].)"
             if segmentation_upid_type==7:
                print "(Tribune Media Systems Program identifier. 12 characters; 2 alpha characters followed by 10 numbers.)" 
             if segmentation_upid_type==8:
                print "(AiringID (Formerly Turner ID), used to indicate a specific airing of a program that is unique within a network.)" 
             if segmentation_upid_type==9:
                print "ADI-CableLabs metadata identifier)" 
             if segmentation_upid_type==10:
                print "(EIDR represented in Compact Binary encoding)" 
             if segmentation_upid_type==11:
                print "(ATSC_content_identifier() structure as defined in [ATSC A/57B].)"  
             if segmentation_upid_type==12:
                print "(Managed Private UPID structure.)"
             if segmentation_upid_type==13:
                print "(Multiple UPID types structure.)" 
             if segmentation_upid_type==14:
                print "(Advertising information.)" 
             if segmentation_upid_type==15:
                print "(UR-Universal Resource Identifier)" 
             if segmentation_upid_type > 15 and segmentation_upid_type  < 256:
                print "(Reserved)" 
             print "segmentation_upid_length=",segmentation_upid_length

             while segmentation_upid_byte < segmentation_upid_length:
                   segmentation_upid.append(struct.unpack("B",buffer[tracker+14+segmentation_upid_byte+m])[0])
                   segmentation_upid_byte +=1
             print "segmentation_upid=",listConcatenator(segmentation_upid)
             segmentation_type_id= struct.unpack("B",buffer[tracker+15+segmentation_upid_length-1+m])[0] 
             segment_num= struct.unpack("B",buffer[tracker+16+segmentation_upid_length-1+m])[0]
             segments_expected= struct.unpack("B",buffer[tracker+17+segmentation_upid_length-1+m])[0]
             print "segmentation_type_id=",segmentation_type_id,
             if segmentation_type_id == 0:
                print "(Not Indicated)"
             if segmentation_type_id == 1:
                print "(Content Identification)"
             if (segmentation_type_id > 1 and segmentation_type_id < 16) or (segmentation_type_id > 25 and segmentation_type_id < 32) or (segmentation_type_id > 39 and segmentation_type_id < 48) or (segmentation_type_id > 59 and segmentation_type_id < 64) or (segmentation_type_id > 65 and segmentation_type_id < 80):
                print "segmentation_type_id is not defined in SCTE35 2019 specification"
             if segmentation_type_id == 16:
                print "(Program Start)"
             if segmentation_type_id == 17:
                print "(Program End)"
             if segmentation_type_id == 18:
                print "(Program Early Termination)"   
             if segmentation_type_id == 19:
                print "(Program Breakaway)"
             if segmentation_type_id == 20:
                print "(Program Resumption)"
             if segmentation_type_id == 21:
                print "(Program Runover Planned)"
             if segmentation_type_id == 22:
                print "(Program Runover Unplanned)"
             if segmentation_type_id == 23:
                print "(Program Overlap Start)" 
             if segmentation_type_id == 24:
                print "(Program Blackout Override)"
             if segmentation_type_id == 25:
                print "(Program Start – In Progress)"
             if segmentation_type_id == 32:
                print "(Chapter Start)"   
             if segmentation_type_id == 33:
                print "(Chapter End)"
             if segmentation_type_id == 34:
                print "(Break Start)"
             if segmentation_type_id == 35:
                print "(Break End)"
             if segmentation_type_id == 36:
                print "(Opening Credit Start)"
             if segmentation_type_id == 37:
                print "(Opening Credit End)"
             if segmentation_type_id == 38:
                print "(Closing Credit Start)"
             if segmentation_type_id == 39:
                print "(Closing Credit End)"
             if segmentation_type_id == 48:
                print "(Provider Advertisement Start)"   
             if segmentation_type_id == 49:
                print "(Provider Advertisement End)"
             if segmentation_type_id == 50:
                print "(Distributor Advertisement Start)"
             if segmentation_type_id == 51:
                print "(Distributor Advertisement End)"
             if segmentation_type_id == 52:
                print "(Provider Placement Opportunity Start)"
             if segmentation_type_id == 53:
                print "(Provider Placement Opportunity End)" 
             if segmentation_type_id == 54:
                print "(Distributor Placement Opportunity Start)"
             if segmentation_type_id == 55:
                print "(Distributor Placement Opportunity End)"
             if segmentation_type_id == 56:
                print "(Provider Overlay Placement Opportunity Start)"   
             if segmentation_type_id == 57:
                print "(Provider Overlay Placement Opportunity End)"
             if segmentation_type_id == 58:
                print "(Distributor Overlay Placement Opportunity Start)"
             if segmentation_type_id == 59:
                print "(Distributor Overlay Placement Opportunity End)"
             if segmentation_type_id == 64:
                print "(Unscheduled Event Start)"
             if segmentation_type_id == 65:
                print "(Unscheduled Event End)"  
             if segmentation_type_id == 80:
                print "(Network Start)"
             if segmentation_type_id == 81:
                print "(Network End)"  
             print "segment_num=",segment_num
             print "segments_expected=",segments_expected

             if segmentation_type_id== 0X34 or segmentation_type_id == 0X36:
                sub_segment_num= struct.unpack("B",buffer[tracker+18+segmentation_upid_length-1+m])[0]
                sub_segments_expected= struct.unpack("B",buffer[tracker+19+segmentation_upid_length-1+m])[0] 
                print "sub_segment_num=",sub_segment_num
                print "sub_segments_expected=",sub_segments_expected
          if not segmentation_duration_flag and not program_segmentation_flag:
             segmentation_upid_byte=0
             segmentation_upid_type=struct.unpack("B",buffer[tracker+19+m])[0]
             segmentation_upid_length=struct.unpack("B",buffer[tracker+20+m])[0]
             print "segmentation_upid_type=",segmentation_upid_type,
             #print "segmentation_upid_type=",segmentation_upid_type,
             if segmentation_upid_type==0:
                print "(The segmentation_upid is not defined and is not present in the descriptor.)"
             if segmentation_upid_type==1:
                print "(Deprecated: use type 0x0C; The segmentation_upid does not follow a standard naming scheme.)" 
             if segmentation_upid_type==2:
                print "(Deprecated: use type 0x03, 8 characters; 4 alpha characters followed by 4 numbers.)" 
             if segmentation_upid_type==3:
                print "(Defined by the Advertising Digital Identification, LLC group. 12 characters; 4 alpha characters (company identification prefix) followed by 8 alphanumeric characters. (See [Ad-ID]).)" 
             if segmentation_upid_type==4:
                print "(UMID-See SMPTE 330)" 
             if segmentation_upid_type==5:
                print "(Deprecated: use type 0x06, ISO 15706 binary encoding.)"   
             if segmentation_upid_type==6:
                print "(Formerly known as V-ISAN. ISO 15706-2 binary encoding (\“versioned\” ISAN). See [ISO 15706-2].)"
             if segmentation_upid_type==7:
                print "(Tribune Media Systems Program identifier. 12 characters; 2 alpha characters followed by 10 numbers.)" 
             if segmentation_upid_type==8:
                print "(AiringID (Formerly Turner ID), used to indicate a specific airing of a program that is unique within a network.)" 
             if segmentation_upid_type==9:
                print "ADI-CableLabs metadata identifier)" 
             if segmentation_upid_type==10:
                print "(EIDR represented in Compact Binary encoding)" 
             if segmentation_upid_type==11:
                print "(ATSC_content_identifier() structure as defined in [ATSC A/57B].)"  
             if segmentation_upid_type==12:
                print "(Managed Private UPID structure.)"
             if segmentation_upid_type==13:
                print "(Multiple UPID types structure.)" 
             if segmentation_upid_type==14:
                print "(Advertising information.)" 
             if segmentation_upid_type==15:
                print "(UR-Universal Resource Identifier)" 
             if segmentation_upid_type > 15 and segmentation_upid_type  < 256:
                print "(Reserved)" 
             print "segmentation_upid_length=",segmentation_upid_length

             while segmentation_upid_byte < segmentation_upid_length:
                   segmentation_upid.append(struct.unpack("B",buffer[tracker+21+segmentation_upid_byte+m])[0])
                   segmentation_upid_byte +=1
             print "segmentation_upid=",listConcatenator(segmentation_upid)
             segmentation_type_id= struct.unpack("B",buffer[tracker+22+segmentation_upid_byte-1+m])[0]  
             segment_num= struct.unpack("B",buffer[tracker+23+segmentation_upid_byte-1+m])[0]
             segments_expected= struct.unpack("B",buffer[tracker+24+segmentation_upid_byte-1+m])[0]
             print "segmentation_type_id=",segmentation_type_id,
             if segmentation_type_id == 0:
                print "(Not Indicated)"
             if segmentation_type_id == 1:
                print "(Content Identification)"
             if (segmentation_type_id > 1 and segmentation_type_id < 16) or (segmentation_type_id > 25 and segmentation_type_id < 32) or (segmentation_type_id > 39 and segmentation_type_id < 48) or (segmentation_type_id > 59 and segmentation_type_id < 64) or (segmentation_type_id > 65 and segmentation_type_id < 80):
                print "segmentation_type_id is not defined in SCTE35 2019 specification"
             if segmentation_type_id == 16:
                print "(Program Start)"
             if segmentation_type_id == 17:
                print "(Program End)"
             if segmentation_type_id == 18:
                print "(Program Early Termination)"   
             if segmentation_type_id == 19:
                print "(Program Breakaway)"
             if segmentation_type_id == 20:
                print "(Program Resumption)"
             if segmentation_type_id == 21:
                print "(Program Runover Planned)"
             if segmentation_type_id == 22:
                print "(Program Runover Unplanned)"
             if segmentation_type_id == 23:
                print "(Program Overlap Start)" 
             if segmentation_type_id == 24:
                print "(Program Blackout Override)"
             if segmentation_type_id == 25:
                print "(Program Start – In Progress)"
             if segmentation_type_id == 32:
                print "(Chapter Start)"   
             if segmentation_type_id == 33:
                print "(Chapter End)"
             if segmentation_type_id == 34:
                print "(Break Start)"
             if segmentation_type_id == 35:
                print "(Break End)"
             if segmentation_type_id == 36:
                print "(Opening Credit Start)"
             if segmentation_type_id == 37:
                print "(Opening Credit End)"
             if segmentation_type_id == 38:
                print "(Closing Credit Start)"
             if segmentation_type_id == 39:
                print "(Closing Credit End)"
             if segmentation_type_id == 48:
                print "(Provider Advertisement Start)"   
             if segmentation_type_id == 49:
                print "(Provider Advertisement End)"
             if segmentation_type_id == 50:
                print "(Distributor Advertisement Start)"
             if segmentation_type_id == 51:
                print "(Distributor Advertisement End)"
             if segmentation_type_id == 52:
                print "(Provider Placement Opportunity Start)"
             if segmentation_type_id == 53:
                print "(Provider Placement Opportunity End)" 
             if segmentation_type_id == 54:
                print "(Distributor Placement Opportunity Start)"
             if segmentation_type_id == 55:
                print "(Distributor Placement Opportunity End)"
             if segmentation_type_id == 56:
                print "(Provider Overlay Placement Opportunity Start)"   
             if segmentation_type_id == 57:
                print "(Provider Overlay Placement Opportunity End)"
             if segmentation_type_id == 58:
                print "(Distributor Overlay Placement Opportunity Start)"
             if segmentation_type_id == 59:
                print "(Distributor Overlay Placement Opportunity End)"
             if segmentation_type_id == 64:
                print "(Unscheduled Event Start)"
             if segmentation_type_id == 65:
                print "(Unscheduled Event End)"  
             if segmentation_type_id == 80:
                print "(Network Start)"
             if segmentation_type_id == 81:
                print "(Network End)"  
             print "segment_num=",segment_num
             print "segments_expected=",segments_expected
             if segmentation_type_id== 0X34 or segmentation_type_id == 0X36:
                sub_segment_num= struct.unpack("B",buffer[tracker+25+segmentation_upid_byte+m])[0]
                sub_segments_expected= struct.unpack("B",buffer[tracker+26+segmentation_upid_byte+m])[0]
                print "sub_segment_num=",sub_segment_num
                print "sub_segments_expected=",sub_segments_expected

    ####Time Descriptor#####################################################################################           
    if splice_descriptor_tag  == 3:
       TAI_seconds=(((struct.unpack(">Q", buffer[tracker+6:tracker+14])[0] )& 0xffffffffffff0000)>>16)
       TAI_ns=struct.unpack(">Q", buffer[tracker+8:tracker+16])[0] 
       UTC_offset= struct.unpack(">H", buffer[tracker+17:tracker+18])[0]
       print "TAI_seconds=",TAI_seconds
       print "TAI_ns=",TAI_ns
       print "UTC_offset",UTC_offset

    ####Audio Descriptor#####################################################################################
    if splice_descriptor_tag  == 4:
         audio_count=(((struct.unpack("B",buffer[tracker+6])[0])&0xF0)>>4)
         reserved10= ((struct.unpack("B",buffer[tracker+6])[0]) &0x0F ) 
         print "audio_count=",audio_count
         print "reserved10=",reserved10        
         while n<audio_count:
            component_tag=struct.unpack("B",buffer[tracker+7+n])[0]
            ISO_code=(((struct.unpack(">Q", buffer[tracker+7+n:tracker+15+n])[0] )& 0xffffff0000000000)>>40)
            Bit_Stream_Mode=(((struct.unpack("B",buffer[tracker+10+n])[0])&0xE0) >> 5)
            Num_Channels=(((struct.unpack("B",buffer[tracker+10+n])[0])&0x1E) >> 1)
            Full_Srvc_Audi=((struct.unpack("B",buffer[tracker+10+n])[0])&0x01)
            print "component_tag=",component_tag
            print "ISO_code=",ISO_code
            print "Bit_Stream_Mode=",Bit_Stream_Mode
            print "Num_Channels=",Num_Channels
            print "Full_Srvc_Audi=",Full_Srvc_Audi
            n +=1

    tracker= tracker+2+i
    return (tracker,tracker-length)
###########################Splice_Info_Section###############################################################


def splice_info_section(buffer, curr_PCR):
   import datetime
   now = datetime.datetime.now()
   print "SpliceInfoSection found at", now.strftime("%Y-%m-%d %H:%M:%S")
   table_id = (struct.unpack(">B", buffer[5:6])[0])
   print "table_id=",table_id
   if table_id != 252:
      print "ERROR:table_id is not 0xFC(252)."
      return
   section_syntax_indicator=((struct.unpack(">B", buffer[6:7])[0])>>7)
   print "section_syntax_indicator=",section_syntax_indicator
   if section_syntax_indicator:
          print "ERROR:section_syntax_indicator is not 0. "
   private_indicator=(((struct.unpack(">B", buffer[6:7])[0]) & 0x80) >>6)
   print "private_indicator=",private_indicator
   if private_indicator:
          print "ERROR:private_indicator is not 0. "
   reserved1=(((struct.unpack(">B", buffer[6:7])[0]) & 0x30) >>4)
   print "reserved1=",reserved1
   section_length= (struct.unpack(">H", buffer[6:8])[0] & 0x0FFF)
   if section_length > 181:
      print "SpliceInfoSection spread across multiple TS packet"
   if section_length > 4093:
      print "ERROR:section_length value exceeds 4093."
   print "section_length=",section_length
   protocol_version=struct.unpack(">B", buffer[8:9])[0]
   print "protocol_version=",protocol_version
   encrypted_packet=((struct.unpack("B",buffer[9])[0] & 0xF0) >>7 )
   if encrypted_packet:
      print "Portions of the splice_info_section, starting with splice_command_type and ending with and including E_CRC_32, are encrypted."
   else:
      print "SpliceInfoSection is not encrypted."
   print "encrypted_packet=",encrypted_packet
   encryption_algorithm=((struct.unpack("B",buffer[9])[0] & 0x7E) >>1 )
   print "encryption_algorithm=",encryption_algorithm
   if encryption_algorithm == 1:
      print "encryption_algorithm: DES –ECB mode"
   if encryption_algorithm == 2:
      print "encryption_algorithm: DES –CBC mode"
   if encryption_algorithm == 3:
      print "encryption_algorithm: Triple DES EDE3 –ECB mode"
   if encryption_algorithm > 3 and encryption_algorithm < 32:
      print " Reserved for future encryption algorithm"
   if encryption_algorithm > 31 and encryption_algorithm < 64:
      print "encryption_algorithm:User Private"
   pts_adjustment=((struct.unpack(">Q", buffer[9:17])[0]) >> 24)
   print "pts_adjustment=", pts_adjustment
   cw_index=(struct.unpack("B",buffer[14])[0])
   print "cw_index=",cw_index
   tier=((struct.unpack(">H", buffer[15:17])[0]&0xFFF0 )>>4)
   print "tier=",tier
   if tier !=  0xFFF:
      print"INFO:Tier field may take any value between 0x000 and 0xFFF. The value of 0xFFF provides backwards compatibility and shall be ignored by downstream equipment.\nWhen using tier, the message provider should keep the entire message in a single transport stream packet."
      if section_length > 181:
         print "ERROR: Tier value used in a Splice Message that has SpliceInfoSection spanning more than one TS packet."
   splice_command_length=(struct.unpack(">H", buffer[16:18])[0]&0x0FFF)

   print "splice_command_length=",splice_command_length
   if int(splice_command_length) == 4095:
      print "(The splice_command_length value of 4095 provides backwards compatibility and shall be ignored by downstream equipment.)"
   splice_command_type=(struct.unpack("B",buffer[18])[0])
   print "splice_command_type=",splice_command_type,
   
   if (splice_command_type) == 0:
      tracker=spliceNull(buffer,19)
   elif (splice_command_type) == 4:
      tracker=spliceSchedule(buffer,19)
   elif (splice_command_type) == 5:
      tracker=spliceInsert(buffer,curr_PCR,pts_adjustment)
   elif (splice_command_type) == 6:
      tracker=time_signal(buffer,curr_PCR,pts_adjustment,19)
   elif (splice_command_type) == 7:
      tracker=bandwidth_reservation(buffer,19)
   elif (splice_command_type) == 255:
      tracker=private_command(buffer)
   else:
      print "Unsupported Splice Command! Check the input device/s or the broadcaster."
      return 
 
   descriptor_loop_length=struct.unpack(">B", buffer[tracker+1:tracker+2])[0]& 0xFFFF
   print "descriptor_loop_length=",descriptor_loop_length
   i=0
   length=0
   tracker +=2
   while i<descriptor_loop_length:
        (tracker,one_descriptor_length)=splice_descriptor(buffer,tracker)
        length=length+one_descriptor_length
        i=length

   if encrypted_packet:
      j=0
      alignment_stuffing=0
      while j<descriptor_loop_length:
        alignment_stuffing=(struct.unpack("B",buffer[tracker+j])[0])
        j +=1
      E_CRC_32=hex((struct.unpack(">Q", buffer[tracker+descriptor_loop_length+j:tracker+descriptor_loop_length+j+8])[0]& 0xFFFFFFFF00000000)>> 32)
      print "alignment_stuffing=",alignment_stuffing
      print "E_CRC_32=",E_CRC_32
      decryption=0
      ### Decryption to be performed before calculating validating the E_CRC32.Presently not supported.Perform the decryption, get the SpliceInfo, set the decryption=1 and perform the ECRC_32 validation#############
      if decryption:
          ecrc_byte_count=0
          decrypted_spliceInfo_section=[]
          if section_length+4 < 184:
             while ecrc_byte_count < section_length-5:
                   decrypted_spliceInfo_section.append(hex(struct.unpack("B",buffer[ecrc_byte_count+17])[0]))
                   ecrc_byte_count += 1

             ecrc32_hexstring= ''
             element=0
             while element < len(decrypted_spliceInfo_section):
                   ecrc32_hexstring += (decrypted_spliceInfo_section[element][2:]).zfill(2)
                   element += 1
              #print "crc32_hexstring=",crc32_hexstring
             crc32(ecrc32_hexstring,CRC_32,1)      

   CRC_32=hex((struct.unpack(">Q", buffer[tracker:tracker+8])[0] & 0xFFFFFFFF00000000)>> 32)
   print "CRC_32=",CRC_32,
   crc_byte_count=0
   spliceInfo_section=[]
   if section_length+4 < 184:
      while crc_byte_count < section_length-1:
            spliceInfo_section.append(hex(struct.unpack("B",buffer[crc_byte_count+5])[0]))
            crc_byte_count += 1
      #print "SpliceInfoSection=",spliceInfo_section

      crc32_hexstring= ''
      element=0
      while element < len(spliceInfo_section):
            crc32_hexstring += (spliceInfo_section[element][2:]).zfill(2)
            element += 1
      #print "crc32_hexstring=",crc32_hexstring
      crc32(crc32_hexstring,CRC_32,0)


   print "=================End of SCTE35 CUE Message ==========================="

def getNextPck(buffer,pckSize,index):
    return buffer[index*pckSize:pckSize*(index+1)]

def getPid(buffer):
    if struct.unpack("B",buffer[0])[0]== 71:
        pid = int(struct.unpack(">H", buffer[1:3])[0] & 0x01FFF)
        return pid
    else:
        return -1

def getPTS(buffer):
    pts = 0
    k = 0
    # adaptation field present
    if ((struct.unpack(">B", buffer[3:4])[0] & 0x20) == 0x20):
        k = int(struct.unpack(">B", buffer[4:5])[0] + 1)
     # payload start indicator present and PTS flag present (depending on the presence of adaptation field k = 0 or k = adaptation field length)
    if ((struct.unpack(">B", buffer[1:2])[0] & 0x40) == 0x40) and ((struct.unpack(">B", buffer[k+11:k+12])[0] & 0x80) == 0x80):
        b32_30 = ((struct.unpack(">Q", buffer[k+10: k+18])[0] & 0x0000000E00000000) >> 3 )
        b29_15 = ((struct.unpack(">Q", buffer[k+10: k+18])[0] & 0x00000000FFFE0000) >> 2 )#pts 29-15
        b14_0 = ((struct.unpack(">Q", buffer[k+10: k+18])[0] & 0x000000000000FFFE) >> 1 )#pts 14-0
        pts = b32_30 + b29_15 + b14_0
    return pts

def getPCR(buffer):
    base =(struct.unpack(">Q", buffer[6:14])[0] & 0xFFFFFFFF80000000) >> 31 #pcr base
    ext = (struct.unpack(">Q", buffer[6:14])[0] & 0x0000000001FF0000) >> 16 #pcr ext (there is 6 reserved bits between base and ext)
    pcr = base*300 + ext
    return pcr

def multicastReceiver(group):
    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo(group, None)[0]
    # Create a socket
    try: 
       print("creating Socket with SO_REUSEADDR option",group)
       s = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    except socket.error as e:
           print(e)

    # Allow multiple copies of this program on one machine
    # (not strictly needed)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind it to the port
    #s.bind(('', MYPORT))

    try:
        print(("Binding socket to port: " + str(MYPORT)))
        s.bind(('', MYPORT))

    except socket.error as msg:
        print(("Socket binding error: " + str(msg) + "\n"))


    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])


    # Join group
    if addrinfo[0] == socket.AF_INET: # IPv4
        mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except:
               print("Connection failed!") 



   #############variable declaration############################################################     
    #PgmPid=8192
    scte_pid=8192
    Pid=8192
    previousTotalMPEGPkts=0
    PCR_previous=0
    TotalMPEGPkts=0
    pcr=0
    streamType=[]
    tsrate=[]
    Avg_tsrate=0   
    current_pcr=0 
    expectedPCR=0
    video_pid=8192
    audio1_pid=8192
    pcr_accuracy= 0L
    ptsIntervalvideo=0
    ptsIntervalaudio1=0
    previousaudio1PTStime=0
    previousvideoPTStime=0
    pgm=[]
    PgmPid=[8192]
    AC3_pid=[]
    MPEG_AAC_pid=[]
    DVB_AC3_pid=[]
    # Loop, printing any data we receive
    print "Joined",group,MYPORT
    print "Waiting for Splice Command..."
    while True:
        PCRfound=False
        PATfound = False
        PMTfound=False
        MPEGPkt = 0
        PMTfound = True
        PATfound = False
        
        data, sender = s.recvfrom(1500)
        ############################ Handling RTP encapsulation ########################################################################
        if hex(struct.unpack("B", data[0])[0]) != '0x47':
           if hex(struct.unpack(">H", data[0:2])[0]) == '0x8021': ## RTP packet with no padding or extension           
               data = data[12:]
           elif (((struct.unpack("B", data[0])[0]) & 0b10110000) == '0x90')  or (((struct.unpack("B", data[0])[0]) & 0b10110000) == '0xA0') or (((struct.unpack("B", data[0])[0]) & 0b10110000) == '0xB0'):
               ### RTP with extension/padding #################################
               RTP_length=0
               while hex(struct.unpack("B", data[0+RTP_length])[0]) != '0x47':
                     RTP_length +=1
               data= data[12+RTP_length:]
       #########RTP data decoding to be implemnted in future. In the current implementation, the RTP data is stripped off from the input and fed for transport stream processing#########
       ################################ FUTURE Implementation: RECORD functionality ###################################################################################### 
        #if RECORD:
        #   with open('received_file.ts', 'wb') as f:
        #       print 'file opened'
        #       while True:
        #             print('receiving data...')
        #             f.write(data)
        #   f.close()
        MPEGPktsPerIP = len(data)/188


        
        while (MPEGPkt < MPEGPktsPerIP):   
            buffer=getNextPck(data,packetL,MPEGPkt)
            MPEGPkt +=1
            Pid=getPid(buffer)
       ###### Decode the PAT#################################################################################
            if  Pid == 0:
                PATfound = True
                #print "PATFound"
                payload_index = 0 #start of payload index
                PatLen =(struct.unpack(">H", buffer[6:8])[0] & 0x0FFF)
                N = (PatLen - 9)/4

                while payload_index < N:
                    if struct.unpack(">H", buffer[13+payload_index*4+2:13+payload_index*4+4])[0] & 0x1FFF >20:
                        #pgm.append(struct.unpack(">H", buffer[13+k*4:13+k*4+2])[0])
                        pgm=(struct.unpack(">H", buffer[13+payload_index*4:13+payload_index*4+2])[0])
                        #PgmPid.append(struct.unpack(">H", buffer[13+k*4+2:13+k*4+4])[0] & 0x1FFF)
                        PgmPid=(struct.unpack(">H", buffer[13+payload_index*4+2:13+payload_index*4+4])[0] & 0x1FFF)
                    payload_index += 1

       ###### Decode the PMT and get the PIDs and the descriptors#########################################

            if  Pid == PgmPid:
                p = 0 #start of payload index
                pgmInfoDesc_i=0
                PatLen =(struct.unpack(">H", buffer[6:8])[0] & 0x0FFF)
                elemPid = []
                PIDDesc = []
                program_desc_tag=0
                program_descLen=0
                FoundCUEidentifier=False
                desc_info=[]
                pcr_pid = ((struct.unpack(">H", buffer[13:15])[0])& 0x0FFF)
                section =(struct.unpack(">B", buffer[11:12])[0])
                last_section = (struct.unpack(">B", buffer[12:13])[0])
                pgmInfoLength = (struct.unpack(">H", buffer[15:17])[0]& 0x0FFF)

                while pgmInfoDesc_i <pgmInfoLength:
                       desc_byte=0
                       program_desc_tag=(struct.unpack("B", buffer[17+pgmInfoDesc_i])[0])
                       program_descLen=(struct.unpack("B", buffer[18+pgmInfoDesc_i])[0])
                       if program_desc_tag == 5 :

                          while desc_byte <program_descLen+2:
                                desc_info.append(hex(struct.unpack("B", buffer[17+pgmInfoDesc_i+desc_byte])[0]))
                                desc_byte += 1
                          if desc_info[2]!= '0x43' or desc_info[3]!='0x55' or desc_info[4] !='0x45' or desc_info[5] != '0x49':
                             print "WARNING:ProgramInfoDescriptor doesn't have CUEI Registration descriptor. For Program Splicing, registration description is must."
                          else:
                               FoundCUEidentifier=True

                       pgmInfoDesc_i=pgmInfoDesc_i+program_descLen+2

                start = 17 + pgmInfoLength
                #N = PatLen - start
                M = PatLen - 9 - pgmInfoLength
                scte_pid_desc=[]

                while p < (M-4): #you cannot have k>= N-22 for struct.unpack(">H", buffer[17+k+3:17+k+5])[0] to work
                    streamType.append(struct.unpack(">B", buffer[start+p:start+p+1])[0])
                    elemPid.append(struct.unpack(">H", buffer[start+p+1:start+p+3])[0] & 0x1FFF)
                    descLen = struct.unpack(">H", buffer[start+p+3:start+p+5])[0] & 0x0FFF
                    piddescloop=0
                    piddesc = []

                    while piddescloop < descLen:
                        piddesc.append(hex(struct.unpack(">B", buffer[start+p+5+piddescloop:start+p+piddescloop+6])[0]))
                        piddescloop += 1
                    p = p + 5 + int(descLen)
                    PIDDesc.append(piddesc)
                    if streamType[-1] == 134:
                       scte_pid_desc=PIDDesc[-1]
                       #if str(scte_pid_desc[0]) == "0x52":

                       #print scte_pid_desc


                if 27 in streamType:
                    video_pidindex=streamType.index(27)
                    video_pid=elemPid[video_pidindex]


                if 2 in streamType:
                    video_pidindex=streamType.index(2)
                    video_pid=elemPid[video_pidindex]


                # if 129 in streamType:
                #    audio_pidindex1=streamType.index(129)
                #    audio1_pid=elemPid[audio_pidindex1]


                # if 192 in streamType:
                #    audio_pidindex2=streamType.index(192)
                #    audio2_pid=elemPid[audio_pidindex2]


                # if 6 in streamType:
                #    audio_pidindex3=streamType.index(6)
                #    audio3_pid=elemPid[audio_pidindex3]

                if 129 in streamType:
                   aud=0
                   AC3_pid=[]
                   audio_pid_index=list_duplicates_of(streamType,129)
                   audioNum=0
                   while audioNum<len(audio_pid_index):
                         aud=audio_pid_index[audioNum]
                         AC3_pid.append(elemPid[aud])
                         audioNum +=1
                   #print (AC3_pid)
                   if not len(audio_pid_index):
                      aud=streamType.index(129)
                      AC3_pid.append(elemPid[aud])
                   #del audio_pid[:]
                   #print (AC3_pid)


                if 192 in streamType:
                   aud=0
                   MPEG_AAC_pid=[]
                   audio_pid_index=list_duplicates_of(streamType,192)
                   audioNum=0
                   while audioNum<len(audio_pid_index):
                         aud=audio_pid_index[audioNum]
                         MPEG_AAC_pid.append(elemPid[aud])
                         audioNum +=1
                   #print (MPEG_AAC_pid)
                   if not len(audio_pid_index):
                      aud=streamType.index(192)
                      MPEG_AAC_pid.append(elemPid[aud])
                   # audio_pidindex2=streamType.index(192)
                   # audio2_pid=elemPid[audio_pidindex2]
                   #del audio_pid[:]


                if 6 in streamType:
                   aud=0
                   DVB_AC3_pid=[]
                   audio_pid_index=list_duplicates_of(streamType,6)
                   audioNum=0
                   while audioNum<len(audio_pid_index):
                         aud=audio_pid_index[audioNum]
                         DVB_AC3_pid.append(elemPid[aud])
                         audioNum +=1
                   #print (DVB_AC3_pid)
                   if not len(audio_pid_index):
                      aud=streamType.index(6)
                      DVB_AC3_pid.append(elemPid[aud])
                   # audio_pidindex3=streamType.index(6)
                   # audio3_pid=elemPid[audio_pidindex3]
                   #del audio_pid[:]


                if 134 in streamType:
                    scte_index=streamType.index(134)
                    if scte_index < len(elemPid):
                       scte_pid=elemPid[scte_index]
                       del streamType[:]
                       del elemPid[:]
                       del PIDDesc[:]


            if PMTfound:
               PMTfound = False


            if PCR_previous and (TotalMPEGPkts > previousTotalMPEGPkts) and Avg_tsrate:
               current_pcr= (PCR_previous)+(((TotalMPEGPkts-previousTotalMPEGPkts)/float(Avg_tsrate))/27000000)


            if Pid == scte_pid:
               print "=================Start of SCTE35 CUE Message ==========================="
               print "SCTE35 PID:",scte_pid
               Payload_unit_start_indicator= ((struct.unpack("B",buffer[1])[0] & 0b01000000 ) >> 6)
               print "ProgramInfo_RegistrationDescriptor:",listConcatenator(desc_info),
               if FoundCUEidentifier:
                  print "(SCTE_splice_format_identifier)" 
               print "SCTE PID descriptors:",(listConcatenator(scte_pid_desc)),

               if str(scte_pid_desc[0]) == "0x8a":
               	  print "(Cue Identifier Descriptor ",
               	  if str(scte_pid_desc[2]) == "0x0":
               	  	 print "PID Usage:splice_insert, splice_null, splice_schedule)"
               	  elif str(scte_pid_desc[2]) == "0x1":
               	  	 print "PID Usage:All Commands)"
               	  elif str(scte_pid_desc[2]) == "0x2":
               	  	 print "PID Usage:Segmentation)"
               	  elif str(scte_pid_desc[2]) == "0x3":
               	  	 print "PID Usage:Tiered Splicing)"
               	  elif str(scte_pid_desc[2]) == "0x4":
               	  	 print "PID Usage:Tiered Segmentation)"
               	  else:
               	  	 print "PID Usage:Reserved or User Defined"

               if str(scte_pid_desc[0]) == "0x52":
               	  print "(stream_identifier_descriptor)",    
               if len(scte_pid_desc) > 3: 
	              if str(scte_pid_desc[3]) == "0x8a":
	               	 print "(Cue Identifier Descriptor ",
	               	 if str(scte_pid_desc[5]) == "0x0":
	               	    print "PID Usage:splice_insert, splice_null, splice_schedule)"
	               	 elif str(scte_pid_desc[5]) == "0x1":
	               	   	 print "PID Usage:All Commands)"
	               	 elif str(scte_pid_desc[5]) == "0x2":
	               	  	 print "PID Usage:Segmentation)"
	               	 elif str(scte_pid_desc[5]) == "0x3":
	               	  	 print "PID Usage:Tiered Splicing)"
	               	 elif str(scte_pid_desc[5]) == "0x4":
	               	  	 print "PID Usage:Tiered Segmentation)"
	               	 else:
	               	  	 print "PID Usage:Reserved or User Defined)"  
	              if str(scte_pid_desc[3]) == "0x52":
	               	 print "(stream_identifier_descriptor)" 

               del scte_pid_desc[:]
               print "Payload_unit_start_indicator=",Payload_unit_start_indicator
               transport_scrambling_control= ((struct.unpack("B",buffer[3])[0] & 0xC0) >> 6)
               print "transport_scrambling_control=",transport_scrambling_control
               if transport_scrambling_control != 0:
                  print "transport_scrambling_control enabled on the scte packet.Check with AdSplicer vendor if Splicer can descramble."
               if not Payload_unit_start_indicator:
                      print "ERROR:Payload_unit_start_indicator not set!"
               pointer_field= (struct.unpack("B",buffer[4])[0])
               print "pointer_field=",pointer_field
               if pointer_field != 0x00:
                  print "SpliceInfoSection is spread across more than one TS packet!"
               splice_info_section(buffer,current_pcr/300)

            PCRPid=isPCRPid(buffer)

            if Pid == video_pid:
              Payload_unit_start_indicator= ((struct.unpack("B",buffer[1])[0] & 0b01000000 ) >> 6)
              if Payload_unit_start_indicator:
                 PTS=getPTS(buffer)

                 if current_pcr:
                    Video_PtsPcrDiff=((PTS-(current_pcr/300))*1000)/90000
                    ptsIntervalvideo=(current_pcr-previousvideoPTStime)/27000000
                    if Video_PtsPcrDiff < 0:
                       print "PTS-PCR(ms) difference  is negative on video pid=", video_pid,Video_PtsPcrDiff
                    if ptsIntervalvideo > 700:
                       print "ERROR:Video PTS Interval > 700ms"
                 previousvideoPTStime=current_pcr

            # if Pid == audio1_pid:            
            #   Payload_unit_start_indicator= ((struct.unpack("B",buffer[1])[0] & 0b01000000 ) >> 6)
            #   if Payload_unit_start_indicator:
            #      PTS=getPTS(buffer)
            #      if current_pcr:
            #         Audio_PtsPcrDiff=((PTS-(current_pcr/300))*1000)/90000 
            #         ptsIntervalaudio1=(current_pcr-previousaudio1PTStime)/27000000
            #         if Audio_PtsPcrDiff < 0:
            #            print "PTS-PCR(ms) difference is negative on audio pid=",audio1_pid,Audio_PtsPcrDiff
            #         if ptsIntervalaudio1 > 700:
            #            print "ERROR:Audio1 PTS Interval > 700ms"
            if len(AC3_pid):
               audioNum=0
               Audio_PtsPcrDiff=0
               while audioNum<len(AC3_pid):
                    if Pid == AC3_pid[audioNum] and Pid != 8192:            
                      Payload_unit_start_indicator= ((struct.unpack("B",buffer[1:2])[0] & 0b01000000 ) >> 6)
                      if Payload_unit_start_indicator:
                         PTS=getPTS(buffer)
                         if current_pcr:
                            Audio_PtsPcrDiff=((PTS-(current_pcr/300))*1000)/90000 
                            #ptsIntervalaudio1=(current_pcr-previousaudio1PTStime)/27000000
                            #print ("AUdio PTS-PCR",Audio_PtsPcrDiff,AC3_pid[audioNum])
                            if Audio_PtsPcrDiff < 0:
                               print("PTS-PCR(ms) difference is negative on audio pid=",AC3_pid[audioNum],Audio_PtsPcrDiff)
                            # if ptsIntervalaudio1 > 700:
                            #    print("ERROR:Audio1 PTS Interval > 700ms")
                         #previousaudio1PTStime=current_pcr
                    audioNum +=1

            if len(MPEG_AAC_pid):
               audioNum=0
               Audio_PtsPcrDiff=0
               while audioNum<len(MPEG_AAC_pid) and Pid != 8192:
                    if Pid == MPEG_AAC_pid[audioNum]:            
                      Payload_unit_start_indicator= ((struct.unpack("B",buffer[1:2])[0] & 0b01000000 ) >> 6)
                      if Payload_unit_start_indicator:
                         PTS=getPTS(buffer)
                         if current_pcr:
                            Audio_PtsPcrDiff=((PTS-(current_pcr/300))*1000)/90000 
                            #ptsIntervalaudio1=(current_pcr-previousaudio1PTStime)/27000000
                            #print ("AUdio PTS-PCR",Audio_PtsPcrDiff,AC3_pid[audioNum])
                            if Audio_PtsPcrDiff < 0:
                               print("PTS-PCR(ms) difference is negative on audio pid=",MPEG_AAC_pid[audioNum],Audio_PtsPcrDiff)
                            # if ptsIntervalaudio1 > 700:
                            #    print("ERROR:Audio1 PTS Interval > 700ms")
                         #previousaudio1PTStime=current_pcr
                    audioNum +=1

            if len(DVB_AC3_pid):
               audioNum=0
               Audio_PtsPcrDiff=0
               while audioNum<len(DVB_AC3_pid):
                    if Pid == DVB_AC3_pid[audioNum] and Pid != 8192:            
                      Payload_unit_start_indicator= ((struct.unpack("B",buffer[1:2])[0] & 0b01000000 ) >> 6)
                      if Payload_unit_start_indicator:
                         PTS=getPTS(buffer)
                         if current_pcr:
                            Audio_PtsPcrDiff=((PTS-(current_pcr/300))*1000)/90000 
                            #ptsIntervalaudio1=(current_pcr-previousaudio1PTStime)/27000000
                            #print ("AUdio PTS-PCR",Audio_PtsPcrDiff,AC3_pid[audioNum])
                            if Audio_PtsPcrDiff < 0:
                               print("PTS-PCR(ms) difference is negative on audio pid=",DVB_AC3_pid[audioNum],Audio_PtsPcrDiff)
                            # if ptsIntervalaudio1 > 700:
                            #    print("ERROR:Audio1 PTS Interval > 700ms")
                         #previousaudio1PTStime=current_pcr
                    audioNum += 1

            if not PCRfound and Pid == PCRPid and ((struct.unpack(">B", buffer[3:4])[0] & 0x20) == 0x20) and (struct.unpack(">B", buffer[4:5])[0] != 0x0) and (struct.unpack(">B", buffer[5:6])[0] & 0x10) == 0x10:
                pcr = getPCR(buffer)
                if pcr != 0:
                    PCRfound = True
                    if TotalMPEGPkts > previousTotalMPEGPkts and pcr != PCR_previous :
                       tsrate.append(((TotalMPEGPkts-previousTotalMPEGPkts)*188*8*27000000)/(pcr-PCR_previous))
                       if current_pcr and  float(tsrate[-1]):
                          time_since_last_pcr=(TotalMPEGPkts-previousTotalMPEGPkts)*188*8/float(tsrate[-1])
                          if float(time_since_last_pcr)*1000 > 40.0 and float(time_since_last_pcr)*1000 < 100:
                             print "Warning:PCR interval exceeding 40ms",
                             print "PCR_interval(ms):",time_since_last_pcr*1000
                          if float(time_since_last_pcr)*1000 > 100.0:
                             print "ERROR:PCR interval exceeding 100ms",float(time_since_last_pcr)*1000 
                             print "PCR_interval(ms):",time_since_last_pcr*1000,
                             print "TS Bitare=", tsrate[-1],
                             print "pcr_accuracy(ns)=", pcr_accuracy
                          expectedPCR=float(PCR_previous)+ float(time_since_last_pcr)*27000000
                          pcr_accuracy= ((float(pcr)-float(expectedPCR))*1000000000)/27000000
                          #print pcr_accuracy
                          if pcr_accuracy > 500.0 or pcr_accuracy < -500.0:
                             print "pcrInacurracy found!", float(pcr_accuracy)
                       previousTotalMPEGPkts=TotalMPEGPkts
                       PCR_previous=pcr


            if len(tsrate) == 100:
               Avg_tsrate=sum(tsrate)/100
               del tsrate[:]
           
        TotalMPEGPkts=TotalMPEGPkts+MPEGPkt 


def main():
    multicastReceiver(MYGROUP_IPv4)       

if __name__ == '__main__':
    main()
