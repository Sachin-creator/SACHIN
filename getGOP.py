##### Import the Modules#############################
import os
import sys
import Tkinter
import tkFileDialog
######Declare the variables,lists#####################
GOP=[]
gopCount= 0
gopLength=0
gopLengthList=[]
MframesbwKeyFrames=[]
bFrames=0
bFramesCount=[]
####### Definitions###################################
def getFilename():
    root=Tkinter.Tk()
    root.withdraw()
    fTyp=[('.ts File','*.ts'),('.TOD File','*.TOD'),('.trp File','*.trp'),('All Files','*.*')]
    iDir='~/'
    filename=tkFileDialog.askopenfilename(filetypes=fTyp,initialdir=iDir)
    root.destroy()
    return filename;

def concatenateFrames(list):
    GOPStruct= ''
    for element in list:
        GOPStruct += str(element)
    return GOPStruct

########### Get the File for processing ###############
fname = getFilename()
cmd='C:\\MLB\\bin\\ffprobe.exe -show_frames -loglevel quiet '+ fname + ' | findstr \"pict_type\" > GOP.txt'
os.system(cmd)
########### GOP Processor #############################

try:
    with open("GOP.txt") as fp:
       for line in fp:
           line = line.rstrip()
           if  str(line) == "pict_type=I" :
               if gopCount > 0 and len(GOP) >0 :
               	 GOP.append("I")
               	 print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                 print "GOP Length:",len(GOP)
                 gopLengthList.append(len(GOP))
                 #print GOP
                 GOP.insert(0, GOP.pop())
                 #"".join(GOP)
                 print concatenateFrames(GOP)
                 #print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                 del GOP[:]
                 bFrames=0
               gopCount +=1
           elif str(line) == "pict_type=B":
                 GOP.append("B")
                 bFrames +=1
           elif str(line) == "pict_type=P":
                 GOP.append("P")
                 bFramesCount.append(bFrames)
                 bFrames=0
    os.remove("GOP.txt")             
    print "#######################################################################################################################################################################"             
    print "File:",fname
    print "Max M=", max(bFramesCount)+1
    print "Min M=", min(bFramesCount)+1
    print "Max GOPLength(Nmax)=", max(gopLengthList)
    print "Min GOPLength(Nmin)=", min(gopLengthList)
    print "GOP Structure(M,N):",max(bFramesCount)+1,max(gopLengthList)
    print "#######################################################################################################################################################################"
except:
    print "I/O error!"
finally:
    fp.close()
