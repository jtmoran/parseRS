'''
ParseRS v20150522 - John Moran (john@jtmoran.com)

ParseRS can be used extract browsing information from Automatic Crash 
Recovery files created by Internet Explorer.  Please use and distribute 
freely.

Requires Python 3 and OleFileIO_PL library.
   
Options:
  
   -d, --directory <directory>   Read the contents of all .dat 
                                 files in a directory
   -r, --recovery <file>         Read a single recovery store file 
                                 and its associated tab data files
   -t, --tab <file>              Read a single tab data file
   -h, --help                    Show help'''

import datetime
import getopt
import glob
import OleFileIO_PL
import os
import struct
import sys
import re

def readDir (dir):
    '''Checks for RecoveryStore files in a given directory and passes each file located on to be parsed.
    Accepts single argument: the relative or absolute directory path as string.'''
    if not os.path.exists(dir):
        print("\n[-] Directory '" + dir + "' does not exist!")
        return
    print("\n[+] Reading files from '" + dir + "'")
    os.chdir(dir)
    fileList = []
    #Get list of RS files in dir
    for file in glob.glob("RecoveryStore*.dat"):
        fileList.append(file)
    #If 1+ RS files found continue
    if(len(fileList) < 1):
        print("\n[-] No RecoveryStore files found in '" + dir + "'")
        return
    else:
        print("\n[+] " + str(len(fileList)) + " RecoveryStore files found in '" + dir + "'")
    #Pass each RS file to readRS to be parsed
    for f in fileList:
        readRSF(dir, f)
        
def readRSF(filePath, fileName): 
    '''Parses the information stored in the RecoveryStore file.
    Accepts single argument: the file name of the RecoveryStore file.'''
    fname = os.path.join(filePath, fileName)
    print("\n[+] Parsing '" + fname + "'")
    try:
        #Check if file is the correct format
        if not (OleFileIO_PL.isOleFile(fname)):
            print("\n  [-] Unable to parse file: Incorrect format!")
            return
        path = os.path.dirname(fname)
        rs = OleFileIO_PL.OleFileIO(fname)
        #Get list of streams
        streams = rs.listdir()
        sStreams = []
        for s in (streams):
            sStreams.append(s[0])
        p = rs.getproperties('\x05KjjaqfajN2c0uzgv1l4qy5nfWe')
        #Check for InPrivate Browsing
        if (int("5") in p):
            print("\n  InPrivate Browsing Detected") 
        #Get session times
        closed = (buildTime(p[3]))
        opened = (buildTime(p[7]))
        print("\n  Opened: " + opened + " UTC")
        if (opened != closed) :
            print("  Closed: " + closed + " UTC")
        #Get all open tabs (TS#)
        print("\n   Open Tabs:")
        for s in streams:
            if((s[0][:2] == "TS") ):
                tempStream = rs.openstream(s[0])
                data = tempStream.read()
                tdName = ""
                n = 0
                while ((n * 16) < len(data)) :
                    tdName = "".join("%02x" % b for b in data[n * 16 : n * 16 + 16])
                    n = n + 1
                    tdName = "{" + buildGUID(tdName[:32]) + "}.dat"
                    readTDF(filePath, tdName)
        #Get all closed tabs
        print("\n   Closed Tabs:")
        for s in streams:
            if(s[0] == "ClosedTabList"):
                tempStream = rs.openstream(s[0])
                data = tempStream.read()
                tdName = ""
                #Build GUID
                n = 0
                while ((n * 16) < len(data)) :
                    tdName = "".join("%02x" % b for b in data[n * 16 : n * 16 + 16])
                    n = n + 1
                    tdName = "{" + buildGUID(tdName[:32]) + "}.dat"
                    readTDF(filePath, tdName)
    except:
        print("\n   [-] Error reading '" + fname + "': ", sys.exc_info()[1])
		
def readTDF(filePath, fileName): 
    '''Parses the information stored in the tab data file.
    Accepts single argument: the file name of the tab data file.'''
    tdName = os.path.join(filePath, fileName)
    print("\n     [+] Parsing '" + tdName + "'\n")
    try:
        #Check if file is the correct format
        if not (OleFileIO_PL.isOleFile(tdName)):
            print("\n     [-] Unable to parse file: Incorrect format!")
            return
        rs = OleFileIO_PL.OleFileIO(tdName)
        #Get list of streams
        streams = rs.listdir()
        #Get travel order
        for s in streams:
            if(s[0] == "TravelLog"):
                tempStream = rs.openstream(s[0])
                data = tempStream.read()
                pos = 0
                travel = []
                while (pos < len(data)):
                    travel.append(struct.unpack('B', data[pos:pos+1])[0])
                    pos = pos + 4
                print("       Page Order: " + '%s' % ', '.join(map(str, travel)) + "\n")
        #Get all pages (TL#)
        sStreams = []
        for s in (streams):
            sStreams.append(s[0])
        p = rs.getproperties('\x05KjjaqfajN2c0uzgv1l4qy5nfWe')    
        print("       Current Page: " + p[3])
        if (any(s.startswith('TL') for s in sStreams)) :
            print ("")
        for s in (natural_sort(sStreams)):
            if((s[:2] == "TL") and (len(s[0]) < 6)):
                #Get page number
                tabNo = re.findall(r'\d+', s)
                tempStream = rs.openstream(s)
                data = tempStream.read()
                #Get URL info
                data_sub = bytes()
                i = 0
                while(i < len(data)) :
                    if (i % 2 == 0) :
                        data_sub += (data[i:i+1]) 
                    i = i + 1
                pattern = re.compile(b"[A-Za-z0-9/\-+:.,_$%?'()[\]=<> &]{5,500}")
                strings = pattern.findall(data_sub, 4)
                if (len(strings) > 0) :
                    print("       Page " + tabNo[0] + ":\n")
                    print("         URL:   " + strings[0].decode("ascii"))
                    print("         Title: " + strings[1].decode("ascii") + "\n")
    except:
        print("       [-] Error reading '" + tdName + "': ", sys.exc_info()[1])
 
def buildGUID(guid):
    '''Build GUID from hex string
    Accepts a single argument: a hex string'''
    if (len(guid) != 32):
        return "00000000-0000-0000-0000-000000000000"
    else :
        return guid[6:8] + guid[4:6] + guid[2:4] + guid[0:2] + "-" + guid[10:12] + guid[8:10] + "-" + guid[14:16] + guid[12:14]  + "-"  + guid[16:18] + guid[18:20] + "-" + guid[20:32]

def buildTime(guid) :
    '''Extract filetime from GUID
    Accepts a single argument: a hex string'''
    if (len(guid) != 36):
        return "Unknown"
    else :
        temp = "0" + guid[15:18] + guid[9:13] + guid[0:8]
        temp = int(temp, 16) - 5748192000000000
        dt = datetime.datetime.utcfromtimestamp(((temp - 116444736000000000) / 10000000)).strftime('%m/%d/%Y %H:%M:%S')
        return dt
        
def natural_sort(l): 
    convert = lambda text: int(text) if text.isdigit() else text.lower() 
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ] 
    return sorted(l, key = alphanum_key)
    
def main (argv):
	#Get command line options
    try:
	    opts, args = getopt.getopt(argv, "d:r:t:h", ["directory=", "recovery=", "tab=", "help"])
    except getopt.GetoptError:
        print("\n[-] Invalid options!")
        print(__doc__)
        sys.exit(2)
	#Check that only one command line option is specified	
    if len(opts) != 1:
        print("\n[-] Invalid options!")
        print(__doc__)
        sys.exit(2)	
    
    print("ParseRS v20150522")
    for opt, arg in opts:
	    #Help
        if opt in ("-h", "--help"):
            print(__doc__)
            sys.exit(2)	
    	#Directory
        if opt in ("-d", "--directory"):
            filePath = os.path.abspath(arg)
            readDir(filePath)
        #Recovery
        if opt in ("-r", "--recovery"):
            filePath = os.path.dirname(os.path.abspath(arg))
            fileName = os.path.basename(os.path.abspath(arg))
            readRSF(filePath, fileName)
    	#Tab
        if opt in ("-t", "--tab"):
            filePath = os.path.dirname(os.path.abspath(arg))
            fileName = os.path.basename(os.path.abspath(arg))
            readTDF(filePath, fileName)


if __name__ == "__main__":
    main(sys.argv[1:])
