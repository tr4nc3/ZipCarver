#!/usr/bin/python
# Author: Rajat Swarup
# Date: 2014-11-25
# Version: 0.1a
import struct
import sys
import ctypes
import getopt
import datetime
import os

class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration
    
    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args: # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False

zipsigs = [ 0x08064b50, 0x08074b50, 0x04034b50, 0x02014b50, 0x05054b50, 0x06054b50, 0x07064b50, 0x06064b50 ] 
commentmax = 250

class CZipCarver:
    def __init__(self,src,dstdir,start,end=0xffffffffffffffff):
        self.sourcefile = src
        self.dstdir = dstdir
        self.zipfiles = []
        self.goodoffset = {}
        self.fhandle = open(self.sourcefile, 'rb')
        self.fsize = 0
        self.start = start
        self.end = end
        self.interesting = {} 
        self.compressioninfo = {} # variable to hold the information on all zip files
    def addToInterestingList(self,testnum,value):
        if testnum not in self.interesting.keys():
            self.interesting[testnum] = [ value ]
        else:
            self.interesting[testnum].extend([value])
    def zipgpparser(self,gpflag):
        genpurposeflags = [ 1 if digit=='1' else 0 for digit in bin(gpflag)[2:].zfill(16) ] # convert gpflag to a list
        genpurposeflags = genpurposeflags[::-1] # reverse the list
        gpstr =  [ '' for i in xrange(16) ]
        if genpurposeflags[0] == 1:
           gpstr[0] = 'encrypted'
        #if genpurposeflags[1] == 1:
        #   gpstr.extend( [ ' encrypted file ' ] )
        #if genpurposeflags[2] == 1:
        #   gpstr += ' encrypted file '
        if genpurposeflags[3] == 1:
           gpstr[3] = 'data descriptor present'
        if genpurposeflags[4] == 1:
           gpstr[4] = 'enhanced deflation'
        if genpurposeflags[5] == 1:
           gpstr[5] = 'compressed patch data'
        if genpurposeflags[6] == 1:
           gpstr[6] = 'strong encryption'
        if genpurposeflags[7] == 1:
           gpstr[7] = 'Unused'
        if genpurposeflags[8] == 1:
           gpstr[8] = 'Unused'
        if genpurposeflags[9] == 1:
           gpstr[9] = 'Unused'
        if genpurposeflags[10] == 1:
           gpstr[10] = 'Unused'
        if genpurposeflags[11] == 1:
           gpstr[11] = 'language encodng'
        if genpurposeflags[12] == 1:
           gpstr[12] = 'reserved'
        if genpurposeflags[13] == 1:
           gpstr[13] = 'mask header values'
        return gpstr
    def compressionmethodparser(self,compmethod):
        comptype = ''
        for case in switch(compmethod):
            if case(0):
               comptype =  'no compression'
               break
            if case(1):
               comptype =  'shrunk'
               break
            if case(2):
               comptype =  'reduced with compression factor 1'
               break
            if case(3):
               comptype =  'reduced with compression factor 2'
               break
            if case(4):
               comptype =  'reduced with compression factor 3'
               break
            if case(5):
               comptype =  'reduced with compression factor 4'
               break
            if case(6):
               comptype =  'imploded'
               break
            if case(7):
               comptype =  'reserved'
               break
            if case(8):
               comptype =  'deflated'
               break
            if case(9):
               comptype =  'enhanced deflated'
               break
            if case(10):
               comptype =  'PKWare DCL imploded'
               break
            if case(11):
               comptype =  'reserved'
               break
            if case(12):
               comptype =  'bzip2'
               break
            if case(13):
               comptype =  'reserved'
               break
            if case(14):
               comptype =  'LZMA'
               break
            if case(15) or case(16) or case(17):
               comptype =  'reserved'
               break
            if case(18):
               comptype =  'IBM Terse compression'
               break
            if case(19):
               comptype =  'IBM LZ77 z compression'
               break
            if case(98):
               comptype =  'PPMd version I, Rev 1'
               break
            if case(): # default, could also just omit condition or 'if True'
               comptype = 'unknown'
        return comptype
 
    def parseOffsets(self):
        head,ver,gpflag,compmethod,modtime,moddate,crc32,compsz,uncompsz,fnamelen,exfieldlen = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        self.fsize = os.path.getsize(self.sourcefile)
        print '[+] File size : {0}'.format(self.fsize)
        if self.start > 0:
           self.fhandle.seek(self.start)
        print self.fhandle.tell(), self.end
        index = 0
        while self.fhandle.tell() <= self.end and self.fhandle.tell() <= self.fsize :
            #print '{0}'.format(self.end-self.fhandle.tell())
            bytes = self.fhandle.read(1)
            #print bytes
            if not bytes:
                print '[+] End of file reached.  Size {0}'.format(self.fhandle.tell())
                break
            head = struct.unpack('B',bytes)[0]
            if bytes == 'P':  #found header
                #offsettosave = self.fhandle.tell()
                #print '0x50 found, at offset {0}'.format(self.fhandle.tell())
                bytes += self.fhandle.read(1)
                if bytes[1] != 'K':
                    continue                
                else:
                    if bytes[1] == 'K':
                        pkhead = struct.unpack('cc',bytes)[0]
                        # read 2 bytes of version
                        bytes += self.fhandle.read(2)
                        if len(bytes) < 4:
                            continue
                        #print bytes
                        testnum = struct.unpack('<I',bytes)[0]
                        #if not ( bytes[2] == '\x03' and bytes[3] == '\x04' ) :
                        #if testnum != 0x04034b50:
                            #print 'Full signature not found, just 2 bytes found :('
                        #    continue
                        #if  testnum != 0x06064b50 and testnum != 0x06054b50 and testnum != 0x04034b50 and testnum != 0x07064b50 and testnum != 0x05054b50 and testnum != 0x02014b50:
                        if testnum not in zipsigs:
                            #print '[-] Full signature not found, just 2 bytes found :( %08x' % testnum
                            pass
                        else:
                            if testnum == 0x08074b50:
                                print '[+] Data Descriptor found at {0}'.format(self.fhandle.tell())
                                self.addToInterestingList(testnum,self.fhandle.tell()-4)
                            if testnum == 0x07064b50:
                                print '[+] End of Central Directory Locator found at {0}'.format(self.fhandle.tell())
                                #self.goodoffset[self.fhandle.tell()-4] = 
                                self.addToInterestingList(testnum,self.fhandle.tell()-4)
                            if testnum == 0x05054b50:
                                print '[+] Digital Signature found at {0}'.format(self.fhandle.tell())
                                self.addToInterestingList(testnum,self.fhandle.tell()-4)
                            if testnum == 0x02014b50:
                                print '[+] Central File Header Signature found at {0}'.format(self.fhandle.tell()) 
                                self.addToInterestingList(testnum,self.fhandle.tell()-4)
                            if testnum == 0x04034b50:
                                index += 1
                                offsettosave = self.fhandle.tell()-4
                                startflag = True
                                self.goodoffset[offsettosave] = [ 0 ] 
                                self.addToInterestingList(testnum,self.fhandle.tell()-4)
                                self.compressioninfo[index] = [ offsettosave, 0, -1, -1, -1, -1, -1, '', '', -1 ] # offset in file, gpbit, compmethod, compressed size, uncompressed size, crc32, extra field length 
                            elif testnum == 0x06054b50 or 0x06064b50 :
                                if startflag:
                                    endflag = True
                                    startflag = False
                                    print '[+] Start: {0}, End of central directory record found {1}'.format(offsettosave,self.fhandle.tell()-4)
                                    self.addToInterestingList(testnum,self.fhandle.tell()-4)
                                    #try:
                                    #    if self.goodoffset[offsettosave] is not None:
                                    #       self.goodoffset[offsettosave][0] = self.fhandle.tell()-4 
                                    #except KeyError as ke:
                                    #    print '[-] *** offset not found *** '    
                                    disknumber = struct.unpack('<H',self.fhandle.read(2))[0]
                                    disknumwithcentdir = struct.unpack('<H',self.fhandle.read(2))[0]
                                    numofcentraldirentries = struct.unpack('<H',self.fhandle.read(2))[0]
                                    totalentries =  struct.unpack('<H',self.fhandle.read(2))[0]
                                    centraldirsize = struct.unpack('<I',self.fhandle.read(4))[0]
                                    offsetcdwrtstartingdisk = struct.unpack('<I',self.fhandle.read(4))[0]
                                    commentlen = struct.unpack('<H',self.fhandle.read(2))[0]
                                    if commentlen > 0 and commentlen + self.fhandle.tell() < self.fsize and commentlen < commentmax:
                                        try:
                                            commentbytes = self.fhandle.read(commentlen)
                                            comment = commentbytes.decode('utf-8')
                                            # TODO: if there are invalid files, then reading commentlen bytes may skip over legitimate zip files
                                            # Need to search for valid offsets inside this
                                            
                                        except:
                                            comment = ''
                                            pass
                                    else:
                                        comment = ''
                                    print '[+] Disk number {0}, Number of disk on which central dir starts {1}, Num of central dir entries {2}, total num of CDEs {3}, central dir size {4}, offset of central dir wrt to starting disk {5}, commentlen {6}, comment {7}'.format(disknumber, disknumwithcentdir, numofcentraldirentries,totalentries, centraldirsize, offsetcdwrtstartingdisk, commentlen, comment)
                                    try:
                                        if self.goodoffset[offsettosave][0] == 0 :
                                           self.goodoffset[offsettosave][0] =  self.fhandle.tell()
                                    except KeyError as ke:
                                        print '[-] *** offset not found ***'  
                                else:
                                    print '[-] End flag encountered without a start??? :-/'
                            
                            if startflag:
                                print '[+] Full signature found at {0}'.format(self.fhandle.tell()-4)
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 6:
                                    print '[-] Header found, version not found'
                                    continue
                                #Version found, read 2 bytes of general purpose stuff
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 8:
                                    print '[-] Header, version found, no general purpose info found'
                                    continue
                                #   read compression type
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 10:
                                    print '[-] Header, version, general purpose found, compression type not found'
                                    continue
                                # read last mod time
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 12:
                                    print '[-] Header, version, general purpose, compression found, last modification time not found'
                                    continue
                                # read last mod date
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 14:
                                    print '[-] Header, version, general purpose, compression, last modification time found, last modification date not found'
                                    continue
                                # read CRC value
                                bytes += self.fhandle.read(4)
                                if len(bytes) < 18:
                                    print '[-] Header, version, general purpose, compression, last modification time, last modification date found, CRC32 not found'
                                    continue
                                # read compressed size 4
                                bytes += self.fhandle.read(4)
                                if len(bytes) < 22:
                                    print '[-] Header, version, general purpose, compression, last modification time, last modification date, CRC32 found, compsz not found'
                                    continue
                                # read uncompressed size 4
                                bytes += self.fhandle.read(4)
                                if len(bytes) < 26:
                                    print '[-] Header, version, general purpose, compression, last modification time, last modification date, CRC32 compsz found, uncomp size not found'
                                    continue
                                # read filename len 2
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 28:
                                    print '[-] Header, version, general purpose, compression, last modification time, last modification date, CRC32, compsz, uncompsz found filenme length not found'
                                    continue
                                # read extra field len 2 
                                bytes += self.fhandle.read(2)
                                if len(bytes) < 30:
                                    print '[-] Header, version, general purpose, compression, last mod time, last mod date, CRC32, compsz, uncompsz, filename len found, extra field length not found'
                                    continue
                                head,ver,gpflag,compmethod,modtime,moddate,crc32,compsz,uncompsz,fnamelen,exfieldlen = struct.unpack('<IHHHHHIIIHH',bytes)
                                day,month,year=self.parseDOSDate(moddate)
                                hour,minute,sec = self.parseDOSTime(modtime)
                                #self.goodoffset[offsettosave] = compsz
                                # Now read filename size number of bytes to determine the filename (but < 250) characters
                                if fnamelen + self.fhandle.tell() <  self.fsize and fnamelen < 250: #filename has to be less than windows file MAX_SIZE
                                    fnamebytes = self.fhandle.read(fnamelen)
                                    try:
                                        fname = fnamebytes.decode('utf-8')
                                    except:
                                        fname = 'badformat'
                                        pass
                                    #fname = struct.unpack('<s',fnamebytes)[0]
                                else:
                                    fname = 'NONE'
                                    continue
                                print '[+] Version {0}, GP Flag {1}, Comp {2},comp size {3} becomes {5} fnamelen {4}, Create Timestamp: {6}-{7}-{8} {10}:{11}:{12}, name:{9}'.format(ver,gpflag,compmethod,compsz,fnamelen,uncompsz,year,month,day,fname,hour,minute,sec)
                                print '[+] {0}, {1} '.format(self.zipgpparser(gpflag),self.compressionmethodparser(compmethod))
                                # Now read the extrafield len number of bytes
                                exfielddata = ''
                                if exfieldlen + self.fhandle.tell() <  self.fsize: 
                                    exfielddata = self.fhandle.read(exfieldlen)
                                    bytes += exfielddata
                                else: # the extra field contains more data than the file size (probably invalid data)
                                    continue   
                                zipdata = ''
                                if compsz + self.fhandle.tell() < self.fsize:
                                    zipdata = self.fhandle.read(compsz)
                                    bytes += zipdata
                                else:
                                    zipdata = '\x00'*compsz
                                # At this point the zip data is all read
                                # read 4 bytes to see if its the optional header
                                signbytes = self.fhandle.read(4) 
                                sign = struct.unpack('<I',signbytes)[0]
                                crc32 = 0
                                if sign != 0x08074b50:
                                    crc32 = sign 
                                else:
                                    crc32 = struct.unpack('<I',self.fhandle.read(4))[0]
                                
                            else: # startflag not set
                                pass 
            if self.fhandle.tell() % 10000000 == 0:
                print 'Bytes read: {0}'.format(self.fhandle.tell())
            bytes = ''    

    def parseDOSTime(self,val):
        sec = 2 * (val & 31)
        minute = (val & 2016) >> 5
        hour = (val & 63488) >> 11
        if sec <= 60 and minute <= 59 and hour <= 23:
            return hour, minute, sec
        return 0,0,0

    def parseDOSDate(self,val):
        day = val & 31
        month = (val & 480) >> 5
        year = 1980 + ((val & 65024) >> 9)
        if day >= 1 and day <= 31 and month >= 1 and month <= 12 and year <= 2040:
            return day,month,year
        return 0,0,0
    def printGoodOffsets(self):
        for offsetval in self.goodoffset.keys():
            print 'Valid offset found at {0} ending at {1} of size {2}'.format(offsetval,self.goodoffset[offsetval],self.goodoffset[offsetval][0]-offsetval)
        for offsetval in self.interesting.keys():
            for values in self.interesting[offsetval]:
                print '%08x found at %d' % (offsetval,values)

    def getGoodOffsets(self):
        return self.goodoffset
            
    def __del__(self):
        self.fhandle.close()

def printUsage(str):
    print 'Usage: ' + str + ' -i <filetocarve> -o outputdir [ -b beginoffset ] [ -e endoffset ] [ -c commentmaxsize ]'
    print '       ' + str + ' --inputfile=<filetocarve> --out <outputdir> [ --begin=<offset> ] [ --end=<offset> ] [ --commentmax=<numberofbytes> ] '
    print '        --inputfile/-i : input file to carve '
    print '        --out/-o: output directory '
    print '        --begin/-b: beginning offset (default: start of file)'
    print '        --end/-e: ending offset (default: end of file)'
    print '        --commentmax/-c: maximum size of the comment field'

def main(argv):
    inputfile = ''
    outputdir = ''
    begin = 0x00000000
    end = 0xffffffffffffffff
    print 'PK signature looks like PK\x03\x04'
    if len(sys.argv) < 4:
        printUsage(sys.argv[0])
        sys.exit(2)
    try:
        opts,args = getopt.getopt(argv,"hi:o:b:e:c:",["inputfile=","out=","begin=","end=","commentmax="])
    except getopt.GetoptError:
        printUsage(sys.argv[0])
        sys.exit(2)
    for opt,arg in opts:
        if opt == '-h':
            printUsage(sys.argv[0])
            sys.exit()
        elif opt in ('-i', '--inputfile'):
            inputfile = arg
        elif opt in ('-o', '--out'):
            outputdir = arg
        elif opt in ('-b', '--begin'):
            print 'This is  {0}'.format( arg )
            begin = int(arg)
        elif opt in ('-e', '--end'):
            end = int(arg)
        elif opt in ('-c','--commentmax'):
            commentmax = int(arg)
    print "%s" % (begin)
    print 'This is end value {0}'.format( arg )
    zc = CZipCarver(inputfile,outputdir,begin,end)
    zc.parseOffsets()
    zc.printGoodOffsets()
    goodoffsets = zc.getGoodOffsets()
    
       
if __name__ == "__main__":
    main(sys.argv[1:])
