# -*- coding: utf-8 -*-

import psutil,sys,time
from datetime import datetime
from ConfigParser import SafeConfigParser

def lookupListDict (liste,value,index):
    """
    Snippet to look for a value inside a list of dictionnaries
    Parameters : list of dictionnaries, value to look for
    Return a boolean (1: value was found)
    """
    for dico in liste:
        #print dico
        if value == dico[index]:
            return 1
    return 0

def fileopen(path,mode):
    """
    Snippet to open files
    The mode (read, write, append, etc.) is taken as a parameter
    Return the file descriptor
    """
    try:
        fd=open(path,mode)
    except IOError:
        print "[!] Error opening path: %s (%s)" %(path,mode)
        sys.exit(2)
    return fd

def fileclose(fd):
    """
    Snippet to close files cleanly
    Return 0
    """
    try:
        fd.close()
    except IOError:
        print "[!] Error closing file descriptor:%s" %fd
        sys.exit(2)

def config(confFile):
    """
    Parse the configuration file, which should look like :
        [log]
        path = c:\\test
        filename = connSpy.log

        [monitor]
        ip = 127.0.0.1
    
    Return :
    a string with the log file full path
    and
    a list of IP to monitor
    """

    valList = []
    path =''
    
    print '[*] Parsing Configuration File: %s' %confFile

    parser = SafeConfigParser()
    parser.read(confFile)

    # parse file content
    for sectionName in parser.sections():
        #print '  Section:', sectionName
        #print '    Options:', parser.options(sectionName)
        for name, value in parser.items(sectionName):
            #print '  %s = %s' % (name, value)
            # retrieve values from valid fields
            if sectionName == 'log':
                if name == 'path':
                    path = value
                elif name == 'filename':
                    filename = value
                elif name == 'frequency':
                    freq = int(value)
            elif sectionName == 'monitor':
                valList = value.split(',')
        #print

    # check whether required fieds were retrieved, exit otherwise
    if not path or not filename or not valList:
        print '[!] Uncorrect configuration file. Exiting.'
        sys.exit(1)

    return (freq, path + '\\\\' + filename, valList)


def main():
    
    print '''
            _     _    _____             
           | |   | |  / ____|            
  ___  ___ | | __| |_| (___  _ __  _   _ 
 / __|/ _ \| |/ /| __|\___ \| '_ \| | | |
 \__ \ (_) |   < | |_ ____) | |_) | |_| |
 |___/\___/|_|\_\ \__|_____/| .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 

    Trap stealthy sockets
    version 1.0 - 05/2012
    //phocean \n'''

    liste = []
    
    # Parse configuration file
    (freq,filePath,ipList) = config('config.cfg')

    print '[*] IP address(es) to monitor: %s\n[*] Logging to file: %s\n[*] Polling frequency = %d sec' %(ipList, filePath, freq)
    raw_input('[?] Press [Enter] to proceed ')

    # Main loop
    print '[*] Entering infinite loop. [Ctrl]+[c] to quit.'
    while True:
        # sleeptime in seconds
        time.sleep(freq)

        # loop among running processes
        for pid in psutil.get_pid_list():

            # only process the first occurence of a given process, skip next ones
            if psutil.pid_exists(pid) and lookupListDict(liste,pid,'pid') == 0:
                process = psutil.Process(pid)

                # parse open sockets of the process
                for conn in process.get_connections():

                    # we will build a dictionnary
                    socket = {}

                    # only keep sockets that match an IP that we want to monitor and fill up the dictionnary
                    if conn.remote_address and conn.remote_address[0] in ipList:

                        # pid and timestamp
                        socket['pid'] = pid
                        socket['ptime'] = datetime.fromtimestamp(process.create_time).strftime('%Y-%m-%d%H:%M:%S')

                        # loop inside interesting process attributes
                        for i in ['name','username']:
                            # in some cases, not all attributes may be readable
                            try:
                                socket[i] = getattr(process,i)
                            except psutil.AccessDenied:
                                socket[i] = '** access denied **'
                        
                        # loop inside interesting socket attributes
                        for i in ['family','local_address','remote_address','status']:
                            try:
                                socket[i] = getattr(conn,i)
                            except psutil.AccessDenied:
                                i[socket] = '** access denied **'
                        
                        # build the list and write to the log file (one line per socket)
                        print '[*] Logged an event'
                        liste.append(socket)
                        flog = fileopen(filePath, 'a')
                        flog.write("%s %s %d %s %d %s %s %s %s\n" % (datetime.now().strftime('%Y-%m-%d%H:%M:%S'),socket['ptime'],socket['pid'],socket['name'],socket['family'],socket['username'],socket['remote_address'],socket['local_address'],socket['status']) )
                        fileclose(flog)
        
    #fileclose(flog)
    return 0

if __name__ == '__main__':
    try:
        ret = main()
        if ret==0:
            sys.exit(0)
        else:
            sys.exit(1)
    except OSError:
        print "[!] I/O Error"
        sys.exit(1)
    except KeyboardInterrupt:
        print "[!] Keyboard Interruption: Exiting."         
