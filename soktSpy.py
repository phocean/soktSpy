# -*- coding: utf-8 -*-

import psutil,sys,time,logging
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
                if name == 'filename':
                    filename = value
                elif name == 'frequency':
                    freq = int(value)
            elif sectionName == 'monitor':
                valList = value.split(',')
        #print

    # check whether required fieds were retrieved, exit otherwise
    if not filename or not valList or not freq:
        print '[!] Uncorrect configuration file. Exiting.'
        sys.exit(1)

    return (freq, filename, valList)


def main(freq,filename,ipList):

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
    excl = []

    print '[*] IP address(es) to monitor: %s\n[*] Logging to file: %s\n[*] Polling frequency = %d sec' %(ipList, filename, freq)
    raw_input('[?] Press [Enter] to proceed ')
    logger.info("Lookup for: %s Frequency: %d sec" %(ipList, freq))

    # Main loop
    print '[*] Entering infinite loop. [Ctrl]+[c] to quit.'

    while True:
        # sleeptime in seconds
        time.sleep(freq)

        # loop among running processes
        for pid in psutil.get_pid_list():

            try:

                # only process the first occurence of a given process, skip next ones
                if pid not in excl and psutil.pid_exists(pid) and lookupListDict(liste,pid,'pid') == 0:
                    process = psutil.Process(pid)

                
                    #if pid not in excl:
                    a = process.name
                    # parse open sockets of the process
                    for conn in process.get_connections():

                        # we will build a dictionnary
                        socket = {}

                        # only keep sockets that match an IP that we want to monitor and fill up the dictionnary
                        if conn.remote_address and conn.remote_address[0] in ipList:

                            # pid and timestamp
                            socket['pid'] = pid
                            socket['ptime'] = datetime.fromtimestamp(process.create_time).strftime('%Y-%m-%d %H:%M:%S')

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
                            logger.critical("- Create_Time: %s Pid: %d - Name: %s - Inet_Family: %d - Username: %s - Local_Address: %s - Remote_Address: %s - Status: %s" % (socket['ptime'],socket['pid'],socket['name'],socket['family'],socket['username'],socket['local_address'],socket['remote_address'],socket['status']))

            except psutil.AccessDenied as e:
                print "[!] Access to process %d denied." %e.pid
                logger.warn("Access to process %d denied." % e.pid)
                excl.append(pid)
                continue
            except psutil.NoSuchProcess as e:
                print "[!] Proccess %d not found or no longer exists (zombie)." % e.pid
                logger.warn("Process %d not found or no longer exists (zombie)" % e.pid)
                continue
            except psutil.TimeoutExpired:
                print "[!] Timeout expired."
                logger.warn('Timeout expired.')
                continue
    return

if __name__ == '__main__':

    try:

        # Parse configuration file
        (freq,filename,ipList) = config('soktSpy.cfg')

        logger = logging.getLogger('soktSpy')
        handler = logging.FileHandler(filename)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.info('** SoktSpy started **')

        main(freq,filename,ipList)

    except OSError:
        print "[!] I/O Error"
        logger.error('I/O Error')
    except KeyboardInterrupt:
        print "[!] Keyboard Interruption"
        logger.info('Keyboard Interruption')
    except:
        logger.exception("")
    finally:
        print "[!] Exiting."
        logger.info('** SoktSpy exited **')
