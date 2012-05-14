import psutil

for proc in psutil.process_iter():
    try:
        print proc
    except psutil.AccessDenied:
        print "AccessDenied exception for PID %s" % (proc.pid)
    except Exception,e:
        print "Other exception: %s" % (e)