# Original script came from excellent post https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/
# Thanks Zerodetail for a great guide to Boofuzz

from boofuzz import *
from sys import exit
 
def get_banner(target, my_logger, session, *args, **kwargs):
    banner_template = "Welcome to Vulnerable Server! Enter HELP for help."
    try:
        banner = target.recv(10000)
    except:
        print "Unable to connect. Target is down. Exiting."
        exit(1)
 
    my_logger.log_check('Receiving banner..')
    if banner_template in banner:
        my_logger.log_pass('banner received')
    else:
        my_logger.log_fail('No banner received')
        print "No banner received, exiting.."
        exit(1)
 
def main():
 
 
    port = 9999
    host = '192.168.190.100'
    protocol = 'tcp'
     
    csv_log = open('boofuzz_results.csv', 'wb') ## create a csv file
    my_logger = [FuzzLoggerCsv(file_handle=csv_log)] ### create a FuzzLoggerCSV object with the file handle of our csv file
 
 
     
    session = Session(
            target=Target(
                connection = SocketConnection(host, port, proto=protocol),
            ),
            fuzz_loggers=my_logger, ## set my_logger (csv) as the logger for the session
    )
 
    s_initialize("lter")
    s_string("LTER", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("FUZZ")
    s_static("\r\n")
 
    session.connect(s_get("lter"), callback=get_banner)
    session.fuzz()
     
 
 
 
 
if __name__ == "__main__":
    main()
