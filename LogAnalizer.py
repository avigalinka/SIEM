import mysql.connector
from mysql.connector import errorcode
import time


USER = 'root'
PASSWORD = 'P@ssw0rd'
HOST = '192.168.10.103'
DATABASE = 'SIEM'
SUS_PORT = [444, 4445] #suspicious port



# DATABASE CONNECTION
def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user=USER, password=PASSWORD,
                                      host=HOST, database=DATABASE)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None


# Select IP_SOURCE, IP_DEST, PORT from Table
def DB_Select():
    cnx, cursor = ConnectToDB()
    # SELECT to database
    cursor.execute("SELECT SCR_IP, DST_IP, PORT FROM fwlogs")
    results = cursor.fetchall()
    return results

#-----------SUSPICIOUS PORT-----------#
def Sus_PORT(log_list):
    for log in log_list:
        if log[1] in SUS_PORT:
            return "Alert!", log[0], "tying to use Suspicious port"
        else:
            return None


#-----------PORT SCAN-----------#

# Get LOGS and make dictionary to count times that IP tryed to use
def PortScan():
    cnx, cursor = ConnectToDB()
    query = ("SELECT DISTINCT SCR_IP, DST_IP, PORT FROM fwlogs ORDER BY SCR_IP")
    cursor.execute(query)
    connection = ''
    counter = 0
    bad_ip = []

    for line in cursor:
        ip_connection = line[0] + ' to ' + line[1]

        if ip_connection == connection:
            counter += 1
            if counter > 10:
                bad_ip.append(ip_connection)
        else:
            counter = 0
            connection = ip_connection

    return bad_ip

def GetTimeDiffreneces(start, end):
    c = end - start
    return divmod(c.days * 86400 + c.seconds, 60)


def pingSweepTimed():
    cnx, cursor = ConnectToDB()
    query = ("SELECT SCR_IP, DST_IP, DATE FROM fwlogs WHERE PORT = 0 ORDER BY SCR_IP, DATE")
    cursor.execute(query)

    bad_ips = []
    cur_src_ip = ''
    # cur_times = []

    for line in cursor:
        #print line
        line_src_ip, line_dst_ip, line_date = line
        line_date = time.mktime(line_date.timetuple())
        #print line_src_ip, line_dst_ip, line_date

        if line_src_ip in bad_ips:
            continue

        elif line_src_ip != cur_src_ip:
            cur_src_ip = line_src_ip
            cur_times = [line_date]
            continue

        else:
            cur_times.append(line_date)

            if len(cur_times) < 10:
               continue

            else:
                # last_time = cur_times[len(cur_times)-1]
                if line_date - cur_times[0] > 10:
                    del cur_times[0]
                    continue
                else:
                    bad_ips.append(cur_src_ip)

    return bad_ips

#-------PING SWEEP (without time aspects)---------#
def pingSweep():
    cnx, cursor = ConnectToDB()
    query = ("SELECT DISTINCT SCR_IP, DST_IP, DATE FROM fwlogs WHERE PORT = 0 ORDER BY DATE")
    cursor.execute(query)
    print 'test', cursor.execute(query)
    print 'test', cursor.fetchall()

    src = ''
    dst = ''
    counter = 0
    bad_ip = []
    bad_ips = []

    for line in cursor:
        # print line
        ip_src = line[0]

        if ip_src == src:
            #print GetTimeDiffreneces(line[2], bad_ips[0][2])
            if GetTimeDiffreneces(line[2], line[2]):
                pass
                counter += 1
                bad_ips.append((src, line[2]))

        else:
            counter = 1
            src = ip_src

    if counter > 10:
        bad_ip.append(src)

    return bad_ips


#-------PING SWEEP (with time aspects)---------#
def pingSweep10():
    cnx, cursor = ConnectToDB()
    query = ("SELECT DISTINCT SCR_IP, DST_IP, DATE FROM fwlogs WHERE PORT = 0 ORDER BY DATE")
    cursor.execute(query)

    src = ''
    dst = ''
    counter = 0
    bad_ip = []

    for line in cursor:
        ip_src = line[0]

        if ip_src == src:
           counter += 1

        else:
            counter = 1
            src = ip_src

    if counter > 10:
        bad_ip.append(src)

    return bad_ip


def main():
    #ConnectToDB()
    #print DB_Select()
    #print Sus_PORT(DB_Select())
    #print IP_counter(DB_Select())
    #print Port_Scan_Alert(IP_counter(DB_Select()))
    #print PortScan()
    #print pingSweep()
    print pingSweepTimed()


if __name__ == '__main__':
    main()
