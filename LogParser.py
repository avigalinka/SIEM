import mysql.connector
from mysql.connector import errorcode

LOG_FILE = 'Ping_Sweep.txt'
HEADERS = ['DATE', 'SRC_IP', 'DST_IP', 'PORT', 'ACTION']
PORTS = {'21' : 'FTP', '22' : 'SSH', '23' : 'TELNET', '25' : 'SMTP' , '67' : 'DHCP' , '53'  : 'DNS' , '80' : 'HTTP', '445'
: 'SMB' ,'443' : 'HTTPS'}

def main():
    ResetDB()
    cnx, cursor = ConnectToDB()
    with open(LOG_FILE, 'r') as logs_file:
        for line in logs_file.readlines():
            log = SetDictionary(line)
            InsertLog(log, cnx, cursor)

def SetDictionary(log_line):
    correct_line = log_line.split()
    correct_line[0] += ' ' + correct_line[1]
    correct_line.remove(correct_line[1])
    log = Create_Dictionary(correct_line)
    log['PROTOCOL'] = PortToProtocol(log.get('PORT'))

def ResetDB():
    cnx, cursor = ConnectToDB()
    cursor.execute('DELETE FROM logs')
    cnx.commit()

def InsertLog(log, cnx, cursor):

    add_log = ("""INSERT INTO logs
                (ID, date, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION)
                VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    cursor.execute(add_log, log)
    cnx.commit()


def Create_Dictionary(log_line):
    return  dict(zip(HEADERS, log_line))

def PortToProtocol(port):

    if PORTS.has_key(port):
        return PORTS.get(port)
    else:
        return 'UNKNOWN'

def ConnectToDB():
    user = 'root'
    password = 'P@ssw0rd'
    host = '192.168.182.129'
    database = 'SIEM'
    try:
        cnx = mysql.connector.connect(user=user, password=password,
                                      host=host, database=database)
        return cnx, cnx.cursor()
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None

if __name__ == '__main__':
    main()

