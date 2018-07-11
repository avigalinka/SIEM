import re
import mysql.connector
from mysql.connector import errorcode

LOG_FILE = r'C:\Users\AvigalinkaR\Desktop\Python_project\Ping_Sweep.txt'
PORTS = {'21' : 'FTP', '22' : 'SSH', '23' : 'TELNET', '25' : 'SMTP', '67' : 'DHCP', '53' : 'DNS', '80' : 'HTTP', '445' : 'SMB', '443' : 'HTTPS'}


# read log file, make list of logs and make dictionary
def ReadLogFile(log_file_path):
    with open(log_file_path, 'r') as opened_file:
        line_lst = []
        new_dic = {} # dictionary with logs
        list_dic = []

        for line in opened_file:
            line_lst.append(line.split())

        for item in line_lst:
            new_dic = {'DATE': item[0] + ' ' + item[1], 'SRC_IP':item[2], 'DST_IP': item[3], 'PORT' : item[4], 'ACTION' : item[5]}
            list_dic.append(new_dic)

        return list_dic


# function that define type of port
def DefinePort(dic):

    x = dic['PORT']
    if x in PORTS:
        dic['PROTOCOL'] = PORTS[x]
    else:
        dic['PROTOCOL'] = 'UNKNOWN PORT'
    return dic


def Port_to_Protocol(list_of_dic):

    dic_with_protocol = []
    for log in list_of_dic:
        dic_with_protocol.append(DefinePort(log))
    return dic_with_protocol


#function that insert log information to DataBase
def InsertToDB(log, cnx, cursor):
    add_log = ("INSERT INTO fwlogs (ID, DATE, SCR_IP, DST_IP, PORT, PROTOCOL, ACTION)"
               "VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    cursor.execute(add_log, log)
    cnx.commit()

#
def ResetDB():
    cnx, cursor = ConnectToDB()
    cursor.execute('DELETE FROM fwlogs')
    cnx.commit()


user = 'root'
password = 'P@ssw0rd'
host = '192.168.10.103'
database = 'SIEM'

def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user=user, password=password,
                                      host=host, database=database)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None


def main():
    ResetDB()
    cnx, cursor = ConnectToDB()

    for dic in Port_to_Protocol(ReadLogFile(LOG_FILE)):
        InsertToDB(dic, cnx, cursor)


if __name__ == '__main__':
    main()



#print ReadLogFile(LOG_FILE)
#print DefinePort({'PROTOCOL':'', 'DATE': '2018-4-21 19:42:41', 'SRC_IP': '192.168.1.1', 'PORT': '23', 'ACTION': 'PASS', 'DST_IP': '192.168.2.100'})
