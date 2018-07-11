import mysql.connector
from mysql.connector import errorcode

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
    cnx, cursor = ConnectToDB()
    query = ("SELECT * FROM fwlogs")
    cursor.execute(query)
    result=cursor.fetchone()
    print result
    cursor.close()
    cnx.close()

if __name__ == '__main__':
    main()

