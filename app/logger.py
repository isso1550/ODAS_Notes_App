import sqlite3
from datetime import datetime

class Logger():
    DB_FILE = "./logbase.db"


    def __init__(self) -> None:
        print("Starting logger on %s" % self.DB_FILE)
        pass

    def initialize_database(self):
        try:
            db = sqlite3.connect(self.DB_FILE)
            sql = db.cursor()
            sql.execute("DROP TABLE IF EXISTS logs;")
            sql.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, date datetime, ip varchar(12), location varchar(100), class varchar(100), action varchar(128));")
            sql.execute("DELETE FROM logs;")
            return 0
        except:
            return 1

    def print_logs(self):
        try:
            db = sqlite3.connect(self.DB_FILE)
            sql = db.cursor()
            logs = sql.execute("SELECT * FROM logs").fetchall()
            for log in logs:
                print(log)
            return 0 
        except:
            return 1

    def log(self, request, cl, action):
        try:
            db = sqlite3.connect(self.DB_FILE)
            sql = db.cursor()
            sql.execute("INSERT INTO logs(date, ip, location, class, action) VALUES (CURRENT_TIMESTAMP, :ip, :location, :class, :action)", {"ip":request.remote_addr, "location":request.url, "class":cl, "action":action})
            db.commit()
            return 0
        except Exception as e:
            print(e)
            return 1

if __name__ == "__main__":
    print("TEST MODE")
    logger = Logger()
    logger.print_logs()
