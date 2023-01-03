from datetime import datetime, timedelta, timezone

def verifyUserBan(db, email, MAX_LOGIN_ATTEMPTS, ACCOUNT_SUSPENSION_TIME):
    sql = db.cursor()
    login_attempts = sql.execute("SELECT * FROM login_attempts WHERE email = :email", {"email":email}).fetchall()
    attempts_count = len(login_attempts)
    if (attempts_count > 0):
        if (attempts_count >= MAX_LOGIN_ATTEMPTS):
            ban_date = datetime.strptime(login_attempts[-1][2], "%Y-%m-%d %H:%M:%S")
            now = datetime.utcnow()
            if(now > (ban_date + ACCOUNT_SUSPENSION_TIME)):
                #czas blokady upłynął
                deleteOldAttempts(db, email, ACCOUNT_SUSPENSION_TIME)
                return 0
            else:
                #czas blokady nadal aktywny
                print("User will be unbanned at %s" % str(ban_date+ACCOUNT_SUSPENSION_TIME))
                return 1
        else:
            return 0
    else:
        #brak nieudanych logowan
        return 0
    return 1

def deleteOldAttempts(db, email, ACCOUNT_SUSPENSION_TIME):
    try:
        sql = db.cursor()
        yesterday = (datetime.utcnow() - ACCOUNT_SUSPENSION_TIME).strftime("%Y-%m-%d %H:%M:%S")
        sql.execute("DELETE FROM login_attempts WHERE email = :email AND date < (:yesterday)", {"email":email, "yesterday":yesterday})
        db.commit()
        return 0
    except Exception as e:
        print(e)
        return 1

def deleteAllAttempts(db, email):
    try:
        sql = db.cursor()
        sql.execute("DELETE FROM login_attempts WHERE email = :email", {"email":email})
        db.commit()
        return 0
    except Exception as e:
        print(e)
        return 1

def saveFailedLogin(db, email, request):
    try:
        sql = db.cursor()
        usr = sql.execute("SELECT email FROM users WHERE email=:email", {"email":email}).fetchall()
        if (len(usr) < 1):
            return 0
        sql.execute("INSERT INTO login_attempts (ip, email, date) VALUES (:ip, :email, CURRENT_TIMESTAMP)", {"ip":request.remote_addr, "email":email})
        login_attempts = sql.execute("SELECT * FROM login_attempts WHERE email = :email", {"email":email}).fetchall()
        attempts_count = len(login_attempts)
        db.commit()
        return attempts_count
    except Exception as e:
        print(e)
        return -1