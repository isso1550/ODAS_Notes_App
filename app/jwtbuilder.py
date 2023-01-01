import jwt
from datetime import datetime, timezone, timedelta
key = "secret"

def buildUserDataJWT(data):
    encoded = jwt.encode({"exp": datetime.now(tz=timezone.utc) + timedelta(minutes=1),"payload":data}, key, algorithm="HS256")
    return encoded
    return None

def decodeUserDataJWT(token):
    try:
        data = jwt.decode(token, key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return 1
    return data

if (__name__ == "__main__"):
    print("###TEST MODE###")
    data = ("bob", "bobuser", "bobpassword")
    token = buildUserDataJWT(data)
    print(token)
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzI1OTAwMzcsInBheWxvYWQiOlsiYm9iIiwiYm9iQGJvYi5jb20iLCIkNSRyb3VuZHM9NTM1MDAwJE5BZ0hRTlJ5RWM0Q2F3eXYkbjBWcEdTSmxBUWguRGYwZ3Z2Zm1vckpyMmJDWUVaSnUwY05VWFZ3V012MSJdfQ.mxbio-YfEN7SA49jS3kSmLqOVUPNv-JCpdtEPS5ueBs"
    decode = decodeUserDataJWT(token)
    print(decode)