from fastapi import FastAPI
from pydantic import BaseModel
from sqlmodel import SQLModel, create_engine, Field
from sqlmodel import Session
from sqlmodel import select
from jose import jwt
import bcrypt
from datetime import datetime
from fastapi import Request
import requests
from fastapi import WebSocket,WebSocketDisconnect

app = FastAPI()



class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    email: str
    password: str
    role: str = "user"
    locked_out: bool = False
    risk_score: int = 0
    


class Activitylog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str
    action: str
    timestamp: datetime
    ip_address: str
    user_agent: str | None = None



class Alert(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str
    reason: str
    severity: str
    timestamp: datetime



class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str



class Update(BaseModel):
    username: str
    password: str



class UnlockUser(BaseModel):
    email: str


class Investigate(BaseModel):
    email: str
    
    
class SessionTable(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str
    ip_address:str
    user_agent: str
    created_at:datetime
    is_active:bool=False
    country:str
    city:str



DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/aegisnet"
engine = create_engine(DATABASE_URL)
SQLModel.metadata.create_all(engine)
SECRET_KEY = "hjgjhihu8476"
ALGORITHM = "HS256"



def createtoken(email, role):
    payload = {"email": email, "role": role}
    token = jwt.encode(payload, SECRET_KEY, ALGORITHM)
    return token



def verify_token(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload



#helper function for country and city geolocation---------------------

def location(ip):
    response=requests.get(f"http://ip-api.com/json/{ip}")
    data=response.json()
    if data["status"]=="fail":
        return "unknown","unknown"
    
    country=data["country"]
    city=data["city"]
    return country,city




connections=[]




#API----------------------------------------------------------------------------------------

@app.post("/signup")
def signup(newuser: UserCreate):
    with Session(engine) as session:
        hashed_pass = bcrypt.hashpw(
            newuser.password.encode(), bcrypt.gensalt()
        ).decode()
        signup_db = User(
            username=newuser.username, email=newuser.email, password=hashed_pass
        )
        session.add(signup_db)
        session.commit()
        return {"message": "deails added"}






@app.post("/userlogin")
def login(login: LoginRequest, request: Request):
    with Session(engine) as session:
        statement = select(User).where(User.email == login.email)
        found_user = session.exec(statement).first()
        
        
        if not found_user:
            log = Activitylog(
                email=login.email,
                action="LOGIN_FAILED",
                timestamp=datetime.now(),
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
            )
            session.add(log)
            session.commit()
            
            
            statement = select(Activitylog).where(
                Activitylog.email == login.email, Activitylog.action == "LOGIN_FAILED"
            )
            failed = session.execute(statement).all()
            count = len(failed)


            if count == 5:
                alert = Alert(
                    email=login.email,
                    reason="LOGIN_FAILED too many times",
                    severity="high",
                    timestamp=datetime.now(),
                )
                session.add(alert)
                session.commit()
            return {"message": "user not found"}
        
        
        if found_user.locked_out:
            print(found_user.locked_out)
            return {"message": "account locked"}



        if not bcrypt.checkpw(login.password.encode(), found_user.password.encode()):
            log = Activitylog(
                email=found_user.email,
                action="LOGIN_FAILED",
                timestamp=datetime.now(),
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
            )
            session.add(log)
            session.commit()
            
            
            statement = select(Activitylog).where(
                Activitylog.email == login.email, Activitylog.action == "LOGIN_FAILED"
            )
            failed = session.execute(statement).all()
            count = len(failed)
            if count == 5:
                alert = Alert(
                    email=login.email,
                    reason="LOGIN_FAILED too many times",
                    severity="high",
                    timestamp=datetime.now(),
                )
                session.add(alert)
                found_user.locked_out = True
                found_user.risk_score += 10
                session.commit()
            return {"message": "login failed"}



        log = Activitylog(
            email=found_user.email,
            action="LOGIN",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(log)
        session.commit()
        token = createtoken(found_user.email, found_user.role)
        
        
        
        
        ip="9.9.9.9"
        country,city=location(ip)
        statement=select(SessionTable).where(SessionTable.email==found_user.email)
        old_sessions=session.exec(statement).all()
        country_found=0
        for sessions in old_sessions:
            if len(old_sessions)>0:
                if sessions.country==country:
                    country_found=1
        if  country_found==0:
            new_alert=Alert(
                    email=login.email,
                    reason="NEW_COUNRTY_LOGIN",
                    severity="high",
                    timestamp=datetime.now(),
                )
            session.add(new_alert)
            
            
            
            
        statement=select(SessionTable).where(SessionTable.email==found_user.email)
        old_sessions=session.exec(statement).all()
        country_found=0
        for sessions in old_sessions:
            if len(old_sessions)>0:
                if sessions.user_agent==request.headers.get("User-Agent"):
                    country_found=1
        if country_found==0:
            new_alerts=Alert(
                    email=login.email,
                    reason="NEW_DEVICE_LOGIN",
                    severity="high",
                    timestamp=datetime.now(),
                )
            session.add(new_alerts)
            
            
            
        sessions=SessionTable(email=found_user.email,
                              ip_address=request.client.host,user_agent=request.headers.get("User-Agent"),
                              created_at=datetime.now(),is_active=True, country=country,city=city
                              )
        session.add(sessions)
        session.commit()
        
        return {"message": "login successful", "access_token": token}
    





@app.get("/viewuser")
def viewuser(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        email = payload["email"]
        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()
        if not found_user:
            
            return "token wrong"
        log = Activitylog(
            email=email,
            action="VIEW_PROFILE",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(log)
        session.commit()
        return {
            "email": found_user.email,
            "password": found_user.password,
            "username": found_user.username,
        }






@app.put("/updatevalues")
def update(new: Update, token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        email = payload["email"]

        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()
        if not found_user:
            return {"message": "user not found"}
        if found_user:
            found_user.username = new.username
            found_user.password = new.password
            session.commit()


        log = Activitylog(
            email=email,
            action="UPDATE_PROFILE",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(log)
        session.commit()
        return {"message": "row updated"}






@app.delete("/deletedata")
def delete(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        email = payload["email"]
        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}
        log = Activitylog(
            email=email,
            action="DELETE_PROFILE",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(log)
        session.commit()
        session.delete(found_user)
        session.commit()
        return {"message": "row deleted"}






@app.get("/viewlogs")
def log(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        role = payload["role"]
        if role != "admin":
            return {"message": "access denied"}
        
        
        statement = select(Activitylog)
        logs = session.exec(statement).all()
        return logs





@app.get("/viewalerts")
def alerts(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        role = payload["role"]
        if role != "admin":
            return {"message": "access denied"}

        statement = select(Alert)
        alerts = session.exec(statement).all()
        return alerts





@app.post("/unlockuser")
def unlock(new: UnlockUser, token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        role = payload["role"]
        if role != "admin":
            return {"message": "access denied"}
        statement = select(User).where(User.email == new.email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}
        found_user.locked_out = False
        session.commit()
        return {"message": "user unlocked"}





@app.get("/investigate_user")
def investigate(new: Investigate, token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        role = payload["role"]

        if role != "admin":
            return {"message": "access denied"}

        statement = select(User).where(User.email == new.email)
        found_user = session.exec(statement).first()
        if not found_user:
            return {"message": "user not found"}
        
        
        statement = select(Alert).where(Alert.email == new.email)
        alerts = session.exec(statement).all()

        statement = select(Activitylog).where(Activitylog.email == new.email)
        logs = session.exec(statement).all()

        return {
            "email": found_user.email,
            "username": found_user.username,
            "role": found_user.role,
            "id": found_user.id,
            "locked_out": found_user.locked_out,
            "risk_score": found_user.risk_score,
            "alerts": alerts,
            "logs": logs,
        }





@app.get("/my_sessions")
def my_sessions(token:str):
    with Session(engine)as session:
        payload=verify_token(token)
        email=payload["email"]
        statement=select(SessionTable).where(SessionTable.email==email)
        found_session=session.exec(statement).all()
        return found_session
    
    
    
    
    
@app.post("/logout_sessions")
def logout_session(token:str,id:int):
    with Session(engine)as session:
        payload=verify_token(token)
        email=payload["email"]
        statement=select(SessionTable).where((SessionTable.email==email) & (SessionTable.id==id))
        found_session=session.exec(statement).first()
        found_session.is_active=False
        session.add(found_session)
        session.commit()
        return{"message":"logout success"}
        
    
    
    
    
@app.websocket("/ws/alerts")
async def alerts (websocket:WebSocket,token:str):
    await websocket.accept()
    payload=verify_token(token)
    email=payload["email"]
    role=payload["role"]
    
    if role!="admin":
        await websocket.close()
        return
    connections.append({
        "email":email,
        "websocket":websocket})
    print(connections)
    while True:
        for connection in connections:
            await connection["websocket"].send_text("new_device_login_detected")  
          