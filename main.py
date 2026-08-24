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
from fastapi import WebSocket, WebSocketDisconnect
import os
from dotenv import load_dotenv

load_dotenv()
import redis

app = FastAPI()

ALGORITHM = "HS256"
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
    ip_address: str
    user_agent: str
    created_at: datetime
    is_active: bool = False
    country: str
    city: str


SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/aegisnet"
)
engine = create_engine(DATABASE_URL)

SQLModel.metadata.create_all(engine)



redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    decode_responses=True
)


def createtoken(email, role, session_id=None):
    payload = {
        "email": email,
        "role": role
    }
    if session_id is not None:
        payload["session_id"] = session_id
    token = jwt.encode(payload, SECRET_KEY, ALGORITHM)
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        return None


# helper function for country and city geolocation---------------------


def location(ip):
    response = requests.get(f"http://ip-api.com/json/{ip}")
    data = response.json()
    if data["status"] == "fail":
        return "unknown", "unknown"

    country = data["country"]
    city = data["city"]
    return country, city


connections = []


# API----------------------------------------------------------------------------------------


@app.get("/")
def root():
    return {"project": "Aegisnet", "status": "online", "docs": "/docs"}


@app.post("/signup")
def signup(newuser: UserCreate):
    with Session(engine) as session:
        hashed_password = bcrypt.hashpw(
            newuser.password.encode(), bcrypt.gensalt()
        ).decode()
        new_user = User(
            username=newuser.username, email=newuser.email, password=hashed_password
        )
        session.add(new_user)
        session.commit()
        return {"message": "details added"}


@app.post("/login")
async def login(login: LoginRequest, request: Request):
    with Session(engine) as session:
        statement = select(User).where(User.email == login.email)
        found_user = session.exec(statement).first()

        if not found_user:
            activity_log = Activitylog(
                email=login.email,
                action="LOGIN_FAILED",
                timestamp=datetime.now(),
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
            )
            session.add(activity_log)
            session.commit()

            redis_client.incr(f"failed:{login.email}")
            redis_client.expire(f"failed:{login.email}", 900)
            failed_login_count = int(redis_client.get(f"failed:{login.email}"))

            if failed_login_count == 5:
                new_alert = Alert(
                    email=login.email,
                    reason="LOGIN_FAILED too many times",
                    severity="high",
                    timestamp=datetime.now(),
                )
                session.add(new_alert)
                session.commit()

                for connection in connections:
                    await connection["websocket"].send_text(
                        "LOGIN_FAILED_TOO_MANY_TIMES"
                    )
            return {"message": "user not found"}

        if found_user.locked_out:
            print(found_user.locked_out)
            return {"message": "account locked"}

        if not bcrypt.checkpw(login.password.encode(), found_user.password.encode()):
            activity_log = Activitylog(
                email=found_user.email,
                action="LOGIN_FAILED",
                timestamp=datetime.now(),
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
            )
            session.add(activity_log)
            session.commit()

            redis_client.incr(f"failed:{login.email}")
            redis_client.expire(f"failed:{login.email}", 900)
            count = int(redis_client.get(f"failed:{login.email}"))

            if count >= 5:
                new_alert = Alert(
                    email=login.email,
                    reason="LOGIN_FAILED too many times",
                    severity="high",
                    timestamp=datetime.now(),
                )
                session.add(new_alert)

                for connection in connections:
                    await connection["websocket"].send_text(
                        "LOGIN_FAILED_TOO_MANY_TIMES"
                    )

                found_user.locked_out = True
                found_user.risk_score += 10
                session.commit()
            return {"message": "login failed"}

        activity_log = Activitylog(
            email=found_user.email,
            action="LOGIN",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(activity_log)
        session.commit()
        redis_client.delete(f"failed:{found_user.email}")
        token = createtoken(found_user.email, found_user.role)

        ip = "9.9.9.9"
        country, city = location(ip)
        statement = select(SessionTable).where(SessionTable.email == found_user.email)
        old_sessions = session.exec(statement).all()
        if len(old_sessions) == 0:
            pass
        else:
            country_found = False
            for sessions in old_sessions:
                if len(old_sessions) > 0:
                    if sessions.country == country:
                        country_found = True
            if country_found == False:
                new_alert = Alert(
                    email=login.email,
                    reason="NEW_COUNRTY_LOGIN",
                    severity="high",
                    timestamp=datetime.now(),
                )
                session.add(new_alert)
            for connection in connections:
                await connection["websocket"].send_text("NEW_COUNRTY_LOGIN")

        statement = select(SessionTable).where(SessionTable.email == found_user.email)
        old_sessions = session.exec(statement).all()

        if len(old_sessions) == 0:
            pass
        else:
            device_found = False
            for existing_session in old_sessions:
                if len(old_sessions) > 0:
                    if existing_session.user_agent == request.headers.get("User-Agent"):
                        device_found = True
            if device_found == False:
                new_alert = Alert(
                    email=login.email,
                    reason="NEW_DEVICE_LOGIN",
                    severity="high",
                    timestamp=datetime.now(),
                )
                session.add(new_alert)

        new_session = SessionTable(
            email=found_user.email,
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
            created_at=datetime.now(),
            is_active=True,
            country=country,
            city=city,
        )
        session.add(new_session)
        session.commit()

        return {"message": "login successful", "access_token": token}


@app.get("/viewuser")
def viewuser(token: str, request: Request):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        email = payload["email"]
        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()
        activity_log = Activitylog(
            email=email,
            action="VIEW_PROFILE",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(activity_log)
        session.commit()
        return {
            "email": found_user.email,
            "username": found_user.username,
        }


@app.put("/updatevalues")
def update(new: Update, token: str, request: Request):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        email = payload["email"]

        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}
        hashed_password = bcrypt.hashpw(
            new.password.encode(), bcrypt.gensalt()
        ).decode()
        found_user.username = new.username
        found_user.password = hashed_password
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
def deletedata(token: str, request: Request):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        email = payload["email"]
        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}
        activity_log = Activitylog(
            email=email,
            action="DELETE_PROFILE",
            timestamp=datetime.now(),
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
        )
        session.add(activity_log)
        session.delete(found_user)
        session.commit()
        return {"message": "row deleted"}


@app.get("/viewlogs")
def view_log(token: str, limit: int = 10, page: int = 1, action: str = None):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        role = payload["role"]
        if role != "admin":
            return {"message": "access denied"}

        if page < 1:
            return {"message": "page must be greater than 0"}
        if limit < 1:
            return {"message": "limit must be greater than 0"}
        offset = (page - 1) * limit
        statement = select(Activitylog)
        if action:
            statement = select(Activitylog).where(Activitylog.action == action)
        statement = statement.offset(offset).limit(limit)
        logs = session.exec(statement).all()
        return logs


@app.get("/viewalerts")
def view_alert(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        role = payload["role"]
        if role != "admin":
            return {"message": "access denied"}

        statement = select(Alert)
        alerts = session.exec(statement).all()
        return alerts


@app.post("/unlock_user")
def unlock_user(new: UnlockUser, token: str, request: Request):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        role = payload["role"]
        if role != "admin":
            return {"message": "access denied"}
        statement = select(User).where(User.email == new.email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}
        found_user.locked_out = False
        activity_log = Activitylog(
            email=payload["email"],
            action="UNLOCK_USER",
            timestamp=datetime.now(),
            ip_address=request.client.host,
        )
        session.add(activity_log)
        session.commit()
        return {"message": "user unlocked"}


@app.post("/investigate_user")
def investigate_user(target: Investigate, token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        role = payload["role"]

        if role != "admin":
            return {"message": "access denied"}

        statement = select(User).where(User.email == target.email)
        found_user = session.exec(statement).first()
        if not found_user:
            return {"message": "user not found"}

        statement = select(Alert).where(Alert.email == target.email)
        alerts = session.exec(statement).all()

        statement = select(Activitylog).where(Activitylog.email == target.email)
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
def my_sessions(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        email = payload["email"]
        statement = select(SessionTable).where(SessionTable.email == email)
        sessions = session.exec(statement).all()
        return sessions


@app.post("/logout_sessions")
def logout_session(token: str, id: int):
    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        email = payload["email"]
        statement = select(SessionTable).where(
            (SessionTable.email == email) & (SessionTable.id == id)
        )
        found_session = session.exec(statement).first()
        if not found_session:
            return {"message": "session not found"}
        found_session.is_active = False
        session.add(found_session)
        session.commit()
        return {"message": "logout success"}


@app.websocket("/ws/alerts")
async def alerts(websocket: WebSocket, token: str):
    await websocket.accept()
    payload = verify_token(token)
    if not payload:
        return {"message": "invalid token"}
    email = payload["email"]
    role = payload["role"]

    if role != "admin":
        await websocket.close()
        return
    connections.append({"email": email, "websocket": websocket})

    try:
        while True:
            await websocket.receive_text()
    except:
        connections.remove(...)


@app.get("/admin_dashboard")
def dashboard():
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        alerts = session.exec(select(Alert)).all()

        alert_count = {}
        for alert in alerts:
            email = alert.email

            if email not in alert_count:
                alert_count[email] = 1
            else:
                alert_count[email] += 1

        max_email = None
        max_count = 0

        for email, count in alert_count.items():
            if count > max_count:
                max_count = count
                max_email = email

            return {
                "total_users": len(users),
                "alerts": len(alerts),
                "high_alert_user": max_email,
                "alerts_of_user": max_count,
            }


@app.get("/investigate/{email}")
def investigate_session(email: str):
    with Session(engine) as session:

        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        if not user:
            return {"message": "user not found"}

        statement = select(Alert).where(Alert.email == email)
        alerts = session.exec(statement).all()
        alert_list = []
        for alert in alerts:
            alert_list.append(
                {
                    "severity": alert.severity,
                    "reason": alert.reason,
                    "timestamp": alert.timestamp,
                }
            )

        statement = select(Activitylog).where(Activitylog.email == email)
        activity = session.exec(statement).all()
        activities = []
        for act in activity:
            activities.append({"action": act.action, "timestamp": act.timestamp})

        statement = select(SessionTable).where(SessionTable.email == email)
        sessions = session.exec(statement).all()
        session_list = []
        for s in sessions:
            session_list.append(
                {
                    "created_at": s.created_at,
                    "is_active": s.is_active,
                    "country": s.country,
                    "city": s.city,
                    "user_agent": s.user_agent,
                    "ip_address": s.ip_address,
                }
            )

        return {
            "user_summary": {
                "username": user.username,
                "role": user.role,
                "risk_score": user.risk_score,
                "locked_out": user.locked_out,
            },
            "alerts": alert_list,
            "activity": activities,
            "sessions": session_list,
        }


@app.delete("/delete/session/{id}")
def delete(id: int):
    with Session(engine) as session:
        statement = select(SessionTable).where(SessionTable.id == id)
        user = session.exec(statement).first()

        session.delete(user)
        session.commit()
        return {"message": "session deleted"}


@app.delete("/logout_all/{email}")
def logout(email: str):
    with Session(engine) as session:
        statement = select(SessionTable).where(SessionTable.email == email)
        sessions = session.exec(statement).all()
        if not sessions:
            return {"message": "session not found"}

        for session_record in sessions:
            session.delete(session_record)
        session.commit()
        return {"message": "session deleted"}


@app.get("/high_riskscore_users/")
def riskusers():
    with Session(engine) as session:
        statement = select(User).where(User.risk_score >= 5)
        users = session.exec(statement).all()
        lists = []
        for user in users:
            lists.append(
                {
                    "username": user.username,
                    "role": user.role,
                    "risk_score": user.risk_score,
                    "locked_out": user.locked_out,
                }
            )
        return lists


@app.get("/timeline/{email}")
def timeline(email: str):
    with Session(engine) as session:
        statement = (
            select(Activitylog)
            .where(Activitylog.email == email)
            .order_by(Activitylog.timestamp)
        )
        users = session.exec(statement).all()

        lists = []
        for user in users:
            lists.append(
                {
                    "action": user.action,
                    "timestamp": user.timestamp,
                    "ip_address": user.ip_address,
                }
            )

        return lists


@app.get("/security_report/{email}")
def security_report(email: str):

    with Session(engine) as session:
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        if not user:
            return {"message": "user not found"}

        statement = select(Alert).where(Alert.email == email)
        alerts = session.exec(statement).all()

        statement = select(Activitylog).where(Activitylog.email == email)
        activities = session.exec(statement).all()

        statement = select(SessionTable).where(SessionTable.email == email)
        sessions = session.exec(statement).all()

        alert_count = len(alerts)
        activity_count = len(activities)
        active_sessions = len(sessions)

        failed_login_count = 0
        for activity in activities:
            if activity.action == "LOGIN_FAILED":
                failed_login_count += 1
        risk_score = user.risk_score

        if risk_score > 80:
            grade = "F"
            recommendation = "Reset password and review active sessions"
        elif risk_score > 60:
            grade = "D"
            recommendation = "Monitor account activity closely"
        elif risk_score > 40:
            grade = "C"
            recommendation = "Review recent alerts"
        elif risk_score > 20:
            grade = "B"
            recommendation = "Account is mostly secure"
        else:
            grade = "A"
            recommendation = "Account appears secure"

        return {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "risk_score": risk_score,
            "security_grade": grade,
            "locked_out": user.locked_out,
            "alerts_count": alert_count,
            "activity_count": activity_count,
            "failed_login_count": failed_login_count,
            "active_sessions": active_sessions,
            "recommendation": recommendation,
        }



@app.get("/health")
def health_check():
    return {"status": "healthy"}



@app.get("/ready")
def readiness_check():

    database_status = False
    redis_status = False

    try:
        with Session(engine) as session:
            session.exec(select(User).limit(1)).first()

        database_status = True
    except Exception:
        database_status = False

    try:
        redis_client.ping()
        redis_status = True
    except Exception:
        redis_status = False

    if database_status and redis_status:
        return {
            "status": "ready",
            "database": "connected",
            "redis": "connected"
        }

    return {
        "status": "not ready",
        "database": "connected" if database_status else "disconnected",
        "redis": "connected" if redis_status else "disconnected"
    }
    
    
    
@app.get("/me")
def get_current_user(token: str):

    with Session(engine) as session:

        payload = verify_token(token)

        if not payload:
            return {"message": "invalid token"}

        email = payload["email"]
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        if not user:
            return {"message": "user not found"}

        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "risk_score": user.risk_score,
            "locked_out": user.locked_out
        }
        
    
        
        
@app.post("/logout")
def logout_current_session(token: str):

    with Session(engine) as session:

        payload = verify_token(token)

        if not payload:
            return {"message": "invalid token"}
        email = payload["email"]
        session_id = payload.get("session_id")
        if session_id is None:
            return {"message": "session information missing"}

        statement = select(SessionTable).where(
            (SessionTable.id == session_id)
            & (SessionTable.email == email)
        )
        found_session = session.exec(statement).first()

        if not found_session:
            return {"message": "session not found"}

        found_session.is_active = False

        session.add(found_session)
        session.commit()

        return {
            "message": "logout successful"
        }
        
        

@app.get("/alerts")
def get_alerts(
    token: str,
    severity: str | None = None,
    email: str | None = None,
    limit: int = 20,
    page: int = 1
):

    with Session(engine) as session:
        payload = verify_token(token)
        if not payload:
            return {"message": "invalid token"}
        if payload["role"] != "admin":
            return {"message": "access denied"}
        if page < 1:
            return {"message": "page must be greater than 0"}
        if limit < 1:
            return {"message": "limit must be greater than 0"}
        statement = select(Alert)
        if severity:
            statement = statement.where(
                Alert.severity == severity
            )
        if email:
            statement = statement.where(
                Alert.email == email
            )
        offset = (page - 1) * limit
        statement = statement.offset(offset).limit(limit)
        alerts = session.exec(statement).all()
        return alerts