from fastapi import FastAPI
from pydantic import BaseModel
from sqlmodel import SQLModel, create_engine, Field
from sqlmodel import Session
from sqlmodel import select
from jose import jwt
import bcrypt
from datetime import datetime

app = FastAPI()


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    email: str
    password: str
    role: str = "user"


class Activitylog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str
    action: str
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


DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/aegisnet"
engine = create_engine(DATABASE_URL)
SQLModel.metadata.create_all(engine)
SQLModel.metadata.create_all(engine)
SECRET_KEY = "hjgjhihu8476"
ALGORITHM = "HS256"


try:
    with Session(engine) as session:
        print("database connected")
except Exception as e:
    print("database not connected")
    print(e)


@app.post("/usercreate")
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


def createtoken(email, role):
    payload = {"email": email, "role": role}
    token = jwt.encode(payload, SECRET_KEY, ALGORITHM)
    return token


def verify_token(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload


@app.post("/userlogin")
def login(login: LoginRequest):
    with Session(engine) as session:

        statement = select(User).where(User.email == login.email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}

        if not bcrypt.checkpw(login.password.encode(), found_user.password.encode()):
            return {"message": "wrong password"}

        log = Activitylog(
            email=found_user.email, action="LOGIN", timestamp=datetime.now()
        )

        session.add(log)
        session.commit()

        token = createtoken(found_user.email, found_user.role)
        return {"access_token": token}


@app.get("/viewuser")
def viewuser(token: str):
    with Session(engine) as session:
        payload = verify_token(token)
        email = payload["email"]
        statement = select(User).where(User.email == email)
        found_user = session.exec(statement).first()

        if not found_user:
            return "token wrong"
        log = Activitylog(email=email, action="VIEW_PROFILE", timestamp=datetime.now())
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
            email=email, action="UPDATE_PROFILE", timestamp=datetime.now()
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
            email=email, action="DELETE_PROFILE", timestamp=datetime.now()
        )
        session.add(log)
        session.commit()

        session.delete(found_user)
        session.commit()
        return {"message": "row deleted"}
