from fastapi import FastAPI
from pydantic import BaseModel
from sqlmodel import SQLModel, create_engine, Field
from sqlmodel import Session
from sqlmodel import select
from jose import jwt

app = FastAPI()


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    email: str
    password: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class Update(BaseModel):
    username: str
    email: str
    password: str


class Delete(BaseModel):
    email: str


DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/aegisnet"
engine = create_engine(DATABASE_URL)
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
        signup_db = User(
            username=newuser.username, email=newuser.email, password=newuser.password
        )

        session.add(signup_db)
        session.commit()

        return {"message": "deails added"}


def createtoken(email):
    payload = {"email": email}
    token = jwt.encode(payload, SECRET_KEY, ALGORITHM)
    return token


@app.post("/userlogin")
def login(login: LoginRequest):
    with Session(engine) as session:

        statement = select(User).where(User.email == login.email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}

        if found_user.password != login.password:
            return {"message": "wrong password"}

        token = createtoken(found_user.email)
        return {"access_token": token}


def verify_token(token):
    payload = jwt.decode(token, SECRET_KEY, ALGORITHM)
    if not payload:
        return "token not valid"
    return payload["email"]


@app.get("/viewuser")
def viewuser():
    with Session(engine) as session:
        statement = select(User)
        res = session.exec(statement).all()
        return res


@app.put("/updatevalues")
def update(new: Update):
    with Session(engine) as session:
        statement = select(User).where(User.email == new.email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}

        if found_user:
            found_user.email = new.email
            found_user.username = new.username
            found_user.password = new.password

            session.commit()
            return {"message": "row updated"}


@app.delete("/deletedata")
def delete(new: Delete):
    with Session(engine) as session:
        statement = select(User).where(User.email == new.email)
        found_user = session.exec(statement).first()

        if not found_user:
            return {"message": "user not found"}

        session.delete(found_user)
        session.commit()
        return {"message": "row deleted"}
