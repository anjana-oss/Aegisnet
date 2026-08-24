import uuid
import redis
import os
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import app, engine, User, Activitylog, Alert, SessionTable

client = TestClient(app)

redis_client = redis.Redis(host=os.getenv("REDIS_HOST","LOCALHOST"), port=6379, decode_responses=True)


def create_test_user(role="user"):
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    password = "TestPassword123!"

    response = client.post(
        "/signup", json={"username": "testuser", "email": email, "password": password}
    )
    assert response.status_code == 200

    if role == "admin":
        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == email)).first()
            user.role = "admin"
            session.add(user)
            session.commit()
    return email, password


def login_user(email, password):
    response = client.post("/login", json={"email": email, "password": password})
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "login successful"
    assert "access_token" in data
    return data["access_token"]


def cleanup_user(email):
    redis_client.delete(f"failed:{email}")

    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()

        if user:
            activities = session.exec(
                select(Activitylog).where(Activitylog.email == email)
            ).all()

            alerts = session.exec(select(Alert).where(Alert.email == email)).all()

            sessions = session.exec(
                select(SessionTable).where(SessionTable.email == email)
            ).all()

            for item in activities:
                session.delete(item)

            for item in alerts:
                session.delete(item)

            for item in sessions:
                session.delete(item)

            session.delete(user)
            session.commit()


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["project"] == "Aegisnet"
    assert response.json()["status"] == "online"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_signup():
    email, password = create_test_user()
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()

        assert user is not None
        assert user.username == "testuser"
        assert user.password != password
        assert user.role == "user"

    cleanup_user(email)


def test_login_success():
    email, password = create_test_user()
    token = login_user(email, password)
    assert isinstance(token, str)
    assert len(token) > 0
    cleanup_user(email)


def test_login_wrong_password():
    email, password = create_test_user()
    response = client.post(
        "/login", json={"email": email, "password": "WrongPassword123!"}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "login failed"
    cleanup_user(email)


def test_login_nonexistent_user():
    email = f"missing_{uuid.uuid4().hex[:8]}@example.com"

    response = client.post(
        "/login", json={"email": email, "password": "TestPassword123!"}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "user not found"
    redis_client.delete(f"failed:{email}")


def test_viewuser_valid_token():
    email, password = create_test_user()
    token = login_user(email, password)
    response = client.get("/viewuser", params={"token": token})
    assert response.status_code == 200
    assert response.json()["email"] == email
    assert response.json()["username"] == "testuser"

    cleanup_user(email)


def test_viewuser_invalid_token():
    response = client.get("/viewuser", params={"token": "invalid-token"})
    assert response.status_code == 200
    assert response.json()["message"] == "invalid token"


def test_update_profile():
    email, password = create_test_user()
    token = login_user(email, password)

    response = client.put(
        "/updatevalues",
        params={"token": token},
        json={"username": "updateduser", "password": "NewPassword123!"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "row updated"

    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        assert user.username == "updateduser"
        assert user.password != "NewPassword123!"

    cleanup_user(email)


def test_admin_rbac_denies_normal_user():
    email, password = create_test_user()
    token = login_user(email, password)
    response = client.get("/viewlogs", params={"token": token})
    assert response.status_code == 200
    assert response.json()["message"] == "access denied"

    cleanup_user(email)


def test_admin_can_view_logs():
    email, password = create_test_user(role="admin")
    token = login_user(email, password)
    response = client.get("/viewlogs", params={"token": token})
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    cleanup_user(email)


def test_admin_can_view_alerts():
    email, password = create_test_user(role="admin")
    token = login_user(email, password)
    response = client.get("/viewalerts", params={"token": token})
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    cleanup_user(email)


def test_admin_dashboard():
    response = client.get("/admin_dashboard")
    assert response.status_code == 200


def test_my_sessions():
    email, password = create_test_user()
    token = login_user(email, password)
    response = client.get("/my_sessions", params={"token": token})
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) >= 1

    cleanup_user(email)


def test_logout_session():
    email, password = create_test_user()
    token = login_user(email, password)
    response = client.get("/my_sessions", params={"token": token})
    sessions = response.json()
    assert len(sessions) >= 1
    session_id = sessions[-1]["id"]
    logout_response = client.post(
        "/logout_sessions", params={"token": token, "id": session_id}
    )

    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "logout success"

    cleanup_user(email)


def test_high_risk_users():
    response = client.get("/high_riskscore_users/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_timeline():
    email, password = create_test_user()
    token = login_user(email, password)
    response = client.get(f"/timeline/{email}")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    cleanup_user(email)


def test_security_report():
    email, password = create_test_user()
    login_user(email, password)
    response = client.get(f"/security_report/{email}")
    assert response.status_code == 200
    data = response.json()

    assert data["email"] == email
    assert data["username"] == "testuser"
    assert "risk_score" in data
    assert "security_grade" in data
    assert "recommendation" in data
    assert "failed_login_count" in data

    cleanup_user(email)


def test_investigate_user_admin():
    user_email, user_password = create_test_user()
    admin_email, admin_password = create_test_user(role="admin")
    admin_token = login_user(admin_email, admin_password)
    response = client.post(
        "/investigate_user", params={"token": admin_token}, json={"email": user_email}
    )
    assert response.status_code == 200
    data = response.json()

    assert data["email"] == user_email
    assert data["role"] == "user"
    assert "alerts" in data
    assert "logs" in data

    cleanup_user(user_email)
    cleanup_user(admin_email)


def test_investigate_user_denied_for_normal_user():
    user_email, user_password = create_test_user()
    target_email, target_password = create_test_user()
    token = login_user(user_email, user_password)
    response = client.post(
        "/investigate_user", params={"token": token}, json={"email": target_email}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "access denied"
    cleanup_user(user_email)
    cleanup_user(target_email)


def test_redis_failed_login_counter():
    email = f"redis_{uuid.uuid4().hex[:8]}@example.com"
    key = f"failed:{email}"
    redis_client.delete(key)
    redis_client.set(key, 1)
    redis_client.incr(key)
    count = int(redis_client.get(key))
    assert count == 2
    redis_client.delete(key)


def test_account_lockout():
    email, password = create_test_user()
    redis_client.delete(f"failed:{email}")
    for _ in range(5):
        response = client.post(
            "/login", json={"email": email, "password": "WrongPassword123!"}
        )
        assert response.status_code == 200

    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        assert user.locked_out is True
        assert user.risk_score >= 10
    response = client.post("/login", json={"email": email, "password": password})
    assert response.status_code == 200
    assert response.json()["message"] == "account locked"

    cleanup_user(email)




def test_readiness():
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "database" in data
    assert "redis" in data

    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["redis"] == "connected"


def test_me():
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    signup_response = client.post(
        "/signup",
        json={"username": "metestuser", "email": email, "password": "TestPassword123!"},
    )

    assert signup_response.status_code == 200
    login_response = client.post(
        "/login", json={"email": email, "password": "TestPassword123!"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    response = client.get("/me", params={"token": token})

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert data["username"] == "metestuser"
    assert "id" in data
    assert "role" in data
    assert "risk_score" in data
    assert "locked_out" in data


def test_logout():
    email = f"logout_{uuid.uuid4().hex[:8]}@example.com"
    signup_response = client.post(
        "/signup",
        json={"username": "logoutuser", "email": email, "password": "TestPassword123!"},
    )
    assert signup_response.status_code == 200

    login_response = client.post(
        "/login", json={"email": email, "password": "TestPassword123!"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = client.post("/logout", params={"token": token})
    assert response.status_code == 200
    data = response.json()
    assert "message" in data


def test_alerts():
    email = f"alert_{uuid.uuid4().hex[:8]}@example.com"

    signup_response = client.post(
        "/signup",
        json={"username": "alertuser", "email": email, "password": "TestPassword123!"},
    )
    assert signup_response.status_code == 200
    login_response = client.post(
        "/login", json={"email": email, "password": "TestPassword123!"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = client.get("/alerts", params={"token": token})

    assert response.status_code == 200
    assert response.json() is not None
