# AegisNet

A security monitoring and threat detection backend built with FastAPI and PostgreSQL.

## Features

- JWT Authentication
- Role Based Access Control
- Activity Logging
- Redis-powered failed login tracking and account lockout
- Alert Generation
- Risk Score System
- Account Lockout
- Session Tracking
- User Investigation APIs
- Security Dashboard
- Security Reports

## Tech Stack

- Python
- FastAPI
- PostgreSQL
- SQLModel
- JWT
- Bcrypt
- Redis
- Websocket
- Railway

## Project Status

current version :v1.1

## latest update:
-integrated Redis for high-performance failed login tracking
-optimized account lockout using Redis TTL

##  Latest Improvements

- Integrated Redis for in-memory failed login tracking.
- Reduced repeated database queries during authentication.
- Added automatic TTL expiration for temporary login counters.
- Improved backend performance and scalability.

## Architecture Diagram

![Architecture](aegisnet_architecture/architecture.png)

## Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Investigation
![Investigation](screenshots/investigate.png)

### Login
![Login](screenshots/login.png)

### Security Report
![Security Report](screenshots/securityreport.png)



### live API
--delpoyment currently unavailable--

run locally:
uvicorn main:app --reload

swagger documentation(not available now):
https://aegisnet-production.up.railway.app/docs

swagger docs:
http://127.0.0.1:8000/docs
