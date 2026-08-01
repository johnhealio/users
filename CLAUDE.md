# Project: User authentication and authorization

## Goals
Create and Maintain user data to use for authentication and authorization
Each function will run in its own container
Each function will have its own rust project (e.g. registration is a function/project.  Logon will be one, Logout will be one)
Each function will be capable of presenting its associated browser-based user interface
Common parts of UI (page navigation and images) will be maintained in common location
Authentication will use WebAuthn and DPoP
Authorization will be a function to determine if a user is allowed to access a specific API
Fine-grained permission will be handled at the API level

## Tech stack
Middle: Rust on Cloud Run behind Global Load Balancer
Database: Firestore (this vm has access to Firestore.  No emulator required)
Front:  HTML/CSS/JS


