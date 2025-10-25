# Authentication Server

Python-based authentication server that manages QR authentication sessions.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Edit `config.yaml` to configure server settings.

## Running

```bash
python auth_server.py
```

## API Endpoints

- `POST /api/session/create` - Create authentication session
- `GET /api/session/status/<id>` - Check session status  
- `POST /api/authenticate` - Authenticate user
- `POST /api/user/register` - Register new user
- `GET /api/users` - List all users
- `GET /health` - Health check

