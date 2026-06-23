# Vulnerability Scanner API

A RESTful backend API for managing vulnerability scan results. Built with Node.js, Express, Socket.IO, Swagger, and JSON Server.

## Features

- Create vulnerability scans
- Retrieve all scans
- Retrieve scan by ID
- Update scan status
- Delete scans
- Dashboard statistics
- Pagination
- Filtering
- Search
- Swagger API documentation
- Real-time updates using Socket.IO

## Technologies Used

- Node.js
- Express.js
- Socket.IO
- Swagger UI
- swagger-jsdoc
- UUID
- CORS
- JSON Server

## Installation

Clone the repository:

```bash
git clone <repository-url>
```

Install dependencies:

```bash
npm install
```

Start the server:

```bash
node server.js
```

The server runs at:

```
http://localhost:5000
```

Swagger Documentation:

```
http://localhost:5000/api-docs
```

---

## API Endpoints

### GET

```
GET /scans
GET /scans/:id
GET /dashboard
```

### POST

```
POST /scans
```

### PUT

```
PUT /scans/:id
```

### DELETE

```
DELETE /scans/:id
```

---

## Example Scan Object

```json
{
  "id": "uuid",
  "target": "example.com",
  "status": "pending",
  "severity": "high",
  "createdAt": "2025-01-01T12:00:00Z"
}
```

---

## Project Structure

```
project/
│── server.js
│── db.json
│── package.json
│── README.md
```

---

## Status Codes

| Code | Meaning |
|------|---------|
|200|Success|
|201|Created|
|400|Bad Request|
|404|Not Found|
|500|Internal Server Error|

---

## Author

PAVITHRAN