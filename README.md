# FastAPI File Scan

This application allows you to scan files using the VirusTotal API through an endpoint in FastAPI.

# Getting Started

You'll need:
- 🐳 [Docker](https://www.docker.com/get-started) installed.
- 🔑 [VirusTotal API key](https://developers.virustotal.com/reference#getting-started) to use the VirusTotal API.

### 🧬 1. Clone the repository
```sh
git clone https://github.com/serasinfin/fastapi-filescan.git
```

### 📜 2. Create the `.env` file
Inside the project directory, create a `.env` file with the following content:

```dotenv
VT_API_KEY=virustotal_api_key
VT_API_URL=https://www.virustotal.com/api/v3
```

Make sure to replace `virustotal_api_key` with your generated key.

### 🚀 3. Build and run the application

Build the Docker image
```sh
docker build -t fastapi-filescan .
```

Run the container
```sh
docker run -p 8000:8000 fastapi-filescan
```

The application will be available at 👉🏻`http://localhost:8000`.

## API Documentation

### Endpoint: `/scan`
- **Description**: Scans a file with VirusTotal.
- **Method**: `POST`
- **Parameters**:
  - `file`: File to scan (type `multipart/form-data`).
- **Response**:
  - `200 OK`: Returns the analysis results.
  - `400 Bad Request`: If the file is too large (more than 32MB).
  - `500 Internal Server Error`: If an error occurs during the scan or when retrieving the analysis results.

### Example request with `curl`
```sh
curl -X POST "http://localhost:8000/scan" -F "file=@/path/to/file"
```

### Also, you can use the Swagger UI
The API documentation is available at 👉🏻`http://localhost:8000/docs`.
