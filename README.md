# FastAPI File Scan 🔍

## Description
This application allows you to scan files using the VirusTotal API through an endpoint in FastAPI.

## Requirements
- Python 3.12 or higher
- Docker

## Configuration

### Create the `.env` file
Before building and running the application, create a `.env` file in the root directory of the project with the following content:

```dotenv
VT_API_KEY=your_virustotal_api_key
VT_API_URL=https://www.virustotal.com/api/v3
```

Make sure to replace `your_virustotal_api_key` with your generated key.

## Building and Running with Docker

### Build the Docker image
```sh
docker build -t fastapi-filescan .
```

### Run the container
```sh
docker run -d -p 8000:8000 fastapi-filescan
```

The application will be available at `http://localhost:8000`.

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