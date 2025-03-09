# Python
import tempfile
# FastAPI
from fastapi import FastAPI, File, UploadFile, HTTPException, status
# App
from app.config import get_logger
from app.scanner import scan_file, get_analysis
from app.schemas import ScanResponse

app = FastAPI()

UPLOAD_MAX_SIZE = 32 * 1024 * 1024  # 32MB

logger = get_logger(__name__)

@app.post(
    path="/scan",
    description="Scan a file with VirusTotal",
    status_code=status.HTTP_200_OK,
    response_model=ScanResponse,
)
async def scan(file: UploadFile = File(...)) -> ScanResponse:
    content = await file.read()
    # Validate file size
    if len(content) > UPLOAD_MAX_SIZE:
        logger.warning("File is too large")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is too large. Max size is 32MB",
        )
    try:
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            temp_file.write(content)
            temp_file.flush()
            # Scan file with VirusTotal
            scan_result = scan_file(temp_file.name)
            if not scan_result:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error scanning file",
                )

    except Exception as e:
        logger.error(f"Error trying to scan file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error scanning file",
        )

    # If the scan was successful, get the analysis results
    analysis = get_analysis(scan_result.data.id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting analysis",
        )

    return ScanResponse(
        id=analysis.data.id,
        status=analysis.data.attributes.status,
        stats=analysis.data.attributes.stats,
    )
