# Python
import time
# External
import requests
# App
from app.config import VT_API_KEY, VT_API_URL, get_logger
from app.schemas import VTUploadResponse, VTAnalysisResponse

MAX_RETRIES = 10

logger = get_logger(__name__)

def scan_file(file_path: str) -> VTUploadResponse | None:
    """Scan file with VirusTotal
    Args:
        file_path (str): File path
    Returns: VTUploadResponse | None
    """
    # Check if API Key and URL are set
    if not VT_API_KEY or not VT_API_URL:
        logger.error("API Key or URL not found")
        return None
    try:
        # Open file
        with open(file_path, "rb") as f:
            files = {"file": f}
            headers = {"x-apikey": VT_API_KEY}
            # Send file to VirusTotal
            response = requests.post(
                f"{VT_API_URL}/files",
                files=files,
                headers=headers,
                timeout=10
            )
        if response.status_code == 200:
            return VTUploadResponse(**response.json())
        else:
            return None

    except Exception as e:
        logger.error(f"Request Error: {e}")
        return None

def get_analysis(analysis_id: str) -> VTAnalysisResponse | None:
    """Get analysis from VirusTotal
    Args:
        analysis_id (str): Analysis ID
    Returns: VTAnalysisResponse | None
    """
    try:
        headers = {"x-apikey": VT_API_KEY}
        retry_count = 0
        while retry_count < MAX_RETRIES:
            response = requests.get(
                f"{VT_API_URL}/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                analysis_response = VTAnalysisResponse(**response.json())
                if analysis_response.data.attributes.status == "completed":
                    return analysis_response

            retry_count += 1
            time.sleep(1)

        logger.warning("Max retries reached")
    except Exception as e:
        logger.error(f"Request Error: {e}")
        return None
