# External
from pydantic import BaseModel

class VTUploadResponseData(BaseModel):
    type: str
    id: str
    links: dict[str, str]


class VTUploadResponse(BaseModel):
    """
    Response model for the VT upload API when uploading a file
    (https://www.virustotal.com/api/v3/files)
    """
    data: VTUploadResponseData


class VTAnalysisStats(BaseModel):
    malicious: int
    suspicious: int
    undetected: int
    harmless: int
    timeout: int
    failure: int


class VTAnalysisAttributes(BaseModel):
    status: str
    stats: VTAnalysisStats


class VTAnalysisResponseData(BaseModel):
    id: str
    attributes: VTAnalysisAttributes


class VTAnalysisResponse(BaseModel):
    """
    Response model for the VT analysis API when requesting the analysis
    (https://www.virustotal.com/api/v3/analyses/{id})
    """
    data: VTAnalysisResponseData


class ScanResponse(BaseModel):
    """
    Response model from this API after scanning a file with VirusTotal
    """
    id: str
    status: str
    stats: VTAnalysisStats
