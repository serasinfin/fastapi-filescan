# External
from pydantic import BaseModel

class VTUploadResponseData(BaseModel):
    type: str
    id: str
    links: dict[str, str]


class VTUploadResponse(BaseModel):
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
    data: VTAnalysisResponseData


class ScanResponse(BaseModel):
    id: str
    status: str
    stats: VTAnalysisStats
