"""
Data models for IOC (Indicator of Compromise) records.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class IOCRecord(BaseModel):
    """Normalised IOC as stored in the local IOC Store after pulling from MISP."""
    ioc_id: str = Field(..., description="MISP attribute UUID")
    ioc_value: str = Field(..., description="Indicator value, e.g. 185.220.101.45")
    ioc_type: str = Field(..., description="MISP attribute type: ip-src, ip-dst, domain, hostname, url")
    detectable: bool = Field(True, description="True when to_ids=1 in MISP")

    # MISP event context
    event_id: Optional[str] = None
    event_uuid: Optional[str] = None
    event_info: Optional[str] = None
    threat_level_id: Optional[int] = None   # 1=High,2=Medium,3=Low,4=Undefined
    threat_level: Optional[str] = None       # Human-readable label

    # Tags (Galaxy/taxonomy)
    tags: List[str] = Field(default_factory=list)

    # Timestamps
    attribute_timestamp: Optional[datetime] = None
    synced_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class IOCSearchRequest(BaseModel):
    value: str = Field(..., description="Value to look up in IOC store")


class IOCSearchResponse(BaseModel):
    found: bool
    ioc: Optional[IOCRecord] = None
    message: str = ""
