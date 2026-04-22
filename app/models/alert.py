"""
Data models for Mata Elang NIDS alerts and enrichment results.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class MataElangAlert(BaseModel):
    """
    Alert structure as produced by Mata Elang / Snort3.
    Maps to the Avro schema in the Kafka topic 'snort_alerts'
    (produced by event-stream-aggr from 'sensor_events').
    Extend fields to match your exact Avro schema.
    """
    alert_id: str = Field(..., description="Unique alert identifier")
    sensor_id: Optional[str] = Field(None, description="Mata Elang sensor_id from .env")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Network fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # Snort/IDS fields
    signature: Optional[str] = None
    signature_id: Optional[int] = None
    classification: Optional[str] = None
    priority: Optional[int] = None
    action: Optional[str] = None   # alert | drop | pass

    # Application layer (optional — populated by Snort HTTP/DNS preprocessors)
    domain: Optional[str] = None
    hostname: Optional[str] = None
    url: Optional[str] = None

    # Passthrough for any extra fields from Kafka payload
    raw: Optional[Dict[str, Any]] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class EnrichmentRequest(BaseModel):
    """Sent by Mata Elang pipeline to POST /enrich/alert."""
    alert_id: str
    sensor_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    hostname: Optional[str] = None
    url: Optional[str] = None
    signature: Optional[str] = None
    timestamp: Optional[datetime] = None


class MISPContext(BaseModel):
    """MISP threat-intelligence context attached when a match is found."""
    matched_ioc_value: str
    matched_ioc_type: str
    event_id: Optional[str] = None
    event_uuid: Optional[str] = None
    event_info: Optional[str] = None
    threat_level_id: Optional[int] = None
    threat_level: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class EnrichmentResponse(BaseModel):
    """Returned by POST /enrich/alert."""
    alert_id: str
    misp_match: bool
    misp_context: Optional[MISPContext] = None
    enriched_at: datetime = Field(default_factory=datetime.utcnow)
    message: str = ""

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
