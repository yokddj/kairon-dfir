from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.case import Case
from app.services.host_network import get_host_network_observations

router = APIRouter()


@router.get("/api/cases/{case_id}/host-network")
def get_case_host_network(
    case_id: str,
    host_id: str = Query(...),
    db: Session = Depends(get_db),
) -> dict:
    """Observed, host-local IP addresses for one host, derived at read
    time from already-indexed evidence (see app.services.host_network for
    which sources are trusted and why). Never returns a remote/peer
    address, never invents gateway/DNS/MAC/interface data a source did not
    itself provide.
    """
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return get_host_network_observations(db, case_id=case_id, host_id=host_id)
