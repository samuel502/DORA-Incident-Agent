"""Read-only connectors to Rheinbank's simulated systems.

The agent reaches bank data only through these functions. Each one takes fixed,
checked inputs and returns a small, fixed-shape result tagged with its source.
No function here writes, changes or deletes anything (CLAUDE.md hard rule 3).
"""

from ._guards import InvalidQuery
from .client_data import get_bank_profile, get_client_impact, get_daily_averages
from .monitoring import get_outage_timeline
from .security import get_security_alerts
from .services import find_service, get_service
from .suppliers import get_supplier, get_supplier_notices, get_suppliers_for_service

__all__ = [
    "InvalidQuery",
    "find_service",
    "get_bank_profile",
    "get_client_impact",
    "get_daily_averages",
    "get_outage_timeline",
    "get_security_alerts",
    "get_service",
    "get_supplier",
    "get_supplier_notices",
    "get_suppliers_for_service",
]
