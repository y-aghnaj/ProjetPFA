# providers/oci_adapter.py
from __future__ import annotations
from typing import Dict, Any

def normalize_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    OCI adapter (v0):
    - For now: pass-through.
    - Later: map OCI-specific resource schemas to a provider-agnostic canonical model.
    """
    return state
