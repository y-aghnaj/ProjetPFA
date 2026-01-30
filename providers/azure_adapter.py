# providers/azure_adapter.py
from __future__ import annotations
from typing import Dict, Any

def normalize_state(state: Dict[str, Any]) -> Dict[str, Any]:
    # v0: pass-through
    return state
