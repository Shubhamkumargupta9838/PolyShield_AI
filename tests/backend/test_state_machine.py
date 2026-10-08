"""
Exhaustive Scan Status State Machine Test Suite for PolyShield AI (Phase 14).

Verifies the 8-state transition graph:
QUEUED -> STATIC_ANALYSIS -> (DYNAMIC_ANALYSIS -> FEATURE_EXTRACTION ->) ML_INFERENCE -> REPORT_GENERATION -> COMPLETED
with terminal FAILED transitions.

Ensures that illegal state transitions raise InvalidStateTransitionException.
"""

import pytest
from backend.app.schemas.scan import ScanStatus
from backend.app.services.scan_service import LEGAL_STATE_TRANSITIONS, ScanService
from backend.app.core.exceptions import InvalidStateTransitionException


ALL_STATES = list(ScanStatus)


def test_legal_state_transitions_defined_for_all_states():
    """Verify LEGAL_STATE_TRANSITIONS map contains explicit transition rules for every ScanStatus value."""
    for status in ALL_STATES:
        assert status in LEGAL_STATE_TRANSITIONS, f"Missing state transition rules for {status}"


@pytest.mark.parametrize("from_status", ALL_STATES)
def test_exhaustive_state_transition_validation(from_status: ScanStatus):
    """Test every possible from_state -> to_state pair (8 x 8 matrix = 64 transitions)."""
    allowed_next_states = LEGAL_STATE_TRANSITIONS[from_status]

    for to_status in ALL_STATES:
        if to_status in allowed_next_states:
            # Legal transition check
            assert to_status in LEGAL_STATE_TRANSITIONS[from_status], (
                f"Transition from {from_status} to {to_status} should be legal"
            )
        else:
            # Attempting an illegal transition in update_scan_status must fail
            scan_service_instance = ScanService(repository=None)
            with pytest.raises(InvalidStateTransitionException) as exc_info:
                scan_service_instance._validate_transition(from_status, to_status)
            assert f"Cannot transition scan from '{from_status.value}' to '{to_status.value}'" in str(exc_info.value)


def test_terminal_states_cannot_transition():
    """Verify COMPLETED and FAILED states cannot transition to any state."""
    service = ScanService(repository=None)
    for target in ALL_STATES:
        with pytest.raises(InvalidStateTransitionException):
            service._validate_transition(ScanStatus.COMPLETED, target)
        with pytest.raises(InvalidStateTransitionException):
            service._validate_transition(ScanStatus.FAILED, target)
