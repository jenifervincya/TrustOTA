"""
TrustOTA - Rollback Trigger Logic (ECU side)

The 3 gates in verify_and_apply.py (authenticity, compatibility,
integrity) catch a BAD PACKAGE before it's ever applied. They do NOT
catch a package that is genuinely signed, genuinely matches the
expected hash, and STILL fails at runtime - e.g. a firmware bug that
only shows up after boot (watchdog reset loop, sensor init failure,
CAN bus silence, etc). That's a real, distinct failure class, and it's
what this module defends against.

This mirrors the standard A/B boot-counter pattern used in real
automotive/embedded OTA systems (and required behavior under UNECE
R156 - a failed update must not leave the ECU bricked):

    1. STAGE   - after Gate 3 passes, the new image is written to the
                 inactive slot and that slot becomes ACTIVE on next
                 boot. State is marked "pending verification" and a
                 boot-attempt counter starts at 0.

    2. PROBE   - the ECU boots the new image and runs a health check
                 (in real firmware: watchdog didn't fire, self-test
                 passed, CAN bus alive, etc). Each attempt is recorded.

    3. COMMIT or ROLLBACK -
         - health check passes -> the new slot is COMMITTED: it
           becomes the new "last known good" and the counter resets.
         - health check fails MAX_BOOT_ATTEMPTS times in a row ->
           automatic ROLLBACK: active slot flips back to the last
           known good slot, and the failed slot is marked bad so it's
           never auto-selected again.

This is intentionally decoupled from crypto_module/diff_module - it
only cares about slot state, not signatures or patches. In the real
pipeline, verify_and_apply.py's Gate 3 success is what calls
stage_update() to hand off into this state machine.
"""

import os
import json
import time

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")
STATE_PATH = os.path.join(STATE_DIR, "slot_state.json")

MAX_BOOT_ATTEMPTS = 3


class RollbackTriggered(Exception):
    """Raised (and caught internally) the moment a rollback fires, so callers can log it distinctly."""
    pass


def _default_state():
    return {
        "active_slot": "A",
        "slots": {
            "A": {"version": "1.0.0", "sha256": None, "status": "good"},
            "B": {"version": None, "sha256": None, "status": "empty"},
        },
        "last_known_good_slot": "A",
        "pending_verification": False,
        "boot_attempts": 0,
        "max_boot_attempts": MAX_BOOT_ATTEMPTS,
        "history": [],
    }


def _log(state, event: str):
    state["history"].append({"t": int(time.time()), "event": event})
    print(f"[rollback] {event}")


def load_state() -> dict:
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(STATE_PATH):
        state = _default_state()
        save_state(state)
        return state
    with open(STATE_PATH) as f:
        return json.load(f)


def save_state(state: dict):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _inactive_slot(state: dict) -> str:
    return "B" if state["active_slot"] == "A" else "A"


def stage_update(version: str, sha256: str) -> dict:
    """
    Called after Gate 3 (integrity) passes in verify_and_apply.py.
    Writes the new image's metadata into the inactive slot, flips
    active_slot to it, and opens a "pending verification" window.
    Nothing is committed yet - it still has to prove itself at boot.
    """
    state = load_state()
    target_slot = _inactive_slot(state)

    state["slots"][target_slot] = {"version": version, "sha256": sha256, "status": "pending"}
    state["active_slot"] = target_slot
    state["pending_verification"] = True
    state["boot_attempts"] = 0

    _log(state, f"STAGED v{version} to slot {target_slot} (now active), boot-attempt window open")
    save_state(state)
    return state


def record_boot_attempt(boot_success: bool) -> dict:
    """
    Called once per boot of the currently active (pending) slot.
    Returns the updated state. Raises RollbackTriggered if this
    attempt was the one that exhausted max_boot_attempts.
    """
    state = load_state()

    if not state["pending_verification"]:
        _log(state, "record_boot_attempt() called with nothing pending - ignoring")
        save_state(state)
        return state

    active = state["active_slot"]

    if boot_success:
        state["slots"][active]["status"] = "good"
        state["last_known_good_slot"] = active
        state["pending_verification"] = False
        state["boot_attempts"] = 0
        _log(state, f"slot {active} booted healthy -> COMMITTED as last-known-good")
        save_state(state)
        return state

    state["boot_attempts"] += 1
    _log(state, f"slot {active} failed health check (attempt {state['boot_attempts']}/{state['max_boot_attempts']})")

    if state["boot_attempts"] >= state["max_boot_attempts"]:
        save_state(state)
        return _rollback(state)

    save_state(state)
    return state


def _rollback(state: dict) -> dict:
    failed_slot = state["active_slot"]
    good_slot = state["last_known_good_slot"]

    state["slots"][failed_slot]["status"] = "bad"
    state["active_slot"] = good_slot
    state["pending_verification"] = False
    state["boot_attempts"] = 0

    _log(
        state,
        f"ROLLBACK TRIGGERED - slot {failed_slot} exceeded {state['max_boot_attempts']} failed boots. "
        f"Reverting to last-known-good slot {good_slot} (v{state['slots'][good_slot]['version']})",
    )
    save_state(state)
    return state


def status(state: dict = None) -> str:
    state = state or load_state()
    lines = [
        f"active_slot           : {state['active_slot']}",
        f"pending_verification  : {state['pending_verification']}",
        f"boot_attempts          : {state['boot_attempts']}/{state['max_boot_attempts']}",
        f"last_known_good_slot   : {state['last_known_good_slot']}",
    ]
    for slot, info in state["slots"].items():
        lines.append(f"  slot {slot}: version={info['version']} status={info['status']}")
    return "\n".join(lines)


def reset_state():
    """Wipe state back to factory default - useful between demo runs."""
    save_state(_default_state())


if __name__ == "__main__":
    reset_state()
    print(status())
