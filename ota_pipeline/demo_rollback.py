"""
TrustOTA - Rollback Trigger Demo

Two scenarios, run back to back on the same slot state:

  SCENARIO 1: update v1.3.0 passes all 3 gates AND boots healthy on
              first try -> should COMMIT, becomes new last-known-good.

  SCENARIO 2: update v1.4.0 passes all 3 gates (it's genuinely signed
              and hash-correct) but has a runtime bug that crashes it
              on boot -> after MAX_BOOT_ATTEMPTS failures, should
              AUTO-ROLLBACK to v1.3.0 (the last-known-good from
              scenario 1), not stay bricked on v1.4.0.

This is the piece that sits AFTER verify_and_apply.py's Gate 3 in the
real pipeline: Gate 3 passing only proves the image wasn't corrupted
in transit/patching - it says nothing about whether the firmware
actually runs correctly once flashed.
"""

from rollback_manager import (
    reset_state,
    stage_update,
    record_boot_attempt,
    status,
    load_state,
)


def main():
    print("=" * 60)
    print("Reset slot state to factory default (active=A, v1.0.0)")
    print("=" * 60)
    reset_state()
    print(status())

    print("\n" + "=" * 60)
    print("SCENARIO 1: v1.3.0 passes gates, boots healthy first try")
    print("=" * 60)
    stage_update(version="1.3.0", sha256="aaa...111")
    print(status())
    print("\n-- ECU boots the new slot --")
    record_boot_attempt(boot_success=True)
    print(status())

    print("\n" + "=" * 60)
    print("SCENARIO 2: v1.4.0 passes gates, but crashes on every boot")
    print("=" * 60)
    stage_update(version="1.4.0", sha256="bbb...222")
    print(status())

    state = load_state()
    max_attempts = state["max_boot_attempts"]
    for attempt in range(1, max_attempts + 1):
        print(f"\n-- ECU boot attempt {attempt} of v1.4.0 (fails health check) --")
        state = record_boot_attempt(boot_success=False)

    print("\nFinal state after exhausting boot attempts:")
    print(status(state))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    final = load_state()
    healthy_committed = final["slots"]["B"]["version"] == "1.3.0" and final["slots"]["B"]["status"] == "good"
    rolled_back = final["active_slot"] == "B" and final["slots"]["B"]["version"] == "1.3.0"
    print(f"v1.3.0 committed as last-known-good : {'PASS' if healthy_committed else 'CHECK'}")
    print(f"v1.4.0 auto-rolled-back after {max_attempts} failed boots -> active is v1.3.0 again : "
          f"{'PASS (correct)' if rolled_back else 'FAIL (WRONG - ECU would be bricked)'}")


if __name__ == "__main__":
    main()
