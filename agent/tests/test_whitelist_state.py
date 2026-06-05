"""Tests for ``WhitelistState.update()`` anti-wipe behaviour.

Background: a race during agent startup caused ``sync_now()`` to fire twice
in quick succession. The second response sometimes arrived as
``{"domains": [], "up_to_date": false, "global_version": "vN+1"}`` even
though the agent legitimately had cached entries from the first sync. The
old code wiped the cache, leaving the firewall manager and GUI staring at
an empty state.

The guard added in ``WhitelistState.update`` keeps the cache when:
  - state was non-empty BEFORE the update,
  - parsed new data is fully empty (no domains / patterns / ips),
  - and there is no ``group_changed`` signal.

These tests pin the new contract without changing the legitimate
replace-on-change path.
"""

import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from whitelist.state import WhitelistState


def _populated_state() -> WhitelistState:
    """Return a state pre-loaded with 3 domains and 2 IPs via the public
    update() API — exercises the same code path production uses."""
    state = WhitelistState()
    initial = state.update({
        "domains": ["example.com", "github.com", "anthropic.com"],
        "ips": ["1.1.1.1", "8.8.8.8"],
        "group_id": "g-initial",
        "up_to_date": False,
        "global_version": "v1",
        "group_version": "gv1",
    })
    assert initial is True, "Initial seeding update should return True"
    assert len(state.get_all_domains()) == 3
    assert len(state.get_all_ips()) == 2
    return state


def test_anti_wipe_preserves_cache_when_server_returns_empty():
    """Race-condition scenario: cache has data, server replies empty."""
    state = _populated_state()
    prev_domains = state.get_all_domains()
    prev_ips = state.get_all_ips()

    changed = state.update({
        "domains": [],
        "ips": [],
        "group_id": "g-initial",   # SAME group — no group_changed
        "up_to_date": False,        # Server claims this IS new data
        "global_version": "v2",     # Versions changed → would normally REPLACE
        "group_version": "gv2",
    })

    # update() must return False (no replacement applied) AND keep the cache.
    assert changed is False
    assert state.get_all_domains() == prev_domains
    assert state.get_all_ips() == prev_ips
    # But version bookkeeping IS updated so the next sync doesn't keep
    # asking the server for the same delta forever.
    assert state._version == "v2"
    assert state._group_version == "gv2"


def test_anti_wipe_does_not_block_legitimate_group_change():
    """If the agent moves to a new group, an empty whitelist for that new
    group IS the correct end state — guard must NOT block the wipe here."""
    state = _populated_state()

    changed = state.update({
        "domains": [],
        "ips": [],
        "group_id": "g-different",  # ← group_changed = True
        "up_to_date": False,
        "global_version": "v2",
        "group_version": "gv2",
    })

    # Wipe is the intended outcome when the agent leaves its group.
    # Either ``update`` returns True (state replaced) or False (no-op
    # because new == current). After a successful group change the cache
    # must be empty regardless.
    assert state.get_all_domains() == set()
    assert state.get_all_ips() == set()
    assert state._group_id == "g-different"


def test_empty_to_empty_is_a_noop():
    """Fresh state + empty server response = no warning, no churn."""
    state = WhitelistState()
    assert state.get_all_domains() == set()

    changed = state.update({
        "domains": [],
        "ips": [],
        "group_id": "",
        "up_to_date": False,
        "global_version": "v0",
        "group_version": "gv0",
    })

    # No previous data → guard doesn't trigger. Either path (no-change
    # short-circuit OR empty replace) leaves the state empty.
    assert changed is False
    assert state.get_all_domains() == set()
    assert state.get_all_ips() == set()


def test_normal_replace_path_still_works():
    """Anti-wipe must NOT block a normal sync that brings real new data."""
    state = _populated_state()

    changed = state.update({
        "domains": ["new-domain.com"],
        "ips": ["9.9.9.9"],
        "group_id": "g-initial",
        "up_to_date": False,
        "global_version": "v2",
        "group_version": "gv2",
    })

    assert changed is True
    assert state.get_all_domains() == {"new-domain.com"}
    assert state.get_all_ips() == {"9.9.9.9"}
    assert state._version == "v2"
