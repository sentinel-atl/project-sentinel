"""
Reputation scoring — weighted vouches with time decay and Sybil resistance.
Compatible with the TypeScript ReputationEngine.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Vouch:
    """A reputation vouch from one agent to another."""
    voucher_did: str
    target_did: str
    polarity: str  # "positive" or "negative"
    weight: float  # 0.0 to 1.0
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReputationScore:
    """Computed reputation score for an agent."""
    did: str
    score: float
    positive_vouches: int
    negative_vouches: int
    total_vouches: int
    quarantined: bool
    computed_at: float


class ReputationEngine:
    """
    Weighted reputation scoring with time decay and Sybil resistance.

    - Vouches decay over time (90-day half-life)
    - Sybil resistance: limit vouches per voucher
    - Quarantine: agents with poor reputation are quarantined
    - Rate limiting: max vouches per voucher per target per window
    """

    def __init__(
        self,
        decay_half_life_days: float = 90.0,
        quarantine_threshold: float = 20.0,
        max_vouches_per_pair: int = 5,
        rate_limit_window_seconds: float = 3600.0,
    ):
        self._vouches: list[Vouch] = []
        self._quarantined: set[str] = set()
        self._decay_half_life = decay_half_life_days * 86400  # seconds
        self._quarantine_threshold = quarantine_threshold
        self._max_vouches_per_pair = max_vouches_per_pair
        self._rate_limit_window = rate_limit_window_seconds

    def vouch(
        self,
        voucher_did: str,
        target_did: str,
        polarity: str,
        weight: float,
        reason: str = "",
    ) -> dict:
        """Submit a reputation vouch. Returns {allowed, reason}."""
        if voucher_did == target_did:
            return {"allowed": False, "reason": "Cannot vouch for yourself"}

        if not 0 <= weight <= 1:
            return {"allowed": False, "reason": "Weight must be between 0 and 1"}

        if polarity not in ("positive", "negative"):
            return {"allowed": False, "reason": "Polarity must be 'positive' or 'negative'"}

        # Rate limit check
        now = time.time()
        recent = [
            v for v in self._vouches
            if v.voucher_did == voucher_did
            and v.target_did == target_did
            and (now - v.timestamp) < self._rate_limit_window
        ]

        if len(recent) >= self._max_vouches_per_pair:
            return {"allowed": False, "reason": "Rate limit: too many vouches for this target"}

        v = Vouch(
            voucher_did=voucher_did,
            target_did=target_did,
            polarity=polarity,
            weight=weight,
            reason=reason,
            timestamp=now,
        )
        self._vouches.append(v)

        # Recompute quarantine
        score = self.compute_score(target_did)
        if score.score < self._quarantine_threshold:
            self._quarantined.add(target_did)

        return {"allowed": True}

    def compute_score(self, did: str) -> ReputationScore:
        """Compute the current reputation score for an agent."""
        now = time.time()
        target_vouches = [v for v in self._vouches if v.target_did == did]

        weighted_sum = 0.0
        total_weight = 0.0
        positive = 0
        negative = 0

        for v in target_vouches:
            age = now - v.timestamp
            decay = math.pow(0.5, age / self._decay_half_life) if self._decay_half_life > 0 else 1.0
            effective_weight = v.weight * decay

            if v.polarity == "positive":
                weighted_sum += effective_weight
                positive += 1
            else:
                weighted_sum -= effective_weight
                negative += 1

            total_weight += effective_weight

        # Normalize to 0-100 scale
        if total_weight > 0:
            raw = (weighted_sum / total_weight + 1) / 2  # -1..1 → 0..1
            score = max(0, min(100, raw * 100))
        else:
            score = 50.0  # Default for unknown agents

        return ReputationScore(
            did=did,
            score=score,
            positive_vouches=positive,
            negative_vouches=negative,
            total_vouches=positive + negative,
            quarantined=did in self._quarantined,
            computed_at=now,
        )

    def is_quarantined(self, did: str) -> bool:
        """Check if an agent is quarantined."""
        return did in self._quarantined

    def unquarantine(self, did: str) -> None:
        """Remove an agent from quarantine."""
        self._quarantined.discard(did)
