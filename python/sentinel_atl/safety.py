"""
Content safety pipeline — regex classifiers + pluggable API classifiers.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SafetyViolation:
    """A content safety violation."""
    category: str
    severity: str
    confidence: float
    description: str
    span_start: Optional[int] = None
    span_end: Optional[int] = None


@dataclass
class ClassificationResult:
    """Result from a single classifier."""
    safe: bool
    violations: list[SafetyViolation]
    classifier_id: str
    latency_ms: float


@dataclass
class SafetyCheckResult:
    """Result from the full safety pipeline."""
    safe: bool
    blocked: bool
    violations: list[SafetyViolation]
    classifier_results: list[ClassificationResult]
    total_latency_ms: float


class ContentClassifier(ABC):
    """Abstract base class for content classifiers."""

    @property
    @abstractmethod
    def id(self) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def classify(self, text: str) -> ClassificationResult: ...


class RegexClassifier(ContentClassifier):
    """Regex-based classifier for common safety patterns."""

    DEFAULT_RULES = [
        {
            "pattern": re.compile(r"ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)", re.I),
            "category": "prompt_injection",
            "severity": "high",
            "description": "Potential prompt injection attempt detected",
        },
        {
            "pattern": re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
            "category": "jailbreak",
            "severity": "high",
            "description": "Potential jailbreak attempt (role reassignment)",
        },
        {
            "pattern": re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
            "category": "pii_exposure",
            "severity": "medium",
            "description": "Potential SSN-like pattern detected",
        },
        {
            "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b", re.I),
            "category": "pii_exposure",
            "severity": "low",
            "description": "Email address detected in content",
        },
    ]

    def __init__(self, rules: list[dict] | None = None):
        self._rules = rules or self.DEFAULT_RULES

    @property
    def id(self) -> str:
        return "regex-basic"

    @property
    def name(self) -> str:
        return "Regex Basic Safety"

    async def classify(self, text: str) -> ClassificationResult:
        start = time.monotonic()
        violations: list[SafetyViolation] = []

        for rule in self._rules:
            match = rule["pattern"].search(text)
            if match:
                violations.append(SafetyViolation(
                    category=rule["category"],
                    severity=rule["severity"],
                    confidence=0.7,
                    description=rule["description"],
                    span_start=match.start(),
                    span_end=match.end(),
                ))

        elapsed_ms = (time.monotonic() - start) * 1000
        return ClassificationResult(
            safe=len(violations) == 0,
            violations=violations,
            classifier_id=self.id,
            latency_ms=elapsed_ms,
        )


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class SafetyPipeline:
    """Chain multiple classifiers for defense-in-depth."""

    def __init__(
        self,
        classifiers: list[ContentClassifier] | None = None,
        block_threshold: str = "medium",
    ):
        self._classifiers = classifiers or [RegexClassifier()]
        self._block_threshold = SEVERITY_ORDER.get(block_threshold, 1)

    async def check(self, text: str) -> SafetyCheckResult:
        """Run all classifiers. Stops on first blocking violation."""
        start = time.monotonic()
        all_violations: list[SafetyViolation] = []
        results: list[ClassificationResult] = []
        blocked = False

        for classifier in self._classifiers:
            result = await classifier.classify(text)
            results.append(result)
            all_violations.extend(result.violations)

            blocking = any(
                SEVERITY_ORDER.get(v.severity, 0) >= self._block_threshold
                for v in result.violations
            )
            if blocking:
                blocked = True
                break

        return SafetyCheckResult(
            safe=len(all_violations) == 0,
            blocked=blocked,
            violations=all_violations,
            classifier_results=results,
            total_latency_ms=(time.monotonic() - start) * 1000,
        )
