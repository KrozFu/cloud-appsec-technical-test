"""Fábricas compartidas, expuestas como fixtures.

Construir una `Threat` exige nueve campos; en los tests de priorización solo
importan el impacto y la probabilidad. Estas fábricas quitan ese ruido.
"""

from collections.abc import Callable

import pytest

from threat_agent.models import Stride, Threat, ThreatModel


@pytest.fixture
def make_threat() -> Callable[..., Threat]:
    def _make(impact: int, likelihood: int, *, component: str = "API Gateway") -> Threat:
        return Threat(
            component=component,
            threat="Escenario de prueba.",
            stride=Stride.SPOOFING,
            impact=impact,
            likelihood=likelihood,
            impact_rationale="—",
            likelihood_rationale="—",
            control="—",
            residual_risk_note="—",
        )

    return _make


@pytest.fixture
def make_model() -> Callable[[list[Threat]], ThreatModel]:
    def _make(threats: list[Threat]) -> ThreatModel:
        return ThreatModel(
            system_summary="Sistema de prueba.",
            assets=["PII"],
            trust_boundaries=["Internet -> API Gateway"],
            threats=threats,
            assumptions=[],
            out_of_scope=[],
        )

    return _make
