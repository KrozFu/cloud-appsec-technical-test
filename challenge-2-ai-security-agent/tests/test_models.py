"""El riesgo y la priorización los calcula el código, no el modelo.

Es la decisión de diseño que sostiene el agente: el LLM emite impacto y
probabilidad con su justificación, y el orden sale de aritmética reproducible.
"""

import pytest
from pydantic import ValidationError

from threat_agent.models import Severity, Stride, Threat


def test_riesgo_es_el_producto_de_impacto_y_probabilidad(make_threat):
    assert make_threat(4, 3).risk == 12


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (25, Severity.CRITICAL), (20, Severity.CRITICAL),
        (19, Severity.HIGH), (12, Severity.HIGH),
        (11, Severity.MEDIUM), (6, Severity.MEDIUM),
        (5, Severity.LOW), (1, Severity.LOW),
    ],
)
def test_las_bandas_de_severidad_cubren_sus_limites(risk: int, expected: Severity):
    """Los valores probados son los extremos de cada banda, que es donde se falla."""
    assert Severity.from_risk(risk) is expected


def test_las_amenazas_se_ordenan_por_riesgo_descendente(make_threat, make_model):
    tm = make_model([
        make_threat(1, 1),   # 1
        make_threat(5, 5),   # 25
        make_threat(3, 2),   # 6
        make_threat(4, 4),   # 16
        make_threat(2, 5),   # 10
    ])
    assert [t.risk for t in tm.ranked_threats()] == [25, 16, 10, 6, 1]


def test_a_igual_riesgo_manda_el_mayor_impacto(make_threat, make_model):
    """12 = 4x3 y 12 = 3x4. Ante el mismo riesgo se atiende antes lo que más daña."""
    tm = make_model([
        make_threat(3, 4), make_threat(4, 3),
        make_threat(1, 1), make_threat(1, 2), make_threat(1, 3),
    ])
    assert [t.impact for t in tm.ranked_threats()[:2]] == [4, 3]


def test_ranked_threats_no_muta_la_lista_original(make_threat, make_model):
    tm = make_model([make_threat(i, 1) for i in (1, 5, 2, 4, 3)])
    tm.ranked_threats()
    assert [t.impact for t in tm.threats] == [1, 5, 2, 4, 3]


def test_top_risks_devuelve_los_tres_de_mayor_riesgo(make_threat, make_model):
    tm = make_model([make_threat(i, 5) for i in range(1, 6)])
    assert [t.risk for t in tm.top_risks()] == [25, 20, 15]


@pytest.mark.parametrize("score", [0, 6, -1])
def test_el_esquema_rechaza_puntuaciones_fuera_de_escala(score: int, make_threat):
    """El modelo no puede inventarse un impacto 7 para colar una amenaza arriba."""
    with pytest.raises(ValidationError):
        make_threat(score, 3)


def test_el_esquema_exige_al_menos_cinco_amenazas(make_threat, make_model):
    """El enunciado pide un mínimo de 5. Lo garantiza el esquema, no el prompt."""
    with pytest.raises(ValidationError):
        make_model([make_threat(3, 3) for _ in range(4)])


def test_cada_categoria_stride_tiene_etiqueta_legible():
    assert all(member.label for member in Stride)


def test_el_riesgo_no_es_un_campo_del_esquema():
    """Si el LLM pudiera emitir 'risk', la priorización dejaría de ser auditable."""
    assert "risk" not in Threat.model_fields
    assert "severity" not in Threat.model_fields
