"""La garantía del esquema es lo que hace revisable la salida.

Los proveedores compatibles con OpenAI exigen JSON Schema en modo estricto:
`additionalProperties: false` en cada objeto y todas las propiedades en
`required`. Pydantic no lo emite así. Si la conversión falla, el proveedor
rechaza el esquema —o lo acepta sin imponerlo, que es peor.
"""

from typing import Any

import pytest

from threat_agent.models import ThreatModel
from threat_agent.providers import ProviderError, _to_strict_schema

SCHEMA = _to_strict_schema(ThreatModel.model_json_schema())


def _objects(node: Any) -> list[dict]:
    """Todos los subesquemas de tipo objeto, a cualquier profundidad."""
    found = []
    if isinstance(node, dict):
        if node.get("type") == "object":
            found.append(node)
        for value in node.values():
            found += _objects(value)
    elif isinstance(node, list):
        for item in node:
            found += _objects(item)
    return found


def test_todo_objeto_prohibe_propiedades_extra():
    objetos = _objects(SCHEMA)
    assert objetos, "el esquema no tiene objetos: la conversión no está haciendo nada"
    assert all(o.get("additionalProperties") is False for o in objetos)


def test_todo_objeto_marca_sus_propiedades_como_obligatorias():
    for obj in _objects(SCHEMA):
        if "properties" in obj:
            assert set(obj["required"]) == set(obj["properties"])


def test_la_amenaza_anidada_tambien_se_convierte():
    """Threat vive en $defs; si la recursión no baja ahí, el esquema es inválido."""
    threat = SCHEMA["$defs"]["Threat"]
    assert threat["additionalProperties"] is False
    assert "impact" in threat["required"] and "likelihood" in threat["required"]


def test_se_conservan_los_limites_de_la_escala():
    """ge=1/le=5 son lo que impide un impacto de 7."""
    impact = SCHEMA["$defs"]["Threat"]["properties"]["impact"]
    assert impact["minimum"] == 1 and impact["maximum"] == 5


def test_se_conserva_el_minimo_de_cinco_amenazas():
    """Es el mínimo que pide el enunciado, y lo garantiza el esquema."""
    assert SCHEMA["properties"]["threats"]["minItems"] == 5


def test_la_conversion_no_muta_el_esquema_original():
    original = ThreatModel.model_json_schema()
    _to_strict_schema(original)
    assert "additionalProperties" not in original


def test_analyze_acepta_un_proveedor_inyectado(make_threat, make_model):
    """Permite probar la orquestación sin llamar a ninguna API."""
    from threat_agent.agent import analyze

    modelo = make_model([make_threat(i, 3) for i in range(1, 6)])

    class FakeProvider:
        name = "fake"
        model = "fake-1"

        def analyze(self, description: str):
            assert "PDFs" in description
            return modelo, {"model": "fake-1", "input_tokens": 10, "output_tokens": 20}

    result = analyze("Subimos PDFs.", provider=FakeProvider())
    assert result.provider == "fake"
    assert result.input_tokens == 10
    assert result.threat_model.ranked_threats()[0].risk == 15
    assert result.request_id is None


class _ChatQueDaTimeout:
    """Doble que agota el tiempo en la llamada, como hace un proveedor lento."""

    def __init__(self) -> None:
        self.completions = self

    def create(self, **kwargs):
        import openai

        raise openai.APITimeoutError(request=None)


def test_los_dos_adaptadores_fijan_timeout_y_reintentos():
    """No heredarlos del SDK es la decisión: 600s x 3 intentos son 15 min mudos."""
    from threat_agent.providers import (
        DEFAULT_MAX_RETRIES,
        DEFAULT_TIMEOUT,
        AnthropicProvider,
        OpenAICompatibleProvider,
    )

    for provider in (
        AnthropicProvider(model="m"),
        OpenAICompatibleProvider(model="m", api_key="k"),
    ):
        assert provider._timeout == DEFAULT_TIMEOUT
        assert provider._max_retries == DEFAULT_MAX_RETRIES
    assert DEFAULT_TIMEOUT < 600, "el valor por defecto del SDK es justo lo que se evita"
    assert DEFAULT_MAX_RETRIES < 2


def test_el_timeout_llega_al_cliente_de_openai(monkeypatch):
    """Fijarlo en el constructor no sirve si no se pasa al cliente."""
    import openai

    from threat_agent.providers import OpenAICompatibleProvider

    capturado = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            capturado.update(kwargs)
            # El cliente se construye fuera del try: fallar aquí escaparía sin
            # traducir. El timeout real ocurre en la llamada.
            self.chat = _ChatQueDaTimeout()

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    provider = OpenAICompatibleProvider(model="m", api_key="k", timeout=42.0, max_retries=0)
    with pytest.raises(ProviderError):
        provider.analyze("Subimos PDFs.")
    assert capturado["timeout"] == 42.0
    assert capturado["max_retries"] == 0


def test_un_timeout_no_se_confunde_con_un_fallo_de_red(monkeypatch):
    """Decir 'revisa la conexión' ante un timeout manda a buscar donde no está."""
    import openai

    from threat_agent.providers import OpenAICompatibleProvider

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = _ChatQueDaTimeout()

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    provider = OpenAICompatibleProvider(model="m", api_key="k", name="nvidia", timeout=180.0)
    with pytest.raises(ProviderError) as exc:
        provider.analyze("Subimos PDFs.")
    mensaje = str(exc.value)
    assert "180s" in mensaje and "nvidia" in mensaje
    assert "conexión" not in mensaje
    assert "show" in mensaje, "debe apuntar al respaldo de examples/"
