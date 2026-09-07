"""Orquestación: elige proveedor, hace la llamada y devuelve el resultado.

Un único turno con salida estructurada. No hay bucle de herramientas: la tarea
está acotada y la salida validada es lo que la hace revisable.

Este módulo ya no sabe qué proveedor hay detrás; eso vive en `providers.py` y
la elección en `config.py`.
"""

from dataclasses import dataclass

from .config import build_provider, load_dotenv
from .models import ThreatModel
from .providers import Provider, ProviderError, RefusalError

# Alias histórico: el CLI y los tests capturan AgentError.
AgentError = ProviderError

__all__ = ["AgentError", "AnalysisResult", "ProviderError", "RefusalError", "analyze"]

DEFAULT_EFFORT = "high"


@dataclass(frozen=True)
class AnalysisResult:
    threat_model: ThreatModel
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    request_id: str | None


def analyze(
    description: str,
    *,
    provider: Provider | None = None,
    provider_name: str | None = None,
    model: str | None = None,
    effort: str = DEFAULT_EFFORT,
) -> AnalysisResult:
    """Genera el modelo de amenazas para una descripción de funcionalidad.

    `provider` permite inyectar un doble en los tests sin tocar el entorno.
    """
    if provider is None:
        load_dotenv()
        provider = build_provider(provider=provider_name, model=model, effort=effort)

    threat_model, meta = provider.analyze(description)

    return AnalysisResult(
        threat_model=threat_model,
        provider=provider.name,
        model=meta.get("model", provider.model),
        input_tokens=meta.get("input_tokens", 0),
        output_tokens=meta.get("output_tokens", 0),
        request_id=meta.get("request_id"),
    )
