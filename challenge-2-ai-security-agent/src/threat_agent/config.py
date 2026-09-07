"""Selección de proveedor desde variables de entorno.

Cambiar de proveedor es editar el `.env`: no se toca código. Los presets de
abajo son atajos con la `base_url` y el modelo por defecto ya puestos; cualquier
endpoint compatible con OpenAI se puede usar aunque no esté en la lista, con
THREAT_AGENT_PROVIDER=openai-compatible y THREAT_AGENT_BASE_URL.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .providers import AnthropicProvider, OpenAICompatibleProvider, Provider, ProviderError


@dataclass(frozen=True)
class Preset:
    """Valores por defecto de un proveedor conocido."""

    api_key_env: str
    default_model: str
    base_url: str | None = None
    bedrock: bool = False


PRESETS: dict[str, Preset] = {
    "anthropic": Preset("ANTHROPIC_API_KEY", "claude-opus-5"),
    "bedrock": Preset("", "anthropic.claude-opus-5", bedrock=True),
    "openai": Preset("OPENAI_API_KEY", "gpt-5"),
    "openrouter": Preset(
        "OPENROUTER_API_KEY",
        "anthropic/claude-opus-4.1",
        base_url="https://openrouter.ai/api/v1",
    ),
    "gemini": Preset(
        "GEMINI_API_KEY",
        "gemini-3.1-pro-preview",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    ),
    "openai-compatible": Preset("THREAT_AGENT_API_KEY", ""),
}

DEFAULT_PROVIDER = "anthropic"


def load_dotenv(path: str = ".env") -> None:
    """Carga un `.env` sencillo. Lo ya definido en el entorno tiene prioridad.

    Se implementa a mano en lugar de añadir una dependencia: el formato que
    necesitamos son pares CLAVE=valor y comentarios. Que el entorno gane sobre
    el fichero es deliberado, para poder sobrescribir en CI sin editar nada.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def build_provider(
    *,
    provider: str | None = None,
    model: str | None = None,
    effort: str = "high",
) -> Provider:
    """Construye el proveedor indicado por el entorno o por los argumentos.

    Los argumentos explícitos (banderas del CLI) ganan al `.env`, y el `.env`
    gana a los valores por defecto.
    """
    env_provider = os.environ.get("THREAT_AGENT_PROVIDER")
    name = (provider or env_provider or DEFAULT_PROVIDER).lower()
    if name not in PRESETS:
        opciones = ", ".join(sorted(PRESETS))
        raise ProviderError(f"Proveedor desconocido: '{name}'. Opciones: {opciones}.")

    # THREAT_AGENT_MODEL y THREAT_AGENT_BASE_URL describen el proveedor activo del `.env`. Si se
    # pide otro con --provider, no se heredan: un modelo o una URL
    # del proveedor equivocado producen un 404, o peor, mandan la clave de un proveedor al
    # endpoint de otro y el error resultante habla de credenciales.
    is_env_provider = env_provider is None or name == env_provider.lower()
    env_model = os.environ.get("THREAT_AGENT_MODEL") if is_env_provider else None

    preset = PRESETS[name]
    chosen_model = model or env_model or preset.default_model
    if not chosen_model:
        raise ProviderError(
            f"El proveedor '{name}' no tiene modelo por defecto. "
            "Define THREAT_AGENT_MODEL en el .env o usa --model."
        )

    if preset.bedrock:
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise ProviderError("Bedrock necesita AWS_REGION en el entorno o en el .env.")
        return AnthropicProvider(model=chosen_model, effort=effort, bedrock_region=region)

    api_key = os.environ.get(preset.api_key_env) or os.environ.get("THREAT_AGENT_API_KEY")

    if name == "anthropic":
        # Sin clave explícita el SDK aún puede resolver una sesión de `ant auth login`.
        return AnthropicProvider(model=chosen_model, effort=effort, api_key=api_key)

    if not api_key:
        raise ProviderError(
            f"Falta la clave del proveedor '{name}'. "
            f"Define {preset.api_key_env} en el fichero .env."
        )

    env_base_url = os.environ.get("THREAT_AGENT_BASE_URL") if is_env_provider else None
    # La URL del preset manda: un proveedor con nombre sabe cuál es la suya. La
    # variable solo rellena a los que no la traen (openai, openai-compatible).
    base_url = preset.base_url or env_base_url
    if not base_url and name == "openai-compatible":
        raise ProviderError("'openai-compatible' necesita THREAT_AGENT_BASE_URL en el .env.")
    return OpenAICompatibleProvider(
        model=chosen_model, api_key=api_key, base_url=base_url, name=name
    )
