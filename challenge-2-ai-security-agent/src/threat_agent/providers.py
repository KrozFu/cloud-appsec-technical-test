"""Adaptadores de proveedor. Es la única parte del paquete que sabe de LLMs.

El resto del agente —esquema, aritmética del riesgo, delimitación de la entrada,
renderizado— es agnóstico. Cambiar de proveedor no toca nada más.

Hay dos adaptadores, no uno por fabricante:

- `AnthropicProvider` cubre la API de Anthropic y Amazon Bedrock.
- `OpenAICompatibleProvider` cubre OpenAI, OpenRouter, Gemini y cualquier otro
  endpoint que hable el protocolo de OpenAI. Se distinguen por `base_url`.

Contrato común: recibir una descripción, devolver un `ThreatModel` validado.
Quien no pueda garantizar el esquema no cumple el contrato (ver `_to_strict_schema`).
"""

from __future__ import annotations

from typing import Any, Protocol

from .models import ThreatModel
from .prompts import SYSTEM_PROMPT, build_user_message

#: Segundos de espera por intento. Explícito a propósito: los SDK traen 600 s y
#: hasta tres reintentos silenciosos, lo que en la práctica supone un cuarto de
#: hora sin señal antes de un error. Un análisis normal tarda entre 1 y 4
#: minutos, así que 180 s deja margen suficiente y falla mientras aún es útil
#: cambiar de proveedor.
DEFAULT_TIMEOUT = 180.0

#: Un solo reintento. Reintentar en bucle contra un servicio ya degradado añade
#: carga y multiplica el coste por token sin que nadie lo pida.
DEFAULT_MAX_RETRIES = 1


class ProviderError(RuntimeError):
    """Fallo del proveedor, ya traducido a algo accionable para el usuario."""


class RefusalError(ProviderError):
    """El proveedor declinó la petición por política de contenido."""


class Provider(Protocol):
    """Lo que el agente necesita de un proveedor. Nada más."""

    name: str
    model: str

    def analyze(self, description: str) -> tuple[ThreatModel, dict[str, Any]]:
        """Devuelve el modelo de amenazas validado y metadatos de la llamada."""
        ...


def _to_strict_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Adapta el JSON Schema de Pydantic al modo estricto de OpenAI.

    El modo estricto exige `additionalProperties: false` en cada objeto y que
    todas las propiedades estén en `required`. Pydantic no lo emite así. Sin
    esta conversión el proveedor rechaza el esquema, o —peor— lo acepta sin
    imponerlo y la garantía del mínimo de 5 amenazas deja de existir.
    """
    if not isinstance(schema, dict):
        return schema
    out = {k: _to_strict_schema(v) if isinstance(v, dict) else v for k, v in schema.items()}
    for key in ("properties", "$defs"):
        if key in out:
            out[key] = {k: _to_strict_schema(v) for k, v in out[key].items()}
    if "items" in out:
        out["items"] = _to_strict_schema(out["items"])
    if out.get("type") == "object":
        out["additionalProperties"] = False
        if "properties" in out:
            out["required"] = list(out["properties"])
    return out


class AnthropicProvider:
    """API de Anthropic y Amazon Bedrock.

    Usa `messages.parse`, que valida la respuesta contra el esquema Pydantic en
    el propio SDK, y el razonamiento adaptativo del modelo.
    """

    def __init__(
        self,
        *,
        model: str,
        effort: str = "high",
        max_tokens: int = 16000,
        bedrock_region: str | None = None,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self.name = "bedrock" if bedrock_region else "anthropic"
        self.model = model
        self._effort = effort
        self._max_tokens = max_tokens
        self._bedrock_region = bedrock_region
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries

    def _client(self):  # noqa: ANN202 - el tipo depende del backend elegido
        try:
            import anthropic
        except ModuleNotFoundError as exc:  # pragma: no cover - depende del entorno
            raise ProviderError("Falta el paquete `anthropic`. Instálalo con `uv sync`.") from exc

        opciones = {"timeout": self._timeout, "max_retries": self._max_retries}
        if self._bedrock_region:
            # Bedrock autentica con credenciales de AWS: no hay clave de Anthropic.
            return anthropic.AnthropicBedrockMantle(aws_region=self._bedrock_region, **opciones)
        if self._api_key:
            return anthropic.Anthropic(api_key=self._api_key, **opciones)
        return anthropic.Anthropic(**opciones)

    def analyze(self, description: str) -> tuple[ThreatModel, dict[str, Any]]:
        import anthropic

        client = self._client()
        try:
            response = client.messages.parse(
                model=self.model,
                max_tokens=self._max_tokens,
                system=SYSTEM_PROMPT,
                thinking={"type": "adaptive"},
                output_config={"effort": self._effort},
                messages=[{"role": "user", "content": build_user_message(description)}],
                output_format=ThreatModel,
            )
        except anthropic.AuthenticationError as exc:
            raise ProviderError(
                "Credenciales no válidas para el proveedor "
                f"'{self.name}'. Revisa tu fichero .env."
            ) from exc
        except anthropic.RateLimitError as exc:
            retry = exc.response.headers.get("retry-after", "60")
            raise ProviderError(f"Límite de peticiones alcanzado. Reintenta en {retry}s.") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Error de la API ({exc.status_code}): {exc.message}") from exc
        except anthropic.APITimeoutError as exc:
            raise ProviderError(
                f"El proveedor '{self.name}' no respondió en {self._timeout:.0f}s. "
                "Prueba con otro modelo o proveedor (--provider, --model), o enseña "
                "una salida guardada con `threat-agent show`."
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("No se pudo contactar con la API. Revisa la conexión.") from exc

        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None)
            raise RefusalError(
                "El modelo declinó la petición"
                + (f" (categoría: {category})" if category else "")
                + ". Revisa la descripción de entrada."
            )
        if response.stop_reason == "max_tokens":
            raise ProviderError(
                f"Respuesta truncada al alcanzar max_tokens ({self._max_tokens}). "
                "Reintenta con un valor mayor."
            )

        return response.parsed_output, {
            "model": response.model,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "request_id": response._request_id,
        }


class OpenAICompatibleProvider:
    """Cualquier endpoint que hable el protocolo de OpenAI.

    Cubre OpenAI, OpenRouter y Gemini (que expone una capa compatible), además
    de servidores locales tipo vLLM o Ollama. Lo único que cambia entre ellos es
    `base_url`, el modelo y la clave.

    Se usa `response_format` con JSON Schema estricto en lugar del helper
    `.parse()` del SDK de OpenAI: el helper es específico de OpenAI, mientras que
    el esquema en crudo es lo que entienden todas las pasarelas compatibles.
    """

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str | None = None,
        name: str = "openai-compatible",
        max_tokens: int = 16000,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self.name = name
        self.model = model
        self._api_key = api_key
        self._base_url = base_url
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._max_retries = max_retries

    def analyze(self, description: str) -> tuple[ThreatModel, dict[str, Any]]:
        try:
            import openai
        except ModuleNotFoundError as exc:
            raise ProviderError(
                "Falta el paquete `openai`, necesario para este proveedor. "
                "Instálalo con `uv sync --extra openai`."
            ) from exc

        client = openai.OpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=self._timeout,
            max_retries=self._max_retries,
        )
        schema = _to_strict_schema(ThreatModel.model_json_schema())

        try:
            response = client.chat.completions.create(
                model=self.model,
                max_completion_tokens=self._max_tokens,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_message(description)},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {"name": "threat_model", "strict": True, "schema": schema},
                },
            )
        except openai.AuthenticationError as exc:
            raise ProviderError(
                f"Credenciales no válidas para el proveedor '{self.name}'. Revisa tu .env."
            ) from exc
        except openai.RateLimitError as exc:
            raise ProviderError("Límite de peticiones alcanzado. Reintenta más tarde.") from exc
        except openai.APIStatusError as exc:
            raise ProviderError(f"Error de la API ({exc.status_code}): {exc.message}") from exc
        except openai.APITimeoutError as exc:
            raise ProviderError(
                f"El proveedor '{self.name}' no respondió en {self._timeout:.0f}s. "
                "Prueba con otro modelo o proveedor (--provider, --model), o enseña "
                "una salida guardada con `threat-agent show`."
            ) from exc
        except openai.APIConnectionError as exc:
            raise ProviderError("No se pudo contactar con la API. Revisa la conexión.") from exc

        choice = response.choices[0]
        if choice.finish_reason == "content_filter":
            raise RefusalError("El proveedor declinó la petición por filtro de contenido.")
        if choice.finish_reason == "length":
            raise ProviderError(
                f"Respuesta truncada al alcanzar el límite de tokens ({self._max_tokens})."
            )

        content = choice.message.content
        if not content:
            raise ProviderError("El proveedor devolvió una respuesta vacía.")

        # La validación de Pydantic es la red: si la pasarela no impuso el
        # esquema de verdad, el fallo aparece aquí y no aguas abajo.
        try:
            threat_model = ThreatModel.model_validate_json(content)
        except ValueError as exc:
            raise ProviderError(
                f"La respuesta de '{self.name}' no cumple el esquema. "
                "Puede que el modelo elegido no soporte JSON Schema estricto.\n"
                f"Detalle: {exc}"
            ) from exc

        usage = response.usage
        return threat_model, {
            "model": response.model,
            "input_tokens": getattr(usage, "prompt_tokens", 0) if usage else 0,
            "output_tokens": getattr(usage, "completion_tokens", 0) if usage else 0,
            "request_id": response.id,
        }
