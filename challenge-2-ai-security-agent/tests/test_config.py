"""Cambiar de proveedor es editar el .env, no tocar código."""

import pytest

from threat_agent.config import PRESETS, build_provider, load_dotenv
from threat_agent.providers import AnthropicProvider, OpenAICompatibleProvider, ProviderError

PROVIDER_VARS = [
    "THREAT_AGENT_PROVIDER", "THREAT_AGENT_MODEL", "THREAT_AGENT_BASE_URL",
    "THREAT_AGENT_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "OPENROUTER_API_KEY", "GEMINI_API_KEY", "AWS_REGION", "AWS_DEFAULT_REGION",
]


@pytest.fixture(autouse=True)
def _entorno_limpio(monkeypatch):
    """Sin esto, la clave real del desarrollador contaminaría los tests."""
    for var in PROVIDER_VARS:
        monkeypatch.delenv(var, raising=False)


def test_sin_configuracion_el_proveedor_por_defecto_es_anthropic():
    provider = build_provider()
    assert isinstance(provider, AnthropicProvider)
    assert provider.name == "anthropic"


def test_la_variable_de_entorno_elige_el_proveedor(monkeypatch):
    monkeypatch.setenv("THREAT_AGENT_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    provider = build_provider()
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name == "openrouter"


def test_cada_proveedor_trae_su_base_url_ya_puesta(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    provider = build_provider(provider="openrouter")
    assert provider._base_url == "https://openrouter.ai/api/v1"


def test_la_bandera_del_cli_gana_a_la_variable_de_entorno(monkeypatch):
    """Para poder comparar proveedores sin editar el .env cada vez."""
    monkeypatch.setenv("THREAT_AGENT_PROVIDER", "anthropic")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert build_provider(provider="openai").name == "openai"


def test_el_modelo_explicito_gana_al_del_preset(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert build_provider(provider="openai", model="gpt-5-mini").model == "gpt-5-mini"


def test_un_proveedor_desconocido_falla_listando_las_opciones():
    with pytest.raises(ProviderError, match="openrouter"):
        build_provider(provider="inventado")


def test_falta_de_clave_da_un_error_accionable(monkeypatch):
    """Debe decir QUÉ variable falta, no 'authentication error' 30 segundos después."""
    with pytest.raises(ProviderError, match="OPENAI_API_KEY"):
        build_provider(provider="openai")


def test_bedrock_no_pide_clave_de_anthropic_sino_region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    provider = build_provider(provider="bedrock")
    assert isinstance(provider, AnthropicProvider)
    assert provider.name == "bedrock"


def test_bedrock_sin_region_falla_explicandolo():
    with pytest.raises(ProviderError, match="AWS_REGION"):
        build_provider(provider="bedrock")


def test_un_endpoint_compatible_sin_modelo_falla_por_el_modelo(monkeypatch):
    """No tiene preset de modelo: hay que decir cuál se usa."""
    monkeypatch.setenv("THREAT_AGENT_API_KEY", "sk-test")
    with pytest.raises(ProviderError, match="THREAT_AGENT_MODEL"):
        build_provider(provider="openai-compatible")


def test_un_endpoint_compatible_necesita_su_base_url(monkeypatch):
    monkeypatch.setenv("THREAT_AGENT_API_KEY", "sk-test")
    monkeypatch.setenv("THREAT_AGENT_MODEL", "llama3")
    with pytest.raises(ProviderError, match="THREAT_AGENT_BASE_URL"):
        build_provider(provider="openai-compatible")


def test_un_endpoint_compatible_completo_se_construye(monkeypatch):
    monkeypatch.setenv("THREAT_AGENT_API_KEY", "sk-test")
    monkeypatch.setenv("THREAT_AGENT_MODEL", "llama3")
    monkeypatch.setenv("THREAT_AGENT_BASE_URL", "http://localhost:11434/v1")
    provider = build_provider(provider="openai-compatible")
    assert provider.model == "llama3"
    assert provider._base_url == "http://localhost:11434/v1"


def test_el_dotenv_no_pisa_lo_que_ya_esta_en_el_entorno(tmp_path, monkeypatch):
    """Así se puede sobrescribir en CI sin editar el fichero."""
    monkeypatch.setenv("OPENAI_API_KEY", "del-entorno")
    env = tmp_path / ".env"
    env.write_text('OPENAI_API_KEY="del-fichero"\nGEMINI_API_KEY=nueva\n')
    load_dotenv(str(env))
    import os
    assert os.environ["OPENAI_API_KEY"] == "del-entorno"
    assert os.environ["GEMINI_API_KEY"] == "nueva"


def test_el_dotenv_ignora_comentarios_y_lineas_vacias(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# comentario\n\nGEMINI_API_KEY = con-espacios \nbasura sin igual\n")
    load_dotenv(str(env))
    import os
    assert os.environ["GEMINI_API_KEY"] == "con-espacios"


def test_un_dotenv_inexistente_no_revienta():
    load_dotenv("/no/existe/.env")


def test_todos_los_presets_declaran_modelo_o_exigen_configurarlo():
    for name, preset in PRESETS.items():
        assert preset.default_model or name == "openai-compatible"


def test_cambiar_de_proveedor_no_hereda_la_base_url_del_env(monkeypatch):
    """Regresión: un .env apuntando a NVIDIA mandaba la clave de Gemini allí.

    El síntoma era un 401 traducido a "credenciales no válidas", con la clave de
    Gemini perfectamente válida. Tener un proveedor de respaldo exige que
    --provider no arrastre la URL del proveedor activo.
    """
    monkeypatch.setenv("THREAT_AGENT_PROVIDER", "openai-compatible")
    monkeypatch.setenv("THREAT_AGENT_BASE_URL", "https://integrate.api.nvidia.com/v1")
    monkeypatch.setenv("GEMINI_API_KEY", "gk-test")
    provider = build_provider(provider="gemini")
    assert provider._base_url == PRESETS["gemini"].base_url
    assert "nvidia" not in (provider._base_url or "")


def test_cambiar_de_proveedor_no_hereda_el_modelo_del_env(monkeypatch):
    """Regresión: el modelo del proveedor activo viajaba al de respaldo."""
    monkeypatch.setenv("THREAT_AGENT_PROVIDER", "openai-compatible")
    monkeypatch.setenv("THREAT_AGENT_BASE_URL", "https://integrate.api.nvidia.com/v1")
    monkeypatch.setenv("THREAT_AGENT_MODEL", "moonshotai/kimi-k3")
    monkeypatch.setenv("GEMINI_API_KEY", "gk-test")
    provider = build_provider(provider="gemini")
    assert provider.model == PRESETS["gemini"].default_model


def test_el_modelo_del_env_sigue_valiendo_para_su_propio_proveedor(monkeypatch):
    """La corrección no debe romper el caso normal: mismo proveedor, sí hereda."""
    monkeypatch.setenv("THREAT_AGENT_PROVIDER", "openai-compatible")
    monkeypatch.setenv("THREAT_AGENT_BASE_URL", "https://integrate.api.nvidia.com/v1")
    monkeypatch.setenv("THREAT_AGENT_MODEL", "moonshotai/kimi-k3")
    monkeypatch.setenv("THREAT_AGENT_API_KEY", "nv-test")
    provider = build_provider()
    assert provider.model == "moonshotai/kimi-k3"
    assert provider._base_url == "https://integrate.api.nvidia.com/v1"


def test_una_base_url_explicita_sigue_valiendo_para_un_preset_sin_url(monkeypatch):
    """Un proxy delante de OpenAI: el preset no trae URL, la variable rellena."""
    monkeypatch.setenv("THREAT_AGENT_BASE_URL", "https://proxy.interno/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider = build_provider(provider="openai")
    assert provider._base_url == "https://proxy.interno/v1"
