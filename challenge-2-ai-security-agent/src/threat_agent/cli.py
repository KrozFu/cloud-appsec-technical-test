"""Interfaz de línea de comandos del Threat Modeling Agent."""

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from .agent import DEFAULT_EFFORT, AgentError, analyze
from .models import ThreatModel
from .prompts import EmptyDescriptionError
from .render import render_console, render_markdown

app = typer.Typer(
    help="Asistente de threat modeling para el Secure SDLC.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _read_description(source: str) -> str:
    """Lee la descripción de un fichero, o de stdin si `source` es '-'."""
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.is_file():
        raise typer.BadParameter(f"No existe el fichero: {source}")
    return path.read_text(encoding="utf-8")


def _emit(tm: ThreatModel, json_out: Path | None, md_out: Path | None) -> None:
    if json_out:
        payload = tm.model_dump(mode="json")
        # El riesgo es derivado; se materializa en el JSON para que sea consumible
        # por otras herramientas sin reimplementar el cálculo.
        payload["threats"] = [
            {**t.model_dump(mode="json"), "risk": t.risk, "severity": t.severity.value}
            for t in tm.ranked_threats()
        ]
        json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[dim]JSON escrito en {json_out}[/dim]")
    if md_out:
        md_out.write_text(render_markdown(tm), encoding="utf-8")
        console.print(f"[dim]Markdown escrito en {md_out}[/dim]")


@app.command()
def analyze_feature(
    source: Annotated[
        str,
        typer.Argument(help="Fichero con la descripción de la funcionalidad, o '-' para stdin."),
    ],
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Guarda el resultado como JSON.")
    ] = None,
    md_out: Annotated[
        Path | None, typer.Option("--md", help="Guarda el resultado como Markdown.")
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option(help="Proveedor: anthropic, bedrock, openai, openrouter, gemini... "
                          "Por defecto, THREAT_AGENT_PROVIDER del .env."),
    ] = None,
    model: Annotated[
        str | None, typer.Option(help="Modelo. Por defecto, el del proveedor elegido.")
    ] = None,
    effort: Annotated[
        str, typer.Option(help="Profundidad de razonamiento: low|medium|high|xhigh|max.")
    ] = DEFAULT_EFFORT,
) -> None:
    """Analiza una funcionalidad y genera un modelo de amenazas STRIDE priorizado."""
    try:
        description = _read_description(source)
    except OSError as exc:
        err_console.print(f"[red]No se pudo leer la entrada: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    try:
        with console.status("Analizando la funcionalidad..."):
            result = analyze(
                description, provider_name=provider, model=model, effort=effort
            )
    except EmptyDescriptionError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    except AgentError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    render_console(result.threat_model, console)
    console.print(
        f"\n[dim]{result.provider} · {result.model} · {result.input_tokens} tokens de entrada, "
        f"{result.output_tokens} de salida · request {result.request_id}[/dim]"
    )
    _emit(result.threat_model, json_out, md_out)


@app.command()
def show(
    path: Annotated[Path, typer.Argument(help="JSON generado previamente por `analyze`.")],
    md_out: Annotated[
        Path | None, typer.Option("--md", help="Guarda el resultado como Markdown.")
    ] = None,
) -> None:
    """Muestra un análisis guardado, sin llamar a la API.

    Pensado para la demo en vivo: si el proveedor falla, las salidas de respaldo
    de `examples/` se enseñan igual. Hay una por proveedor verificado, en vez de
    un único fichero canónico, para no reatar el proyecto a un solo fabricante.
    """
    try:
        tm = ThreatModel.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as exc:
        err_console.print(f"[red]No se pudo leer {path}: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    render_console(tm, console)
    _emit(tm, None, md_out)


if __name__ == "__main__":
    app()
