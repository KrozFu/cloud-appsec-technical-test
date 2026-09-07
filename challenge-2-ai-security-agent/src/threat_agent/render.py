"""Presentación del modelo de amenazas: tabla para la terminal y Markdown."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Severity, ThreatModel

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
}


def render_console(tm: ThreatModel, console: Console) -> None:
    console.print(Panel(tm.system_summary, title="Sistema analizado", border_style="cyan"))

    if tm.trust_boundaries:
        console.print("\n[bold]Fronteras de confianza[/bold]")
        for boundary in tm.trust_boundaries:
            console.print(f"  • {boundary}")

    if tm.assets:
        console.print("\n[bold]Activos a proteger[/bold]")
        for asset in tm.assets:
            console.print(f"  • {asset}")

    table = Table(
        title=f"\nAmenazas priorizadas por riesgo ({len(tm.threats)})",
        show_lines=True,
        title_justify="left",
    )
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Componente", max_width=20)
    table.add_column("Amenaza", max_width=48)
    table.add_column("Cat.", justify="center", no_wrap=True)
    table.add_column("Imp", justify="center", no_wrap=True)
    table.add_column("Prob", justify="center", no_wrap=True)
    table.add_column("Riesgo", justify="center", no_wrap=True)
    table.add_column("Control", max_width=42)

    for i, t in enumerate(tm.ranked_threats(), start=1):
        style = _SEVERITY_STYLE[t.severity]
        table.add_row(
            str(i),
            t.component,
            t.threat,
            t.stride.value,
            str(t.impact),
            str(t.likelihood),
            f"[{style}]{t.risk} {t.severity.value}[/{style}]",
            t.control,
        )
    console.print(table)

    console.print("\n[bold]Justificación de las 3 de mayor riesgo[/bold]")
    for t in tm.top_risks():
        console.print(f"\n  [bold]{t.component}[/bold] — {t.stride.label} (riesgo {t.risk})")
        console.print(f"    Impacto {t.impact}: {t.impact_rationale}")
        console.print(f"    Probabilidad {t.likelihood}: {t.likelihood_rationale}")
        console.print(f"    Riesgo residual: {t.residual_risk_note}")

    if tm.assumptions:
        console.print("\n[bold yellow]Asunciones a validar con Producto[/bold yellow]")
        for a in tm.assumptions:
            console.print(f"  • {a}")

    if tm.out_of_scope:
        console.print("\n[bold yellow]Fuera de alcance / requiere revisión humana[/bold yellow]")
        for o in tm.out_of_scope:
            console.print(f"  • {o}")

    console.print(
        "\n[dim]Borrador generado por IA. Requiere revisión y aprobación de un "
        "especialista de seguridad antes de usarse como decisión.[/dim]"
    )


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(tm: ThreatModel) -> str:
    """Markdown listo para pegar en la documentación del Secure SDLC."""
    lines: list[str] = [
        "# Modelo de amenazas",
        "",
        "> Borrador generado por el Threat Modeling Agent. Requiere revisión y",
        "> aprobación de un especialista de seguridad.",
        "",
        "## Sistema analizado",
        "",
        tm.system_summary,
        "",
    ]

    if tm.assets:
        lines += ["## Activos", ""] + [f"- {a}" for a in tm.assets] + [""]
    if tm.trust_boundaries:
        lines += ["## Fronteras de confianza", ""] + [f"- {b}" for b in tm.trust_boundaries] + [""]

    lines += [
        "## Amenazas priorizadas",
        "",
        "| # | Componente | Amenaza | Categoría | Impacto | Probabilidad | Riesgo | Control |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, t in enumerate(tm.ranked_threats(), start=1):
        lines.append(
            f"| {i} | {_escape_cell(t.component)} | {_escape_cell(t.threat)} "
            f"| {t.stride.value} — {t.stride.label} | {t.impact} | {t.likelihood} "
            f"| **{t.risk}** ({t.severity.value}) | {_escape_cell(t.control)} |"
        )

    lines += ["", "## Justificación de la priorización", ""]
    for i, t in enumerate(tm.ranked_threats(), start=1):
        lines += [
            f"### {i}. {t.component} — riesgo {t.risk} ({t.severity.value})",
            "",
            f"- **Amenaza:** {t.threat}",
            f"- **Impacto {t.impact}:** {t.impact_rationale}",
            f"- **Probabilidad {t.likelihood}:** {t.likelihood_rationale}",
            f"- **Control:** {t.control}",
            f"- **Riesgo residual:** {t.residual_risk_note}",
            "",
        ]

    if tm.assumptions:
        lines += ["## Asunciones a validar", ""] + [f"- {a}" for a in tm.assumptions] + [""]
    if tm.out_of_scope:
        lines += ["## Fuera de alcance", ""] + [f"- {o}" for o in tm.out_of_scope] + [""]

    return "\n".join(lines)
