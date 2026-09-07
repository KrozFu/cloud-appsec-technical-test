"""Esquema de salida del agente.

Decisión de diseño: el modelo emite únicamente los juicios que requieren
criterio experto (componente, amenaza, categoría STRIDE, impacto, probabilidad,
control, justificación). El *riesgo* y el orden de prioridad NO los produce el
modelo: los calcula este módulo a partir de impacto x probabilidad. Así la
priorización es aritmética reproducible y auditable, no una opinión del LLM.
"""

from enum import StrEnum

from pydantic import BaseModel, Field


class Stride(StrEnum):
    """Categorías STRIDE. El valor es el código de una letra usado en la tabla."""

    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"

    @property
    def label(self) -> str:
        return _STRIDE_LABELS[self]


_STRIDE_LABELS: dict[Stride, str] = {
    Stride.SPOOFING: "Spoofing (suplantación)",
    Stride.TAMPERING: "Tampering (manipulación)",
    Stride.REPUDIATION: "Repudiation (repudio)",
    Stride.INFORMATION_DISCLOSURE: "Information Disclosure (fuga de información)",
    Stride.DENIAL_OF_SERVICE: "Denial of Service (denegación de servicio)",
    Stride.ELEVATION_OF_PRIVILEGE: "Elevation of Privilege (elevación de privilegios)",
}


class Severity(StrEnum):
    """Banda de severidad derivada del riesgo (1-25)."""

    CRITICAL = "Crítico"
    HIGH = "Alto"
    MEDIUM = "Medio"
    LOW = "Bajo"

    @classmethod
    def from_risk(cls, risk: int) -> "Severity":
        if risk >= 20:
            return cls.CRITICAL
        if risk >= 12:
            return cls.HIGH
        if risk >= 6:
            return cls.MEDIUM
        return cls.LOW


class Threat(BaseModel):
    """Una amenaza concreta sobre un componente concreto."""

    component: str = Field(
        description="Componente o flujo afectado, tal y como aparece en la descripción "
        "(p. ej. 'API Gateway', 'S3 bucket de documentos', 'Lambda -> Bedrock')."
    )
    threat: str = Field(
        description="Escenario de ataque concreto y accionable: quién hace qué, sobre qué "
        "componente y con qué resultado. No una buena práctica genérica."
    )
    stride: Stride = Field(description="Categoría STRIDE que mejor describe la amenaza.")
    impact: int = Field(
        ge=1,
        le=5,
        description="Impacto si la amenaza se materializa. 1=insignificante, "
        "3=degradación seria o fuga limitada, 5=fuga masiva de PII, pérdida de "
        "integridad de datos o caída total del servicio.",
    )
    likelihood: int = Field(
        ge=1,
        le=5,
        description="Probabilidad de explotación dada la arquitectura descrita. "
        "1=requiere un atacante con acceso interno privilegiado, 3=atacante "
        "autenticado con esfuerzo moderado, 5=explotable desde Internet sin "
        "autenticación o por error de configuración habitual.",
    )
    impact_rationale: str = Field(
        description="Por qué ese impacto: qué activo se pierde y con qué alcance. "
        "Debe referirse a los datos y componentes de esta funcionalidad."
    )
    likelihood_rationale: str = Field(
        description="Por qué esa probabilidad: qué tendría que conseguir el atacante y "
        "qué se lo pone fácil o difícil en la arquitectura descrita."
    )
    control: str = Field(
        description="Control concreto y verificable que reduce el riesgo, nombrando el "
        "servicio o mecanismo (p. ej. 'Bucket policy con aws:SecureTransport y Block "
        "Public Access'). No 'aplicar el principio de mínimo privilegio' a secas."
    )
    residual_risk_note: str = Field(
        description="Qué queda sin cubrir después de aplicar el control, o qué asunción "
        "hay que validar con el equipo. Una frase."
    )

    @property
    def risk(self) -> int:
        """Riesgo = impacto x probabilidad (1-25). Calculado, no generado por el modelo."""
        return self.impact * self.likelihood

    @property
    def severity(self) -> Severity:
        return Severity.from_risk(self.risk)


class ThreatModel(BaseModel):
    """Resultado completo del análisis de una funcionalidad."""

    system_summary: str = Field(
        description="Resumen en 2-3 frases de lo que hace el sistema, tal y como se ha "
        "entendido de la descripción. Sirve para que el analista detecte malentendidos."
    )
    assets: list[str] = Field(
        description="Activos que hay que proteger (datos, credenciales, disponibilidad), "
        "derivados de la descripción."
    )
    trust_boundaries: list[str] = Field(
        description="Fronteras de confianza cruzadas por los flujos de datos "
        "(p. ej. 'Internet -> API Gateway', 'Lambda -> Bedrock')."
    )
    threats: list[Threat] = Field(
        min_length=5,
        description="Al menos 5 amenazas relevantes. Prioriza escenarios específicos de "
        "esta arquitectura frente a amenazas genéricas.",
    )
    assumptions: list[str] = Field(
        description="Lo que no estaba en la descripción y se ha tenido que asumir. "
        "Cada asunción es una pregunta pendiente para el equipo de Producto."
    )
    out_of_scope: list[str] = Field(
        description="Aspectos relevantes que la descripción no permite evaluar y que "
        "requieren revisión humana o más información."
    )

    def ranked_threats(self) -> list[Threat]:
        """Amenazas ordenadas por riesgo descendente.

        El desempate por impacto es deliberado: ante el mismo riesgo se atiende
        antes lo que más daño hace. El orden lo fija el código, no el modelo.
        """
        return sorted(self.threats, key=lambda t: (t.risk, t.impact), reverse=True)

    def top_risks(self, n: int = 3) -> list[Threat]:
        return self.ranked_threats()[:n]
