# Prueba técnica — Cloud & Application Security

Dos retos independientes: una revisión de seguridad sobre una arquitectura AWS, y un agente de IA que asiste al equipo de Ciberseguridad durante el Secure SDLC.

Ambos comparten el mismo caso: la carga de documentos desde una aplicación móvil, su procesamiento con Amazon Bedrock y el almacenamiento de los resultados. Eso permite algo que ninguno de los dos consigue por separado: **contrastar el modelo de amenazas que escribe una persona con el que genera el agente sobre el mismo sistema.** Coinciden en la amenaza principal y en la *prompt injection* a través del documento; el [contraste completo, con sus limitaciones](./challenge-2-ai-security-agent/README.md#contraste-con-el-threat-model-manual), está en el Reto 2.

Todo está en español. Los documentos se leen sin ejecutar nada: los diagramas y los resultados del agente están versionados.

## Reto 1 — Arquitectura Cloud

Revisión de seguridad de una funcionalidad de carga y procesamiento de documentos con IA en AWS, realizada **antes de que comience el desarrollo**.

| Entregable | Documento |
| --- | --- |
| Diagrama de arquitectura con controles | [`challenge-1-cloud-architecture/README.md`](./challenge-1-cloud-architecture/README.md) |
| Threat model (STRIDE, priorizado por riesgo) | [`challenge-1-cloud-architecture/threat-model.md`](./challenge-1-cloud-architecture/threat-model.md) |
| Riesgos de seguridad asociados a IA | [`challenge-1-cloud-architecture/ai-security-risks.md`](./challenge-1-cloud-architecture/ai-security-risks.md) |

La tabla STRIDE prioriza **11 amenazas por riesgo**, no por categoría. La probabilidad se puntúa sobre la arquitectura original del enunciado, no sobre la reforzada: si se puntuara sobre la reforzada, cada control rebajaría el riesgo de su propia amenaza y la tabla no justificaría nada. El riesgo residual va en una sección aparte.

Los diagramas son [código ejecutable](./challenge-1-cloud-architecture/diagrams/architecture.py) con iconos oficiales de AWS.

## Reto 2 — Agente de seguridad con IA

*Threat Modeling Agent* (Opción 1 del enunciado): recibe la descripción en texto de una funcionalidad nueva y devuelve un modelo de amenazas STRIDE priorizado por riesgo, con la justificación de cada puntuación y su control.

| Entregable | Documento |
| --- | --- |
| Agente | [`challenge-2-ai-security-agent/src/threat_agent/`](./challenge-2-ai-security-agent/src/threat_agent/) |
| Arquitectura del agente (Parte B) | [`challenge-2-ai-security-agent/README.md`](./challenge-2-ai-security-agent/README.md) |

**La priorización no la hace el modelo.** El LLM puntúa impacto y probabilidad por separado, cada uno con su justificación; el código calcula `riesgo = impacto × probabilidad` y ordena. La aritmética es reproducible y auditable; el modelo solo aporta el juicio sobre cada eje.

```bash
cd challenge-2-ai-security-agent
uv sync
uv run threat-agent analyze-feature examples/upload-pdf-feature.txt
```

Ese comando **necesita una clave de API** del proveedor que se configure —Anthropic por defecto, o cualquiera de los otros cinco—. Para revisar el resultado sin clave y sin red, hay dos análisis reales versionados:

```bash
uv run threat-agent show examples/upload-pdf-feature.kimi-k3.json
```

Verificado contra dos proveedores de LLM de fabricantes distintos, que **convergen en la misma amenaza principal**. Ambas salidas están versionadas en [`challenge-2-ai-security-agent/examples/`](./challenge-2-ai-security-agent/examples/) para poder compararlas.

> Ninguno de los dos retos sustituye la decisión del especialista de seguridad. El agente produce un borrador revisable: declara siempre lo que ha asumido y lo que no puede evaluar.
