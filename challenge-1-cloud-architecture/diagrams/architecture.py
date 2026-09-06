# /// script
# requires-python = ">=3.12"
# dependencies = ["diagrams>=0.25.1"]
# ///
"""Genera los diagramas de arquitectura del Reto 1 con los iconos oficiales de AWS.

Uso:  uv run architecture.py
Requiere el binario de Graphviz en el PATH (ver README.md de este directorio).

Las etiquetas numeradas ①-⑥ de las aristas se corresponden una a una con los
límites de confianza del DFD de ../threat-model.md, para que ambos documentos se
puedan leer cruzados.
"""

from pathlib import Path

from diagrams.aws.compute import Lambda
from diagrams.aws.database import Dynamodb
from diagrams.aws.integration import SQS
from diagrams.aws.management import Cloudtrail, Cloudwatch, Config
from diagrams.aws.ml import Bedrock
from diagrams.aws.network import APIGateway, CloudFront
from diagrams.aws.security import (
    KMS,
    WAF,
    Guardduty,
    Macie,
    SecretsManager,
    SecurityHub,
)
from diagrams.aws.storage import S3
from diagrams.generic.blank import Blank
from diagrams.onprem.auth import Oauth2Proxy
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.client import Client, Users

from diagrams import Cluster, Diagram, Edge

OUT = Path(__file__).parent / "out"
OUT.mkdir(exist_ok=True)

# Un límite de confianza se dibuja como borde discontinuo rojo: si no se ve, no
# está comunicando nada. El resto de agrupaciones usan borde sólido y neutro.
BOUNDARY = {
    "style": "dashed",
    "color": "#c0392b",
    "penwidth": "2.0",
    "bgcolor": "#fdf6f5",
    "fontcolor": "#c0392b",
    "fontsize": "15",
    "margin": "18",
}
ZONE = {
    "style": "rounded",
    "color": "#5a6f8a",
    "penwidth": "1.6",
    "bgcolor": "#f5f8fc",
    "fontcolor": "#3d5470",
    "fontsize": "15",
    "margin": "18",
}

GRAPH = {
    "fontsize": "20",
    "fontcolor": "#2c3e50",
    "labelloc": "t",
    "pad": "0.6",
    "nodesep": "0.6",
    "ranksep": "1.1",
    "splines": "spline",
}
NODE = {"fontsize": "12", "fontcolor": "#2c3e50"}
EDGE = {"fontsize": "11", "fontcolor": "#40566f"}


# Aristas con significado propio: el flujo del binario no confiable y el aviso
# de que el atacante entra por el mismo canal que el cliente legítimo. `Edge` no
# es reutilizable entre conexiones, así que cada una se construye al vuelo.
def untrusted_blob(label: str) -> Edge:
    return Edge(label=label, color="#c0392b", penwidth="3.0", fontcolor="#c0392b")


def attacker_edge(label: str) -> Edge:
    return Edge(label=label, color="#c0392b", style="dashed", fontcolor="#c0392b")


def ret(label: str) -> Edge:
    """Arista de retorno: se dibuja pero no restringe el cálculo de rangos."""
    return Edge(label=label, constraint="false")


def architecture() -> None:
    """Diagrama principal: flujo de datos y zonas de confianza."""
    with Diagram(
        "Reto 1 — Arquitectura segura de carga y procesamiento de documentos",
        filename=str(OUT / "architecture"),
        outformat=["png", "svg"],
        show=False,
        direction="LR",
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    ):
        with Cluster("INTERNET — zona no confiable", graph_attr=BOUNDARY):
            cliente = Users("Cliente\nweb / móvil")
            atacante = Client("Atacante")

        with Cluster("EDGE — primer filtro", graph_attr=ZONE):
            cf = CloudFront("CloudFront + Shield\nTLS 1.2+")
            waf = WAF("WAF\nrate limiting")
            apigw = APIGateway("API Gateway\nesquema · throttling")
            authz = Lambda("Authorizer\nverifica JWT")
            idp = Oauth2Proxy("Emisor de identidad\nOIDC · JWKS")

        with Cluster("APLICACIÓN — VPC privada", graph_attr=ZONE):
            lambda_api = Lambda("API\npresigned URL")
            cola = SQS("SQS + DLQ")
            lambda_proc = Lambda("Procesado")
            lambda_read = Lambda("Consulta\nsolo lectura")

        with Cluster("IA — límite de confianza propio", graph_attr=BOUNDARY):
            bedrock = Bedrock("Bedrock\n+ Guardrails")

        with Cluster("DATOS — cifrado con CMK", graph_attr=ZONE):
            s3 = S3("S3 documentos\nlifecycle: expiración")
            ddb = Dynamodb("DynamoDB\nresultados")
            secrets = SecretsManager("Secrets Manager")

        with Cluster("RED INTERNA — requisito 5", graph_attr=BOUNDARY):
            privapi = APIGateway("API privada\nautorización IAM")
            interno = Client("Servicio interno")

        # ① Internet -> Edge: el token llega como dato no confiable.
        cliente >> Edge(label="① HTTPS") >> cf
        atacante >> attacker_edge("mismo canal") >> cf
        cf >> waf >> apigw >> authz
        # El emisor es quien firma; el authorizer solo verifica contra su JWKS. Se
        # dibuja sin logo a propósito: el enunciado no dice quién emite el token y
        # el diseño solo exige que publique JWKS. Ver §5.
        # constraint=false: sin esto Graphviz mete al emisor en la cadena del edge
        # y parte CloudFront -> WAF -> API Gateway -> Authorizer en dos filas.
        idp >> Edge(label="JWKS", style="dashed", constraint="false") >> authz

        # ③ Edge -> Aplicación, solo con token verificado.
        authz >> Edge(label="③ token verificado") >> lambda_api

        # Las aristas de retorno llevan constraint=false: se dibujan, pero no
        # participan en el cálculo de rangos. Sin esto forman ciclos y Graphviz
        # invierte el orden de las zonas, dejando el Edge después de la Aplicación.
        lambda_api >> ret("presigned URL\nvida corta · tipo\ny tamaño") >> cliente

        # ② El binario no confiable va directo a S3: no pasa por el backend.
        cliente >> untrusted_blob("② PUT directo\nno pasa por el backend") >> s3

        s3 >> Edge(label="evento") >> cola >> lambda_proc

        # ④/⑤ El modelo es una frontera: entra dato no confiable y sale dato no confiable.
        lambda_proc >> Edge(label="④ doc. no confiable\nvía VPC endpoint") >> bedrock
        bedrock >> ret("⑤ salida NO confiable:\nvalidar esquema") >> lambda_proc
        # Sin etiqueta: se solapaba con el título del cluster, y que todo el
        # tráfico a servicios AWS va por VPC endpoint ya se dice en el §3.3.
        lambda_proc >> Edge() >> ddb
        lambda_proc >> Edge(style="dotted") >> secrets

        # ⑥ Datos -> consumidor interno. Se dibuja en el sentido del dato, igual
        # que en el DFD: la PII es lo que cruza hacia el otro dominio. La etiqueta
        # va sobre lambda_read -> privapi, que es el salto que cruza a RED INTERNA;
        # ddb -> lambda_read no sale de la zona de aplicación.
        ddb >> lambda_read >> Edge(label="⑥ solo red interna") >> privapi >> interno


def cross_cutting() -> None:
    """Planos transversales: despliegue, cifrado y detección."""
    with Diagram(
        "Reto 1 — Planos transversales: CI/CD, cifrado y detección",
        filename=str(OUT / "cross-cutting"),
        outformat=["png", "svg"],
        show=False,
        direction="LR",
        graph_attr=GRAPH | {"ranksep": "1.4"},
        node_attr=NODE,
        edge_attr=EDGE,
    ):
        with Cluster("CI/CD — privilegio sobre la cuenta", graph_attr=BOUNDARY):
            gha = GithubActions(
                "GitHub Actions\nOIDC → rol de AWS\nsin llaves estáticas\ncondición sobre sub"
            )

        with Cluster("CIFRADO", graph_attr=ZONE):
            kms = KMS("KMS CMK\npolítica de clave\nrotación anual")

        # Placeholder que representa el diagrama de §2.1 entero: sin él, cada
        # plano transversal tendría que tirar una arista a los ~15 nodos del
        # otro diagrama. INTERNET queda fuera a propósito (el cliente y el
        # atacante no son infraestructura propia); RED INTERNA sí entra, porque
        # la API privada y la Lambda de consulta también se despliegan, se
        # cifran y se auditan. Se dibuja como caja para que se lea como nodo y
        # no como la etiqueta de una arista.
        infra = Blank(
            "Arquitectura (sección 2.1)\nEdge · Aplicación · IA\nDatos · Red interna",
            shape="box",
            style="rounded,filled",
            fillcolor="#eef2f7",
            color="#8899aa",
            fontcolor="#2e3440",
            width="2.4",
            height="1.0",
            imagescale="false",
        )

        with Cluster("DETECCIÓN Y RESPUESTA", graph_attr=ZONE):
            ct = Cloudtrail("CloudTrail\n+ data events S3 y KMS")
            cw = Cloudwatch("CloudWatch\nlogs sin PII · CMK\nretención · alarmas")
            gd = Guardduty("GuardDuty\n+ Malware Protection")
            macie = Macie("Macie\ndescubrimiento de PII")
            cfg = Config("AWS Config\nderiva de configuración")
            hub = SecurityHub("Security Hub")

        (
            gha
            >> Edge(
                label="despliega la infraestructura\nIaC escaneada · revisión obligatoria"
            )
            >> infra
        )
        (
            kms
            >> Edge(label="cifra S3, DynamoDB,\nSQS y grupos de logs", style="dashed")
            >> infra
        )
        # El label va en una sola arista: en el fan-out se repetiría cinco veces.
        infra >> Edge(label="eventos y logs", style="dotted") >> ct
        infra >> Edge(style="dotted") >> [cw, gd, macie, cfg]
        [ct, cw, gd, macie, cfg] >> Edge(style="dotted") >> hub


if __name__ == "__main__":
    architecture()
    cross_cutting()
    print(f"Diagramas generados en {OUT}")
