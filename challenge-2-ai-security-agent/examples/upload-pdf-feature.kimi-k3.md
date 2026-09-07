# Modelo de amenazas

> Borrador generado por el Threat Modeling Agent. Requiere revisión y
> aprobación de un especialista de seguridad.

## Sistema analizado

Funcionalidad que permite a clientes subir documentos PDF desde una app móvil. La entrada es API Gateway con autenticación JWT; los PDF se almacenan en S3; una Lambda los procesa invocando Amazon Bedrock para extraer datos, y los resultados se persisten en DynamoDB.

## Activos

- Documentos PDF subidos por los clientes (contenido potencialmente sensible y PII)
- Datos extraídos de los documentos almacenados en DynamoDB (PII estructurada)
- Tokens JWT de los clientes y la identidad asociada
- Disponibilidad del pipeline de procesamiento (API Gateway, Lambda, Bedrock)
- Coste de invocaciones de Bedrock y recursos de cómputo de Lambda
- Credenciales IAM de la Lambda y acceso a S3/DynamoDB/Bedrock

## Fronteras de confianza

- Internet / app móvil -> API Gateway
- API Gateway -> S3 (subida del documento)
- S3 -> Lambda (disparo del procesamiento)
- Lambda -> Amazon Bedrock (envío del contenido del documento a un servicio gestionado)
- Lambda -> DynamoDB (escritura de resultados)

## Amenazas priorizadas

| # | Componente | Amenaza | Categoría | Impacto | Probabilidad | Riesgo | Control |
|---|---|---|---|---|---|---|---|
| 1 | API Gateway / subida a S3 | Un cliente autenticado con un JWT válido modifica el identificador de documento o de cliente en la petición de subida o consulta y accede al PDF de otro cliente, si la autorización valida solo la firma del token y no la propiedad del recurso (IDOR). | I — Information Disclosure (fuga de información) | 4 | 4 | **16** (Alto) | Autorizador Lambda o validación en backend que compare el claim 'sub' del JWT con el propietario del recurso en cada operación; claves de objeto S3 prefijadas por usuario e IAM/bucket policy que limite el acceso al prefijo propio; URLs prefirmadas de vida corta si se usa subida directa. |
| 2 | API Gateway (entrada) | Un atacante reutiliza un JWT robado o un JWT emitido para otra audiencia/otro servicio porque el autorizador no valida emisor, audiencia o expiración, actuando como el cliente legítimo para subir documentos o consultar resultados. | S — Spoofing (suplantación) | 4 | 3 | **12** (Alto) | Autorizador de API Gateway que valide firma, emisor (iss), audiencia (aud) y expiración (exp) del JWT contra el IdP; rotación de claves del IdP y TTL corto de tokens. |
| 3 | S3 bucket de documentos | Un cliente sube un fichero que no es un PDF real o un PDF malicioso (malware, contenido activo) que la Lambda procesa sin validación, ejecutándose o propagándose a sistemas internos o a otros clientes que lo descarguen. | T — Tampering (manipulación) | 3 | 4 | **12** (Alto) | Validación del tipo MIME real y del tamaño del fichero (sniffing de cabecera, no solo extensión) en Lambda antes de procesar; análisis antimalware; cuarentena de ficheros no conformes y restricción de tamaño en la URL prefirmada o el endpoint. |
| 4 | API Gateway / Lambda / Bedrock (recursos) | Un atacante (autenticado o no, según el endpoint) envía ráfagas de subidas de PDFs grandes, disparando invocaciones masivas de Lambda y Bedrock que agotan cuotas de concurrencia, encarecen el servicio (denial of wallet) o degradan la disponibilidad para clientes legítimos. | D — Denial of Service (denegación de servicio) | 3 | 4 | **12** (Alto) | Throttling y cuotas por cliente en API Gateway, WAF con reglas de rate limiting, límite de tamaño de subida, reserva de concurrencia de Lambda acotada y límites de gasto/invocación en Bedrock con alarmas de facturación. |
| 5 | S3 y DynamoDB (datos en reposo y retención) | Documentos y resultados extraídos permanecen indefinidamente y/o accesibles por una configuración permisiva del bucket (acceso público, política IAM ancha), exponiendo PII acumulada si una credencial interna se compromete o ante una mala configuración. | I — Information Disclosure (fuga de información) | 5 | 2 | **10** (Medio) | Block Public Access en el bucket, bucket policy con aws:SecureTransport, cifrado con claves KMS gestionadas por el cliente con política de clave restrictiva, roles IAM por función con mínimo privilegio, reglas de ciclo de vida de S3 y TTL de DynamoDB para el borrado del documento original según política de retención. |
| 6 | Lambda -> Bedrock (contenido del documento) | Un cliente incluye en el PDF instrucciones adversarias (prompt injection) que Bedrock interpreta como parte del prompt, alterando la extracción de datos: resultados falsificados en DynamoDB o fuga del prompt del sistema o de datos de contexto. | T — Tampering (manipulación) | 3 | 3 | **9** (Medio) | Separación estricta entre instrucciones del sistema y contenido del documento (marcado del contenido como dato no confiable), guardarraíles de Bedrock, validación de la salida contra un esquema esperado antes de escribir en DynamoDB. |
| 7 | Trazabilidad end-to-end (API Gateway -> Lambda -> DynamoDB) | Sin logs correlacionados por petición ni data events de S3/DynamoDB, ante un acceso indebido a documentos no es posible demostrar qué cliente descargó qué PDF ni qué escribió la Lambda, impidiendo la investigación y las notificaciones de brecha. | R — Repudiation (repudio) | 3 | 3 | **9** (Medio) | CloudTrail con data events de S3 y DynamoDB, logs de acceso de API Gateway y del bucket, y trazas correlacionadas por request ID (p. ej. X-Ray) a lo largo del pipeline. |

## Justificación de la priorización

### 1. API Gateway / subida a S3 — riesgo 16 (Alto)

- **Amenaza:** Un cliente autenticado con un JWT válido modifica el identificador de documento o de cliente en la petición de subida o consulta y accede al PDF de otro cliente, si la autorización valida solo la firma del token y no la propiedad del recurso (IDOR).
- **Impacto 4:** Exposición de documentos PDF con PII de un subconjunto de clientes a un usuario distinto del propietario.
- **Probabilidad 4:** Cualquier usuario autenticado puede probar IDs secuenciales o predecibles con esfuerzo bajo; es un fallo habitual cuando la autorización se resuelve solo en el gateway.
- **Control:** Autorizador Lambda o validación en backend que compare el claim 'sub' del JWT con el propietario del recurso en cada operación; claves de objeto S3 prefijadas por usuario e IAM/bucket policy que limite el acceso al prefijo propio; URLs prefirmadas de vida corta si se usa subida directa.
- **Riesgo residual:** La descripción no indica cómo se realiza la subida a S3 (directa con URL prefirmada o a través de API); el control exacto depende de ello y debe validarse con el equipo.

### 2. API Gateway (entrada) — riesgo 12 (Alto)

- **Amenaza:** Un atacante reutiliza un JWT robado o un JWT emitido para otra audiencia/otro servicio porque el autorizador no valida emisor, audiencia o expiración, actuando como el cliente legítimo para subir documentos o consultar resultados.
- **Impacto 4:** Suplantación completa de un cliente: acceso a sus documentos y resultados extraídos.
- **Probabilidad 3:** Requiere obtener un token válido o un fallo de validación; común cuando el autorizador solo comprueba la firma y no aud/iss/exp.
- **Control:** Autorizador de API Gateway que valide firma, emisor (iss), audiencia (aud) y expiración (exp) del JWT contra el IdP; rotación de claves del IdP y TTL corto de tokens.
- **Riesgo residual:** Se asume que existe un IdP con claves publicadas; validar la configuración exacta del autorizador con el equipo.

### 3. S3 bucket de documentos — riesgo 12 (Alto)

- **Amenaza:** Un cliente sube un fichero que no es un PDF real o un PDF malicioso (malware, contenido activo) que la Lambda procesa sin validación, ejecutándose o propagándose a sistemas internos o a otros clientes que lo descarguen.
- **Impacto 3:** Compromiso del pipeline de procesamiento o distribución de contenido malicioso a otros usuarios; no implica fuga masiva por sí solo.
- **Probabilidad 4:** Cualquier cliente autenticado puede subir ficheros arbitrarios; la descripción no menciona validación de tipo ni análisis.
- **Control:** Validación del tipo MIME real y del tamaño del fichero (sniffing de cabecera, no solo extensión) en Lambda antes de procesar; análisis antimalware; cuarentena de ficheros no conformes y restricción de tamaño en la URL prefirmada o el endpoint.
- **Riesgo residual:** Si la app móvil solo acepta PDF, la barrera es débil porque el cliente controla la petición; confirmar si hay validación del lado del cliente y que no sea el único control.

### 4. API Gateway / Lambda / Bedrock (recursos) — riesgo 12 (Alto)

- **Amenaza:** Un atacante (autenticado o no, según el endpoint) envía ráfagas de subidas de PDFs grandes, disparando invocaciones masivas de Lambda y Bedrock que agotan cuotas de concurrencia, encarecen el servicio (denial of wallet) o degradan la disponibilidad para clientes legítimos.
- **Impacto 3:** Indisponibilidad temporal del procesamiento y coste elevado de Bedrock/Lambda; sin pérdida de datos.
- **Probabilidad 4:** Subir documentos es la operación natural del servicio y no hay throttling, cuotas ni límites de tamaño descritos.
- **Control:** Throttling y cuotas por cliente en API Gateway, WAF con reglas de rate limiting, límite de tamaño de subida, reserva de concurrencia de Lambda acotada y límites de gasto/invocación en Bedrock con alarmas de facturación.
- **Riesgo residual:** Asunción: los endpoints de consulta de resultados también requieren protección de ratio; validar límites acordados con Producto.

### 5. S3 y DynamoDB (datos en reposo y retención) — riesgo 10 (Medio)

- **Amenaza:** Documentos y resultados extraídos permanecen indefinidamente y/o accesibles por una configuración permisiva del bucket (acceso público, política IAM ancha), exponiendo PII acumulada si una credencial interna se compromete o ante una mala configuración.
- **Impacto 5:** Fuga masiva de PII: el bucket acumula los documentos de todos los clientes y DynamoDB sus datos extraídos.
- **Probabilidad 2:** Requiere mala configuración o credencial comprometida; el bloqueo de acceso público es estándar pero las políticas IAM demasiado anchas son frecuentes.
- **Control:** Block Public Access en el bucket, bucket policy con aws:SecureTransport, cifrado con claves KMS gestionadas por el cliente con política de clave restrictiva, roles IAM por función con mínimo privilegio, reglas de ciclo de vida de S3 y TTL de DynamoDB para el borrado del documento original según política de retención.
- **Riesgo residual:** La política de retención (¿cuánto tiempo se conserva el PDF original?) no está definida en la descripción; es una decisión de Producto que debe documentarse.

### 6. Lambda -> Bedrock (contenido del documento) — riesgo 9 (Medio)

- **Amenaza:** Un cliente incluye en el PDF instrucciones adversarias (prompt injection) que Bedrock interpreta como parte del prompt, alterando la extracción de datos: resultados falsificados en DynamoDB o fuga del prompt del sistema o de datos de contexto.
- **Impacto 3:** Pérdida de integridad de los datos extraídos almacenados en DynamoDB y posible exposición del prompt/instrucciones internas; alcance limitado al documento del atacante salvo encadenamiento.
- **Probabilidad 3:** El atacante controla por completo el contenido del documento; requiere conocer que se usa un LLM y algo de ensayo, esfuerzo moderado.
- **Control:** Separación estricta entre instrucciones del sistema y contenido del documento (marcado del contenido como dato no confiable), guardarraíles de Bedrock, validación de la salida contra un esquema esperado antes de escribir en DynamoDB.
- **Riesgo residual:** La robustez depende del diseño del prompt y de la validación de salida, no descritos; revisar el prompt con el equipo.

### 7. Trazabilidad end-to-end (API Gateway -> Lambda -> DynamoDB) — riesgo 9 (Medio)

- **Amenaza:** Sin logs correlacionados por petición ni data events de S3/DynamoDB, ante un acceso indebido a documentos no es posible demostrar qué cliente descargó qué PDF ni qué escribió la Lambda, impidiendo la investigación y las notificaciones de brecha.
- **Impacto 3:** Imposibilidad de acotar el alcance de un incidente sobre datos personales, con consecuencias regulatorias, aunque no implica pérdida directa de datos.
- **Probabilidad 3:** CloudTrail registra eventos de gestión por defecto pero no data events de S3/DynamoDB; sin configuración explícita la trazabilidad queda incompleta, situación habitual.
- **Control:** CloudTrail con data events de S3 y DynamoDB, logs de acceso de API Gateway y del bucket, y trazas correlacionadas por request ID (p. ej. X-Ray) a lo largo del pipeline.
- **Riesgo residual:** Confirmar si existe un estándar corporativo de logging que ya cubra esto y su nota de retención.

## Asunciones a validar

- La subida a S3 se realiza mediante URL prefirmada o a través de un endpoint de API Gateway; la descripción no lo especifica y ambas opciones cambian los controles aplicables.
- Los JWT proceden de un IdP corporativo con claves públicas verificables; no se describe el emisor ni los claims disponibles.
- Los documentos contienen PII; el impacto se ha calibrado asumiendo datos personales de clientes, lo razonable para documentos subidos por clientes.
- La Lambda es disparada por un evento de S3 tras la subida; no se describe el mecanismo de activación.
- No hay requisito descrito de retención o borrado de los documentos originales.
- No se describe si el tráfico a S3/DynamoDB/Bedrock usa VPC endpoints o sale por Internet; se asume configuración por defecto salvo confirmación.
- Existen controles de cuenta estándar (Block Public Access, CloudTrail) que deben verificarse, no darse por hechos.

## Fuera de alcance

- Seguridad de la aplicación móvil (almacenamiento del JWT en el dispositivo, certificate pinning): no evaluable con esta descripción.
- Gestión del ciclo de vida del JWT en el IdP (emisión, revocación, refresh tokens).
- Diseño del prompt de Bedrock, modelo usado y posible uso de datos por parte del proveedor del modelo (configuración de retención de Bedrock).
- Requisitos regulatorios y de residencia de datos aplicables a los documentos (GDPR u otros).
- Cifrado en tránsito dentro de la VPC y gobierno de cuentas AWS (Guardrails/SCPs), no descritos.
