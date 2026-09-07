# Modelo de amenazas

> Borrador generado por el Threat Modeling Agent. Requiere revisión y
> aprobación de un especialista de seguridad.

## Sistema analizado

La funcionalidad permite a usuarios móviles subir documentos PDF a S3 a través de una API Gateway protegida por JWT. Un proceso Lambda extrae información de estos archivos utilizando Amazon Bedrock y guarda los resultados estructurados en una base de datos DynamoDB.

## Activos

- Contenido de los documentos PDF (posible PII o datos sensibles del cliente)
- Metadatos extraídos en DynamoDB
- Disponibilidad del servicio de extracción (Bedrock)
- Créditos/Presupuesto de consumo de modelos de IA
- Integridad del sistema de procesamiento (Lambda)

## Fronteras de confianza

- Aplicación móvil -> API Gateway (Internet pública a entorno AWS)
- API Gateway -> S3 (Ingreso de datos de usuario a almacenamiento)
- S3 -> Lambda (Evento de procesamiento)
- Lambda -> Amazon Bedrock (Frontera de servicio de IA)

## Amenazas priorizadas

| # | Componente | Amenaza | Categoría | Impacto | Probabilidad | Riesgo | Control |
|---|---|---|---|---|---|---|---|
| 1 | API Gateway / DynamoDB | Un usuario autenticado con un JWT válido intenta acceder o modificar datos de extracción de otros usuarios manipulando identificadores en las peticiones (Broken Object Level Authorization - BOLA). | I — Information Disclosure (fuga de información) | 4 | 4 | **16** (Alto) | Validar en la lógica de la Lambda o mediante políticas de IAM dinámicas que el 'sub' del JWT coincide con el propietario del registro en DynamoDB. |
| 2 | Lambda -> Bedrock | Un atacante sube un PDF con texto diseñado específicamente para confundir al modelo de lenguaje (Prompt Injection), ordenándole ignorar las instrucciones de extracción y revelar información del sistema o realizar acciones no previstas. | T — Tampering (manipulación) | 3 | 4 | **12** (Alto) | Uso de Amazon Bedrock Guardrails para filtrar contenido malicioso y una clara delimitación entre las instrucciones del sistema y el contenido del PDF en el prompt. |
| 3 | API Gateway / S3 | Un atacante sube archivos masivos o de gran tamaño repetidamente para agotar la cuota de almacenamiento, saturar la Lambda de procesamiento o elevar los costes de invocación de Bedrock desmesuradamente. | D — Denial of Service (denegación de servicio) | 3 | 4 | **12** (Alto) | Implementar Throttling y Usage Plans en API Gateway, validar el Content-Length antes de permitir la subida a S3 y limitar el tamaño máximo procesable por la Lambda. |
| 4 | S3 Bucket de documentos | Exposición accidental de los documentos PDF a Internet debido a una configuración permisiva del bucket o falta de controles de acceso específicos. | I — Information Disclosure (fuga de información) | 5 | 2 | **10** (Medio) | Habilitar S3 Block Public Access a nivel de cuenta/bucket y usar una Bucket Policy que solo permita acceso al rol de la Lambda y al servicio de subida mediante SSL. |
| 5 | Lambda -> S3 / DynamoDB | La función Lambda utiliza un rol de IAM con permisos excesivos (p.ej. s3:* o dynamodb:*), permitiendo que si el código es comprometido, un atacante pueda leer o borrar todos los datos de la cuenta. | E — Elevation of Privilege (elevación de privilegios) | 4 | 2 | **8** (Medio) | Aplicar el principio de mínimo privilegio asignando políticas que limiten el acceso únicamente a los buckets y tablas específicos necesarios para esta funcionalidad. |

## Justificación de la priorización

### 1. API Gateway / DynamoDB — riesgo 16 (Alto)

- **Amenaza:** Un usuario autenticado con un JWT válido intenta acceder o modificar datos de extracción de otros usuarios manipulando identificadores en las peticiones (Broken Object Level Authorization - BOLA).
- **Impacto 4:** Fuga de información sensible (PII) de otros clientes, lo que supone un incumplimiento de privacidad y daño reputacional.
- **Probabilidad 4:** Es un vector de ataque común en APIs donde la autorización se limita a validar el token pero no la propiedad del recurso solicitado.
- **Control:** Validar en la lógica de la Lambda o mediante políticas de IAM dinámicas que el 'sub' del JWT coincide con el propietario del registro en DynamoDB.
- **Riesgo residual:** Requiere que el JWT contenga de forma íntegra el identificador de usuario y que este no pueda ser suplantado.

### 2. Lambda -> Bedrock — riesgo 12 (Alto)

- **Amenaza:** Un atacante sube un PDF con texto diseñado específicamente para confundir al modelo de lenguaje (Prompt Injection), ordenándole ignorar las instrucciones de extracción y revelar información del sistema o realizar acciones no previstas.
- **Impacto 3:** Los datos extraídos podrían ser erróneos, maliciosos o causar que la Lambda procese información de forma inesperada, afectando la integridad de la base de datos.
- **Probabilidad 4:** Las técnicas de Prompt Injection son sencillas de ejecutar si el contenido del documento se concatena directamente con las instrucciones del sistema.
- **Control:** Uso de Amazon Bedrock Guardrails para filtrar contenido malicioso y una clara delimitación entre las instrucciones del sistema y el contenido del PDF en el prompt.
- **Riesgo residual:** Las técnicas de jailbreak en LLMs evolucionan constantemente; no existe una mitigación 100% efectiva.

### 3. API Gateway / S3 — riesgo 12 (Alto)

- **Amenaza:** Un atacante sube archivos masivos o de gran tamaño repetidamente para agotar la cuota de almacenamiento, saturar la Lambda de procesamiento o elevar los costes de invocación de Bedrock desmesuradamente.
- **Impacto 3:** Agotamiento de presupuesto y posible denegación de servicio para usuarios legítimos debido a límites de concurrencia en Lambda o cuotas de Bedrock.
- **Probabilidad 4:** Sin límites de tamaño de archivo o rate limiting por usuario, es trivial automatizar la subida de archivos.
- **Control:** Implementar Throttling y Usage Plans en API Gateway, validar el Content-Length antes de permitir la subida a S3 y limitar el tamaño máximo procesable por la Lambda.
- **Riesgo residual:** Aun con límites, un ataque distribuido desde múltiples cuentas válidas podría generar costes significativos.

### 4. S3 Bucket de documentos — riesgo 10 (Medio)

- **Amenaza:** Exposición accidental de los documentos PDF a Internet debido a una configuración permisiva del bucket o falta de controles de acceso específicos.
- **Impacto 5:** Fuga masiva de documentos originales de clientes, lo que podría incluir datos altamente confidenciales.
- **Probabilidad 2:** AWS aplica 'Block Public Access' por defecto, pero configuraciones manuales erróneas o políticas de IAM demasiado abiertas siguen ocurriendo.
- **Control:** Habilitar S3 Block Public Access a nivel de cuenta/bucket y usar una Bucket Policy que solo permita acceso al rol de la Lambda y al servicio de subida mediante SSL.
- **Riesgo residual:** Se asume que no se requieren URLs prefirmadas para acceso público de larga duración.

### 5. Lambda -> S3 / DynamoDB — riesgo 8 (Medio)

- **Amenaza:** La función Lambda utiliza un rol de IAM con permisos excesivos (p.ej. s3:* o dynamodb:*), permitiendo que si el código es comprometido, un atacante pueda leer o borrar todos los datos de la cuenta.
- **Impacto 4:** Pérdida total de integridad y confidencialidad en el almacenamiento de la aplicación si el entorno de ejecución se ve comprometido.
- **Probabilidad 2:** Requiere una vulnerabilidad previa en la Lambda o sus dependencias para ser explotado, pero es un fallo de configuración muy común.
- **Control:** Aplicar el principio de mínimo privilegio asignando políticas que limiten el acceso únicamente a los buckets y tablas específicos necesarios para esta funcionalidad.
- **Riesgo residual:** La gestión de identidades sigue dependiendo de la correcta administración de los roles por parte de los desarrolladores.

## Asunciones a validar

- Se asume que el JWT es validado por API Gateway (Lambda Authorizer o Cognito Authorizer) antes de llegar a la lógica de negocio.
- Se asume que la comunicación entre la aplicación móvil y AWS se realiza íntegramente sobre HTTPS/TLS 1.2+.
- Se asume que la Lambda se dispara automáticamente mediante un evento S3 ObjectCreated.
- Se asume que el identificador de usuario (owner ID) está presente en las demandas (claims) del JWT.

## Fuera de alcance

- Seguridad del dispositivo móvil del cliente y almacenamiento local de documentos.
- Proceso de generación, rotación y revocación de los tokens JWT.
- Protección de red a nivel de infraestructura (VPC Endpoints, WAF), ya que no se mencionan detalles de red.
- Análisis de malware de los archivos PDF subidos (se recomienda integrar un escáner).
