# Plataforma de intercambio de Threat Intelligence con IA y Blockchain
### Informe de planificación de proyecto (TFM Full Stack + Blockchain)

---

## 1. Resumen ejecutivo

Este documento describe de principio a fin un proyecto académico-profesional consistente en el diseño y desarrollo de una **plataforma de intercambio de inteligencia de amenazas (Threat Intelligence)** con tres piezas: **microservicios en Java** que exponen la plataforma a las organizaciones (API, autenticación y aportación de indicadores), un **motor de ingesta e Inteligencia Artificial en Python** que recoge fuentes abiertas y puntúa y prioriza los indicadores de compromiso (IOCs), y una **capa de blockchain permisionada** que garantiza la trazabilidad e inmutabilidad de la información compartida entre organizaciones.

El proyecto está pensado para poder desarrollarse íntegramente sin coste económico, usando exclusivamente software open source ejecutado en local, y su enfoque de negocio está alineado con las prioridades actuales del sector de ciberseguridad en España, en particular con las líneas de trabajo de Minsait Cyber (unidad de ciberseguridad de Indra Group).

---

## 2. El problema que resuelve

Las organizaciones —especialmente aquellas con infraestructuras críticas, entornos industriales o alta dependencia tecnológica— se enfrentan hoy a tres problemas interrelacionados:

1. **Fragmentación de la inteligencia de amenazas.** Cada empresa detecta indicadores de compromiso (IPs maliciosas, hashes de malware, dominios de phishing, etc.) de forma aislada, sin un mecanismo ágil y confiable para compartirlos con otras organizaciones del mismo sector.
2. **Falta de confianza en la procedencia del dato.** Cuando sí se comparte inteligencia de amenazas (por ejemplo, a través de foros sectoriales o CERTs), es difícil verificar quién reportó qué y cuándo, y detectar manipulaciones o duplicados.
3. **Sobrecarga de alertas para los analistas de un SOC (Security Operations Center).** El volumen de IOCs e incidentes supera la capacidad humana de análisis manual, generando fatiga de alertas y retrasos en la respuesta.

El sector está señalando explícitamente estos retos de cara a 2026: se anticipa un aumento de ataques dirigidos a la cadena de suministro de software (pipelines, contenedores, dependencias open source), un entorno marcado por tensiones geopolíticas y una superficie de ataque en expansión, lo que refuerza la necesidad de compartir inteligencia de forma más ágil, verificable y automatizada. También se insiste en que la adopción de IA en ciberseguridad debe hacerse de forma segura y alineada con el negocio, y en la importancia de la gestión continua de la exposición a amenazas (CTEM) y de automatizar las operaciones de seguridad.

**La plataforma propuesta ataca los tres problemas a la vez:**
- Ofrece un canal común y estructurado para compartir IOCs entre organizaciones (microservicios).
- Garantiza que cada IOC compartido queda registrado de forma inmutable y auditable, con su origen verificado (blockchain).
- Reduce la carga del analista humano priorizando y resumiendo automáticamente las amenazas más relevantes (IA).

---

## 3. Objetivos del proyecto

**Objetivo general:**
Diseñar, implementar y validar un prototipo funcional de plataforma de intercambio de inteligencia de amenazas que combine microservicios en Java, un motor de ingesta e IA en Python para análisis y priorización, y una capa blockchain para garantizar la integridad y trazabilidad de los datos compartidos.

**Objetivos específicos:**
- Definir un modelo de datos estándar para representar IOCs y sus metadatos (fuente, severidad, timestamp, tipo).
- Automatizar la ingesta y normalización de fuentes abiertas de IOCs, respetando sus términos de uso.
- Implementar una arquitectura de microservicios desacoplada, escalable y contenerizada para exponer la plataforma a las organizaciones.
- Entrenar y desplegar un modelo de IA capaz de puntuar el riesgo de un IOC y, opcionalmente, generar resúmenes legibles de incidentes.
- Desplegar una red blockchain permisionada que registre cada IOC compartido de forma inmutable.
- Construir un dashboard funcional para analistas de seguridad.
- Validar el sistema con un dataset real de amenazas de fuentes abiertas.
- Documentar el proyecto de forma que sirva como caso de uso presentable ante un departamento de ciberseguridad corporativo (p. ej. Minsait Cyber / Indra).

---

## 4. Alcance del proyecto (MVP)

Para que el proyecto sea abarcable en el marco de un TFM, se recomienda acotar el alcance a un **producto mínimo viable (MVP)** con los siguientes límites:

**Incluido en el MVP:**
- 2 microservicios Java: un API Gateway con autenticación por organización y un servicio de IOCs (consulta de indicadores y su severidad, aportación de IOCs por parte de las organizaciones y registro de esas aportaciones en la blockchain).
- Un motor de ingesta y scoring en Python: ingesta programada de fuentes abiertas, normalización y carga en PostgreSQL, y cálculo de la severidad de cada indicador. Se comunica con los microservicios a través de la base de datos compartida.
- Un modelo de IA de clasificación/scoring de riesgo entrenado con datos abiertos.
- Un resumen automático de IOCs mediante un modelo de lenguaje (LLM) local, como funcionalidad complementaria.
- Una red blockchain de prueba con 2-3 nodos simulando organizaciones distintas.
- Un dashboard web simple (React) para visualizar alertas priorizadas.
- Documentación técnica y memoria académica.

**Fuera de alcance (posibles líneas futuras):**
- Integración con SIEMs comerciales reales (Splunk, QRadar, etc.).
- Autenticación federada entre organizaciones reales (OAuth2/SAML entre distintas entidades).
- Despliegue en producción con alta disponibilidad.
- Cumplimiento normativo formal (ENS, ISO 27001) — se puede mencionar como trabajo futuro.

---

## 5. Arquitectura general

La plataforma se organiza en cinco capas, con flujo de datos de arriba hacia abajo:

1. **Fuentes externas**: feeds OSINT abiertos (abuse.ch ThreatFox y URLhaus, blocklist.de, PhishTank, TweetFeed, IPsum como señal de fiabilidad) y los IOCs que aportan las propias organizaciones participantes.
2. **Motor de ingesta e IA (Python)**: descarga programada de los feeds, validación, normalización a un modelo común y carga idempotente en PostgreSQL; scoring de riesgo (reglas de fiabilidad por fuente con un modelo de ML como señal adicional) y, opcionalmente, generación de resúmenes (LLM).
3. **Capa de microservicios Java**: API Gateway (autenticación por organización y enrutamiento) + servicio de IOCs (consulta de indicadores y severidad, y recepción de los IOCs que aportan las organizaciones).
4. **Capa blockchain**: red permisionada que registra el hash y la procedencia de cada IOC que aporta una organización, garantizando inmutabilidad y trazabilidad.
5. **Capa de consumo**: dashboard para analistas del SOC y API segura para que empresas socias consulten inteligencia verificada.

El motor Python y los microservicios Java no se llaman entre sí: comparten la base de datos PostgreSQL, cuyo esquema versionado actúa como contrato entre ambos. Esta separación en capas permite desarrollar y probar cada componente de forma independiente, algo especialmente útil cuando se trabaja en solitario en un TFM, ya que se puede avanzar por fases sin bloquear el resto del sistema.

---

## 6. Tecnologías y stack por capa

### 6.1 Backend / microservicios
- **Java 17+ / Spring Boot** — framework principal de los microservicios (API y aportaciones de las organizaciones; la ingesta de feeds la hace el motor Python, sección 6.2).
- **Spring Cloud Gateway** — API Gateway y enrutamiento.
- **Spring Data JPA + PostgreSQL** (o MongoDB si se prefiere un modelo documental para los IOCs).
- **Apache Kafka o RabbitMQ** — comunicación asíncrona entre microservicios (opcional pero recomendable para mostrar dominio de arquitecturas event-driven).
- **Docker + Docker Compose** — contenerización y orquestación local.
- **Maven o Gradle** — gestión de dependencias y build.

### 6.2 Ingesta e Inteligencia Artificial
- **Python + pandas + requests** — ingesta programada de los feeds (tarea horaria), validación, normalización y carga idempotente en PostgreSQL (psycopg).
- **Python + scikit-learn** — modelo de clasificación de dominios maliciosos a partir de rasgos léxicos del propio dominio (longitud, entropía, dígitos, TLD…), y fórmula de severidad que combina la fiabilidad medida de cada fuente, la antigüedad, la corroboración entre fuentes y el modelo. La fuente, la frecuencia o el contexto no entran en el modelo, porque delatarían la respuesta: se usan en las reglas.
- **Ollama** — para ejecutar modelos de lenguaje open source en local (Llama 3, Mistral, etc.) sin coste de API, usados para generar resúmenes o explicaciones de las alertas.
- **Pandas / Jupyter Notebook** — exploración y preparación de datos durante el entrenamiento.

### 6.3 Blockchain
- **Hyperledger Fabric** — red blockchain permisionada (no pública, sin criptomonedas ni gas).
- **Chaincode (Go o Java)** — lógica de negocio para registrar el hash y metadatos de cada IOC que aporta una organización (los feeds públicos ya conservan su procedencia en la base de datos).
- **Fabric SDK for Java** — integración desde los microservicios hacia la red blockchain.

### 6.4 Frontend
- **React** — dashboard para analistas.
- **Recharts o Chart.js** — visualización de métricas y alertas.
- **Tailwind CSS** — estilos.

### 6.5 Infraestructura y DevOps
- **Docker Compose** — para levantar todo el entorno (microservicios, BD, red Fabric) con un solo comando.
- **GitHub** — control de versiones.
- **GitHub Actions** — integración continua (tests automáticos, build de imágenes).
- **Postman o Insomnia** — pruebas manuales de las APIs.

---

## 7. Software requerido (instalación local)

| Herramienta | Uso | Coste |
|---|---|---|
| JDK 17+ | Desarrollo backend Java | Gratis |
| IntelliJ IDEA Community o VS Code | IDE | Gratis |
| Docker Desktop / Docker Engine | Contenerización | Gratis |
| Node.js + npm | Frontend React | Gratis |
| Python 3.10+ | Ingesta de fuentes, entrenamiento del modelo de IA y scoring | Gratis |
| Ollama | Ejecución de LLM en local | Gratis |
| Git | Control de versiones | Gratis |
| Postman | Testing de APIs | Gratis |
| Hyperledger Fabric samples/binaries | Red blockchain de pruebas | Gratis |

No se requiere ninguna licencia de pago ni suscripción para completar el desarrollo y la defensa del proyecto.

---

## 8. Datasets recomendados

- **MISP (Malware Information Sharing Platform)** — formato estándar de IOCs, permite exportar datasets de ejemplo.
- **AlienVault OTX (Open Threat Exchange)** — feeds gratuitos de IOCs tras registro simple.
- **abuse.ch (URLhaus, MalwareBazaar, ThreatFox)** — feeds públicos y gratuitos de IPs, dominios y hashes maliciosos.
- **CIC-IDS o datasets de Kaggle sobre ciberseguridad** — útiles si se quiere entrenar un modelo de detección de anomalías más robusto.

*Nota (octubre de 2026):* tras evaluar más de quince fuentes, el conjunto definitivo es ThreatFox y URLhaus (abuse.ch), blocklist.de, PhishTank y TweetFeed, con IPsum como señal de fiabilidad y Tranco como base de la clase no maliciosa. MISP, OTX y MalwareBazaar se descartaron; los motivos están en el documento de la fase de datos.

---

## 9. Modelo de datos simplificado (IOC)

Como punto de partida para el diseño de la base de datos y el chaincode:

- `id` — identificador único
- `tipo` — IP, dominio, hash, URL, etc.
- `valor` — el propio indicador (ej. la IP o el hash)
- `fuente` — organización o feed que lo reportó
- `severidad` — score de 0 a 100 calculado por reglas de fiabilidad de las fuentes y el modelo de IA, con cada componente guardado por separado
- `timestamp` — fecha de detección/reporte
- `hash_blockchain` — referencia al registro inmutable correspondiente (solo en los IOCs que aporta una organización)
- `estado` — activo, resuelto, falso positivo

---

## 10. Plan de trabajo (cronograma orientativo)

| Fase | Contenido | Duración estimada |
|---|---|---|
| 1. Diseño y modelado | Modelo de datos, diagrama de arquitectura, casos de uso | 1-2 semanas |
| 2. Datos, ingesta y modelo de IA (Python) | Selección y validación de fuentes, base de datos, ingesta programada, entrenamiento del modelo y fórmula de severidad, pruebas con LLM local | 2 semanas |
| 3. Microservicios Java | API Gateway con autenticación por organización y servicio de IOCs (consulta y aportaciones) sobre la base de datos compartida | 3 semanas |
| 4. Red blockchain | Despliegue de Hyperledger Fabric, chaincode de registro | 3 semanas |
| 5. Integración end-to-end | Conexión de todas las capas, dashboard React | 2 semanas |
| 6. Pruebas, documentación y memoria | Testing, redacción de la memoria, preparación de la defensa | 3-4 semanas |

**Duración total estimada:** 14-16 semanas a dedicación parcial (compatible con clases), o 8-10 semanas a dedicación intensiva.

---

## 11. Presupuesto y coste

El proyecto puede desarrollarse íntegramente **sin coste económico**, siempre que se mantenga en un entorno local:

- Todo el software listado en la sección 7 es gratuito y open source.
- El entrenamiento del modelo de IA se realiza en local, sin necesidad de GPU en la nube.
- La red blockchain es una red de pruebas local, sin interacción con redes públicas ni gas.
- Los datasets utilizados son de acceso gratuito.

**Gastos opcionales (no imprescindibles):**
- Despliegue de una demo pública en la nube para la presentación final: existen niveles gratuitos suficientes (Oracle Cloud Always Free, Render, Railway, Fly.io).
- Dominio propio para la demo (~10 €/año): puramente estético.
- Uso intensivo de una API comercial de LLM (OpenAI, Anthropic) en lugar de un modelo local: se recomienda evitarlo o limitarlo al nivel gratuito para mantener el coste en cero.

---

## 12. Riesgos y mitigación

| Riesgo | Mitigación |
|---|---|
| Complejidad de Hyperledger Fabric (curva de aprendizaje alta) | Empezar con la red de pruebas oficial ("test network") antes de personalizar el chaincode |
| Dataset insuficiente o poco representativo para el modelo de IA | Combinar varias fuentes abiertas (MISP + OTX + abuse.ch) y documentar las limitaciones en la memoria |
| Alcance demasiado ambicioso para el tiempo disponible | Priorizar el MVP definido en la sección 4 y dejar el resto como "trabajo futuro" |
| Integración entre las tres capas (Java, IA en Python, blockchain) | El esquema de PostgreSQL, versionado, es el contrato entre Python y Java; REST/JSON entre los microservicios y hacia los clientes |
| Duplicar lógica entre Python y Java | Cada responsabilidad vive en un solo lado: ingesta, normalización y scoring en Python; API, aportaciones y blockchain en Java |

---

## 13. Criterios de éxito

- El sistema ingiere IOCs de al menos una fuente externa real.
- El modelo de IA asigna una puntuación de riesgo coherente y explicable.
- Cada IOC compartido queda registrado de forma verificable en la red blockchain.
- El dashboard muestra alertas priorizadas de forma clara para un analista.
- La memoria documenta claramente el problema de negocio, la arquitectura y los resultados obtenidos.

---

## 14. Alineación con el sector (Indra / Minsait Cyber)

El proyecto se apoya en tendencias que el propio sector está señalando de cara a 2026: refuerzo de la seguridad de la cadena de suministro de software, gestión continua de la exposición a amenazas, automatización de operaciones de seguridad, y adopción segura de la inteligencia artificial en un contexto de creciente tensión geopolítica. A nivel de grupo, Indra está reforzando explícitamente sus capacidades en ciberdefensa e inteligencia artificial como líneas estratégicas. Un proyecto que demuestre de forma práctica cómo combinar microservicios, IA y blockchain para resolver un problema real de intercambio de inteligencia de amenazas resulta, por tanto, directamente relevante para el discurso actual de un departamento de ciberseguridad como Minsait Cyber.

---

## 15. Fuentes consultadas

- Minsait Cyber — tendencias de ciberseguridad para 2026 (Computer Weekly en español, infochannel.info, agenciaeluniversal.mx)
- Indra Group — reestructuración de negocio hacia ciberdefensa, IA y tecnologías estratégicas (elconciso.es)
- Minsait — información corporativa sobre áreas de actividad y ciberseguridad (EOI, indragroup.com)

---

## 16. Cambios respecto al planteamiento inicial

**27 de octubre de 2026 — reparto entre Python y Java, blockchain y orden de trabajo.**

1. **La ingesta y el scoring se quedan en Python; Java expone la plataforma.** El planteamiento inicial asignaba a los microservicios Java la ingesta, la normalización y el scoring. Durante la fase de datos esas funciones se construyeron en Python, se validaron y quedaron en ejecución horaria. Reescribirlas en Java duplicaría código ya probado y abriría la puerta a dos versiones que se contradigan. Por eso los microservicios Java se centran en lo que es propio de una plataforma de intercambio: la API de consulta, la recepción de los IOCs que aportan las organizaciones, la autenticación de cada organización y el registro en blockchain. Ambos lados se comunican a través de PostgreSQL.
2. **En la blockchain se registran solo los IOCs que aportan las organizaciones.** Es la procedencia que hay que garantizar. Los feeds públicos ya conservan su fuente y cada descarga en la base de datos; registrarlos supondría miles de transacciones por hora en una red de prueba y sus términos de uso no autorizan expresamente redistribuirlos.
3. **Orden: primero los microservicios Java, después Hyperledger Fabric.** Se construye sobre la base de datos que ya funciona y cada pieza se prueba por separado antes de unirlas.

**Octubre de 2026 — fuentes y modelo.** El conjunto de fuentes y los rasgos del modelo cambiaron respecto a las secciones 6.2 y 8 originales: ver la nota de la sección 8 y el documento de la fase de datos.

---

*Este informe está pensado como documento vivo de trabajo: se recomienda revisarlo y ajustarlo a medida que avance el desarrollo del proyecto.*
