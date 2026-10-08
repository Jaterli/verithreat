# Plataforma de intercambio de Threat Intelligence con IA y Blockchain
### Informe de planificación de proyecto (TFM Full Stack + Blockchain)

---

## 1. Resumen ejecutivo

Este documento describe de principio a fin un proyecto académico-profesional consistente en el diseño y desarrollo de una **plataforma de intercambio de inteligencia de amenazas (Threat Intelligence)** construida sobre una arquitectura de **microservicios en Java**, con un **motor de Inteligencia Artificial** para correlación y priorización de indicadores de compromiso (IOCs), y una **capa de blockchain permisionada** que garantiza la trazabilidad e inmutabilidad de la información compartida entre organizaciones.

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
Diseñar, implementar y validar un prototipo funcional de plataforma de intercambio de inteligencia de amenazas que combine microservicios en Java, un motor de IA para análisis y priorización, y una capa blockchain para garantizar la integridad y trazabilidad de los datos compartidos.

**Objetivos específicos:**
- Definir un modelo de datos estándar para representar IOCs y sus metadatos (fuente, severidad, timestamp, tipo).
- Implementar una arquitectura de microservicios desacoplada, escalable y contenerizada.
- Entrenar y desplegar un modelo de IA capaz de puntuar el riesgo de un IOC y, opcionalmente, generar resúmenes legibles de incidentes.
- Desplegar una red blockchain permisionada que registre cada IOC compartido de forma inmutable.
- Construir un dashboard funcional para analistas de seguridad.
- Validar el sistema con un dataset real de amenazas de fuentes abiertas.
- Documentar el proyecto de forma que sirva como caso de uso presentable ante un departamento de ciberseguridad corporativo (p. ej. Minsait Cyber / Indra).

---

## 4. Alcance del proyecto (MVP)

Para que el proyecto sea abarcable en el marco de un TFM, se recomienda acotar el alcance a un **producto mínimo viable (MVP)** con los siguientes límites:

**Incluido en el MVP:**
- 2-3 microservicios Java (ingesta/normalización, API Gateway, y consulta/scoring).
- Un modelo de IA de clasificación/scoring de riesgo entrenado con un dataset abierto.
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

1. **Fuentes externas**: feeds OSINT, CERTs, listas de IOCs públicas (MISP, AlienVault OTX, abuse.ch).
2. **Capa de microservicios Java**: API Gateway + microservicio de ingesta y normalización de IOCs.
3. **Motor de IA**: correlación de eventos, scoring de riesgo (modelo de ML) y generación de resúmenes (LLM).
4. **Capa blockchain**: red permisionada que registra el hash y la procedencia de cada IOC compartido, garantizando inmutabilidad y trazabilidad.
5. **Capa de consumo**: dashboard para analistas del SOC y API segura para que empresas socias consulten inteligencia verificada.

Esta separación en capas permite desarrollar y probar cada componente de forma independiente, algo especialmente útil quen se trabaja en solitario en un TFM, ya que se puede avanzar por fases sin bloquear el resto del sistema.

---

## 6. Tecnologías y stack por capa

### 6.1 Backend / microservicios
- **Java 17+ / Spring Boot** — framework principal de los microservicios.
- **Spring Cloud Gateway** — API Gateway y enrutamiento.
- **Spring Data JPA + PostgreSQL** (o MongoDB si se prefiere un modelo documental para los IOCs).
- **Apache Kafka o RabbitMQ** — comunicación asíncrona entre microservicios (opcional pero recomendable para mostrar dominio de arquitecturas event-driven).
- **Docker + Docker Compose** — contenerización y orquestación local.
- **Maven o Gradle** — gestión de dependencias y build.

### 6.2 Inteligencia Artificial
- **Python + scikit-learn** (o **Deeplearning4j** si se prefiere mantener todo en el ecosistema Java) — modelo de scoring de riesgo (clasificación/regresión sobre features del IOC: tipo, fuente, frecuencia de aparición, contexto).
- **Ollama** — para ejecutar modelos de lenguaje open source en local (Llama 3, Mistral, etc.) sin coste de API, usados para generar resúmenes o explicaciones de las alertas.
- **Pandas / Jupyter Notebook** — exploración y preparación de datos durante el entrenamiento.

### 6.3 Blockchain
- **Hyperledger Fabric** — red blockchain permisionada (no pública, sin criptomonedas ni gas).
- **Chaincode (Go o Java)** — lógica de negocio para registrar el hash y metadatos de cada IOC compartido.
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
| Python 3.10+ | Entrenamiento del modelo de IA | Gratis |
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

---

## 9. Modelo de datos simplificado (IOC)

Como punto de partida para el diseño de la base de datos y el chaincode:

- `id` — identificador único
- `tipo` — IP, dominio, hash, URL, etc.
- `valor` — el propio indicador (ej. la IP o el hash)
- `fuente` — organización o feed que lo reportó
- `severidad` — score calculado por el modelo de IA
- `timestamp` — fecha de detección/reporte
- `hash_blockchain` — referencia al registro inmutable correspondiente
- `estado` — activo, resuelto, falso positivo

---

## 10. Plan de trabajo (cronograma orientativo)

| Fase | Contenido | Duración estimada |
|---|---|---|
| 1. Diseño y modelado | Modelo de datos, diagrama de arquitectura, casos de uso | 1-2 semanas |
| 2. Dataset y modelo de IA | Descarga de datos, entrenamiento del modelo de scoring, pruebas con LLM local | 2 semanas |
| 3. Microservicios base | API Gateway, ingesta/normalización, base de datos | 3 semanas |
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
| Integración entre las tres capas (Java, IA en Python, blockchain) | Definir contratos de API claros (REST/JSON) entre capas desde el principio |

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

*Este informe está pensado como documento vivo de trabajo: se recomienda revisarlo y ajustarlo a medida que avance el desarrollo del proyecto.*
