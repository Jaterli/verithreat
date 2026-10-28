# VeriThreat — contexto del proyecto (TFM)

> Léelo entero antes de tocar nada. Resume el estado a octubre de 2026 de la **fase de datos / módulo de IA**.
> Idioma (decidido el 16-10-2026): **código en inglés** (identificadores, ficheros, tablas y columnas, valores de
> estado, columnas de CSV, mensajes de consola y `--help`); **comentarios, docstrings y documentación en español**.

## 1. Qué es VeriThreat

Plataforma de intercambio de **Threat Intelligence** entre organizaciones (TFM Full Stack + Blockchain). Comparte
**IOCs** (dominios, URLs, hashes, IPs) con tres piezas:

- **Microservicios Java** (Spring Boot, Spring Cloud Gateway, PostgreSQL, Docker Compose; Kafka/RabbitMQ opcional):
  API Gateway con autenticación por organización y servicio de IOCs (consulta, aportaciones de las organizaciones y
  registro en Fabric). **No ingieren ni puntúan** (decisión 14).
- **Motor de ingesta e IA** (Python, scikit-learn): ingesta programada de los feeds, normalización, carga en
  PostgreSQL y severidad de cada indicador; opcionalmente, resúmenes con un LLM local (Ollama). Python y Java se
  comunican solo a través de PostgreSQL.
- **Blockchain permisionada** (Hyperledger Fabric, 2–3 nodos): registra hash y procedencia de cada IOC compartido.
- **Dashboard** React (Recharts, Tailwind) para analistas.

Criterio de éxito clave: el score de riesgo debe ser **coherente y explicable**. Por eso cada componente del score se
guarda por separado y se conoce la fiabilidad de cada fuente.

**La carpeta `ai/` cubre los datos, la ingesta, el modelo y la severidad** (hechos y en ejecución horaria), y `db/`
la base de datos. Los microservicios Java, Fabric y el dashboard son el paso 6 y siguientes, y aún no están hechos.

## 2. Estructura y archivos

Rutas según los comandos del autor (ajústalas si difieren):

```
verithreat/ai/
  src/    
    loaders.py                   cargadores de las fuentes, lista DUAL_USE, bloques /24, IPsum, source_sightings()
    optional_loaders.py          cargadores de fuentes DESCARTADAS (MalwareBazaar, ThreatCluster); nada depende de él
    vt_sampling.py               muestra reproducible + consulta a VirusTotal (reintentos, reanudación)
    blocklist_history.py         histórico propio de blocklist.de (antes extract_historic_blocklist.py)
    learning_trial.py            ensayo del modelo A (curva de aprendizaje, generalización sin una fuente); referencia
                                 en docs/ensayo_aprendizaje_referencia.txt (salida del script antes de traducirlo)
    load_db.py                   carga idempotente de las fuentes en PostgreSQL (usa source_sightings)
    ingest.py                    ingesta programada: descarga, valida y carga lo que toque según la frecuencia de cada
                                 fuente; instantáneas y estado en data/raw/ingest/ (3 últimas por fuente, state.json)
    run_ingest.sh                lanzador para WSL (Programador de tareas de Windows o cron); log en data/raw/ingest/
    model_a.py                   modelo A: datos desde la base de datos, 3 evaluaciones, entrenamiento, registro en
                                 model_version; load_artifact() y score_hosts() para puntuar (paso 5)
    score.py                     severidad 0-100 de cada indicador (decisión 13); escribe en `score` solo los cambios
    severity_config.json         pesos de la fórmula (fiabilidades, decaimiento, β del modelo, disputado)
  models/model_a/<versión>/      model.joblib, metrics.json, params.json, training_hosts.csv (no se versiona)
    threatfox_download_data.py, virustotal_*_filter.py   descargadores antiguos del autor, sin traducir; sustituidos
                                 por ingest.py
  notebooks/01_exploration.ipynb exploración, calidad, solapes, clase no maliciosa, esquema común, validación VT
  data/raw/                      CSV de las fuentes (NO se versionan)
  tests/test_normalization.py    normalize_value (loaders.py) contra db/normalization_cases.json
verithreat/db/schema.sql         esquema PostgreSQL (se aplica solo al crear el contenedor)
verithreat/db/migrations/        cambios posteriores numerados (002_organizations.sql); en una base existente, con psql
verithreat/db/normalization_cases.json   casos compartidos de normalización (Python y Java deben dar lo mismo)
verithreat/services/ioc-service/ Spring Boot 4.0.9 (Java 17, Maven): API de consulta y aportaciones (paso 6a)
verithreat/services/gateway/     Spring Cloud Gateway Server MVC 5.0 (Spring Cloud 2025.1.4): claves de API por
                                 organización (paso 6b); scripts/new-api-key.sh crea una clave y la muestra una vez
verithreat/blockchain/network.sh red Fabric de prueba: up | deploy | smoke | down (usa ~/fabric/fabric-samples)
verithreat/blockchain/chaincode/iocregistry/   chaincode Java 11 (Maven, fabric-chaincode-shim 2.5.11): RegisterIoc,
                                 GetRecord, GetRecordsByIndicator
verithreat/docker-compose.yml    por ahora solo `postgres` (puerto 5433 en 127.0.0.1; contraseña POSTGRES_PASSWORD en .env)
```

Datos esperados en `data/raw/`: `threatfox.csv`, `urlhaus.csv`, `export-ips_all.txt` (o `all.txt` de blocklist.de),
`verified_online.csv` (PhishTank), `month.csv` y `exclusive.csv` (TweetFeed), `top-1m.csv` (Tranco),
`ipsum_level1.txt` … `ipsum_level8.txt` (los descarga el notebook). La muestra y la salida de VirusTotal
(`vt_sample.csv`, `vt_results.csv`; columnas `indicator`, `type`, `group`, `expected_class` = `malicious`/`benign`…)
están en `ai/src/`; `muestra_vt.csv` y `resultados_vt.csv` son las versiones en español anteriores a la migración. Nada de esto se versiona (`.gitignore`: `ai/data/raw/`,
`*.csv`).

## 3. Fuentes: qué se usa y qué se descartó

| Fuente | Papel | Datos (exportación analizada) | Particularidades |
|---|---|---|---|
| ThreatFox (abuse.ch) | Núcleo: IOCs mixtos, familia, confianza, C2 | 11.941 · 7 días | fechas con sufijo UTC; `tags` como texto de lista; `last_seen` vacío al 81 % |
| URLhaus (abuse.ch) | Núcleo: URLs de malware, estado online/offline | 31.166 · 31 días | cabecera `# id`; un reportero (`shmulc`) = 44 % |
| blocklist.de | Núcleo: IPs que atacan servicios | `all.txt` = últimas 48 h (24–27 k IPs) | sin fechas; **incluye /24 completos listados en bloque** |
| PhishTank | Núcleo: phishing verificado | 69.007 (12.606 en 90 días) | histórico desde 2011; `&amp;` en URLs |
| TweetFeed (`month.csv`) | Núcleo: IOCs de investigadores con reportero, etiquetas y tweet | 4.323 filas · 30 días | sin cabecera; dominios derivados de URLs; IDN; no verificado por ellos |
| IPsum | **Señal** de fiabilidad de IPs (nº de listas), no aporta indicadores | 119.353 IPs | nivel N = IPs en ≥N listas |
| Tranco | Base de la clase no maliciosa | top 50.000 | popularidad ≠ benignidad |

**Descartadas** (no reabrir sin un hueco medible): MalwareBazaar (solo hashes, 17 % de los sha256, formato complejo),
ThreatCluster (1,7 % de los indicadores, solape casi nulo, confianza constante, falsos positivos de extracción), OTX,
Feodo Tracker (vacío tras derribos), Spamhaus (30 días gratis: solo validar), `IoCs_Identifiers.json` (200 dominios
alfabéticos, subconjunto de Tranco), filtro de Bloom de CIRCL (0,7–1 GB, «conocido» ≠ «benigno»), MISP como vía
principal (duplica abuse.ch), vciso.au (agregador), C2IntelFeeds/C2-Tracker, FireHOL, otras listas de IPs de ataque.

**Términos de uso** (leídos en las páginas oficiales el 17-10-2026; ninguna autoriza ni prohíbe expresamente
redistribuir los IOCs entre organizaciones, salvo TweetFeed e IPsum):

| Fuente | Uso permitido | Límites para la ingesta | Pendiente |
|---|---|---|---|
| abuse.ch ([términos](https://abuse.ch/terms-of-use/), 4-11-2025) | Gratis solo para usuarios autenticados y fines **no lucrativos**; uso comercial = suscripción vía Spamhaus | Volumen «razonable» sin cifra; prohíbe la recolección masiva automatizada; las exportaciones de URLhaus se generan cada 5 min y no deben pedirse más a menudo | Nada sobre redistribución ni licencia de datos |
| blocklist.de ([términos](https://www.blocklist.de/en/terms.html)) | Gratis, «salvo descarga de las listas con demasiado volumen» | `all.txt` = últimas 48 h, regenerada cada 30 min | Nada sobre redistribución ni uso comercial |
| PhishTank ([FAQ](https://phishtank.org/faq.php), [developer info](https://phishtank.org/developer_info.php)); operado por Cisco Talos | Gratis para todos; la FAQ permite **uso comercial y no comercial** de la API y los datos. Rigen los [General Terms de Cisco](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/Cisco_General_Terms.pdf) (v6.0, 10-9-2025): licencia «for Your direct benefit», prohíben «transfer, sell, sublicense, monetize, or provide the functionality… to any third party» | Datos cada hora; límite de peticiones por hora. Sin clave funciona (`http://data.phishtank.com/data/online-valid.csv`) pero solo «unas pocas descargas al día»; con clave, más; User-Agent descriptivo obligatorio; HEAD con ETag ilimitado | Ni la FAQ ni los términos hablan de **redistribuir** los datos a terceros; los términos generales, leídos al pie de la letra, lo restringen. `online-valid.csv` = mismas columnas que `verified_online.csv` |
| TweetFeed ([API](https://tweetfeed.live/api/)) | Datos CC0; no verifica los indicadores y desaconseja usarlos directamente como lista de bloqueo | Feeds oficiales `https://tweetfeed.live/feeds/month.csv` y `exclusive.csv`, regenerados cada 15 min, con ETag; sin límite estricto. La API JSON (`/v1/month`) corta a 10.000 filas y no trae la corroboración; el README desaconseja descargar del repositorio de GitHub | — |
| IPsum ([repo](https://github.com/stamparm/ipsum)) | The Unlicense (dominio público) | Se actualiza cada 24 h | — |
| Tranco ([web](https://tranco-list.eu/)) | Sin licencia propia declarada; fuentes con CC BY, CC BY-SA y **CC BY-NC 4.0** (Cloudflare Radar) | — | Uso comercial dudoso; citar el artículo de Tranco por buena práctica |
| VirusTotal ([API pública](https://docs.virustotal.com/reference/public-vs-premium-api)) | API pública **prohibida en productos o servicios comerciales** y en flujos de negocio | 4 peticiones/min, 500/día | Solo para la validación académica, nunca dentro de la plataforma |

Consecuencia: el TFM (académico, sin ánimo de lucro) está cubierto; un despliegue comercial (caso Minsait)
necesitaría suscripción de abuse.ch, API premium de VirusTotal y revisar el origen NC de Tranco; PhishTank permite el
uso comercial, pero no aclara la redistribución. Compartir IOCs de terceros entre organizaciones no está autorizado expresamente: conservar siempre la
fuente de origen de cada observación y presentarlo como limitación en la memoria.

Claves y URLs de abuse.ch: las exportaciones llevan la **clave en la ruta**
(`https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv`); no escribirla en logs ni subirla al repo.
Las exportaciones `recent` cubren pocos días y se regeneran cada pocos minutos.

## 4. Decisiones de diseño (no cambiar sin documentarlo)

1. **Esquema**: un **indicador** (`indicator`) único `(type, value normalizado)` con una o varias **observaciones**
   (`sighting`) por fuente. Campos de observación: `source`, `source_record_id`, `seen_at` (UTC), `category`,
   `malware_family`, `confidence`, `status`, `reporter`, `corroborated` (TweetFeed); la familia de la fuente va en la
   tabla `source` y el nivel de IPsum en `ipsum_signal` (decisión 12).
2. **Tipos**: `sha256`, `md5`, `sha1`, `domain`, `url`, `ip`, `cidr` (un /24 completo de blocklist.de = 1 indicador).
3. **Categorías**: `malware_distribution`, `c2`, `phishing`, `attack_source`, `attack_network`, `malware`, `skimming`…
   La severidad solo se compara/pondera **dentro de una categoría**.
4. **`source_family`**: ThreatFox y URLhaus cuentan como una (`abuse.ch`). La corroboración se cuenta por **familias**,
   no por observaciones (solo 41 indicadores aparecen en dos familias).
5. **Etiqueta del modelo (opción A)**: dominio malicioso vs no malicioso. Descartadas como etiqueta: confianza
   (depende del reportero), estado online (decae con la edad), familia (133 clases). Pasan a ser **reglas**.
6. **Clase no maliciosa**: top 50.000 de Tranco menos 228 dominios que chocan con fuentes maliciosas y 43 de
   doble uso → **49.767** (decidido el 15-10-2026; antes 49.766 por un fallo: el registrable vacío de los hosts IP
   descartaba `bet.br`, que es un sufijo público). Maliciosos utilizables: **11.208** (≈9.900 registrables únicos). Entrenar **a nivel de
   dominio** (host de las URLs).
7. **Fuga de información**: el modelo solo usa rasgos calculables para un dominio desconocido (longitud, entropía,
   dígitos, guiones, subdominios, TLD). Fuente, reportero, tags, familia, confianza, nº de fuentes, antigüedad, estado
   e IPsum quedan para las **reglas**.
8. **Lista `DUAL_USE`** (en `loaders.py`, única fuente de verdad): plataformas donde cualquier host es
   de un usuario (GitHub, Dropbox, acortadores, `pages.dev`, `weebly.com`, `duckdns.org`, `amazonaws.com`…).
   No se etiquetan a nivel de dominio; siguen valiendo como URL/host. Antes de ampliarla: 34 registrables concentraban
   el 25 % de los hosts maliciosos.
9. **blocklist.de**: `all.txt` incluye **30 bloques /24 de 256 IPs** (7.680 IPs, ~30 % de la lista) que **no son
   ataques individuales**: sin registro DNS propio, no salen en `getlast.php`, solo en 1–2 listas de IPsum. Se
   detectan con `mark_full_blocks` (umbral 250) y se representan como `cidr`. Las estadísticas de fiabilidad
   se calculan solo con IPs individuales.
10. **Umbral de confirmación**: ≥3 detecciones en VirusTotal (con 1 hay mucho ruido de un motor aislado). «Disputado» =
    se guarda con severidad rebajada y marcado (p. ej. dominio popular con ≥3 detecciones).
11. **Sin ventana temporal configurable por el usuario** (decidido el 16-10-2026): añade complejidad, apenas mejora
    la detección y obliga al usuario a elegir una temporalidad. La antigüedad entra solo como **decaimiento** interno
    en la fórmula de severidad (paso 5). Criterio general: no añadir complejidad que no mejore claramente la detección.
    La ingesta será un trabajo programado normal (cron / `@Scheduled`), no un agente con LLM.
12. **Esquema PostgreSQL** (`db/schema.sql`, esquema `verithreat`, 16-10-2026; desarrolla la decisión 1):
    - `source`: catálogo con la `family` de cada fuente (ThreatFox y URLhaus = `abuse.ch`).
    - `download`: una fila por fichero crudo, identificado por su **sha256** (`UNIQUE(source, sha256)`): recargar el
      mismo fichero no hace nada. Solo `file_name`, nunca la URL (las de abuse.ch llevan la clave).
    - `indicator`: único por `(type, fingerprint)`, con `fingerprint = sha256(value)` (función `fingerprint()`; hay
      URLs de PhishTank de 25.000 caracteres, más de lo que admite un índice) y `CHECK` de formato por tipo. La huella
      servirá para Fabric.
    - `sighting`: única por `(source, source_record_id)`. `seen_at` = fecha de la fuente (o de descarga);
      `last_confirmed_at` = última descarga en la que seguía apareciendo (para el decaimiento); `raw` jsonb = registro
      original. Al reaparecer solo se actualizan `last_confirmed_at`, `status`, `corroborated` y `last_download_id`,
      y solo si la descarga es más reciente.
    - **Cambio frente a la decisión 1**: el nivel de IPsum no va en la observación sino en `ipsum_signal` (nivel por
      IP y descarga de IPsum), porque es una propiedad diaria de la IP, no de un registro.
    - `model_version` (una activa por modelo) y `score` (historial, `components` en jsonb, versión del modelo); el
      contenido de los componentes se fija en el paso 5. Vistas `v_indicator` (resumen para las reglas) y
      `v_current_score`.
    - La normalización vive en `source_sightings()` (`loaders.py`); `load_db.py` y el notebook la usan.
13. **Fórmula de severidad** (`score.py` + `severity_config.json`, 19-10-2026). Por indicador:
    1. Fiabilidad `r` de cada observación = peso **por fuente y tipo** (decidido: URLs y hashes con peso propio):
       PhishTank 0,97 (URL 1,00); URLhaus 0,59 (URL 0,73); ThreatFox 0,59 (sha256 0,90: medido 1,00 pero en parte
       circular); TweetFeed 1,00 corroborado / 0,94 malware-C2 / 0,60 phishing / 0,28 sin etiqueta (URL 0,82; sha256
       1,00 corroborado / 0,82); blocklist.de IP 0,96 / 0,82 / 0,36 según IPsum, cidr 0,41. Lo no validado usa el
       peso `*` de su fuente. URLhaus `offline` × 0,8.
    2. Decaimiento `d = 0,5^(días desde last_confirmed_at / vida media)`: IP y cidr 7 d, URL 14, dominio 30; los
       hashes no decaen.
    3. Evidencia `E = 1 − Π(1 − máx r·d por familia)` (OR probabilístico; la corroboración cuenta por familias). Para
       IPs que no vienen de blocklist.de, IPsum es una familia más (0,96 con ≥3 listas, 0,82 con 1–2; por analogía,
       sin validar; sin decaimiento).
    4. Modelo A como señal débil en dominios y hosts de URL (no IP, no doble uso): `S = 1 − (1 − E)(1 − 0,3·p)`.
    5. Disputado = dominio cuyo registrable está en el top 10.000 de Tranco, **salvo plataformas de doble uso**
       (un `x.workers.dev` no hereda la popularidad): se marca y `S × 0,5`.
    6. `severity = round(100·S)`; `components` guarda cada término, la categoría (la de la familia que más aporta) y
       el hash de la configuración. Historial: fila nueva solo si no había puntuación, cambia ≥5 puntos o cambia
       `disputed`. Se ejecuta tras cada ingesta horaria (`run_ingest.sh`, ~15 s).

14. **Reparto Python / Java y blockchain** (27-10-2026; cambia el enunciado original, ver la sección 16 del informe
    de planificación):
    - **Python ingiere y puntúa; Java expone.** La ingesta, la normalización y el scoring se quedan en `ai/` (ya
      validados y en ejecución horaria). Los microservicios Java hacen la API de consulta, la recepción de IOCs que
      aportan las organizaciones, la autenticación por organización (Gateway) y el registro en Fabric. El contrato
      entre ambos es el esquema de PostgreSQL (`db/schema.sql`); no se llaman entre sí. Ninguna lógica se duplica.
    - **En Fabric solo se registran los IOCs que aportan las organizaciones** (procedencia que hay que garantizar).
      Los feeds públicos ya tienen su procedencia en `source`/`download`, son ~100.000 cambios al día y sus términos
      no autorizan redistribuirlos.
    - **Orden del paso 6:** API Java → Gateway → red Fabric y chaincode → conectar las aportaciones con Fabric.

## 5. Cifras de referencia

- **Unificado**: 75.511 observaciones · 74.884 indicadores únicos (46.293 URLs, 18.338 IPs, 6.307 sha256,
  3.467 dominios, 273 md5, 176 sha1, 30 cidr). blocklist.de = 93 % de las IPs individuales.
- **Validación VirusTotal** (muestra de 825, semilla 42, **completa**: 818 `ok` y 7 `not_found`; resultados en
  `ai/src/vt_results.csv`). Tasas sobre los `ok`; cobertura = parte del grupo que VirusTotal conoce:

| Grupo | n | Cobertura | ≥1 | ≥3 |
|---|---|---|---|---|
| Dominios PhishTank | 66 | 100 % | 100 % | 97 % |
| Dominios abuse.ch | 66 | 100 % | 91 % | 59 % |
| Dominios TweetFeed | 66 | 100 % | 91 % | 61 % |
| IPs individuales blocklist.de | 141 | 100 % | 90 % | 70 % |
| IPs de bloques /24 | 59 | 100 % | 98 % | 41 % |
| Dominios Tranco (3 tramos) | 198 | 100 % | 6 % | 0,5 % |
| URLs PhishTank | 32 | 97 % | 100 % | 100 % |
| URLs URLhaus | 33 | 100 % | 100 % | 73 % |
| URLs TweetFeed | 33 | 100 % | 97 % | 82 % |
| Raíces `https://dominio/` de Tranco | 30 | 100 % | 17 % | 0 % |
| sha256 ThreatFox | 49 | 98 % | 100 % | 100 % |
| sha256 TweetFeed | 45 | 90 % | 93 % | 91 % |

- **TweetFeed se gradúa**: dominios con ≥3 detecciones: 100 % si lo corroboran sus 5 feeds de referencia (n=11),
  94 % con etiqueta malware/C2 (n=18), 60 % phishing (n=30), 28 % sin etiqueta (n=18). En hashes, corroborados 100 %
  (n=23) frente a 82 % (n=22); VirusTotal no conoce 5 de 50 (10 %).
- **URLs**: el host de plataforma de doble uso no impide juzgar la URL (PhishTank 14/14 con ≥3; URLhaus 5/8). Las
  URLs de URLhaus sin confirmar son sobre todo ficheros en GitHub/Drive y binarios de botnet; las de TweetFeed,
  instaladores legítimos de ScreenConnect usados como señuelo.
- **Hashes**: el 100 % de ThreatFox es en parte circular (los motores de VirusTotal y abuse.ch comparten muestras) y su
  último análisis tiene una mediana de 34 días. Los 3 hashes de TweetFeed con 0 detecciones son ficheros Text/ICO/C.
- **IPsum gradúa las IPs individuales**: ≥3 listas → 96 % (n=54); 1–2 → 82 % (n=34); ninguna → 36 % (n=53);
  Spearman 0,71.
- **Pesos preliminares (configurables, no hay verdad contra la que validarlos)**: PhishTank ≈0,97; abuse.ch ≈0,59;
  TweetFeed ≈0,61 (≈1,00 corroborado / 0,94 malware-C2 / 0,60 phishing / 0,28 sin etiqueta); IPs individuales
  0,96 / 0,82 / 0,36 según IPsum; bloques /24 ≈0,41. Son pesos de **dominio/IP**; para URLs y hashes la evidencia
  (tabla) es más alta, pero con n=30–50 y sin decidir aún si se usan pesos distintos por tipo.
- **Modelo A, ensayo con la instantánea de `data/raw` (`learning_trial.py`, semilla 0)**: PR-AUC 0,44 con 100 registros → 0,64–0,65 con
  300 → 0,72 con 3.000 → 0,78 con 10.000 (ROC-AUC 0,88) → 0,80 con todos (ROC-AUC 0,90; test de 12.158 con 17,6 % de
  maliciosos). Sin abuse.ch en el entrenamiento, ROC-AUC 0,79 (sin PhishTank 0,92,
  sin TweetFeed 0,85): **la variedad pesa más que el volumen**. Un ensayo anterior daba 0,87 porque incluía
  plataformas compartidas (inflaba el resultado). Parámetros no obvios: `HistGradientBoostingClassifier(max_iter=200,
  learning_rate=0.1)`, `GroupShuffleSplit` 80/20 por registrable, 3 repeticiones por tamaño, 51 rasgos (11 léxicos +
  40 TLD one-hot elegidos sobre todo el conjunto: pequeña filtración que el modelo definitivo debe evitar). Semillas
  1 y 2: PR-AUC con todos 0,80–0,81, mismo orden PhishTank > TweetFeed > abuse.ch. Las filas de 100–300 son frágiles.
- **Modelo A desplegado** (`model_a.py`, versión activa `20261019T173751Z`, entrenada en WSL con scikit-learn 1.9.1;
  datos de la base de datos a 19-10-2026: 14.871 hosts maliciosos de 12.888 registrables, del 10-7 al 19-10-2026, y
  49.717 no maliciosos; prevalencia en test 0,22). Por registrable: PR-AUC 0,806 / ROC-AUC 0,892 (sin ponderar
  campañas: igual, porque `DUAL_USE` ya quitó las concentraciones). **Por tiempo** (20 % más reciente de cada
  familia): PR-AUC 0,810 / ROC-AUC 0,887, sin pérdida. Sin abuse.ch 0,804 de ROC-AUC, sin PhishTank 0,926, sin
  TweetFeed 0,837 (mismo orden que el ensayo). La primera versión (`20261019T153149Z`, scikit-learn 1.8.0, PR-AUC
  0,816 / temporal 0,808) queda inactiva: **un modelo solo se carga con la versión de scikit-learn que lo entrenó**,
  así que se entrena en el `.venv` de WSL, que es donde se usa; `score.py` lo comprueba.
  TLD elegidos solo con el entrenamiento (sin la filtración del ensayo). Platt no mejora el Brier (0,0878 → 0,0878):
  **sin calibración**, y el modelo final usa el 100 % de los datos. Reproducible exactamente con `--from-hosts`.
- **blocklist.de por DNS** (`bl.blocklist.de`, 200 IPs de `all.txt`): las 131 individuales tienen todas `Last-Attack`
  (mediana 26,7 h, siempre <48 h) y servicio coherente con las listas; las 69 de bloques no tienen fecha.
- Las consultas a VirusTotal se hicieron el 13 y el 14 de octubre de 2026 (415 y 410); no se aprecia efecto del día.
  VirusTotal devuelve el último análisis que tiene (antigüedad mediana 76 h en dominios/IPs; 8–16 días en URLs), no
  uno nuevo.

## 6. Cómo ejecutar

```bash
pip install pandas matplotlib requests tldextract dnspython scikit-learn jupyter nbformat
# Notebook (busca los CSV en VERITHREAT_DATA, data/raw, ../data/raw, ...):
VERITHREAT_DATA=../data/raw jupyter lab 01_exploration.ipynb

# Validación con VirusTotal (clave SOLO en variable de entorno; la muestra se reutiliza y se amplía sola):
export VT_API_KEY=...
python vt_sampling.py --data-dir ../data/raw --sample-only
python vt_sampling.py --data-dir ../data/raw --pause 1          # reanuda: solo consulta lo que falta

# Ensayo del modelo A (sin red; necesita scikit-learn; referencia: sklearn 1.8.0, pandas 3.0.2, numpy 2.4.4,
# tldextract 5.4.0). En otro equipo las métricas pueden variar ±0,003; el conjunto y la partición, no:
python learning_trial.py --data-dir ../data/raw [--seed 0] [--output trial_results/]

# Base de datos (Docker Desktop en marcha; POSTGRES_PASSWORD en .env; necesita pip install "psycopg[binary]"):
docker compose up -d --wait postgres            # desde la raíz del repo; el esquema se aplica la primera vez
# Conexión con variables estándar: PGHOST=127.0.0.1 PGPORT=5433 PGUSER=verithreat PGDATABASE=verithreat PGPASSWORD
python load_db.py --data-dir ../data/raw --dry-run     # sin base de datos: debe dar 75.511 / 74.884
python load_db.py --data-dir ../data/raw               # idempotente: relanzarlo dice «already loaded»
docker compose down -v                           # borra la base de datos (empezar de cero)

# Ingesta programada (AUTH_KEY y POSTGRES_PASSWORD en .env; conecta por defecto a 127.0.0.1:5433):
python ingest.py --data-dir ../data/raw                 # lo que toque; «nothing due» si no toca nada
python ingest.py --data-dir ../data/raw --sources urlhaus --force   # forzar una fuente (respetar sus términos)
python ingest.py --data-dir ../data/raw --no-db         # descargar y validar sin cargar
# Programada en Windows: tarea «VeriThreat ingest», cada hora en el minuto 7, sin ventana (conhost --headless
# wsl.exe -d Ubuntu-26.04 -e sh .../ai/src/run_ingest.sh). Necesita sesión iniciada y Docker Desktop en marcha.
#   Get-ScheduledTaskInfo "VeriThreat ingest"   |   Disable-ScheduledTask "VeriThreat ingest"
#   Get-Content ai/data/raw/ingest/ingest.log -Tail 20

# Modelo A (necesita scikit-learn y tldextract; conecta a la base de datos como load_db.py):
python model_a.py --data-dir ../data/raw --activate     # evalúa, entrena, guarda en ai/models y la activa
python model_a.py --from-hosts ../models/model_a/<versión>/training_hosts.csv --output-dir /tmp/repro   # reproducir

# Severidad (la ejecuta run_ingest.sh tras cada ingesta; usa el modelo A activo):
python score.py --data-dir ../data/raw --dry-run        # calcula y resume por categoría y tipo, sin escribir
python score.py --data-dir ../data/raw                  # guarda solo los cambios (≥5 puntos o disputado)

# Normalización compartida Python / Java:
python ai/tests/test_normalization.py

# Servicio de IOCs (en WSL, desde services/ioc-service; lee POSTGRES_PASSWORD de ../../.env):
mvn test                                         # unitarios + integración con Testcontainers (PostgreSQL 17 real)
mvn -DskipTests package && java -jar target/ioc-service-0.1.0.jar   # http://127.0.0.1:8081/swagger-ui.html
#   GET  /api/v1/indicators/lookup?type=domain&value=evil.com   GET /api/v1/indicators?category=&type=&minSeverity=
#   GET  /api/v1/indicators/{id}                                POST /api/v1/sightings  (cabecera X-Organization)

# Gateway (en WSL, desde services/gateway; GATEWAY_TOKEN en .env, el mismo para los dos servicios):
mvn -DskipTests package && java -jar target/gateway-0.1.0.jar        # http://127.0.0.1:8080/api/...
sh scripts/new-api-key.sh org-alpha "descripción"                    # clave nueva, se muestra una vez
#   curl -H "X-API-Key: vt_..." "http://127.0.0.1:8080/api/v1/indicators/lookup?type=domain&value=evil.com"

# Histórico de blocklist.de (opcional, fuera de la ingesta; --dns necesita dnspython):
python blocklist_history.py --verify 200 --verify-only --seed 7
python blocklist_history.py --dns --max-dns 500
```

La muestra (`ai/src/vt_sample.csv`, 825 indicadores) está **consultada entera**: incluye 99 URLs maliciosas
(URLhaus, PhishTank, TweetFeed; máx. 2 por dominio registrable y grupo), 30 raíces de sitios populares como base de
falsos positivos y 100 hashes sha256 (ThreatFox y TweetFeed), consultados con `/urls` y `/files` de la API v3. Si
VirusTotal nunca analizó algo, devuelve 404 → `not_found`. Relanzar el script solo consulta lo que falte; el resumen
final da la cobertura por grupo. En Windows: el `.venv` del repo es de Linux/WSL y `python-dotenv` es opcional.

## 7. Cosas NO verificadas (tratarlas como hipótesis)

- Los límites del DNS de blocklist.de: su documentación lo recomienda frente a la API HTTP «para una consulta
  estable» (y sigue activo durante un DDoS), sin cifras. VirusTotal: la API pública declara 4/min y 500/día; la
  clave del autor admite en la práctica ~0,4 s/consulta (probado en 825 consultas sin errores), pero se mantiene una
  pausa prudente y por debajo de 500 al día.
- Si alguna fuente (salvo TweetFeed e IPsum) permite redistribuir sus IOCs a terceros (resumen en la sección 3); en
  PhishTank el uso comercial está permitido, pero la redistribución no se menciona. TweetFeed no verifica los
  indicadores: no debe afirmarse que un IOC es malicioso solo por aparecer allí.
- Qué lista de IPsum contiene los bloques /24 de blocklist.de: el README de IPsum no enumera sus 30+ fuentes, así que
  no está confirmado que blocklist.de sea una de ellas.
- Que `getlast.php` devuelva IPs por último ataque (no por primera aparición); su ventana máxima declarada es 50.000 s.
  Su documentación solo dice «Get only the last added IP-Adresses», sin definir «added». No lo usa ningún script.
- Que las IPs/hosts de plataformas compartidas o sitios comprometidos sean maliciosos como dominio (no lo son).
- Sin validar con VirusTotal: md5/sha1, URLs de ThreatFox, IPs de ThreatFox y TweetFeed. Los grupos de URLs y
  hashes validados son pequeños (n=30–50, intervalos de ±10–15 puntos).
- Que los hashes de TweetFeed con 0 detecciones sean artefactos benignos y no malware sin detectar.
- La consulta DNS por IPv6 de blocklist.de: su documentación solo describe IPv4 (confirmado), así que esas IPs quedan
  `IPV6_UNSUPPORTED`; no se sabe si el servicio la admite de forma no documentada.

## 8. Reglas de trabajo

1. **Nunca** escribas claves (`VT_API_KEY`, `AUTH_KEY` de abuse.ch) en código, notebooks, logs ni commits. Los datos de
   `data/raw/` y los resultados de VirusTotal no se versionan.
2. No presentes como hecho lo que figura en la sección 7. Si una cifra cambia, actualízala en el notebook y en los dos
   documentos de referencia.
3. Mantén la **reproducibilidad**: semilla fija, fechas en UTC con zona horaria, cada consulta con su `queried_at`.
4. `DUAL_USE` y los cargadores se modifican solo en `loaders.py`; el notebook y los scripts lo importan.
5. Estados explícitos (`ok`, `not_found`, `error`, `NOT_LISTED`…); nunca texto como `ERROR` dentro de columnas numéricas.
6. Con servicios externos: reintentos con espera, pausas, reanudación sin repetir, y avisar antes de lanzar miles de
   peticiones. Probar la lógica con respuestas simuladas antes de usar la red.
7. La severidad solo se compara dentro de una categoría; no uses detecciones de VirusTotal como característica de
   entrenamiento (circular) ni la confianza/estado/familia como etiqueta.
8. Los pesos de las reglas son **configurables** y deben justificarse en la memoria del TFM.

## 9. Próximos pasos (por orden)

1. ~~Validar URLs y hashes con VirusTotal~~ (hecho el 14-10-2026; cifras en la sección 5). Pendiente de decidir:
   ¿pesos de fiabilidad distintos por tipo de indicador (URL/hash frente a dominio)?
2. ~~Esquema **PostgreSQL** y carga **idempotente**~~ (hecho el 16-10-2026, decisión 12; probado en Docker: carga
   75.511 / 74.884, segunda carga sin cambios, actualización solo con descargas más recientes, `CHECK` rechazan
   valores mal normalizados). La sección 11 del notebook ya usa `source_sightings`. IPsum se carga con la ingesta.
   Las cifras de referencia (75.511 / 74.884) son las de la exportación analizada en `data/raw`; la base de datos
   crece con la ingesta y ya no coincide con ellas.
3. ~~Ingesta programada~~ (`ingest.py`, 19-10-2026). Frecuencias: ThreatFox (API `get_iocs`, días desde el último
   éxito, máx. 7), URLhaus (`recent.csv`), blocklist.de (`all.txt`) y TweetFeed (ETag) cada hora; PhishTank
   (`online-valid.csv`, sin clave, ETag, User-Agent descriptivo) cada 6 h; IPsum cada 24 h. Cada fuente se valida y
   falla por separado; la clave nunca sale en logs ni en `state.json`. Probada con respuestas simuladas (base
   `verithreat_test`) y en real: primera ejecución → 108.818 observaciones y 107.576 indicadores, IPsum cargado
   (16.066 IPs indicador con nivel). La exportación oficial de URLhaus lleva un bloque de comentarios antes de
   `# id,...`: `load_urlhaus` salta todas las líneas iniciales con `#`. Decisiones: crudos = 3 últimas descargas
   (el registro original ya está en `sighting.raw`); **el histórico y el DNS de blocklist.de quedan fuera** (la
   descarga horaria ya da `last_confirmed_at` con resolución de 1 h; poca mejora para su coste). Programación:
   Programador de tareas de Windows → `wsl.exe … run_ingest.sh` cada hora (cron dentro de WSL solo funciona con
   WSL encendido).
4. ~~Entrenar el **modelo A**~~ (`model_a.py`, 19-10-2026; cifras en la sección 5). Decisiones: datos desde la base
   de datos con la lista exacta de hosts guardada por versión; partición por registrable, por tiempo (20 % más
   reciente de cada familia) y por familia; ponderación por registrable (hoy sin efecto, se mantiene); **sin
   calibración** (no mejoraba el Brier); `p_malicious` se usa como ordenación. Reentrenar cuando la base de datos
   haya crecido bastante (p. ej. cada mes) y activar la nueva versión solo si su PR-AUC temporal no empeora.
   Entrenar siempre en el `.venv` de WSL (scikit-learn 1.9.1).
5. ~~Fórmula de **severidad**~~ (`score.py`, 19-10-2026; decisión 13). Primera puntuación: 108.319 indicadores, 70
   disputados, 23.409 con término del modelo. Mediana por categoría y tipo: URLs de phishing 99, sha256 de
   distribución 90, URLs de distribución 58, dominios C2 60, IPs de ataque 36 (p90 96). Pendiente: justificar los
   pesos en la memoria y revisar la distribución con unos días de ingesta.
6. Integración con Java y con Fabric (decisión 14), en este orden: (a) ~~servicio Spring Boot de IOCs~~ (hecho el
   27-10-2026, `services/ioc-service`: lookup, listado, detalle y `POST /sightings`; cada organización es una fuente
   con `role = 'organization'` y familia propia, migración 002; una aportación repetida renueva `last_confirmed_at`
   en vez de duplicarse; severidad en la siguiente ejecución de `score.py` con `organization_reliability` 0,5;
   normalización Java = Python con 35 casos compartidos; 6 tests con Testcontainers; prueba de humo contra la base
   real, listado en 0,2 s); (b) ~~Gateway con autenticación por organización~~ (hecho el 27-10-2026,
   `services/gateway`, migración 003 `api_key`: solo el sha256 de cada clave de 192 bits; caché de claves válidas de
   60 s = una revocación tarda ≤ 60 s. El Gateway exige `X-API-Key`, borra `X-Organization`/`X-Gateway-Token` del
   cliente, pone la organización real y el secreto `X-Gateway-Token`; `ioc-service` rechaza /api/** sin ese secreto
   si `GATEWAY_TOKEN` está configurado. 2 + 3 tests nuevos; prueba de principio a fin con 8 comprobaciones. Fuera por
   complejidad: límite de peticiones por organización y rotación de claves); (c) ~~red Fabric y chaincode~~ (hecho
   el 28-10-2026: Fabric **2.5.16 LTS** + CA 1.5.22 instalados por el autor en `~/fabric` (WSL), fuera del repo, más
   la imagen `hyperledger/fabric-javaenv:2.5`; test-network con Org1MSP = `org-alpha` y Org2MSP = `org-beta`, canal
   `iocchannel`. Chaincode `iocregistry` (4 tests): en la cadena va la **huella** sha256 del valor, no el IOC; la
   organización sale del MSP que firma y la fecha de la transacción; hash canónico = sha256(tipo|huella|MSP|fecha);
   registros inmutables; consulta por huella con clave compuesta. Despliegue propio con `peer lifecycle` y el jar ya
   compilado (el deployCC de fabric-samples solo compila Java con Gradle). `jq` no está en WSL: `network.sh anchors`
   fija los anchor peers editando el JSON con Python (necesarios para el descubrimiento del SDK). Prueba: registro
   desde las dos organizaciones, consulta con ambos y rechazo de una huella no válida al avalar.
   **La red no sobrevive a un reinicio de Docker**: `network.sh down && network.sh up && network.sh deploy` la recrea
   vacía); (d) registrar en Fabric
   cada IOC aportado (hash canónico: tipo + valor normalizado + organización + timestamp). Entorno en WSL: Java 17,
   Maven, Docker y Node instalados; faltan los binarios de Fabric (Go no hace falta con chaincode en Java).
7. Mantenimiento: revisar `DUAL_USE` (candidatos vistos: `upload.cc`, `replit.dev`, `trycloudflare.com`,
   `wasmer.app`, `backblazeb2.com`); repetir la validación con
   VirusTotal cuando cambie el conjunto de fuentes o pasen meses.

## 10. Documentos de referencia

Guárdalos (exportados desde el visor de Claude como Markdown o PDF) en `docs/`:

- **«VeriThreat · Fase de datos: recopilación, validación y fiabilidad de las fuentes de Threat Intelligence»**:
  referencia vigente (fuentes, descartes, preparación, validación, fiabilidad, modelo, reproducción, limitaciones).
- **«Etiqueta de entrenamiento y score de riesgo para VeriThreat»**: registro de la decisión de diseño del modelo y
  del score.
- **Informe de planificación del TFM** (`informe_proyecto_threat_intel_ia_blockchain.md`): arquitectura global,
  stack y cronograma.
