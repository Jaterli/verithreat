# VeriThreat — contexto del proyecto (TFM)

> Léelo entero antes de tocar nada. Resume el estado a octubre de 2026 de la **fase de datos / módulo de IA**.
> Idioma de trabajo: **español** (código, comentarios, docstrings y documentación).

## 1. Qué es VeriThreat

Plataforma de intercambio de **Threat Intelligence** entre organizaciones (TFM Full Stack + Blockchain). Comparte
**IOCs** (dominios, URLs, hashes, IPs) con tres piezas:

- **Microservicios Java** (Spring Boot, Spring Cloud Gateway, PostgreSQL, Docker Compose; Kafka/RabbitMQ opcional):
  ingesta/normalización, API Gateway y consulta/scoring.
- **Motor de IA** (Python, scikit-learn): puntúa el riesgo de cada indicador (`severidad`) y, opcionalmente, resume
  alertas con un LLM local (Ollama).
- **Blockchain permisionada** (Hyperledger Fabric, 2–3 nodos): registra hash y procedencia de cada IOC compartido.
- **Dashboard** React (Recharts, Tailwind) para analistas.

Criterio de éxito clave: el score de riesgo debe ser **coherente y explicable**. Por eso cada componente del score se
guarda por separado y se conoce la fiabilidad de cada fuente.

**Esta carpeta (`ai/`) cubre solo la fase de datos y el modelo.** La ingesta Java, la base de datos definitiva,
Fabric y el dashboard son fases posteriores y aún no están hechas.

## 2. Estructura y archivos

Rutas según los comandos del autor (ajústalas si difieren):

```
verithreat/ai/
  src/    
    cargadores_corregidos.py     cargadores de las fuentes, lista DOBLE_USO, detección de bloques /24, IPsum
    cargadores_opcionales.py     cargadores de fuentes DESCARTADAS (MalwareBazaar, ThreatCluster); nada depende de él
    vt_muestreo.py               muestra reproducible + consulta a VirusTotal (reintentos, reanudación)
    extract_historic_blocklist.py   histórico propio de blocklist.de (en el chat: blocklist_historico.py)
  notebooks/01_exploracion.ipynb         exploración, calidad, solapes, clase no maliciosa, esquema común, validación VT
  data/raw/                      CSV de las fuentes (NO se versionan)
```

Datos esperados en `data/raw/`: `threatfox.csv`, `urlhaus.csv`, `export-ips_all.txt` (o `all.txt` de blocklist.de),
`verified_online.csv` (PhishTank), `month.csv` y `exclusive.csv` (TweetFeed), `top-1m.csv` (Tranco),
`ipsum_level1.txt` … `ipsum_level8.txt` (los descarga el notebook), `resultados_vt.csv` (salida de VirusTotal).

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

Claves y URLs de abuse.ch: las exportaciones llevan la **clave en la ruta**
(`https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv`); no escribirla en logs ni subirla al repo.
Las exportaciones `recent` cubren pocos días y se regeneran cada pocos minutos.

## 4. Decisiones de diseño (no cambiar sin documentarlo)

1. **Esquema**: un **indicador** único `(tipo, valor normalizado)` con una o varias **observaciones** (`sighting`) por
   fuente. Campos de observación: `source`, `source_family`, `source_record_id`, `seen_at` (UTC), `category`,
   `family`, `confidence`, `status`, `reporter`, `corroborado` (TweetFeed), `ipsum_nivel` (IPs).
2. **Tipos**: `sha256`, `md5`, `sha1`, `domain`, `url`, `ip`, `cidr` (un /24 completo de blocklist.de = 1 indicador).
3. **Categorías**: `malware_distribution`, `c2`, `phishing`, `attack_source`, `attack_network`, `malware`, `skimming`…
   La severidad solo se compara/pondera **dentro de una categoría**.
4. **`source_family`**: ThreatFox y URLhaus cuentan como una (`abuse.ch`). La corroboración se cuenta por **familias**,
   no por observaciones (solo 41 indicadores aparecen en dos familias).
5. **Etiqueta del modelo (opción A)**: dominio malicioso vs no malicioso. Descartadas como etiqueta: confianza
   (depende del reportero), estado online (decae con la edad), familia (133 clases). Pasan a ser **reglas**.
6. **Clase no maliciosa**: top 50.000 de Tranco menos 229 dominios que chocan con fuentes maliciosas y 43 de
   doble uso → **49.766**. Maliciosos utilizables: **11.208** (≈9.900 registrables únicos). Entrenar **a nivel de
   dominio** (host de las URLs).
7. **Fuga de información**: el modelo solo usa rasgos calculables para un dominio desconocido (longitud, entropía,
   dígitos, guiones, subdominios, TLD). Fuente, reportero, tags, familia, confianza, nº de fuentes, antigüedad, estado
   e IPsum quedan para las **reglas**.
8. **Lista `DOBLE_USO`** (en `cargadores_corregidos.py`, única fuente de verdad): plataformas donde cualquier host es
   de un usuario (GitHub, Dropbox, acortadores, `pages.dev`, `weebly.com`, `duckdns.org`, `amazonaws.com`…).
   No se etiquetan a nivel de dominio; siguen valiendo como URL/host. Antes de ampliarla: 34 registrables concentraban
   el 25 % de los hosts maliciosos.
9. **blocklist.de**: `all.txt` incluye **30 bloques /24 de 256 IPs** (7.680 IPs, ~30 % de la lista) que **no son
   ataques individuales**: sin registro DNS propio, no salen en `getlast.php`, solo en 1–2 listas de IPsum. Se
   detectan con `marcar_bloques_completos` (umbral 250) y se representan como `cidr`. Las estadísticas de fiabilidad
   se calculan solo con IPs individuales.
10. **Umbral de confirmación**: ≥3 detecciones en VirusTotal (con 1 hay mucho ruido de un motor aislado). «Disputado» =
    se guarda con severidad rebajada y marcado (p. ej. dominio popular con ≥3 detecciones).

## 5. Cifras de referencia

- **Unificado**: 75.513 observaciones · 74.886 indicadores únicos (46.295 URLs, 18.338 IPs, 6.307 sha256,
  3.467 dominios, 273 md5, 176 sha1, 30 cidr). blocklist.de = 93 % de las IPs individuales.
- **Validación VirusTotal** (muestra de 596, semilla 42, resultados en `resultados_vt.csv`; ≥1 / ≥3 detecciones):

| Grupo | n | ≥1 | ≥3 |
|---|---|---|---|
| Dominios PhishTank | 66 | 100 % | 97 % |
| Dominios abuse.ch | 66 | 91 % | 59 % |
| Dominios TweetFeed | 66 | 91 % | 61 % |
| IPs individuales blocklist.de | 141 | 90 % | 70 % |
| IPs de bloques /24 | 59 | 98 % | 41 % |
| Dominios Tranco (3 tramos) | 198 | 6 % | 0,5 % |

- **TweetFeed se gradúa**: con ≥3 detecciones, 100 % si lo corroboran sus 5 feeds de referencia (n=11), 94 % con
  etiqueta malware/C2, 60 % phishing, 28 % sin etiqueta.
- **IPsum gradúa las IPs individuales**: ≥3 listas → 96 % (n=54); 1–2 → 82 % (n=34); ninguna → 36 % (n=53);
  Spearman 0,71.
- **Pesos preliminares (configurables, no hay verdad contra la que validarlos)**: PhishTank ≈0,97; abuse.ch ≈0,59;
  TweetFeed ≈0,61 (≈1,00 corroborado / 0,94 malware-C2 / 0,60 phishing / 0,28 sin etiqueta); IPs individuales
  0,96 / 0,82 / 0,36 según IPsum; bloques /24 ≈0,41.
- **Modelo A (ensayo rápido, gradient boosting)**: PR-AUC 0,44 con 100 registros → 0,72 con 3.000 → 0,80 con todos
  (ROC-AUC 0,91; test con 17,6 % de maliciosos). Sin abuse.ch en el entrenamiento, ROC-AUC 0,79 (sin PhishTank 0,92,
  sin TweetFeed 0,85): **la variedad pesa más que el volumen**. Un ensayo anterior daba 0,87 porque incluía
  plataformas compartidas (inflaba el resultado).
- **blocklist.de por DNS** (`bl.blocklist.de`, 200 IPs de `all.txt`): las 131 individuales tienen todas `Last-Attack`
  (mediana 26,7 h, siempre <48 h) y servicio coherente con las listas; las 69 de bloques no tienen fecha.
- Las consultas a VirusTotal se hicieron en dos días (415 y 181); no se aprecia efecto del día. VirusTotal devuelve el
  último análisis que tiene (antigüedad mediana 76 h), no uno nuevo.

## 6. Cómo ejecutar

```bash
pip install pandas matplotlib requests tldextract dnspython scikit-learn jupyter nbformat
# Notebook (busca los CSV en VERITHREAT_DATA, data/raw, ../data/raw, ...):
VERITHREAT_DATA=../data/raw jupyter lab 01_exploracion.ipynb

# Validación con VirusTotal (clave SOLO en variable de entorno; la muestra se reutiliza y se amplía sola):
export VT_API_KEY=...
python vt_muestreo.py --data-dir ../data/raw --solo-muestra
python vt_muestreo.py --data-dir ../data/raw --pausa 1          # reanuda: solo consulta lo que falta

# Histórico de blocklist.de (ejecutar cada hora; --dns necesita dnspython):
python extract_historic_blocklist.py --verificar 200 --solo-verificar --semilla 7
python extract_historic_blocklist.py --dns --max-dns 500
```

`vt_muestreo.py` ya incluye, **pendientes de ejecutar**, 229 consultas nuevas: 99 URLs maliciosas (URLhaus, PhishTank,
TweetFeed; máx. 2 por dominio registrable y grupo), 30 raíces de sitios populares como base de falsos positivos y
100 hashes sha256 (ThreatFox y TweetFeed). Usan `/urls` y `/files` de la API v3; **no se han probado contra la API
real** (solo con respuestas simuladas). Si VirusTotal nunca analizó algo, devuelve 404 → `not_found`.

## 7. Cosas NO verificadas (tratarlas como hipótesis)

- Los límites de consultas del DNS de blocklist.de y de la API de VirusTotal (la clave del autor admitió ~0,4 s/consulta).
- Términos de uso y licencias de casi todas las fuentes. Solo se leyeron los de TweetFeed (datos CC0; no verifica los
  indicadores y no debe afirmarse que un IOC es malicioso solo por aparecer allí).
- Qué lista de IPsum contiene los bloques /24 de blocklist.de (quizá la propia blocklist.de).
- Que `getlast.php` devuelva IPs por último ataque (no por primera aparición); su ventana máxima declarada es 50.000 s.
- Que las IPs/hosts de plataformas compartidas o sitios comprometidos sean maliciosos como dominio (no lo son).
- Hashes, URLs completas e IPs/hashes/URLs de TweetFeed: **sin validar** con VirusTotal todavía.
- La consulta DNS por IPv6 de blocklist.de no está documentada (esas IPs quedan `IPV6_NO_SOPORTADO`).

## 8. Reglas de trabajo

1. **Nunca** escribas claves (`VT_API_KEY`, `AUTH_KEY` de abuse.ch) en código, notebooks, logs ni commits. Los datos de
   `data/raw/` y los resultados de VirusTotal no se versionan.
2. No presentes como hecho lo que figura en la sección 7. Si una cifra cambia, actualízala en el notebook y en los dos
   documentos de referencia.
3. Mantén la **reproducibilidad**: semilla fija, fechas en UTC con zona horaria, cada consulta con su `queried_at`.
4. `DOBLE_USO` y los cargadores se modifican solo en `cargadores_corregidos.py`; el notebook y los scripts lo importan.
5. Estados explícitos (`ok`, `not_found`, `error`, `NO_LISTADA`…); nunca texto como `ERROR` dentro de columnas numéricas.
6. Con servicios externos: reintentos con espera, pausas, reanudación sin repetir, y avisar antes de lanzar miles de
   peticiones. Probar la lógica con respuestas simuladas antes de usar la red.
7. La severidad solo se compara dentro de una categoría; no uses detecciones de VirusTotal como característica de
   entrenamiento (circular) ni la confianza/estado/familia como etiqueta.
8. Los pesos de las reglas son **configurables** y deben justificarse en la memoria del TFM.

## 9. Próximos pasos (por orden)

1. Ejecutar las 229 consultas de URLs y hashes con VirusTotal y actualizar las secciones de validación y fiabilidad.
2. Diseñar el esquema **PostgreSQL** (`indicator`, `sighting`, tipos incl. `cidr`, familia de fuente, categoría) y una
   carga **idempotente** (`ON CONFLICT`) desde los cargadores. Guardar crudo y fecha de descarga.
3. Pipeline de ingesta programada: abuse.ch (con clave), TweetFeed (`month.csv` + `exclusive.csv`), PhishTank,
   blocklist.de cada hora (histórico + DNS para IPs nuevas), IPsum diario.
4. Entrenar el **modelo A** con partición por campaña y por tiempo, calibrar la probabilidad (el prior es artificial),
   medir con PR-AUC y limitar el peso de campañas dominantes (`shmulc`).
5. Fórmula de **severidad**: reglas + pesos configurables, componentes guardados por separado, umbral ≥3 detecciones.
6. Integración con la ingesta Java y con Fabric (hash canónico: tipo + valor normalizado + fuente + timestamp).
7. Mantenimiento: revisar `DOBLE_USO` (candidatos vistos: `upload.cc`, `replit.dev`, `trycloudflare.com`,
   `wasmer.app`, `backblazeb2.com`); unificar el nombre del script de blocklist.de; repetir la validación con
   VirusTotal cuando cambie el conjunto de fuentes o pasen meses.

## 10. Documentos de referencia

Guárdalos (exportados desde el visor de Claude como Markdown o PDF) en `docs/`:

- **«VeriThreat · Fase de datos: recopilación, validación y fiabilidad de las fuentes de Threat Intelligence»**:
  referencia vigente (fuentes, descartes, preparación, validación, fiabilidad, modelo, reproducción, limitaciones).
- **«Etiqueta de entrenamiento y score de riesgo para VeriThreat»**: registro de la decisión de diseño del modelo y
  del score.
- **Informe de planificación del TFM** (`informe_proyecto_threat_intel_ia_blockchain.md`): arquitectura global,
  stack y cronograma.
