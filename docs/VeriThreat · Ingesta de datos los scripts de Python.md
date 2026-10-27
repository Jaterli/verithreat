# VeriThreat · Ingesta de datos: los scripts de Python

Oct 20, 2026 · @Someone

## Resumen

Cada hora, la ingesta de VeriThreat descarga las fuentes que tocan, valida cada fichero, lo normaliza a un formato común y lo carga en PostgreSQL sin duplicar nada; después recalcula la severidad de cada indicador. Funciona sola desde el 19 de octubre de 2026 y la forman cuatro ficheros de Python y un lanzador:

| Fichero | Qué hace | Quién lo ejecuta |
| --- | --- | --- |
| `ai/src/ingest.py` | Decide qué fuentes tocan, las descarga, las valida y guarda una instantánea | `run_ingest.sh`, cada hora |
| `ai/src/loaders.py` | Lee el formato propio de cada fuente y lo convierte en observaciones normalizadas | `ingest.py` (vía `load_db.py`), el notebook y los demás scripts |
| `ai/src/load_db.py` | Carga las observaciones en PostgreSQL de forma idempotente | `ingest.py`, o a mano para cargar una carpeta |
| `ai/src/score.py` | Calcula la severidad 0–100 y guarda solo los cambios | `run_ingest.sh`, después de la ingesta |
| `ai/src/run_ingest.sh` | Lanza la ingesta y la puntuación dentro de WSL y escribe el log | Tarea de Windows «VeriThreat ingest», cada hora en el minuto 7 |

Lo que garantiza: volver a cargar el mismo contenido no cambia nada; si una fuente falla, las demás siguen; cada fuente se descarga con la frecuencia que permiten sus términos; y la clave de abuse.ch nunca aparece en los registros. El esquema de la base de datos está en `db/schema.sql` y el contenedor en `docker-compose.yml`.

## loaders.py: leer y normalizar cada fuente

`loaders.py` es la única fuente de verdad sobre cómo se lee cada fuente y cómo se convierte en observaciones: lo usan la ingesta, el notebook, el modelo y la validación. Cambiar un cargador aquí cambia todos esos usos a la vez.

**Cargadores.** Cada uno resuelve las rarezas de su formato:

| Función | Fuente | Qué corrige |
| --- | --- | --- |
| `load_threatfox` | ThreatFox | Fechas a UTC; `tags` guardadas como texto de lista → lista real |
| `load_urlhaus` | URLhaus | Salta todas las líneas iniciales con `#`: la exportación oficial trae un bloque de comentarios antes de la cabecera `# id,…`. No usa `comment='#'`, que cortaría las URLs con `#` |
| `load_blocklist` | blocklist.de | Una IP por línea; columnas `ip` (forma canónica), `version` y `private` |
| `load_phishtank` | PhishTank | `unescape_amp` deshace `&amp;` (también doble); marca `recent` los últimos 90 días |
| `load_tweetfeed` | TweetFeed | Sin cabecera; dominios en minúsculas y punycode; marca `derived` (el host de una URL del mismo tweet) y `corroborated` (no aparece en `exclusive.csv`) |
| `load_ipsum` | IPsum | Nivel máximo de cada IP (nº de listas) a partir de los 8 ficheros |
| `load_tranco` | Tranco | Ranking y dominio |

**Utilidades.** `DUAL_USE` es la lista de plataformas de doble uso (GitHub, `pages.dev`, acortadores…) y `is_dual_use` comprueba un host contra ella; `registered_domain` da el dominio registrable con `tldextract` sin red; `mark_full_blocks` detecta los /24 con 250 o más IPs listadas, que se guardan como un indicador `cidr`.

**`source_sightings(fuente, carpeta, fecha_de_descarga)`** devuelve las observaciones normalizadas de una fuente, con las columnas de la tabla `sighting`: tipo, valor, identificador del registro en la fuente, categoría, fecha, familia de malware, confianza, estado, reportero, corroboración y el registro original (`raw`). Cada fuente se traduce así:

| Fuente | Identificador del registro | Categoría | Fecha (`seen_at`) |
| --- | --- | --- | --- |
| ThreatFox | `id` | `c2`, `malware_distribution`, `skimming` u `other` | `first_seen` |
| URLhaus | `id` | `malware_distribution` | `dateadded` |
| blocklist.de | la IP o el bloque `/24` | `attack_source` (IP) o `attack_network` (bloque) | la de descarga: la fuente no trae fecha |
| PhishTank | `phish_id` (solo los últimos 90 días) | `phishing` | `submission_time` |
| TweetFeed | tweet + valor (sin los dominios derivados) | `phishing`, `c2`, `malware` o `unspecified` según sus etiquetas | `date` |

Con los ficheros de referencia de `data/raw` da 75.511 observaciones y 74.884 indicadores, exactamente las cifras del notebook.

## load\_db.py: cargar en PostgreSQL sin duplicar

`load_db.py` carga una fuente a partir de sus ficheros, en una sola transacción: o entra todo, o no entra nada. Su función principal, `load_source`, la usa la ingesta para cada descarga; también se puede lanzar a mano sobre una carpeta.

Pasos de `load_source`:

1. Calcula el **sha256 del contenido** de los ficheros de la fuente (por ejemplo, `month.csv` y `exclusive.csv` juntos en TweetFeed).
2. Inserta una fila en `download` (fuente, nombre del fichero, sha256, bytes, filas, fecha de descarga). Si ese contenido ya estaba cargado, la restricción `UNIQUE(source, sha256)` lo impide y la fuente responde «already loaded» sin tocar nada más.
3. Normaliza con `source_sightings` y copia las observaciones a una tabla temporal (`COPY`, rápido).
4. Inserta los **indicadores nuevos** en `indicator` (`ON CONFLICT DO NOTHING`); la unicidad va por tipo y huella sha256 del valor, porque hay URLs de más de 25.000 caracteres.
5. Inserta las **observaciones** en `sighting`. Si una ya existía (misma fuente e identificador de registro), solo actualiza `last_confirmed_at`, `status`, `corroborated` y la última descarga, y solo si esta descarga es más reciente. La fecha original (`seen_at`) y el registro original (`raw`) no se tocan.

IPsum se carga aparte: guarda en `ipsum_signal` el nivel de cada IP que ya es indicador, una fila por IP y descarga.

| Tabla | Qué escribe `load_db.py` |
| --- | --- |
| `download` | Una fila por fichero crudo distinto |
| `indicator` | Un indicador por tipo y valor normalizado |
| `sighting` | Una observación por registro de cada fuente, con su primera y su última descarga |
| `ipsum_signal` | Nivel de IPsum por IP indicador y descarga |

La conexión usa `VERITHREAT_DSN` o las variables `PG*`; si faltan, se conecta al contenedor de `docker-compose.yml` (127.0.0.1:5433, usuario y base `verithreat`) con `POSTGRES_PASSWORD` de `.env`. Con `--dry-run` no conecta: cuenta lo que cargaría y debe dar 75.511 / 74.884 con la exportación de referencia.

## ingest.py: decidir, descargar, validar y cargar

`ingest.py` hace una pasada: comprueba qué fuentes tocan según su frecuencia, las descarga, valida lo descargado, guarda una instantánea y la carga con `load_source`. Si no toca ninguna, escribe «nothing due» y termina.

**Frecuencias y descarga por fuente** (respetan los términos de uso de cada una):

| Fuente | Qué descarga | Cada | Validación antes de cargar |
| --- | --- | --- | --- |
| ThreatFox | API `get_iocs` (POST con `Auth-Key`); pide los días desde la última descarga correcta + 1 de solape, máximo 7 | 1 h | `query_status` = `ok` y columnas obligatorias; `no_result` = nada nuevo |
| URLhaus | `recent.csv` (la clave va en la URL) | 1 h | La cabecera `# id,dateadded,url` aparece en las primeras 20 líneas |
| blocklist.de | `all.txt` | 1 h | Al menos 1.000 IPs (suele tener más de 20.000) |
| TweetFeed | `month.csv` (con ETag) y `exclusive.csv` | 1 h | Filas de 6 campos; respuesta 304 = sin cambios |
| PhishTank | `online-valid.csv` sin clave, con ETag | 6 h | Cabecera `phish_id,url,phish_detail_url`; 304 = sin cambios |
| IPsum | `ipsum_level1.txt` … `ipsum_level8.txt` | 24 h | El nivel 1 tiene al menos 1.000 IPs |

**Peticiones.** Todas llevan un User-Agent descriptivo (`VeriThreat-ingest/1.0 …`), que PhishTank exige. Los fallos de red, los 429 y los 5xx se reintentan hasta 3 veces con espera creciente (10, 20, 40 s); un 401, 403 o 404 no se reintenta. Una respuesta 304 significa «no ha cambiado» y cuenta como éxito.

**Instantáneas.** Cada descarga válida se guarda en `data/raw/ingest/<fuente>/<fecha UTC>/` con los nombres que espera `load_db.py`, y esa carpeta es la que se carga, con su fecha como fecha de descarga. Se conservan las 3 últimas por fuente: el registro original de cada observación ya queda en la base de datos.

**Estado** (`data/raw/ingest/state.json`). Por fuente guarda el último intento, el último éxito, el último resultado o error y el ETag. Una fuente toca si han pasado su intervalo menos 10 minutos de margen desde el último intento; así el cron horario no se salta una ejecución por unos segundos. El estado se guarda después de cada fuente, para que un corte no pierda lo ya hecho.

**Cerrojo.** `ingest.lock` impide dos ejecuciones a la vez; si tiene más de 2 horas, se considera abandonado y se borra.

**Opciones.** `--sources` limita las fuentes, `--force` ignora los intervalos (úsese respetando los términos, por ejemplo URLhaus no más de una vez cada 5 minutos) y `--no-db` descarga y valida sin cargar. El código de salida es 1 si alguna fuente falló.

## run\_ingest.sh, la tarea programada y score.py

**`run_ingest.sh`** ejecuta, dentro de WSL y con el `.venv` del repositorio, primero `ingest.py` y después `score.py --quiet`, y añade su salida a `data/raw/ingest/ingest.log`. La puntuación se lanza aunque falle alguna fuente, porque el decaimiento cambia con el tiempo aunque no lleguen datos nuevos. Usa rutas absolutas para que Python reconozca el entorno virtual.

**Tarea de Windows «VeriThreat ingest».** Se ejecuta cada hora en el minuto 7, sin abrir ventana:

```
conhost.exe --headless wsl.exe -d Ubuntu-26.04 -e sh ".../ai/src/run_ingest.sh"
```

`wsl.exe` arranca WSL si está apagado, por eso se eligió frente a un cron dentro de WSL, que solo funciona con WSL encendido. Si una ejecución se alarga no se lanza otra encima, y si el equipo estaba apagado se ejecuta en cuanto puede. Necesita la sesión de Windows iniciada y Docker Desktop en marcha.

**`score.py`** no es parte de la ingesta, pero es su último paso. Recalcula la severidad de todos los indicadores (unos 15 s para 108.000) con los pesos de `severity_config.json` y el modelo A activo, y añade una fila a `score` solo cuando la severidad cambia 5 puntos o más o cambia la marca de disputado. Con `--quiet` escribe una línea en el log. La fórmula se explica en el documento «Etiqueta de entrenamiento y score de riesgo».

## Garantías y decisiones de diseño

La ingesta se diseñó para poder relanzarse en cualquier momento sin dañar los datos. Estas son sus garantías, con lo que las sostiene:

| Garantía | Cómo se consigue |
| --- | --- |
| Recargar no duplica | sha256 del contenido en `download`; indicadores y observaciones con `ON CONFLICT` |
| Lo antiguo no pisa lo nuevo | Una observación solo se actualiza si la descarga es más reciente que la que ya tenía |
| Todo o nada por fuente | Cada fuente se carga en una transacción; un fallo a mitad no deja datos a medias |
| Una fuente caída no para las demás | Cada fuente en su propio bloque de errores; el resto continúa y el log dice cuál falló y por qué |
| No se carga basura | Validación del formato antes de guardar (cabecera, nº mínimo de filas, columnas) |
| Se respetan los términos de uso | Frecuencias por fuente, peticiones condicionales con ETag y User-Agent descriptivo |
| La clave no se filtra | `AUTH_KEY` solo en el entorno o en `.env`; los mensajes de error se limpian antes de escribirse; en `download` solo se guarda el nombre del fichero, nunca la URL |
| Dos ejecuciones no se pisan | Cerrojo con caducidad de 2 horas |

Tres decisiones se tomaron por simplicidad, porque mejoraban poco la detección:

- **Solo se guardan las 3 últimas descargas** de cada fuente: el registro original ya está en `sighting.raw` y guardar todo ocuparía varios GB al mes.
- **El histórico y la consulta DNS de blocklist.de quedan fuera** (`blocklist_history.py` sigue disponible a mano): la descarga horaria ya da la última confirmación con resolución de una hora.
- **PhishTank sin clave de aplicación, cada 6 horas**: cumple su límite de «unas pocas descargas al día» y unas horas de retraso apenas importan.

## Cómo ejecutarlo y comprobar que funciona

Requisitos: Docker Desktop en marcha con el contenedor `postgres` (`docker compose up -d --wait postgres`), `AUTH_KEY` y `POSTGRES_PASSWORD` en `.env`, y en el `.venv` de WSL `pandas`, `requests`, `psycopg`, `tldextract`, `python-dotenv` y, para la puntuación, `scikit-learn`.

Comandos, desde `ai/src`:

```
python ingest.py --data-dir ../data/raw                          # lo que toque
python ingest.py --data-dir ../data/raw --sources phishtank --force
python ingest.py --data-dir ../data/raw --no-db                  # descargar y validar sin cargar
python load_db.py --data-dir ../data/raw --dry-run               # contar sin base de datos
python score.py --data-dir ../data/raw --dry-run                 # severidad sin escribir
```

Para vigilar la tarea, desde PowerShell:

```
Get-ScheduledTaskInfo "VeriThreat ingest"          # última ejecución y resultado (0 = bien)
Get-Content ai/data/raw/ingest/ingest.log -Tail 20
Disable-ScheduledTask "VeriThreat ingest"          # pararla
```

Una hora normal deja en el log una línea por fuente procesada y una de la puntuación, por ejemplo: `threatfox 2,689 sightings (2,689 new or updated), 33 new indicators` … `score 108,319 indicators scored, 0 new score rows`. Un fallo aparece como `FAILED:` con el motivo, y en `state.json` como `last_error`.

En la base de datos, la tabla `download` dice cuándo se cargó cada fuente por última vez:

```
SELECT source, count(*) AS downloads, max(fetched_at) AS last FROM verithreat.download GROUP BY source;
```

Las pruebas hechas antes de ponerla en marcha están en el historial del proyecto: con respuestas simuladas sobre una base de datos de prueba (primera carga, repetición, 304, fuentes caídas, poda de instantáneas, cerrojo y ausencia de la clave en la salida) y una primera ejecución real el 19-10-2026 que llevó la base de datos a 108.818 observaciones y 107.576 indicadores.

## Limitaciones y pendientes

- **Depende del equipo del autor:** la tarea solo corre con la sesión de Windows iniciada y Docker Desktop en marcha. En el paso 6 la ejecución periódica puede pasar a un contenedor o al microservicio Java.
- **Sin alertas:** si una fuente falla varias horas seguidas, solo queda en el log y en `state.json`.
- **El log crece sin rotación,** unas pocas líneas por hora (del orden de MB al año).
- **Formatos externos:** un cambio de formato en una fuente hace fallar su validación y la fuente se queda sin actualizar hasta corregir el cargador, como pasó con la cabecera de URLhaus en la primera ejecución real.
- **Recolección y redistribución:** los términos de abuse.ch prohiben la recolección masiva automatizada sin cifra concreta (la ingesta descarga muy por debajo de su generación cada 5 minutos), y ninguna fuente salvo TweetFeed e IPsum autoriza expresamente redistribuir sus indicadores.
- **La base de datos ya no coincide con las cifras de referencia** de los documentos de fase (75.511 / 74.884), que salen de la exportación analizada; crece cada hora con la ingesta.
- **Scripts antiguos:** `threatfox_download_data.py` y `virustotal_*_filter.py` quedan sustituidos por `ingest.py` y `vt_sampling.py`; se pueden retirar.
