# VeriThreat · Fase de datos: recopilación, validación y fiabilidad de las fuentes de Threat Intelligence

*Documento de fase del TFM · Octubre 2026 · Estado: fuentes definitivas; validación con VirusTotal completa (825 indicadores: dominios, IPs, URLs y hashes)*

## 1. Resumen

VeriThreat es una plataforma para compartir indicadores de compromiso (IOCs: dominios, URLs, hashes e IPs asociados a actividad maliciosa) entre organizaciones. Incorpora un motor de IA que puntúa el riesgo de cada indicador y una blockchain que registra quién lo reportó y cuándo. Esta fase responde a tres preguntas: de dónde salen los datos, cómo se preparan y hasta qué punto se puede confiar en ellos.

En lenguaje llano: se evaluaron más de quince fuentes abiertas y se ha dejado un conjunto deliberadamente corto, con **cinco fuentes de indicadores, una señal de fiabilidad y una lista de dominios populares**. Todo lo que aportaba poco o añadía complejidad se ha descartado. Los datos se unifican en un formato común y se contrastan con VirusTotal, un servicio que agrupa más de 90 motores antivirus. **Las fuentes son razonablemente fiables**: entre el 90 y el 100 % de los dominios, IPs, URLs y hashes maliciosos medidos tienen al menos una detección independiente, frente al 6 % de los dominios populares. Con tres o más detecciones, que es el umbral de confirmación, las diferencias entre fuentes y tipos son grandes. Este documento las detalla.

Cifras clave:

- **75.511 observaciones y 74.884 indicadores únicos** (con PhishTank limitado a 90 días y los bloques /24 de blocklist.de contados como un indicador de red cada uno).
- **Solo 41 indicadores aparecen en dos familias de fuentes distintas**: las fuentes se complementan más que se corroboran.
- **11.208 dominios maliciosos (unos 9.900 dominios registrables) y 49.767 no maliciosos** utilizables para el modelo de IA.
- **825 indicadores consultados a VirusTotal**: 818 con análisis y 7 que VirusTotal nunca había visto (6 hashes y 1 URL).
- **Confirmación con ≥3 detecciones**: PhishTank 97 % (dominios) y 100 % (URLs); abuse.ch 59 % (dominios), 73 % (URLs de URLhaus) y 100 % (hashes de ThreatFox); TweetFeed 61 % (dominios), 82 % (URLs) y 91 % (hashes); IPs individuales de blocklist.de 70 %.
- **Se descartan MalwareBazaar y ThreatCluster**, además de otras fuentes evaluadas (sección 3).

Tres ideas para recordar:

1. ThreatFox y URLhaus son de abuse.ch y no son independientes entre sí: que coincidan no equivale a una corroboración fuerte.
2. Popular no es lo mismo que benigno, y el host de una URL maliciosa no siempre es un dominio malicioso (puede ser una plataforma compartida o un sitio legítimo comprometido).
3. VirusTotal es una referencia útil, pero no una verdad absoluta: sus motores consumen fuentes como estas.

## 2. Contexto y objetivo

El informe del proyecto define una plataforma con microservicios en Java, un motor de IA para puntuar el riesgo de los IOCs y una blockchain permisionada para garantizar su trazabilidad. Uno de los criterios de éxito exige que la puntuación de riesgo sea **coherente y explicable**, lo que obliga a conocer con precisión qué datos alimentan el score y qué fiabilidad tienen.

Esta fase cubre la recopilación y preparación de los datos, la decisión sobre qué etiqueta aprende el modelo, la selección de fuentes y la validación externa. Quedan fuera, y son fases posteriores, la ingesta automática, la base de datos definitiva, la integración con la blockchain y el dashboard.

El documento está pensado para cuatro usos: implementar la fase, conocer su fiabilidad, mejorarla ahora o en el futuro y explicarla a posibles interesados en la plataforma.

## 3. Decisión de fuentes

### 3.1 Criterios

Cada fuente se evaluó con los mismos cinco criterios, y solo se mantiene si aporta valor claro:

- **Cobertura nueva**: cuántos indicadores aporta que las demás no tienen.
- **Fiabilidad medida**: qué proporción confirma VirusTotal sobre una muestra.
- **Metadatos**: fecha, categoría y procedencia por indicador.
- **Independencia**: si comparte origen con otra fuente.
- **Coste de complejidad**: formato, estabilidad, licencia y mantenimiento.

### 3.2 Se mantienen

| Fuente | Qué aporta | Datos | Por qué se queda |
| --- | --- | --- | --- |
| ThreatFox (abuse.ch) | IOCs mixtos (hashes, dominios, URLs, ip:puerto) con familia, confianza y etiquetas; única fuente con C2 | 11.941 registros · 7 días | Metadatos más ricos y categoría de C2 |
| URLhaus (abuse.ch) | URLs de distribución de malware con estado online u offline | 31.166 · 31 días | Mayor volumen de URLs y señal de actividad |
| blocklist.de | IPs que atacan servicios | 24.714 (24.121 IPv4 y 593 IPv6) · sin fechas; incluye 30 bloques /24 completos | Única fuente grande de IPs; con IPsum se puede graduar su fiabilidad |
| PhishTank | URLs de phishing verificadas por la comunidad | 69.007 (12.606 en 90 días) | La más fiable de las medidas y una categoría nueva |
| TweetFeed (`month.csv`) | IOCs de investigadores, con reportero, etiquetas y enlace al tweet | 4.323 filas · 30 días | Mayor aporte de cobertura nueva y procedencia verificable |
| IPsum | Número de listas en las que aparece cada IP; es una señal, no aporta indicadores | 119.353 IPs | Separa muy bien las IPs fiables de las dudosas (sección 8) |
| Tranco | Ranking de popularidad | top 50.000 | Única base de la clase no maliciosa |

### 3.3 Se descartan

| Fuente o enfoque | Motivo | Cuándo reconsiderarlo |
| --- | --- | --- |
| MalwareBazaar | Solo hashes (1.383 muestras en 2 días, el 17 % de los sha256); el modelo no usa hashes y no están validados; su formato (comentarios, `n/a`, valores entre comillas) añade complejidad; ThreatFox ya aporta unos 6.000 sha256 | Si hacen falta atributos de fichero o vincular md5, sha1 y sha256 |
| ThreatCluster | 607 dominios y 862 hashes (≈1,7 % de los indicadores), 0 dominios en común con ThreatFox, confianza siempre `high` y 3 de 53 dominios sin detección, uno un sitio informativo: la corroboración independiente esperada no se materializó | Si se mide un valor claro con su feed completo |
| AlienVault OTX | Solo 754 registros, fechas hasta 2025 frente a 2026 en el resto y esquema distinto | Si se necesitan CVE o YARA, o más volumen |
| Feodo Tracker | Conjuntos vacíos tras los derribos policiales (Emotet en 2021, Operación Endgame en 2024) | Cuando vuelva a publicar datos |
| Spamhaus (listas DNS) | El acceso gratuito dura 30 días por API: no sirve para ingesta continua | Si hay acceso sostenido |
| `IoCs_Identifiers.json` | 200 dominios alfabéticos, subconjunto del top 10.000 de Tranco, sin veredictos ni IPs (queda por aclarar si se subió el archivo correcto) | Si se aporta una exportación completa con veredictos |
| Filtro de Bloom de CIRCL (0,7–1 GB) | Casi todo es SHA-1 y la mayoría de nuestros hashes SHA-256; solo indica «conocido», no «benigno»; un hash no sirve para entrenar | Tras medir con la API cuántos de nuestros hashes aparecen |
| MISP como vía principal | Duplicaría los datos de abuse.ch y añade servicios (base de datos, caché) | Tras probar un solo feed ajeno a abuse.ch |
| vciso.au | Agregador de otros feeds, datos no accesibles desde el entorno de trabajo y licencia sin ver | Si se descarga una muestra con la lista de feeds de origen |
| C2IntelFeeds y C2-Tracker | 238 IPs y 89 dominios en 30 días, etiquetas «Possible», sin fechas y una IP no enrutable; la URL de C2-Tracker del catálogo da error 404 y ThreatFox ya cubre C2 | Si hace falta más variedad de C2 |
| FireHOL level1 | Lista de rangos (≈611 millones de direcciones), no de indicadores | n/a |
| Otras listas de IPs de ataque (GreenSnow, CINS, Emerging Threats, Binary Defense, Snort...) | Misma semántica que blocklist.de, y IPsum ya las resume | n/a |
| CERT.PL, CERT-FR, Botvrij, SiberKapan, OpenPhish y Phishing Army | No analizadas (no accesibles desde el entorno) o marginales frente a PhishTank y TweetFeed | Si aparece un hueco medible |

Se descartan también, como enfoque: usar confianza, estado o familia como etiqueta del modelo, y las detecciones de VirusTotal como característica de entrenamiento (sección 9); y usar Tranco o PhishTank completos, que se emplean filtrados (top 50.000 y 90 días).

## 4. Método seguido

1. **Exploración inicial** (notebook `01_exploration.ipynb`). Se revisó el cargador original y se corrigieron los fallos que impedían leer bien los CSV: nombres de columna de ThreatFox, comparación de fechas con y sin zona horaria, `tags` almacenados como texto de lista, cabecera `# id` de URLhaus y valores `n/a` o `None` tratados como texto.
2. **Evaluación de fuentes.** Cada candidata se midió con los criterios de la sección 3: volumen, solape con las demás, calidad del formato y, cuando fue posible, validación con VirusTotal.
3. **Poda.** Se dejó solo lo que aporta valor claro y se descartó lo marginal.
4. **Esquema común.** Un indicador único con una observación por cada fuente que lo reporta, con categoría de amenaza, familia de fuente y nivel de IPsum.
5. **Clase no maliciosa.** Un top de Tranco depurado, necesario porque todas las fuentes contienen solo amenazas.
6. **Lista de doble uso.** Plataformas y servicios compartidos que no deben etiquetarse como maliciosos a nivel de dominio.
7. **Validación externa.** Una muestra aleatoria y reproducible consultada a la API de VirusTotal con `vt_sampling.py`.
8. **Ensayo de aprendizaje.** Un experimento rápido para estimar cuántos datos necesita el modelo.

## 5. Preparación de los datos

### 5.1 Reglas de normalización

- Tipos unificados: `sha256`, `md5`, `sha1`, `domain`, `url`, `ip` y `cidr`. En ThreatFox, `ip:port` se separa en IP y puerto.
- Hosts y hashes en minúsculas; las URLs conservan su capitalización.
- `n/a` y `None` pasan a nulos reales, y todas las fechas a UTC con zona horaria.
- PhishTank: se deshace `&amp;` antes de deduplicar (4.213 URLs lo llevaban, 45 con doble escape `&amp;amp;`; tras limpiarlas quedan 237 duplicadas). Solo se sustituye `&amp;`: un decodificador HTML genérico (`html.unescape`) alteraba 48 URLs al interpretar parámetros como entidades (`&regform=` → `®form=`).
- TweetFeed: los dominios que son solo el host de una URL del mismo tweet (1.587 de 1.620, el 98 %) se marcan como derivados y no cuentan como observación; los nombres no ASCII (12 valores, entre ellos homógrafos cirílicos y dominios `.zip` japoneses) se pasan a punycode.
- blocklist.de: como fecha de observación se usa la de descarga del archivo; se aceptan IPv4 e IPv6 y se descartan las privadas. `all.txt` incluye **30 bloques /24 completos** (7.680 IPs, casi un tercio del IPv4) que no son ataques individuales: no tienen registro propio en el DNS de blocklist.de ni aparecen en su lista de últimos ataques, y solo están en 1–2 listas de IPsum. Se detectan (un /24 con 250 o más IPs listadas) y cada bloque se guarda como un indicador `cidr` con categoría `attack_network`. Las estadísticas de fiabilidad de IPs se calculan solo con IPs individuales.
- La unicidad se garantiza sobre la pareja (tipo, valor normalizado).

### 5.2 Esquema común

Cada IOC es un **indicador** único con una o varias **observaciones** (una por fuente y registro original). Cada observación guarda: fuente, familia de la fuente, identificador de origen, fecha, categoría de amenaza, familia de malware, confianza, estado, reportero, si TweetFeed lo marca como corroborado por otros feeds y, para IPs, el nivel de IPsum.

- **Categoría de amenaza** (`malware_distribution`, `c2`, `phishing`, `attack_source`, `malware`...): cada fuente mide algo distinto, y la severidad solo debe compararse, o ponderarse, dentro de una misma categoría.
- **Familia de la fuente**: ThreatFox y URLhaus cuentan como una (abuse.ch). La corroboración se cuenta por familias, no por observaciones.
- **Nivel de IPsum**: número de listas (0 a 8) en las que aparece una IP; es la señal de fiabilidad de las IPs.

### 5.3 Clase no maliciosa y lista de doble uso

Todas las fuentes contienen solo amenazas, así que el modelo necesita ejemplos negativos. Se parte del top 50.000 de Tranco y se excluyen **228 dominios que chocan con las fuentes maliciosas** y **43 de doble uso**, de modo que quedan **49.767 dominios no maliciosos**. (Una versión anterior del notebook daba 229 y 49.766: excluía por error `bet.br`, un sufijo público sin dominio registrable, porque los hosts que son IP también tienen registrable vacío y contaban como choque.)

La lista de doble uso reúne cuatro tipos de servicio, donde cualquier host pertenece a un usuario y no a la plataforma:

- Almacenamiento y compartición de ficheros (GitHub, Dropbox, Pastebin, Discord, Mega...).
- Acortadores y generadores de QR (bit.ly, qrco.de, t.co...).
- Plataformas de subdominios, constructores de sitios y DNS dinámico (pages.dev, weebly.com, duckdns.org, replit.app...).
- Almacenamiento en la nube (amazonaws.com, windows.net, r2.dev...).

La ampliación de esta lista salió de los datos: antes de añadirlas, 34 dominios registrables concentraban 3.401 hosts maliciosos (el 25 %), con `pages.dev` (1.007) y `weebly.com` (702) a la cabeza. Con la lista ampliada quedan **11.208 dominios maliciosos utilizables** (unos 9.900 registrables únicos) y esa concentración baja al 1 % (9 registrables agrupan 117 hosts). Los hosts bajo esas plataformas siguen siendo válidos como URLs o hosts, pero no como dominio etiquetado.

## 6. Hallazgos de calidad

- **Concentración por campaña**: el reportero `shmulc` aporta el 44 % de las URLs de URLhaus (13.795), casi todas alojadas en `githubusercontent.com`.
- **Concentración por fuente**: blocklist.de aporta el 93 % de las IPs individuales.
- **Plataformas compartidas**: en PhishTank, `docs.google.com` (5.247 URLs), `qrco.de` (4.591), `q-r.to` (3.512), `l.ead.me` (3.293) y `bit.ly` (1.771); en total, 8.394 URLs tienen su host en el top 100.000 de Tranco. En TweetFeed, el 8,4 % de las URLs está en plataformas de doble uso.
- **Columnas inútiles**: `last_seen` de ThreatFox está vacío al 81 %; en TweetFeed el 35 % de las filas no tiene etiqueta.
- **Ventanas distintas**: de 7 días (ThreatFox) a 31 (URLhaus y TweetFeed); PhishTank llega a 2011 y blocklist.de no tiene fechas. La ausencia de un indicador en una fuente no implica que esté inactivo ni que sea benigno.
- **Solapamiento muy bajo**: 66 URLs entre ThreatFox y URLhaus, ninguna entre PhishTank y las demás, 0 de las 822 IPs de ThreatFox en blocklist.de, y en TweetFeed solo el 2 % de las URLs y el 2,6 % de las IPs ya estaban en las demás fuentes.
- **Volumen unificado por tipo**: 46.293 URLs, 18.338 IPs individuales, 6.307 sha256, 3.467 dominios, 273 md5, 176 sha1 y 30 bloques /24 (`cidr`).

## 7. Validación con VirusTotal

### 7.1 Diseño

Se consulta la API v3 de VirusTotal sobre una muestra reproducible (semilla 42) de **825 indicadores** de los cuatro tipos:

| Grupo | Origen | Tamaño |
| --- | --- | --- |
| IPs | blocklist.de, aleatoria (141 individuales y 59 de bloques /24) | 200 |
| Dominios maliciosos | abuse.ch / PhishTank (90 días) / TweetFeed | 66 cada uno |
| Dominios no maliciosos | Tranco, tramos 1–1.000 / 1.001–10.000 / 10.001–50.000 | 66 cada tramo |
| URLs maliciosas | URLhaus / PhishTank (90 días) / TweetFeed, con un máximo de 2 por dominio registrable | 33 cada una |
| URLs no maliciosas | Raíz `https://dominio/` de sitios del top 10.000 de Tranco | 30 |
| Hashes sha256 | ThreatFox / TweetFeed | 50 cada uno |

Los dominios maliciosos excluyen plataformas de doble uso y el top 10.000 de Tranco, y los no maliciosos excluyen los que chocan con las fuentes maliciosas. Las URLs sí pueden estar en plataformas de doble uso, porque se juzgan como URL y no como dominio. El límite de dos URLs por dominio registrable evita que una sola campaña domine un grupo.

Las consultas no piden análisis nuevos: VirusTotal devuelve el último que tiene (en dominios e IPs, con una antigüedad mediana de 76 horas; en URLs, de 8 a 16 días; en hashes de ThreatFox, de 34 días). Si nunca ha visto una URL o un hash, responde que no lo conoce, y el indicador queda como `not_found`: cuenta para la **cobertura** del grupo, no para sus tasas de detección.

### 7.2 Ejecuciones realizadas

- **Primera prueba:** 250 IPs de blocklist.de, pero eran las primeras en orden alfabético (rangos `1.`, `101.` y `102.`) y 156 filas dieron error de forma contigua, por lo que solo había 94 válidas. Con esa muestra sesgada salía un 83 % de IPs con detección.
- **Corrección del script:** muestra aleatoria con semilla, orden de consulta barajado, reintentos con espera, reanudación sin repetir y estado explícito por fila.
- **Prueba extensa:** 485 consultas en dos tandas de 240, cada una en unos 100 segundos (≈0,4 s por consulta), todas con respuesta correcta. Incluyó un grupo de ThreatCluster (53 dominios) que se conserva solo como evidencia histórica.
- **Muestra final:** tras podar fuentes y ampliar la lista de doble uso, el script adaptó la muestra anterior sin repetir lo ya consultado. El 13 de octubre de 2026 había 415 consultas válidas y el 14 se hicieron las 410 restantes: 181 de dominios e IPs (66 de TweetFeed) y 229 de URLs y hashes. No se aprecia efecto del día.
- **Corrección de una URL:** una URL de PhishTank se consultó primero con `&amp;` sin deshacer (doble escape en el origen) y VirusTotal no la conocía. Tras corregir la limpieza (sección 5.1) se volvió a consultar y tiene 17 detecciones.

### 7.3 Resultados

| Grupo | n | Cobertura | ≥1 detección | IC 95 % | ≥3 detecciones | IC 95 % |
| --- | --- | --- | --- | --- | --- | --- |
| Dominios PhishTank | 66 | 100 % | 100 % | 94–100 | 97 % | 90–99 |
| Dominios abuse.ch | 66 | 100 % | 91 % | 82–96 | 59 % | 47–70 |
| Dominios TweetFeed | 66 | 100 % | 91 % | 82–96 | 61 % | 49–71 |
| IPs individuales (blocklist.de) | 141 | 100 % | 90 % | 84–94 | 70 % | 62–77 |
| IPs de bloques /24 (blocklist.de) | 59 | 100 % | 98 % | 91–100 | 41 % | 29–53 |
| Dominios de Tranco (3 tramos) | 198 | 100 % | 6 % | 4–10 | 0,5 % | 0–3 |
| URLs PhishTank | 32 | 97 % | 100 % | 89–100 | 100 % | 89–100 |
| URLs URLhaus | 33 | 100 % | 100 % | 90–100 | 73 % | 56–85 |
| URLs TweetFeed | 33 | 100 % | 97 % | 85–99 | 82 % | 66–91 |
| Raíces de sitios de Tranco | 30 | 100 % | 17 % | 7–34 | 0 % | 0–11 |
| sha256 ThreatFox | 49 | 98 % | 100 % | 93–100 | 100 % | 93–100 |
| sha256 TweetFeed | 45 | 90 % | 93 % | 82–98 | 91 % | 79–96 |
| ThreatCluster (descartada, histórico) | 53 | 100 % | 94 % | 85–98 | 74 % | 60–84 |

IC 95 % es el intervalo de confianza de Wilson: el rango en el que, con un 95 % de seguridad, está la proporción real. Las tasas se calculan sobre los indicadores que VirusTotal conoce.

- **Dominios.** PhishTank es la fuente más fiable (97 % con ≥3 detecciones). abuse.ch y TweetFeed quedan parecidas (59 y 61 %), pero TweetFeed se puede graduar por etiqueta y corroboración (sección 8.1).
- **IPs.** Las individuales se confirman en un 70 %; los bloques /24 casi siempre tienen alguna detección (98 %), pero solo el 41 % llega a tres: el rango aparece en alguna lista, pero cada IP rara vez tiene actividad propia. Ninguna IP tiene reputación positiva. Siete IPs de Cisco Webex tienen 0–2 detecciones, lo que sugiere infraestructura legítima de un servicio (hipótesis sin verificar).
- **URLs.** Se confirman más que los dominios de la misma fuente (URLhaus 73 % frente a 59 % de abuse.ch; TweetFeed 82 % frente a 61 %): una URL concreta contiene la ruta maliciosa, mientras que su host puede ser un sitio legítimo comprometido. En plataformas de doble uso la URL sigue siendo juzgable: 14 de 14 URLs de PhishTank en plataformas tienen ≥3 detecciones, y 5 de 8 de URLhaus.
- **Hashes.** Casi todos se confirman. El 100 % de ThreatFox es en parte circular, porque abuse.ch y los motores de VirusTotal comparten muestras. En TweetFeed, VirusTotal no conoce el 10 % de los hashes (5 de 50).
- **Clase no maliciosa.** Solo 12 de 198 dominios de Tranco (6 %) tienen alguna detección y solo 1 (0,5 %) tiene tres o más. De las 30 raíces de sitios populares, 5 tienen 1–2 detecciones y ninguna llega a tres.

### 7.4 Casos discordantes

- **Dominios de Tranco con detecciones.** Once tienen una sola detección y reputación 0 o negativa (`nginx.com`, `avito.ru`, `mixcloud.com`, `eepurl.com`, `tripod.com`...): falsos positivos de un motor aislado o, en `tripod.com` y `eepurl.com`, plataformas donde publican terceros. Con tres o más solo queda `123tt.ru` (10 detecciones), que se trataría como **disputado**.
- **Raíces de sitios populares con detecciones:** `bxcdn.net` (2), `evernote.com`, `fitgirl-repacks.site`, `gamebanana.com` y `missav.live` (1 cada uno).
- **Dominios maliciosos sin ninguna detección.** Ninguno de PhishTank. En abuse.ch, 6 (`dieuhoadaikin.com.vn`, `110digitech.com.au`, `industriaalimenticiasanjuan.com`, `mghsolutions.com.au`, `venamyko.com` y `upload.cc`). Parecen sitios de empresas, probablemente comprometidos (hipótesis), salvo `upload.cc`, una plataforma de subida de ficheros candidata a la lista de doble uso. En TweetFeed, 6 dominios con aspecto de phishing (`share-files-onedrive.com`, `joyalukkas-karama.store`...): probablemente aún sin analizar, no benignos.
- **URLs maliciosas sin confirmar (<3 detecciones).** En URLhaus, ficheros en GitHub o Google Drive y binarios de botnet servidos desde IPs (`/i`, `skid.arm64`). En TweetFeed, instaladores legítimos de ScreenConnect (una herramienta de acceso remoto usada como señuelo) y `script.google.com`. En todos el contenido es lo malicioso, no el host.
- **Hashes de TweetFeed con 0 detecciones:** tres ficheros de tipo Text, ICO y C, probablemente artefactos de un análisis y no malware (hipótesis).
- **ThreatCluster:** los 3 dominios sin detección, entre ellos `zombieloadattack.com` (el sitio informativo de la vulnerabilidad ZombieLoad), fueron uno de los motivos para descartarla.

## 8. Fiabilidad de los datos

### 8.1 Por fuente y tipo de indicador

| Fuente o tipo | Evidencia (≥3 detecciones) | Fiabilidad estimada | Cómo usarla |
| --- | --- | --- | --- |
| PhishTank (90 días) | Dominios 97 % (n=66); URLs 100 % (n=32), también en plataformas | Alta | Peso alto. Filtrar por fecha; las URLs de plataformas compartidas se juzgan a nivel de URL |
| abuse.ch: dominios (hosts) | 59 % (n=66) | Media | El host de una URL de malware puede ser un sitio legítimo comprometido |
| abuse.ch: URLs de URLhaus | 73 % (n=33) | Media-alta | Peso mayor que el del host |
| abuse.ch: hashes de ThreatFox | 100 % (n=49); en parte circular | Alta | Peso alto, con la reserva de la circularidad |
| TweetFeed: dominios | 61 % de media (n=66): 100 % corroborados (n=11), 94 % malware/C2 (n=18), 60 % phishing (n=30), 28 % sin etiqueta (n=18) | De baja a alta según etiqueta y corroboración | Peso graduado |
| TweetFeed: URLs | 82 % (n=33); 83 % phishing (n=18), 67 % sin etiqueta (n=9) | Media-alta | Peso graduado por etiqueta |
| TweetFeed: hashes | 91 % (n=45): 100 % corroborados (n=23), 82 % no corroborados (n=22); cobertura 90 % | Alta | Peso alto si está corroborado |
| blocklist.de: IPs individuales con IPsum | 70 % (n=141); 96 %, 82 % o 36 % según IPsum | De baja a alta según IPsum | Peso graduado por el nivel de IPsum |
| blocklist.de: bloques /24 | 41 % (n=59) | Baja | Indicador de red (`cidr`) con peso bajo |
| md5, sha1, URLs e IPs de ThreatFox, IPs de TweetFeed | No validados | Sin medir | Reglas por ahora |
| Tranco como clase no maliciosa | 0,5 % (n=198); 6 % con alguna detección | Alta como aproximación | Disputar los dominios con ≥3 detecciones |

Los grupos de URLs y hashes son pequeños (30–50 indicadores, intervalos de ±10–15 puntos) y los subgrupos por etiqueta aún más: son pautas, no medidas precisas.

### 8.2 IPsum como señal de fiabilidad de las IPs

IPsum no aporta indicadores propios: indica en cuántas listas aparece cada IP. Cruzado con las 141 IPs individuales de blocklist.de consultadas en VirusTotal, separa muy bien las fiables de las dudosas:

| Aparece en IPsum | n | ≥3 detecciones | IC 95 % |
| --- | --- | --- | --- |
| ≥3 listas | 54 | 96 % | 87–99 |
| 1–2 listas | 34 | 82 % | 66–92 |
| No aparece | 53 | 36 % | 24–49 |

La correlación de Spearman entre el nivel de IPsum (0 a 8) y las detecciones es 0,71. El 70 % medio de las IPs individuales esconde esa variación enorme. Los bloques /24 se excluyen de este cálculo: casi todos están solo en 1–2 listas de IPsum, quizá en la propia de blocklist.de (sin verificar).

Precauciones: los grupos son pequeños, no se sabe si IPsum usa blocklist.de como entrada y los motores de VirusTotal probablemente consumen listas parecidas, de modo que parte de la relación es circular. Es una señal relativa muy útil, no una verdad. IPsum se actualiza a diario, así que los niveles cambian con la fecha de descarga.

### 8.3 Qué se puede afirmar y qué no

Se puede afirmar que la gran mayoría de los dominios, IPs, URLs y hashes de estas fuentes están respaldados por al menos un motor independiente, que la clase no maliciosa es casi toda limpia, que una URL concreta se confirma más que el dominio que la aloja, que la fiabilidad de las IPs depende mucho de su corroboración y que combinar fuentes y reglas es defendible con la evidencia actual.

No se puede afirmar que un indicador sea malicioso con certeza, que las diferencias pequeñas entre grupos sean reales (los intervalos se solapan), que los md5, sha1 y las IPs de ThreatFox y TweetFeed tengan la misma fiabilidad que lo medido, ni que exista una severidad real con la que comparar el score: solo hay una referencia externa aproximada.

### 8.4 Criterios de decisión propuestos

- **Umbral de tres detecciones** para confirmar un indicador o para disputar un dominio popular. Con una sola detección el ruido de un motor aislado es alto.
- **Peso de fiabilidad por fuente** igual a su tasa de confirmación con ≥3 detecciones en dominios e IPs: PhishTank ≈0,97 y abuse.ch ≈0,59. TweetFeed, graduado: ≈1,00 si está corroborado, ≈0,94 con etiqueta de malware o C2, ≈0,60 de phishing y ≈0,28 sin etiqueta. blocklist.de, graduado por IPsum: ≈0,96 con tres o más listas, ≈0,82 con una o dos y ≈0,36 si no aparece; los bloques /24, ≈0,41.
- **URLs y hashes:** la evidencia es más alta que la de los dominios de la misma fuente (sección 8.1). Queda por decidir si se usan pesos distintos por tipo de indicador o el de la fuente como cota inferior conservadora. En cualquier caso, `not_found` en VirusTotal no rebaja un indicador: solo significa que nadie lo ha enviado a analizar.
- Son valores preliminares y deben ser **configurables**, porque no hay una verdad contra la que validarlos.
- **Disputado** significa que el indicador sigue almacenado, pero con severidad rebajada y marcado para revisión: un dominio popular con ≥3 detecciones, una IP de infraestructura legítima o un indicador cuya etiqueta contradice otra señal.
- La severidad solo se compara dentro de una misma categoría de amenaza.

## 9. Modelo de IA: etiqueta y volumen de datos

### 9.1 Qué aprende el modelo

Un modelo supervisado necesita ejemplos con respuesta. Como los datos solo contienen amenazas, hubo que decidir qué predecir:

| Opción | Qué predice | Resultado |
| --- | --- | --- |
| **A. Malicioso o no malicioso** | Si un dominio es malicioso | **Elegida**: cubre todas las fuentes y encaja con puntuar el riesgo |
| B. Nivel de confianza | Confianza alta o baja | Descartada: depende sobre todo del reportero (39 de 57 reporteros de ThreatFox usan siempre el mismo valor) |
| C. Activo o inactivo | Si una URL sigue viva | Descartada: depende de la antigüedad (98 % online el primer día, 5 % a las dos semanas) |
| D. Familia de malware | Qué familia es | Descartada: 133 clases muy desequilibradas |

B y C no se pierden: pasan a ser **reglas** de la fórmula de severidad (fiabilidad de la fuente y actividad con decaimiento temporal).

### 9.2 Características y fuga de información

Los indicadores maliciosos tienen atributos que los de Tranco no pueden tener (fuente, reportero, tags, familia, confianza, número de fuentes). Si el modelo los usara como entrada aprendería «tiene reportero, luego es malicioso» y daría una precisión engañosa. Por eso solo entran características calculables para un dominio desconocido: longitud, entropía, proporción de dígitos, guiones, subdominios y TLD. El número de fuentes, la antigüedad, el estado, el nivel de IPsum y la fiabilidad del reportero quedan para las reglas.

### 9.3 Cuántos datos hacen falta

Se midió con un experimento rápido sobre el conjunto final (`learning_trial.py`, semilla 0): gradient boosting (`HistGradientBoostingClassifier`, 200 iteraciones) con esas características, con todos los hosts de un mismo dominio registrable siempre en el mismo lado del reparto, y un test de 12.158 registros retenidos con un 17,6 % de maliciosos (la referencia del azar para PR-AUC es 0,18). Cada tamaño se repite tres veces con submuestras distintas y se da la media.

| Registros de entrenamiento | Maliciosos aprox. | PR-AUC | ROC-AUC |
| --- | --- | --- | --- |
| 100 | 25 | 0,44 | 0,76 |
| 300 | 64 | 0,64–0,65 | 0,80 |
| 1.000 | 195 | 0,69 | 0,82 |
| 3.000 | 562 | 0,72 | 0,85 |
| 10.000 | 1.857 | 0,78 | 0,88 |
| 48.817 (todos) | 9.063 | 0,80 | 0,90 |

- **Reproducibilidad.** La salida de referencia (con versiones de Python y librerías) está en `ensayo_aprendizaje_referencia.txt`. En otro equipo, con las mismas versiones de librerías, el conjunto y la partición son idénticos y las métricas varían en ±0,003 como máximo; en un mismo equipo el resultado es exactamente igual en cada ejecución. Con otras semillas (1 y 2) la PR-AUC con todos los datos queda entre 0,80 y 0,81 y el orden de la generalización por familia se mantiene. Las filas de 100 y 300 registros son frágiles: quitar un solo host del conjunto mueve la PR-AUC con 100 registros de 0,44 a 0,38.
- **El volumen actual es suficiente para un primer modelo,** pero la curva no se aplana del todo: de 3.000 a 48.817 registros se ganan unos 0,08 de PR-AUC. Hay 11.208 dominios maliciosos (unos 9.900 registrables únicos) y 49.767 no maliciosos.
- **La variedad pesa más que la cantidad.** Al entrenar sin una familia y probar en ella, el ROC-AUC es 0,92 para PhishTank, 0,85 para TweetFeed y **0,79 para abuse.ch**: lo que no se parece a lo ya visto se generaliza peor. TweetFeed aporta variedad de reporteros y de campañas.
- **Una versión anterior del ensayo daba 0,87 de PR-AUC** porque incluía las plataformas compartidas: sus campañas (por ejemplo, un millar de subdominios de `pages.dev`) eran fáciles de aprender e inflaban el resultado. Las cifras de arriba son las corregidas.
- **Es un ensayo indicativo:** sin ajustar el modelo, con una clase no maliciosa de dominios populares (relativamente fácil de distinguir) y agrupando por dominio registrable, lo que no captura campañas con subdominios aleatorios repartidos en dominios distintos. Además, los 40 TLD que se codifican como rasgo se eligen sobre todo el conjunto, test incluido: usa nombres y no etiquetas, pero es una pequeña filtración que el modelo definitivo debe evitar. La tendencia es fiable; las cifras absolutas, no.

### 9.4 Dónde no aplica el modelo

El modelo solo puntúa dominios, y los hosts extraídos de las URLs. Un hash es una cadena aleatoria sin rasgos de los que aprender, y las IPs no tienen una clase negativa equivalente. Los 6.307 sha256, 273 md5, 176 sha1, 18.338 IPs individuales y 30 bloques /24 reciben su severidad solo de las reglas (en las IPs, graduada por el nivel de IPsum).

## 10. Otras fuentes y criterio para ampliar

### 10.1 Criterio general

No se necesitan más fuentes ahora. Añadir más volumen del mismo tipo aporta poco, y cada fuente nueva suma formato, mantenimiento y licencia. Solo compensa si cubre un **hueco medible** y cumple la mayoría de los criterios de la sección 3.1: cobertura nueva, fiabilidad medida, fecha y categoría, independencia y poca complejidad.

### 10.2 Qué podría justificarse en el futuro

| Hueco medible | Candidata | Estado |
| --- | --- | --- |
| IPs con fecha y categoría (blocklist.de concentra el 93 % de las IPs individuales y no tiene fechas) | Una segunda fuente de IPs con fecha, por ejemplo AbuseIPDB (requiere clave; límites sin verificar) | No evaluada |
| Dominios de fuentes institucionales independientes | CERT.PL, CERT-FR, Botvrij y SiberKapan | No analizadas (no accesibles desde el entorno de trabajo) |
| Conflictos y falsos positivos | Warninglists de MISP (ficheros JSON, sin instalar MISP) | Basado en documentación pública; contenido actual y licencia sin verificar |
| Hashes conocidos o benignos | CIRCL hashlookup por API (no el filtro de Bloom) | Medir primero con una muestra de nuestros hashes |
| Descubrir feeds nuevos | Catálogo `Bert-JanP/Open-Source-Threat-Intel-Feeds` (151 entradas, 28 % marcadas como `Offline`; la licencia BSD-3 es solo del catálogo) | Útil como directorio y para cribar con su campo de estado |

### 10.3 Qué no conviene añadir

- **Más feeds del mismo tipo** que abuse.ch o blocklist.de: repiten la falta de independencia y la semántica; IPsum ya resume las listas de IPs de ataque.
- **Listas agregadas sin curar:** contienen muchas entradas de una sola fuente y ruido.
- **Fuentes sin fecha ni categoría,** salvo que cubran un hueco que nada más cubre, como pasa con blocklist.de en IPs.

### 10.4 Cómo evaluar una fuente nueva

1. Escribir su cargador y una sección en el notebook.
2. Medir su solape con las fuentes actuales en una ventana de tiempo común.
3. Validar una muestra de 50 a 100 indicadores con `vt_sampling.py`.
4. Decidir su peso, o descartarla, con los criterios de la sección 3.

## 11. Cómo reproducirlo

### 11.1 Archivos de la fase

| Archivo | Función |
| --- | --- |
| `01_exploration.ipynb` | Carga, calidad, ventanas temporales, solapamientos, clase no maliciosa y esquema común |
| `loaders.py` | Cargadores de las fuentes del núcleo, de IPsum y de Tranco, y la lista de doble uso |
| `optional_loaders.py` | Cargadores de MalwareBazaar y ThreatCluster, descartadas pero conservadas por si se reconsideran |
| `vt_sampling.py` | Construcción de la muestra y consulta a VirusTotal, con reintentos y reanudación |
| `learning_trial.py` | Ensayo del modelo A: curva de aprendizaje y generalización sin una fuente (sección 9.3); salida de referencia en `ensayo_aprendizaje_referencia.txt` |

### 11.2 Pasos

1. **Carpeta de datos.** Poner los siete archivos en `data/raw`: `threatfox.csv`, `urlhaus.csv`, `export-ips_all.txt`, `verified_online.csv`, `month.csv` y `exclusive.csv` (TweetFeed) y `top-1m.csv`. Los ficheros de IPsum (`ipsum_level1.txt` a `ipsum_level8.txt`) los descarga el notebook si `DOWNLOAD_IPSUM` está activo.
2. **Dependencias.** Python 3.10 o superior y `pip install pandas matplotlib requests tldextract`. `scikit-learn` solo hace falta para el ensayo de aprendizaje (`python learning_trial.py --data-dir data/raw`; la referencia se obtuvo con scikit-learn 1.8.0, pandas 3.0.2, numpy 2.4.4 y tldextract 5.4.0).
3. **Notebook.** Abrir `01_exploration.ipynb` junto a `loaders.py` y ejecutarlo entero. Las cifras de las secciones 5 y 6 salen de él.
4. **Muestra de VirusTotal.** Generarla sin clave y revisarla:

```
python vt_sampling.py --data-dir data/raw --sample-only
```

5. **Consultas.** Con la clave en una variable de entorno, que no se guarda en ningún fichero:

```
export VT_API_KEY=tu_clave
python vt_sampling.py --data-dir data/raw --pause 16 --max-queries 200
```

6. **Reanudar.** Relanzar el mismo comando: solo consulta lo que falta. El resumen por grupo (con la cobertura y las tasas de detección) se muestra al terminar y los datos quedan en `vt_results.csv`.

### 11.3 Parámetros y avisos

- Parámetros usados: semilla 42, ventana de PhishTank de 90 días y exclusión del top 10.000 de Tranco para los dominios maliciosos. El notebook admite la variable de entorno `VERITHREAT_DATA` para indicar la carpeta de datos.
- La pausa por defecto es de 16 segundos, una suposición conservadora: la clave utilizada admitió ≈0,4 s por consulta, así que la muestra completa de 825 tarda entre unos 6 minutos y casi 4 horas según la pausa. Ajustarla a los límites de la cuenta, que no se han verificado.
- Si ya existe una muestra anterior, el script la reutiliza: descarta los grupos obsoletos y las plataformas de doble uso y añade los grupos que falten (TweetFeed, URLs, hashes), sin repetir lo ya consultado.
- La clave puede ir también en un fichero `.env` fuera del control de versiones (se lee si `python-dotenv` está instalado; es opcional).
- Las claves de abuse.ch y de VirusTotal van fuera del repositorio. Las URLs de exportación de abuse.ch llevan la clave en la ruta, por lo que no deben escribirse en logs.
- IPsum se descarga de GitHub (sin clave); su licencia no se ha verificado. De TweetFeed se leyeron sus términos (datos CC0, sin verificar los indicadores); de las demás fuentes no.

## 12. Limitaciones y riesgos

- **VirusTotal no es una verdad absoluta:** sus motores consumen feeds como estos, de modo que parte del acuerdo es circular; cero detecciones no equivale a benigno ni una sola a malicioso, y los resultados son una foto del momento de la consulta.
- **Fuentes poco independientes:** solo 41 indicadores de 74.884 aparecen en dos familias de fuentes distintas, y ThreatFox y URLhaus comparten ecosistema.
- **TweetFeed tiene una fiabilidad muy variable:** sin etiqueta y sin corroborar, sus dominios se confirman poco (28 %). Sus propios términos advierten de que no verifica los indicadores y de que no debe afirmarse que un IOC es malicioso solo por aparecer allí.
- **Ventanas temporales distintas** y fuentes sin fecha (blocklist.de): no se puede medir actividad ni aplicar decaimiento en todas.
- **Concentración:** una campaña del 44 % en URLhaus, una fuente del 93 % en IPs individuales y plataformas compartidas en PhishTank y TweetFeed. Hay que limitar el peso por campaña y por fuente al entrenar.
- **La lista de doble uso necesita mantenimiento:** aún aparecen plataformas sin recoger (por ejemplo `upload.cc`, `replit.dev`, `trycloudflare.com`, `wasmer.app` o `backblazeb2.com`).
- **Muestras pequeñas por grupo:** con 66 dominios el intervalo de confianza ronda ±10 puntos, y con 30–50 URLs o hashes, ±10–15. Para comparar familias con ±5 puntos harían falta unos 400 por grupo.
- **Validación parcial por tipo:** los md5, sha1, las URLs e IPs de ThreatFox y las IPs de TweetFeed no se han validado. VirusTotal no conoce una parte de los hashes (10 % en TweetFeed), y el acuerdo en hashes de ThreatFox es en parte circular. Al descartar MalwareBazaar se pierde el 17 % de los sha256 y la vinculación entre md5, sha1 y sha256.
- **El modelo A** aprende lo que se parece a lo ya conocido, su clase no maliciosa son dominios populares y el score debe leerse como una ordenación, no como una probabilidad. Los resultados del ensayo de aprendizaje son indicativos.
- **Hosts de plataformas y sitios comprometidos:** un dominio legítimo comprometido y el subdominio de un usuario de una plataforma no son dominios maliciosos, aunque aparezcan en una URL de malware.
- **Datos personales y licencias:** las IPs y los nombres de usuario de los reporteros pueden considerarse datos personales según el contexto (RGPD), algo a valorar al compartirlos entre organizaciones, y los términos de uso de la mayoría de las fuentes no se han analizado a fondo.
- **Dependencia de servicios externos:** TweetFeed se alimenta de feeds de Twitter/X y es un proyecto personal sin garantía de disponibilidad, IPsum depende de GitHub y VirusTotal de su cuota; los formatos pueden cambiar, como el paso de abuse.ch a claves de acceso.

## 13. Próximos pasos

1. Definir el esquema de PostgreSQL con el modelo de indicador y observación (incluido el tipo `cidr`), y una carga idempotente.
2. Entrenar el modelo A con partición por campaña y por tiempo, calibrar la probabilidad y limitar el peso por campaña.
3. Fijar pesos de reglas configurables, incluida la graduación por IPsum y por etiqueta en TweetFeed, decidir si URLs y hashes llevan pesos propios, y documentar la fórmula de severidad.
4. Revisar periódicamente la lista de doble uso con los datos nuevos (candidata nueva: `upload.cc`).
5. Repetir la validación con VirusTotal cuando cambie el conjunto de fuentes o pasen meses; si hace falta, ampliarla a md5, sha1 y a las IPs de ThreatFox y TweetFeed.
6. Reconsiderar una fuente descartada solo si aparece un hueco medible (sección 10).

## 14. Glosario

- **IOC (indicador de compromiso):** dato que delata actividad maliciosa, como un dominio, una URL, un hash o una IP.
- **Observación (sighting):** cada vez que una fuente reporta un indicador.
- **Familia de fuentes:** conjunto de fuentes que comparten origen; ThreatFox y URLhaus cuentan como una (abuse.ch).
- **Nivel de IPsum:** número de listas públicas de IPs maliciosas en las que aparece una dirección (de 1 a 8).
- **Doble uso:** servicio compartido (plataforma, acortador, almacenamiento) cuyos hosts pertenecen a usuarios, no al servicio.
- **Dominio registrable:** la parte que se registra de un nombre, por ejemplo `ejemplo.com` en `www.ejemplo.com`.
- **Disputado:** indicador cuya etiqueta contradice otra señal y que se mantiene con severidad rebajada.
- **Fuga de información:** cuando el modelo usa como entrada algo que revela la respuesta y da una precisión engañosa.
- **PR-AUC y ROC-AUC:** medidas de calidad de un clasificador (de 0 a 1); la PR-AUC se compara con la proporción de positivos del test.
- **IC 95 % (Wilson):** rango en el que, con un 95 % de seguridad, se encuentra la proporción real.
