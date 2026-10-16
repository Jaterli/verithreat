# Etiqueta de entrenamiento y score de riesgo para VeriThreat

*Documento de decisión de diseño, actualizado con las fuentes definitivas · Proyecto TFM «VeriThreat» · Octubre 2026*

## 1. Contexto y finalidad

VeriThreat es una plataforma para compartir indicadores de compromiso (IOCs: dominios, URLs, hashes e IPs) entre organizaciones, con un motor de IA que puntúa su riesgo y una blockchain que registra su procedencia. El modelo de datos incluye un campo `severidad`, y uno de los criterios de éxito exige que sea **coherente y explicable**.

Este documento recoge una decisión de diseño: **qué aprende el modelo de IA y cómo se construye el score de riesgo**. Las fuentes, su validación con VirusTotal, su fiabilidad y cómo reproducirlo están en el documento [VeriThreat · Fase de datos](https://claude.ai/artifact/Qe4s1ydJ4mCEThpj4wS2YK), que es la referencia vigente; aquí solo se repiten las cifras necesarias para entender la decisión.

## 2. Datos de partida

Tras evaluar y podar fuentes, el conjunto definitivo es:

| Fuente | Papel | Datos |
| --- | --- | --- |
| ThreatFox (abuse.ch) | Núcleo: IOCs mixtos, familia, confianza y C2 | 11.941 · 7 días |
| URLhaus (abuse.ch) | Núcleo: URLs de distribución de malware | 31.166 · 31 días |
| blocklist.de | Núcleo: IPs que atacan servicios | 24.714 · sin fechas |
| PhishTank | Núcleo: phishing verificado por la comunidad | 69.007 (12.606 en 90 días) |
| TweetFeed | Núcleo: IOCs de investigadores con reportero y enlace al tweet | 4.323 filas · 30 días |
| IPsum | Señal de fiabilidad de las IPs, no aporta indicadores | 119.353 IPs |
| Tranco | Base de la clase no maliciosa | top 50.000 |

Unificadas, suman **75.511 observaciones y 74.884 indicadores únicos**: 46.293 URLs, 18.338 IPs individuales, 6.307 sha256, 3.467 dominios, 273 md5, 176 sha1 y 30 bloques /24 de blocklist.de (un indicador de red cada uno). Solo 41 aparecen en dos familias de fuentes distintas. Se descartaron MalwareBazaar, ThreatCluster, OTX, Feodo Tracker y otras (los motivos están en el documento de fase).

Hay un punto clave: **todas las fuentes contienen únicamente amenazas**. Tranco no es una lista de dominios seguros, sino de dominios populares.

## 3. Por qué hablamos de modelos y de «etiquetas»

Un modelo de aprendizaje supervisado aprende a partir de ejemplos que ya traen la respuesta correcta. Esa respuesta es la **etiqueta** (o variable objetivo): lo que queremos que el modelo aprenda a predecir. Por ejemplo, si le damos miles de dominios marcados como «malicioso» o «no malicioso», aprende qué rasgos distinguen unos de otros y después puede puntuar dominios que no ha visto.

Nuestro problema es que los datos no traen una respuesta natural: todo lo que descargamos es malicioso. Por eso, antes de entrenar nada, hay que **decidir qué queremos predecir** y de dónde sacar esa etiqueta.

## 4. Opciones consideradas

| Opción | Qué predice | De dónde sale | Limitación |
| --- | --- | --- | --- |
| **A. Malicioso o no malicioso** | Si un dominio es malicioso | Fuentes maliciosas frente a Tranco depurado | Decisión de diseño; solo cubre dominios |
| B. Nivel de confianza | Confianza alta o baja | `confidence_level` de ThreatFox (50–100) | Solo existe en ThreatFox |
| C. Activo o inactivo | Si una URL sigue viva | `url_status` de URLhaus | Solo URLhaus; mide actividad, no peligrosidad |
| D. Familia de malware | Qué familia es | `malware_printable` | 133 familias, muy desequilibradas |

## 5. Decisión: opción A

Se elige la opción A porque es la única que cubre todas las fuentes y encaja con el objetivo de puntuar el riesgo de un IOC. La probabilidad de que un dominio sea malicioso se transforma en un score de 0 a 100.

### 5.1 Construcción de la clase no maliciosa

Tranco mide popularidad, no benignidad. Por ejemplo, `github.com` está en Tranco y a la vez aloja malware: 1.644 URLs de URLhaus apuntan a él. Para construir la clase negativa:

1. Tomar solo el **top N** (50.000), no el millón completo.
2. **Excluir** los dominios que aparecen en las fuentes maliciosas (228 en el top 50.000).
3. **Excluir** los servicios de doble uso: almacenamiento y compartición de ficheros, acortadores y QR, plataformas de subdominios y DNS dinámico, y almacenamiento en la nube (43 en el top 50.000).
4. Trabajar **a nivel de dominio**, extrayendo el host de las URLs, para que el modelo no aprenda a distinguir «URL con ruta» de «dominio».

Quedan **49.767 dominios no maliciosos** frente a **11.208 maliciosos** (unos 9.900 dominios registrables únicos). La lista de doble uso salió de los datos: antes de ampliarla, 34 dominios registrables concentraban el 25 % de los hosts maliciosos (`pages.dev` y `weebly.com` a la cabeza) y ahora solo el 1 %.

### 5.2 Evitar la fuga de información

Los indicadores maliciosos tienen atributos que los de Tranco no pueden tener (fuente, reportero, tags, familia, confianza, número de fuentes). Si el modelo los usara como entrada aprendería «tiene reportero, luego es malicioso» y daría una precisión engañosa. Por eso:

- **Entran al modelo** solo características calculables para un dominio desconocido: longitud, entropía, proporción de dígitos, guiones, subdominios y TLD.
- **Quedan para las reglas** el número de fuentes, la antigüedad, el estado online, el nivel de IPsum y la fiabilidad del reportero.

## 6. B y C como reglas, y IPsum como señal

La confianza y el estado no sirven como etiqueta, pero sí como componentes de la fórmula de severidad.

### 6.1 Confianza de ThreatFox (opción B)

Depende sobre todo de **quién reporta**, no del indicador: 39 de los 57 reporteros usan siempre el mismo valor y la media por reportero va de 50,7 a 96,1. Mide la **fiabilidad de la fuente**, no la peligrosidad. Como característica de entrenamiento introduciría el sesgo del reportero; como **peso de la fuente** sí es útil.

### 6.2 Estado de URLhaus (opción C)

Depende del **tiempo transcurrido** desde el reporte: 98 % de URLs online el primer día, 37 % entre 1 y 3 días, 20 % entre 3 y 7, 8 % entre 7 y 14 y 5 % entre 14 y 31. Es una foto del momento de la exportación que decae con el tiempo, así que se usa como factor de **actividad** con decaimiento temporal y alimenta el campo `estado`. Hay que refrescarlo periódicamente.

### 6.3 IPsum: corroboración para las IPs

IPsum indica en cuántas listas públicas aparece cada IP. Cruzado con las 141 IPs individuales de blocklist.de consultadas en VirusTotal (los bloques /24 se analizan aparte):

| Aparece en IPsum | n | ≥3 detecciones | IC 95 % |
| --- | --- | --- | --- |
| ≥3 listas | 54 | 96 % | 87–99 |
| 1–2 listas | 34 | 82 % | 66–92 |
| No aparece | 53 | 36 % | 24–49 |

La correlación de Spearman es 0,71. El 70 % medio de las IPs individuales escondía una variación enorme, así que el nivel de IPsum gradúa la fiabilidad de cada IP. Los grupos son pequeños y los motores de VirusTotal probablemente consumen listas parecidas: es una señal relativa, no una verdad.

## 7. Cobertura del modelo y diseño en dos capas

El modelo A **solo puntúa dominios** (y los hosts extraídos de las URLs), porque Tranco solo contiene dominios. Un hash es una cadena aleatoria sin rasgos de los que aprender y las IPs no tienen una clase negativa equivalente. Por eso las 18.338 IPs individuales, los 30 bloques /24 y los 6.307 sha256, 273 md5 y 176 sha1 reciben su severidad solo de las reglas.

El diseño tiene dos capas:

1. **Modelo A.** Produce `p_malicioso` para dominios, entrenado solo con características del propio dominio.
2. **Reglas.** Combinan `p_malicioso`, la fiabilidad de la fuente, la actividad, el número de fuentes independientes y, en las IPs, el nivel de IPsum en un `severidad` de 0 a 100. Cuando el modelo A no aplica, ese término se omite y se reponderan los demás.

Cada componente se guarda por separado, de modo que se puede explicar por qué un indicador tiene su puntuación. Como cada fuente mide algo distinto (distribución de malware, C2, phishing, ataques a servicios, informes de la comunidad), cada observación guarda una **categoría de amenaza** y la **familia de la fuente**: la severidad solo se compara, o pondera, dentro de una misma categoría, y la corroboración se cuenta por familias, no por observaciones.

**Pesos de fiabilidad preliminares** (tasa de confirmación con ≥3 detecciones en VirusTotal, medida en dominios e IPs): PhishTank ≈0,97 y abuse.ch ≈0,59. TweetFeed, graduado por corroboración y etiqueta: ≈1,00 si lo corroboran sus feeds de referencia, ≈0,94 con etiqueta de malware o C2, ≈0,60 de phishing y ≈0,28 sin etiqueta. blocklist.de, graduado por IPsum: ≈0,96, ≈0,82 o ≈0,36; los bloques /24, ≈0,41. En URLs y hashes la confirmación es más alta que en los dominios de la misma fuente (sección 8), y queda por decidir si llevan pesos propios. Todos deben ser configurables, porque no hay una verdad contra la que validarlos. Un indicador **disputado** (por ejemplo, un dominio popular con ≥3 detecciones) sigue almacenado con la severidad rebajada y marcado para revisión.

## 8. Evidencia que respalda la decisión

| Grupo | n | ≥1 detección | ≥3 detecciones |
| --- | --- | --- | --- |
| Dominios PhishTank | 66 | 100 % | 97 % |
| Dominios abuse.ch | 66 | 91 % | 59 % |
| Dominios TweetFeed | 66 | 91 % | 61 % |
| IPs individuales blocklist.de | 141 | 90 % | 70 % |
| IPs de bloques /24 | 59 | 98 % | 41 % |
| Dominios de Tranco | 198 | 6 % | 0,5 % |
| URLs PhishTank / URLhaus / TweetFeed | 32 / 33 / 33 | 100 / 100 / 97 % | 100 / 73 / 82 % |
| Raíces de sitios de Tranco | 30 | 17 % | 0 % |
| sha256 ThreatFox / TweetFeed | 49 / 45 | 100 / 93 % | 100 / 91 % |

VirusTotal respalda las fuentes maliciosas y también la clase no maliciosa. La muestra de validación está completa: 825 indicadores, de los que VirusTotal conoce 818 (los 7 restantes son 6 hashes y 1 URL que nunca ha analizado). Dos lecturas importan para el score: una URL concreta se confirma más que el dominio que la aloja, lo que respalda separar la severidad de la URL de la de su host; y la confianza en TweetFeed depende mucho de su etiqueta y de si lo corroboran otros feeds, lo que justifica un peso graduado. El detalle está en las secciones 7 y 8 del documento de fase.

En el ensayo de aprendizaje con el conjunto final (`learning_trial.py`, reproducible; detalle en la sección 9.3 del documento de fase), la PR-AUC sube de 0,44 con 100 registros a 0,72 con 3.000 y a 0,80 con todos (ROC-AUC 0,90), sobre un test con un 17,6 % de maliciosos. Hay datos suficientes para un primer modelo, pero la variedad pesa más que la cantidad: sin abuse.ch en el entrenamiento el ROC-AUC baja a 0,79, y sin PhishTank o sin TweetFeed a 0,92 y 0,85. Una versión anterior del ensayo daba 0,87 porque incluía las plataformas compartidas, cuyas campañas eran fáciles de aprender.

## 9. Cómo hacer más fiable el score

1. **Conjunto de referencia.** La validación con VirusTotal cubre ya dominios, IPs, URLs y hashes. Repetirla cuando cambien las fuentes o pasen meses y, si hace falta, ampliarla a md5, sha1 y a las IPs de ThreatFox y TweetFeed.
2. **Calibrar el modelo A.** La clase negativa es artificial (unos 50.000 dominios benignos frente a unos 11.000 maliciosos), así que la probabilidad no equivale al riesgo real. Calibrar, medir con PR-AUC y presentar el score como una ordenación, no como una probabilidad.
3. **Validar por campaña y por tiempo,** y limitar el peso de las campañas dominantes (por ejemplo, `shmulc`, el 44 % de URLhaus).
4. **Marcar conflictos.** Un dominio que aparece a la vez como malicioso y entre los más populares debe bajar su score y mostrarse como disputado.
5. **Decaimiento temporal.** Atenuar el peso de las observaciones antiguas.
6. **Cerrar el ciclo con el analista.** El estado «falso positivo» del modelo de datos, registrado en la blockchain, se convierte con el tiempo en etiquetas reales para reentrenar.

No se prevén más fuentes por ahora: añadir volumen del mismo tipo aporta poco, y solo se reconsiderará una fuente si cubre un hueco medible (criterios y candidatas en la sección 10 del documento de fase).

## 10. Limitaciones y riesgos

- **VirusTotal no es una verdad absoluta:** sus motores consumen feeds como estos, y cero detecciones no equivale a benigno. En los hashes de ThreatFox el acuerdo es en parte circular.
- **Fuentes poco independientes:** solo 41 indicadores de 74.884 aparecen en dos familias de fuentes.
- **Los pesos de las reglas no se pueden validar** contra una severidad real: hay que justificarlos y mantenerlos configurables.
- **El modelo A mide parecido a lo malicioso conocido,** no peligrosidad: un dominio malicioso nuevo con aspecto normal puntuará bajo.
- **Ventanas temporales distintas:** la ausencia de un indicador en una fuente no implica que esté inactivo ni que sea benigno.
- **Concentración por campaña y por fuente:** blocklist.de aporta el 93 % de las IPs individuales.
- **Muestras de validación pequeñas:** 30–66 indicadores por grupo (intervalos de ±10–15 puntos), y menos aún en los subgrupos por etiqueta de TweetFeed.

## 11. Próximos pasos

1. Preparar el esquema de PostgreSQL, guardando la confianza, el estado, la categoría de amenaza, la familia de la fuente y el nivel de IPsum por observación, y calculando la severidad en una vista.
2. Cargar las fuentes definitivas con los cargadores validados.
3. Entrenar el modelo A con partición por campaña y por tiempo, y calibrarlo.
4. Fijar la fórmula de severidad con los pesos medidos y decidir si URLs y hashes llevan pesos propios.
