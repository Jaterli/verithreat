# Etiqueta de entrenamiento y score de riesgo para VeriThreat

*Documento de decisión de diseño · Proyecto TFM «VeriThreat» · Octubre 2026 · Estado (19-10-2026): modelo A desplegado y fórmula de severidad implementada y en ejecución horaria*

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

Se elige la opción A porque es la única que cubre todas las fuentes y encaja con el objetivo de puntuar el riesgo de un IOC. La probabilidad de que un dominio sea malicioso es uno de los componentes del score de 0 a 100, junto con la fiabilidad de las fuentes, la actividad y la corroboración (sección 7).

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

Depende sobre todo de **quién reporta**, no del indicador: 39 de los 57 reporteros usan siempre el mismo valor y la media por reportero va de 50,7 a 96,1. Mide la **fiabilidad de la fuente**, no la peligrosidad. Como característica de entrenamiento introduciría el sesgo del reportero. Al final tampoco se usa como peso: la fiabilidad de ThreatFox ya se mide como fuente con VirusTotal, y la confianza por reportero no se ha validado (sección 7.2).

### 6.2 Estado de URLhaus (opción C)

Depende del **tiempo transcurrido** desde el reporte: 98 % de URLs online el primer día, 37 % entre 1 y 3 días, 20 % entre 3 y 7, 8 % entre 7 y 14 y 5 % entre 14 y 31. Es una foto del momento de la exportación que decae con el tiempo, así que se usa como factor de **actividad**: una URL `offline` pesa 0,8 de su fiabilidad, y la ingesta horaria la refresca. El decaimiento general se mide con la última vez que cada fuente seguía listando el indicador (sección 7.1).

### 6.3 IPsum: corroboración para las IPs

IPsum indica en cuántas listas públicas aparece cada IP. Cruzado con las 141 IPs individuales de blocklist.de consultadas en VirusTotal (los bloques /24 se analizan aparte):

| Aparece en IPsum | n | ≥3 detecciones | IC 95 % |
| --- | --- | --- | --- |
| ≥3 listas | 54 | 96 % | 87–99 |
| 1–2 listas | 34 | 82 % | 66–92 |
| No aparece | 53 | 36 % | 24–49 |

La correlación de Spearman es 0,71. El 70 % medio de las IPs individuales escondía una variación enorme, así que el nivel de IPsum gradúa la fiabilidad de cada IP. Los grupos son pequeños y los motores de VirusTotal probablemente consumen listas parecidas: es una señal relativa, no una verdad.

## 7. Cobertura del modelo y fórmula de severidad

El modelo A **solo puntúa dominios** (y los hosts extraídos de las URLs), porque Tranco solo contiene dominios. Un hash es una cadena aleatoria sin rasgos de los que aprender y las IPs no tienen una clase negativa equivalente. Por eso las IPs, los bloques /24 y los hashes reciben su severidad solo de las reglas.

El diseño tiene dos capas, implementadas en `model_a.py` y `score.py`:

1. **Modelo A.** Produce `p_malicioso` para dominios y hosts de URL, entrenado solo con características del propio dominio.
2. **Reglas.** Combinan la fiabilidad de cada fuente, la actividad (decaimiento con la antigüedad), la corroboración entre familias, IPsum y, como señal débil, `p_malicioso`, en una `severidad` de 0 a 100.

Como cada fuente mide algo distinto (distribución de malware, C2, phishing, ataques a servicios, informes de la comunidad), cada observación guarda una **categoría de amenaza** y la **familia de la fuente**: la severidad solo se compara dentro de una misma categoría, y la corroboración se cuenta por familias, no por observaciones.

### 7.1 La fórmula

Para cada indicador:

1. **Fiabilidad `r` de cada observación**: el peso de su fuente **para ese tipo de indicador**, igual a su tasa de confirmación con ≥3 detecciones en VirusTotal (sección 8). Se decidió dar a URLs y hashes su peso propio, porque se confirman más que los dominios de la misma fuente.

| Fuente | Peso por defecto (dominios y tipos sin validar) | Pesos propios |
| --- | --- | --- |
| PhishTank | 0,97 | URL 1,00 |
| URLhaus | 0,59 | URL 0,73 |
| ThreatFox | 0,59 | sha256 0,90 (medido 1,00, rebajado por ser en parte circular) |
| TweetFeed | 1,00 corroborado · 0,94 malware o C2 · 0,60 phishing · 0,28 sin etiqueta | URL 0,82 · sha256 1,00 corroborado / 0,82 |
| blocklist.de | IP 0,96 / 0,82 / 0,36 según IPsum (≥3 listas / 1–2 / ninguna) | bloque /24 0,41 |

   Una URL de URLhaus marcada como `offline` pesa 0,8 de su fiabilidad (el estado como señal de actividad, opción C).

2. **Decaimiento** `d = 0,5^(días desde la última confirmación / vida media)`. La última confirmación es la última descarga en la que la fuente seguía listando el indicador. Vida media: 7 días para IPs y bloques, 14 para URLs, 30 para dominios; los hashes no decaen.
3. **Evidencia combinada por familias** (OR probabilístico): `E = 1 − Π(1 − r·d)`, con la mejor observación de cada familia. Dos familias independientes se refuerzan; dos observaciones de abuse.ch no cuentan doble. Para las IPs que no vienen de blocklist.de, **IPsum cuenta como una familia más** (0,96 con ≥3 listas, 0,82 con 1–2, sin decaimiento porque es la descarga del día).
4. **Modelo A como señal débil** en dominios y hosts de URL que no son IP ni plataformas de doble uso: `S = 1 − (1 − E)(1 − 0,3·p_malicioso)`. Puede añadir hasta 30 puntos si no hay otra evidencia, pero nunca domina sobre las fuentes.
5. **Disputado**: un dominio cuyo registrable está en el top 10.000 de Tranco se marca y su severidad se reduce a la mitad. No se aplica a los subdominios de plataformas de doble uso: `x.workers.dev` pertenece a un usuario y no hereda la popularidad de `workers.dev`.
6. **Severidad** = `round(100·S)`.

Todos los pesos están en un fichero de configuración (`severity_config.json`) y cada puntuación guarda su versión, porque no hay una severidad real contra la que validarlos. Cada término (fiabilidad, decaimiento y antigüedad por familia, evidencia, nivel de IPsum, `p_malicioso`, motivo de la disputa y categoría) se guarda por separado, de modo que se puede explicar por qué un indicador tiene su puntuación. Por ejemplo:

> URL de phishing `allegrolokalnie.pl-oferta…click`: severidad 100 · PhishTank, fiabilidad 1,00, decaimiento 0,99 (vista hace 0,1 días) · modelo A, `p_malicioso` 0,9999.
>
> IP C2 `160.119.66.206`: severidad 97 · ThreatFox, fiabilidad 0,59, decaimiento 0,25 (14 días) · IPsum, nivel ≥3, 0,96.

### 7.2 Lo que no entra en la fórmula

- **La confianza de ThreatFox** (opción B): depende sobre todo del reportero y no se ha validado contra VirusTotal, así que no se usa. La fiabilidad de ThreatFox ya está medida como fuente.
- **Las detecciones de VirusTotal**: solo sirven para medir los pesos; usarlas como entrada sería circular y la API pública no se puede usar en un producto.

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

VirusTotal respalda las fuentes maliciosas y también la clase no maliciosa. La muestra de validación está completa: 825 indicadores, de los que VirusTotal conoce 818 (los 7 restantes son 6 hashes y 1 URL que nunca ha analizado). Dos lecturas importan para el score: una URL concreta se confirma más que el dominio que la aloja, lo que justifica sus pesos propios; y la confianza en TweetFeed depende mucho de su etiqueta y de si lo corroboran otros feeds, lo que justifica un peso graduado. El detalle está en las secciones 7 y 8 del documento de fase.

### 8.1 El modelo A: ensayo y versión desplegada

En el **ensayo** con la exportación analizada (`learning_trial.py`; sección 9.3 del documento de fase), la PR-AUC sube de 0,44 con 100 registros a 0,72 con 3.000 y a 0,80 con todos (ROC-AUC 0,90), sobre un test con un 17,6 % de maliciosos. La variedad pesa más que la cantidad: sin abuse.ch en el entrenamiento el ROC-AUC baja a 0,79, y sin PhishTank o sin TweetFeed a 0,92 y 0,85.

La **versión desplegada** (`model_a.py`, 19-10-2026) se entrena con lo que acumula la ingesta: 14.871 hosts maliciosos de 12.888 dominios registrables, vistos entre el 10 de julio y el 19 de octubre de 2026, y 49.717 no maliciosos.

| Evaluación | PR-AUC | ROC-AUC |
| --- | --- | --- |
| Por dominio registrable (prevalencia en test 0,22) | 0,806 | 0,892 |
| **Por tiempo**: el 20 % más reciente de cada familia como test | 0,810 | 0,887 |
| Sin abuse.ch / sin PhishTank / sin TweetFeed en el entrenamiento | 0,778 / 0,927 / 0,649 | 0,804 / 0,926 / 0,837 |

El modelo **no pierde calidad con el tiempo** (0,806 frente a 0,810): predice igual de bien los dominios más recientes, que no ha visto. Respecto al ensayo, se corrigió una pequeña filtración (los 40 TLD que se codifican como rasgo se eligen ahora solo con los datos de entrenamiento) y cada versión guarda la lista exacta de hosts con la que se entrenó, de modo que se puede reconstruir idéntica aunque la base de datos siga creciendo.

### 8.2 Primera puntuación

El 19-10-2026 se puntuaron 108.319 indicadores. Mediana de severidad por categoría y tipo: URLs de phishing 99, sha256 de distribución de malware 90, dominios C2 60, URLs de distribución de malware 58 e IPs que atacan servicios 36 (el 10 % más alto llega a 96, según IPsum y el decaimiento). 70 dominios quedaron disputados y 23.409 indicadores llevan término del modelo. Las cifras dependen de la fecha: la severidad baja sola cuando una fuente deja de listar un indicador.

## 9. Cómo hacer más fiable el score

1. **Conjunto de referencia.** La validación con VirusTotal cubre dominios, IPs, URLs y hashes. Repetirla cuando cambien las fuentes o pasen meses y, si hace falta, ampliarla a md5, sha1 y a las IPs de ThreatFox y TweetFeed, que hoy usan el peso por defecto de su fuente.
2. **Calibración: evaluada y descartada.** Platt no mejoró el Brier (0,0878 en ambos casos), así que el modelo no se calibra y usa todos los datos. Como la clase negativa es artificial (unos 50.000 dominios populares frente a unos 15.000 maliciosos), `p_malicioso` se usa como ordenación, no como probabilidad real.
3. **Validación por campaña y por tiempo: hecha** (sección 8.1). La ponderación por dominio registrable se mantiene, aunque hoy no cambia el resultado porque la lista de doble uso ya eliminó las grandes concentraciones (como la de `shmulc`, el 44 % de URLhaus, casi toda en `githubusercontent.com`).
4. **Conflictos: implementados** como marca de disputado (sección 7.1).
5. **Decaimiento temporal: implementado**, con la última confirmación de cada fuente.
6. **Cerrar el ciclo con el analista (pendiente).** El estado «falso positivo» del modelo de datos, registrado en la blockchain, se convierte con el tiempo en etiquetas reales para reentrenar y para revisar los pesos.
7. **Reentrenar periódicamente** (por ejemplo, cada mes) y activar la nueva versión solo si su PR-AUC temporal no empeora.

No se prevén más fuentes por ahora: añadir volumen del mismo tipo aporta poco, y solo se reconsiderará una fuente si cubre un hueco medible (criterios y candidatas en la sección 10 del documento de fase).

## 10. Limitaciones y riesgos

- **VirusTotal no es una verdad absoluta:** sus motores consumen feeds como estos, y cero detecciones no equivale a benigno. En los hashes de ThreatFox el acuerdo es en parte circular.
- **Fuentes poco independientes:** pocos indicadores aparecen en dos familias de fuentes, así que la corroboración rara vez actúa.
- **Los pesos de las reglas no se pueden validar** contra una severidad real: están medidos donde ha sido posible, son configurables y deben justificarse en la memoria. Los de IPsum para IPs que no vienen de blocklist.de, las vidas medias, el factor de `offline`, el peso del modelo (0,3) y el factor de disputa son decisiones razonadas, no medidas.
- **El modelo A mide parecido a lo malicioso conocido,** no peligrosidad: un dominio malicioso nuevo con aspecto normal puntuará bajo. Por eso solo puede sumar hasta 30 puntos.
- **La disputa solo usa Tranco:** un sitio legítimo comprometido que no esté en el top 10.000 no se marca.
- **Ventanas temporales distintas:** la ausencia de un indicador en una fuente no implica que esté inactivo ni que sea benigno; el decaimiento lo trata como pérdida de actividad.
- **Concentración por fuente:** blocklist.de aporta la gran mayoría de las IPs individuales.
- **Muestras de validación pequeñas:** 30–66 indicadores por grupo (intervalos de ±10–15 puntos), y menos aún en los subgrupos por etiqueta de TweetFeed.

## 11. Próximos pasos

1. Revisar la distribución de la severidad con unos días de ingesta y justificar los pesos en la memoria.
2. Integrar el score con los microservicios Java (consulta y API) y con Hyperledger Fabric (hash canónico del indicador y procedencia).
3. Recoger el estado «falso positivo» de los analistas para revisar pesos y reentrenar.
4. Reentrenar el modelo A periódicamente con la base de datos.
