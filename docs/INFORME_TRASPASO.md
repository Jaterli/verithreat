# VeriThreat — informe de traspaso (tramo: ensayo de aprendizaje y CLAUDE.md)

> Para el otro chat (Claude Code / VS Code). Resume lo hecho **desde que se pidió el código del ensayo de aprendizaje**.
> Complementa a `CLAUDE.md` (contexto general, ya fusionado). Idioma de trabajo: español. Octubre de 2026.

## 1. Resumen en seis líneas

1. Se escribió `ensayo_aprendizaje.py`, un script independiente que **reproduce exactamente** el ensayo del modelo A
   (curva de aprendizaje y prueba sin una fuente). Importa cargadores y `DOBLE_USO` de `cargadores_corregidos.py`; sin red ni claves.
2. Al reproducirlo apareció una **discrepancia sin resolver**: el ensayo usó **49.767** no maliciosos, no 49.766 como dicen
   notebook y documentos (causa: el dominio `bet.br`).
3. Se midió la **sensibilidad** del ensayo (semillas y criterio): las conclusiones se mantienen; las filas de 100–300
   registros son frágiles.
4. Se detectaron **dos redondeos erróneos** en los documentos del ROC-AUC de la curva.
5. Se **fusionó** el `CLAUDE.md` actualizado por la otra sesión (con la validación de URLs y hashes) con los cambios de este
   tramo, sin pisar lo suyo.
6. Los **documentos de Claude** (fase de datos y decisión de diseño) quedaron **desactualizados** respecto a la otra sesión;
   falta el `resultados_vt.csv` de 825 filas para verificar y actualizarlos.

## 2. El script `ensayo_aprendizaje.py`

**Petición**: script independiente, mismo conjunto (11.208 maliciosos, no maliciosos del top 50.000 de Tranco sin choques ni
doble uso, a nivel de host), mismos rasgos, misma partición por dominio registrable, misma semilla, curva con
100 / 300 / 1.000 / 3.000 / 10.000 / todos y prueba dejando fuera una fuente; `--data-dir`, `--semilla`, CSV opcional.

**Entregado**: `ensayo_aprendizaje.py` y `ensayo_aprendizaje_referencia.txt` (salida de referencia con versiones).

```bash
python ensayo_aprendizaje.py --data-dir ../data/raw --salida resultados_ensayo/
python ensayo_aprendizaje.py --data-dir ../data/raw --semilla 1
python ensayo_aprendizaje.py --data-dir ../data/raw --excluir-registrable-vacio   # criterio del notebook (49.766)
```

Otras opciones: `--tamano-test` (0,2), `--repeticiones` (3), `--top-tranco` (50.000). Necesita `tldextract` (lista de sufijos
incluida, sin descargas) y scikit-learn.

**Verificación**: se ejecutó el código original del ensayo y el script nuevo en el mismo entorno
(Python 3.12.3, **scikit-learn 1.8.0**, **pandas 3.0.2**, numpy 2.4.4, tldextract 5.4.0): las nueve líneas de resultados
(curva y generalización) son **idénticas**. **El autor aún no lo ha ejecutado en su máquina**: con otras versiones los
números pueden moverse algo; compararlos con `ensayo_aprendizaje_referencia.txt`.

### Resultados de referencia (semilla 0, 48.817 para entrenar, 12.158 para test, 17,6 % de maliciosos, 51 rasgos)

| n entrenamiento | Maliciosos aprox. | PR-AUC | ROC-AUC |
|---|---|---|---|
| 100 | 25 | 0,440 ±0,022 | 0,758 |
| 300 | 64 | 0,644 ±0,037 | 0,799 |
| 1.000 | 195 | 0,689 ±0,009 | 0,821 |
| 3.000 | 562 | 0,724 ±0,005 | 0,847 |
| 10.000 | 1.857 | 0,777 ±0,002 | 0,885 |
| 48.817 (todos) | 9.063 | 0,802 ±0,000 | 0,905 |

| Familia fuera del entrenamiento | Maliciosos en test | PR-AUC (base) | ROC-AUC |
|---|---|---|---|
| PhishTank | 5.995 | 0,918 (0,37) | 0,923 |
| abuse.ch | 3.872 | 0,685 (0,28) | 0,794 |
| TweetFeed | 1.341 | 0,634 (0,12) | 0,845 |

### Parámetros que **no** figuraban en los documentos

- Modelo: `HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, random_state=<semilla de la repetición>)`; resto, por
  defecto. `early_stopping='auto'` solo se activa con más de 10.000 muestras (solo la fila «todos»; por eso su desviación es ~0).
- Partición: `GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=<semilla>)` sobre el dominio registrable.
- Curva: 3 repeticiones por tamaño (`RandomState(semilla + i)`, sin reemplazo, proporción natural); media y desviación (ddof=0);
  «maliciosos aprox.» = los de la última repetición.
- Rasgos (51): longitud del host, nº de etiquetas, longitud y niveles del subdominio, longitud del dominio, fracción de dígitos,
  guiones, entropía (sobre el dominio sin sufijo), fracción de vocales (aeiou), racha de dígitos más larga y longitud del sufijo,
  más 40 indicadores one-hot de los TLD más frecuentes. **Los 40 TLD se eligen sobre todo el conjunto, test incluido**
  (usa nombres, no etiquetas, pero es una pequeña filtración de información).
- Generalización: el test incluye todos los hosts de la familia excluida más los no maliciosos del test; si dos familias comparten
  registrable, el de la otra puede estar en el entrenamiento.

## 3. Hallazgos de este tramo

### 3.1 Discrepancia 49.767 frente a 49.766 (sin resolver)

- El ensayo usó **49.767**; notebook y documentos dicen **49.766**. Los 11.208 maliciosos coinciden.
- **Causa**: `bet.br`. Es un sufijo público para `tldextract`, así que su registrable queda **vacío**. El ensayo lo mantiene como
  no malicioso; el notebook lo excluye por accidente (hay URLs de ThreatFox con IP como host y su registrable también es vacío, lo
  que mete `''` en la lista de colisiones).
- `--excluir-registrable-vacio` reproduce 49.766, pero cambia la partición (48.778 / 12.196; 18,5 % de maliciosos en el test) y mueve
  las métricas:

| | Criterio del ensayo (49.767) | Criterio del notebook (49.766) |
|---|---|---|
| PR-AUC con 100 registros | 0,440 | 0,380 |
| PR-AUC con 1.000 | 0,689 | 0,712 |
| PR-AUC con todos | 0,802 | 0,809 |
| ROC-AUC con todos | 0,905 | 0,904 |
| ROC-AUC sin abuse.ch | 0,794 | 0,787 |

**Decisión pendiente del autor**: qué criterio se documenta. Hasta entonces, las cifras de rendimiento de los documentos
corresponden al de **49.767**.

### 3.2 Sensibilidad a la semilla (criterio del ensayo)

| | Semilla 0 | Semilla 1 | Semilla 2 |
|---|---|---|---|
| PR-AUC con todos | 0,802 | 0,808 | 0,802 |
| ROC-AUC con todos | 0,905 | 0,904 | 0,900 |
| ROC-AUC sin PhishTank | 0,923 | 0,923 | 0,922 |
| ROC-AUC sin abuse.ch | 0,794 | 0,796 | 0,786 |
| ROC-AUC sin TweetFeed | 0,845 | 0,855 | 0,849 |

El orden PhishTank > TweetFeed > abuse.ch es estable. Las filas de 100–300 registros son **frágiles**: quitar un solo host mueve
el PR-AUC con 100 registros de 0,44 a 0,38.

### 3.3 Errores de redondeo en los documentos (hay que corregirlos)

- Fila de 10.000 registros: ROC-AUC real **0,885** (0,8849) → debe ser **0,88**; los documentos dicen 0,89.
- Con todos los datos: ROC-AUC **0,905** → los documentos y el `CLAUDE.md` original decían 0,91 (0,90 o 0,91 según redondeo;
  mejor escribir 0,905).
- Los demás valores (0,76 / 0,80 / 0,82 / 0,85 y los de generalización 0,92 / 0,79 / 0,85) son correctos.

## 4. `CLAUDE.md` fusionado

El autor aportó un `CLAUDE.md` actualizado en otra sesión. **Lo que trae esa versión** (se conservó íntegro):

- Estructura: scripts en `ai/src/`, notebook en `ai/notebooks/01_exploracion.ipynb`, datos en `ai/data/raw/`; script de blocklist.de
  renombrado a **`extract_historic_blocklist.py`**; `.gitignore` con `ai/data/raw/` y `*.csv`.
- **Validación con VirusTotal completa**: muestra de 825 indicadores (818 `ok`, 7 `not_found`), consultada el 13 y el 14 de octubre
  (415 y 410). Resultados nuevos de URLs y hashes (**según esa sesión; no verificados aquí**, porque el `resultados_vt.csv` que
  tengo es el de 596 filas):

| Grupo | n | ≥1 | ≥3 |
|---|---|---|---|
| URLs PhishTank | 32 | 100 % | 100 % |
| URLs URLhaus | 33 | 100 % | 73 % |
| URLs TweetFeed | 33 | 97 % | 82 % |
| Raíces `https://dominio/` de Tranco | 30 | 17 % | 0 % |
| sha256 ThreatFox | 49 | 100 % | 100 % |
| sha256 TweetFeed | 45 | 93 % | 91 % |

- Cifras del unificado distintas a las de este chat: **75.511 / 74.884 / 46.293 URLs** (este chat: 75.513 / 74.886 / 46.295).

**Lo que se añadió en este tramo**: `ensayo_aprendizaje.py` y su referencia en la estructura; el comando de ejecución; la discrepancia
49.767 / 49.766; ROC-AUC 0,905; parámetros, versiones y sensibilidad; y se quitó «unificar el nombre del script» de los pasos
pendientes (ya está hecho).

## 5. Notebook

`01_exploracion.ipynb` estaba pensado para estar junto a `cargadores_corregidos.py`. Se modificó la celda de importación para
buscarlo también en `../src` y `./src`, y se probó con la estructura `ai/notebooks` + `ai/src` + `ai/data/raw`: se ejecuta sin
errores. Con los datos de este chat da 75.513 observaciones y 74.886 indicadores. El comando del `CLAUDE.md` lo lanza desde `src`:
conviene comprobar que coincide con el directorio desde el que se ejecuta.

## 6. Estado de los documentos de Claude (siguen desactualizados)

Los dos documentos del visor — «VeriThreat · Fase de datos: recopilación, validación y fiabilidad…» y «Etiqueta de entrenamiento y
score de riesgo para VeriThreat» — **no reflejan** todavía:

- la validación de URLs y hashes (siguen como «pendiente de ejecutar», con 229 consultas);
- el nombre `extract_historic_blocklist.py` (usan `extract_historic_blocklist.de.py`);
- las cifras del unificado de la otra sesión (siguen con 75.513 / 74.886);
- los redondeos del apartado 3.3 y la discrepancia 49.767 / 49.766;
- el script `ensayo_aprendizaje.py` (los documentos citan el ensayo, pero no su código).

## 7. Pendiente, por orden

1. **El autor sube el `resultados_vt.csv` de 825 filas** → verificar las cifras de URLs y hashes, actualizar el notebook y los dos
   documentos, y revisar los pesos de fiabilidad (¿distintos por tipo de indicador: URL / hash frente a dominio? Pendiente de
   decidir; los pesos actuales son de dominio e IP).
2. **Decidir el criterio de no maliciosos** (49.767 o 49.766) y unificarlo en notebook, documentos y `CLAUDE.md`.
3. **Resolver la discrepancia de 2 URLs** (75.511 frente a 75.513): ejecutar el notebook en el entorno del autor y comparar.
4. **Ejecutar `ensayo_aprendizaje.py` en el entorno del autor** y comparar con la referencia.
5. Corregir los redondeos (3.3) y el nombre del script en los documentos.
6. Seguir con los pasos de `CLAUDE.md` (esquema PostgreSQL con carga idempotente, ingesta programada, modelo A con partición por
   campaña y por tiempo y calibración, fórmula de severidad, integración con Java y Fabric).
7. Mantenimiento de `DOBLE_USO` (candidatos: `upload.cc`, `replit.dev`, `trycloudflare.com`, `wasmer.app`, `backblazeb2.com`).

## 8. Lo que **no** está verificado

- Las cifras de URLs y hashes de VirusTotal y las del unificado de la otra sesión (no tengo el archivo de 825 filas).
- Que el ensayo dé los mismos números en el entorno del autor (versiones distintas pueden mover los decimales).
- Que los hashes de TweetFeed con 0 detecciones sean artefactos benignos y no malware sin detectar (lo dice el `CLAUDE.md` del autor).
- Los límites de consultas del DNS de blocklist.de y de la API de VirusTotal, y los términos de uso de casi todas las fuentes
  (solo se leyeron los de TweetFeed).

## 9. Contexto inmediatamente anterior (fuera de este tramo, abierto)

Se evaluó **Hybrid Analysis** (sandbox de CrowdStrike, API v2 con clave gratuita). Conclusión: no como fuente de ingesta; como mucho,
una **segunda referencia no circular para una muestra pequeña de hashes**, después de la validación de VirusTotal. Sin límites ni
términos verificados, y sin enviar nunca ficheros ni URLs a analizar (las muestras enviadas suelen quedar públicas).

## 10. Reglas para quien continúe

- No cambiar una cifra sin actualizarla en el notebook, en los dos documentos y en `CLAUDE.md`, y sin indicar de dónde sale.
- No dar por buenas las cifras de la sección 8 hasta verificarlas.
- Nunca claves en código, notebooks, logs ni commits; los datos y los resultados de VirusTotal no se versionan.
- Probar la lógica con respuestas simuladas antes de usar la red, y avisar antes de lanzar miles de peticiones.
