## Qué contiene

1. **Carga:** cargadores para las tres fuentes de abuse.ch y para Tranco. Buscan la carpeta de datos automáticamente (`data/raw`, `data`, `.`...).
2. **Calidad:** nulos por columna y duplicados.
3. **Ventanas temporales:** el rango de cada fuente y los registros por día.
4. **ThreatFox, URLhaus y MalwareBazaar:** tipos, familias, tags, confianza, estados y reporteros de cada una.
5. **Solapamiento entre fuentes:** hashes, URLs y dominios.
6. **Tranco:** comprobaciones del archivo, cruce con las fuentes maliciosas y construcción de una clase no maliciosa depurada.
7. **Esquema común:** una tabla de observaciones (`sightings`) y otra de indicadores únicos, como prototipo de las tablas de la base de datos.
8. **Conclusiones** para el diseño.

## Lo que ha salido al ejecutarlo

- **Una campaña domina URLhaus.** El reportero `shmulc` aporta el 44 % de las URLs (13.795), casi todas alojadas en `githubusercontent.com`. Si entrenas sin corregirlo, el modelo aprenderá esa campaña. Hay que limitar el peso por reportero o campaña.
- **Ventanas desiguales:** ThreatFox cubre 7 días, URLhaus 31 y MalwareBazaar 2.
- **Columnas inservibles:** `clamav` y `vtpercent` están vacías al 100 %, y `last_seen` de ThreatFox al 81,5 %.
- **Solapamiento bajo:** 10 sha256 y 66 URLs en común. Tras unificar quedan 44.490 observaciones y 44.023 indicadores únicos, y solo 76 aparecen en dos fuentes.
- **Tranco depurado:** del top 50.000 se descartan 65 dominios por chocar con las fuentes maliciosas y 19 por ser de doble uso (incluí plataformas como `github.io` o `workers.dev`). Quedan 49.927.

Para dominios registrables, el notebook usa `tldextract` si lo tienes instalado. Si no, aproxima con las dos últimas etiquetas, que falla en casos como `.co.uk`. Te conviene `pip install tldextract`.

