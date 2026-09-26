# Databricks notebook source
# MAGIC %md
# MAGIC # 01 - BRONZE | Ingestao do catalogo de seguranca do Pitaia
# MAGIC
# MAGIC **Etapa 4.2 do MVP (Coleta)**
# MAGIC
# MAGIC Le os 8 CSVs extraidos do SQL Editor do Supabase e persiste como tabelas
# MAGIC Delta, **sem nenhuma transformacao de conteudo**.
# MAGIC
# MAGIC ## Decisoes de projeto
# MAGIC
# MAGIC 1. **Tudo entra como STRING** (`inferSchema=False`). A Bronze e o cofre de
# MAGIC    evidencias: se o Postgres devolveu `t` em vez de `true`, ou um array
# MAGIC    `{anon;authenticated}`, fica registrado assim. A tipagem acontece na Silver.
# MAGIC 2. **Nenhum filtro de schema.** Os schemas internos do Supabase (`auth`,
# MAGIC    `storage`, `realtime`, `vault`) entram junto. Eles serao usados na analise
# MAGIC    como **grupo de comparacao** contra os schemas da aplicacao.
# MAGIC 3. **Metadados de controle** em toda tabela: `_ingerido_em`, `_fonte`,
# MAGIC    `_snapshot`, `_arquivo_origem`.

# COMMAND ----------

from pyspark.sql.functions import current_timestamp, lit, input_file_name
from datetime import date

CATALOGO   = "workspace"          # ajuste se criou catalogo proprio
SCH_BRONZE = "pitaia_bronze"
VOLUME     = "raw"
SNAPSHOT   = date.today().isoformat()

VOL = f"/Volumes/{CATALOGO}/{SCH_BRONZE}/{VOLUME}"

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {CATALOGO}.{SCH_BRONZE} "
          f"COMMENT 'Camada Bronze: catalogo de seguranca do Postgres/Supabase do Pitaia, "
          f"exatamente como extraido, sem transformacao.'")
spark.sql(f"CREATE VOLUME IF NOT EXISTS {CATALOGO}.{SCH_BRONZE}.{VOLUME}")

print(f"Suba os 8 CSVs em: {VOL}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Ingestao das 8 fontes

# COMMAND ----------

FONTES = {
    "objetos":     "objetos.csv",
    "politicas":   "politicas.csv",
    "colunas":     "colunas.csv",
    "grants":      "grants.csv",
    "funcoes":     "funcoes.csv",
    "buckets":     "buckets.csv",
    "extensoes":   "extensoes.csv",
    "constraints": "constraints.csv",
}

resumo = []

for tabela, arquivo in FONTES.items():
    df = (spark.read
          .option("header", True)
          .option("multiLine", True)        # expressoes SQL das politicas tem \n
          .option("escape", '"')            # e virgulas dentro de aspas
          .option("inferSchema", False)     # Bronze = cru, tudo string
          .csv(f"{VOL}/{arquivo}")
          .withColumn("_arquivo_origem", input_file_name())
          .withColumn("_fonte", lit(f"supabase_sql_editor::{arquivo}"))
          .withColumn("_snapshot", lit(SNAPSHOT))
          .withColumn("_ingerido_em", current_timestamp()))

    destino = f"{CATALOGO}.{SCH_BRONZE}.{tabela}"
    (df.write.mode("overwrite")
       .option("overwriteSchema", "true")
       .saveAsTable(destino))

    n = spark.table(destino).count()
    resumo.append((tabela, arquivo, n, len(df.columns)))
    print(f"  {destino:45s}  {n:6d} linhas  {len(df.columns)} colunas")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Evidencia de persistencia (screenshot deste resultado para o README)

# COMMAND ----------

df_resumo = spark.createDataFrame(
    resumo, "tabela string, arquivo_origem string, linhas int, colunas int")
display(df_resumo.orderBy("tabela"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Documentacao das tabelas Bronze no Unity Catalog

# COMMAND ----------

COMENTARIOS = {
 "objetos": "Um registro por objeto do banco (tabela, view, materializada). Traz o estado do Row Level Security e as reloptions. Fonte: pg_class + pg_namespace.",
 "politicas": "Um registro por politica de RLS. Coluna roles vem como array serializado com ';'. expressao_using e NULL em politicas que so definem WITH CHECK. Fonte: pg_policies.",
 "colunas": "Um registro por coluna de cada objeto. Base para a classificacao de dado pessoal (LGPD). Fonte: information_schema.columns.",
 "grants": "Um registro por combinacao role x objeto x privilegio. Maior volume da extracao. Fonte: information_schema.role_table_grants.",
 "funcoes": "Um registro por funcao. Somente FLAGS (security_definer, config); o corpo da funcao NAO foi extraido por decisao de seguranca. Fonte: pg_proc.",
 "buckets": "Um registro por bucket do Supabase Storage. publico=true significa leitura anonima. Fonte: storage.buckets.",
 "extensoes": "Um registro por extensao instalada. Cadeia de suprimentos, OWASP A03:2025. Fonte: pg_extension.",
 "constraints": "Um registro por constraint de PK, UNIQUE ou FK. Fonte: information_schema.table_constraints.",
}

for tabela, txt in COMENTARIOS.items():
    spark.sql(f"COMMENT ON TABLE {CATALOGO}.{SCH_BRONZE}.{tabela} IS '{txt}'")

for tabela in FONTES:
    t = f"{CATALOGO}.{SCH_BRONZE}.{tabela}"
    spark.sql(f"ALTER TABLE {t} ALTER COLUMN _ingerido_em COMMENT 'Timestamp da carga na Bronze. Metadado de controle.'")
    spark.sql(f"ALTER TABLE {t} ALTER COLUMN _fonte COMMENT 'Identificacao da fonte e do arquivo de origem. Linhagem.'")
    spark.sql(f"ALTER TABLE {t} ALTER COLUMN _snapshot COMMENT 'Data do snapshot do catalogo de seguranca (AAAA-MM-DD).'")

print("Comentarios aplicados. Screenshot do Catalog Explorer agora.")
