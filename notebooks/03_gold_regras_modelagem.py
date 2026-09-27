# Databricks notebook source
# MAGIC %md
# MAGIC # 03 - Gold | esquema estrela e motor de regras
# MAGIC
# MAGIC ```
# MAGIC                   dim_tempo
# MAGIC                       |
# MAGIC  dim_objeto ---- fato_achado ---- dim_regra
# MAGIC                   /      \
# MAGIC           dim_coluna     dim_role
# MAGIC ```
# MAGIC
# MAGIC Fato na granularidade de **um achado**: uma regra violada por um objeto, num snapshot.
# MAGIC
# MAGIC `dim_regra` e curada a mao. Ela coloca o OWASP Top 10:2025 e a escala de severidade
# MAGIC dentro do modelo dimensional, para que o referencial de seguranca seja consultavel
# MAGIC por SQL em vez de virar prosa no relatorio.

# COMMAND ----------

from pyspark.sql import functions as F

CATALOGO = "workspace"
SILVER   = f"{CATALOGO}.silver"
GOLD     = f"{CATALOGO}.gold"

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {GOLD} COMMENT "
          "'Achados de seguranca modelados em estrela e backlog de remediacao priorizado.'")

# COMMAND ----------

# MAGIC %md
# MAGIC ## dim_regra
# MAGIC 18 regras. As quatro ultimas (R15-R18) sao especificas de dado de saude - existem
# MAGIC porque o Pitaia cai no art. 11 da LGPD, e uma tabela de prontuario exposta nao tem
# MAGIC o mesmo peso que uma tabela de configuracao exposta.

# COMMAND ----------

REGRAS = [
    ("R01", "Tabela exposta via API PostgREST com RLS desabilitado",            "Critico", 10, "A01:2025"),
    ("R02", "Politica USING(true) concedida a role anonima",                    "Critico", 10, "A01:2025"),
    ("R03", "Coluna com dado pessoal em tabela sem RLS",                        "Critico", 10, "A01:2025"),
    ("R04", "Funcao SECURITY DEFINER sem search_path fixado",                   "Critico", 10, "A02:2025"),
    ("R05", "Bucket de Storage publico",                                        "Critico", 10, "A02:2025"),
    ("R06", "RLS habilitado sem nenhuma politica definida",                     "Alto",     6, "A06:2025"),
    ("R07", "View sobre dado protegido sem security_invoker",                    "Alto",     6, "A01:2025"),
    ("R08", "Role anonima com privilegio de escrita",                           "Alto",     6, "A01:2025"),
    ("R09", "Politica sem isolamento por usuario ou tenant",                    "Alto",     6, "A01:2025"),
    ("R10", "Politicas nao cobrem todos os comandos da tabela",                 "Medio",    3, "A06:2025"),
    ("R11", "Tabela sem chave primaria",                                        "Medio",    3, "A08:2025"),
    ("R12", "Extensao instalada fora do schema extensions",                     "Medio",    3, "A03:2025"),
    ("R13", "RLS habilitado mas nao forcado para o owner",                      "Baixo",    1, "A02:2025"),
    ("R14", "Objeto sem COMMENT: ausencia de documentacao",                     "Baixo",    1, "A02:2025"),
    ("R15", "Dado de saude (LGPD art. 11) em tabela sem RLS",                   "Critico", 10, "A01:2025"),
    ("R16", "Role anonima com leitura em tabela que contem dado de saude",      "Critico", 10, "A01:2025"),
    ("R17", "Tabela de saude com politica para authenticated sem filtro de usuario", "Critico", 10, "A01:2025"),
    ("R18", "Tabela com dado de saude e nenhuma politica de RLS",               "Alto",     6, "A06:2025"),
]

REFERENCIAS = {
    "A01:2025": "OWASP A01:2025 Broken Access Control",
    "A02:2025": "OWASP A02:2025 Security Misconfiguration",
    "A03:2025": "OWASP A03:2025 Software Supply Chain Failures",
    "A06:2025": "OWASP A06:2025 Insecure Design",
    "A08:2025": "OWASP A08:2025 Software and Data Integrity Failures",
}

dim_regra = (spark.createDataFrame(REGRAS, """id_regra string, descricao string,
                                              severidade string, peso int, categoria_owasp string""")
             .withColumn("referencia", F.create_map(
                 *[x for k, v in REFERENCIAS.items() for x in (F.lit(k), F.lit(v))])[F.col("categoria_owasp")])
             .withColumn("escopo_saude", F.col("id_regra").isin("R15", "R16", "R17", "R18"))
             # R08 e R16 disparam em massa porque o Supabase concede GRANT amplo a anon e
             # authenticated POR DESIGN - a protecao fica no RLS, nao no grant. Sem marcar
             # isso, 333 achados de arquitetura abafam os 8 que sao defeito real da aplicacao.
             # A flag permite calcular um score ajustado sem descartar o achado.
             .withColumn("esperado_por_design", F.col("id_regra").isin("R08", "R16"))
             .withColumn("sk_regra", F.monotonically_increasing_id()))

dim_regra.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(f"{GOLD}.dim_regra")
display(spark.table(f"{GOLD}.dim_regra").orderBy("id_regra"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Motor de regras
# MAGIC Cada bloco do UNION ALL e uma regra. E aqui que o catalogo do Postgres vira achado
# MAGIC acionavel - o Transform de verdade deste pipeline.

# COMMAND ----------

motor = f"""
WITH cobertura AS (
  SELECT schema_nome, objeto,
         concat_ws('/', collect_set(upper(comando)))            AS comandos,
         max(CASE WHEN upper(comando) = 'ALL' THEN 1 ELSE 0 END) AS tem_all,
         count(DISTINCT upper(comando))                         AS n_comandos
  FROM {SILVER}.politica
  GROUP BY schema_nome, objeto
),
tab_saude AS (      -- tabelas que guardam pelo menos uma coluna de dado de saude
  SELECT DISTINCT schema_nome, objeto
  FROM {SILVER}.coluna
  WHERE is_dado_saude
)

SELECT 'R01' AS id_regra, o.schema_nome, o.objeto, CAST(NULL AS STRING) AS coluna,
       CAST(NULL AS STRING) AS role_nome,
       concat(o.tipo_objeto, ' exposta via API sem RLS') AS detalhe, o._snapshot
FROM {SILVER}.objeto o
WHERE o.tipo_objeto IN ('tabela','tabela_particionada')
  AND o.exposto_api AND NOT o.rls_habilitado

UNION ALL
SELECT 'R02', p.schema_nome, p.objeto, NULL, p.role_nome,
       concat('Politica ', p.politica, ' libera acesso total a ', p.role_nome), p._snapshot
FROM {SILVER}.politica p
WHERE p.libera_tudo AND p.role_nome IN ('anon','public')

UNION ALL
SELECT 'R03', c.schema_nome, c.objeto, c.coluna, NULL,
       concat('Coluna de tipo ', c.classe_dado, ' em tabela sem RLS'), c._snapshot
FROM {SILVER}.coluna c
JOIN {SILVER}.objeto o USING (schema_nome, objeto)
WHERE c.is_dado_pessoal AND NOT c.is_dado_saude
  AND o.exposto_api AND NOT o.rls_habilitado

UNION ALL
SELECT 'R04', f.schema_nome, f.funcao, NULL, NULL,
       'SECURITY DEFINER sem search_path fixado', f._snapshot
FROM {SILVER}.funcao f
WHERE f.security_definer AND NOT f.tem_search_path

UNION ALL
SELECT 'R05', 'storage', b.bucket_nome, NULL, NULL,
       'Bucket com leitura anonima habilitada', b._snapshot
FROM {SILVER}.bucket b WHERE b.publico

UNION ALL
SELECT 'R06', o.schema_nome, o.objeto, NULL, NULL,
       'RLS habilitado e nenhuma politica: nega todo acesso', o._snapshot
FROM {SILVER}.objeto o
WHERE o.rls_habilitado
  AND NOT EXISTS (SELECT 1 FROM {SILVER}.politica p
                  WHERE p.schema_nome = o.schema_nome AND p.objeto = o.objeto)

UNION ALL
SELECT 'R07', o.schema_nome, o.objeto, NULL, NULL,
       'View sem security_invoker: roda com privilegio do criador', o._snapshot
FROM {SILVER}.objeto o
WHERE o.tipo_objeto IN ('view','view_materializada')
  AND o.exposto_api AND NOT o.security_invoker

UNION ALL
SELECT 'R08', g.schema_nome, g.objeto, NULL, g.role_nome,
       concat(g.role_nome, ' possui ', g.privilegio), g._snapshot
FROM {SILVER}.grant_role g
WHERE g.role_nome IN ('anon','public')
  AND g.privilegio IN ('INSERT','UPDATE','DELETE','TRUNCATE')

UNION ALL
SELECT 'R09', p.schema_nome, p.objeto, NULL, p.role_nome,
       concat('Politica ', p.politica, ' nao amarra a linha ao usuario'), p._snapshot
FROM {SILVER}.politica p
WHERE NOT p.tem_isolamento AND NOT p.libera_tudo

UNION ALL
SELECT 'R10', o.schema_nome, o.objeto, NULL, NULL,
       concat('RLS ativo, politicas cobrem apenas: ', c.comandos), o._snapshot
FROM {SILVER}.objeto o
JOIN cobertura c USING (schema_nome, objeto)
WHERE o.rls_habilitado AND c.tem_all = 0 AND c.n_comandos < 4

UNION ALL
SELECT 'R11', o.schema_nome, o.objeto, NULL, NULL, 'Tabela sem chave primaria', o._snapshot
FROM {SILVER}.objeto o
WHERE o.tipo_objeto IN ('tabela','tabela_particionada')
  AND NOT EXISTS (SELECT 1 FROM {SILVER}.constraint_tabela k
                  WHERE k.schema_nome = o.schema_nome AND k.objeto = o.objeto
                    AND k.tipo = 'PRIMARY KEY')

UNION ALL
SELECT 'R12', e.schema_nome, e.extensao, NULL, NULL,
       concat(e.extensao, ' v', e.versao, ' instalada em ', e.schema_nome), e._snapshot
FROM {SILVER}.extensao e
WHERE e.schema_nome NOT IN ('extensions','pg_catalog')

UNION ALL
SELECT 'R13', o.schema_nome, o.objeto, NULL, NULL,
       'RLS habilitado mas nao forcado para o owner', o._snapshot
FROM {SILVER}.objeto o
WHERE o.rls_habilitado AND NOT o.rls_forcado

UNION ALL
SELECT 'R14', o.schema_nome, o.objeto, NULL, NULL,
       'Objeto sem COMMENT no catalogo de origem', o._snapshot
FROM {SILVER}.objeto o
WHERE o.dominio = 'aplicacao' AND NOT o.tem_documentacao

UNION ALL
SELECT 'R15', c.schema_nome, c.objeto, c.coluna, NULL,
       concat('Dado de saude (', c.classe_dado, ') em tabela sem RLS'), c._snapshot
FROM {SILVER}.coluna c
JOIN {SILVER}.objeto o USING (schema_nome, objeto)
WHERE c.is_dado_saude AND o.exposto_api AND NOT o.rls_habilitado

UNION ALL
SELECT 'R16', g.schema_nome, g.objeto, NULL, g.role_nome,
       concat(g.role_nome, ' possui ', g.privilegio, ' em tabela com dado de saude'), g._snapshot
FROM {SILVER}.grant_role g
JOIN tab_saude s USING (schema_nome, objeto)
WHERE g.role_nome IN ('anon','public') AND g.privilegio = 'SELECT'

UNION ALL
SELECT 'R17', p.schema_nome, p.objeto, NULL, p.role_nome,
       concat('Politica ', p.politica, ' permite a qualquer usuario autenticado ler dado de saude'), p._snapshot
FROM {SILVER}.politica p
JOIN tab_saude s USING (schema_nome, objeto)
WHERE p.role_nome = 'authenticated' AND NOT p.filtra_uid AND NOT p.filtra_tenant

UNION ALL
SELECT 'R18', s.schema_nome, s.objeto, NULL, NULL,
       'Tabela com dado de saude sem nenhuma politica de RLS', o._snapshot
FROM tab_saude s
JOIN {SILVER}.objeto o USING (schema_nome, objeto)
WHERE NOT EXISTS (SELECT 1 FROM {SILVER}.politica p
                  WHERE p.schema_nome = s.schema_nome AND p.objeto = s.objeto)
"""

achados = spark.sql(motor)
achados.createOrReplaceTempView("achados_brutos")
print(f"{achados.count()} achados detectados")
display(achados.groupBy("id_regra").count().orderBy("id_regra"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Dimensoes

# COMMAND ----------

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.dim_objeto AS
SELECT row_number() OVER (ORDER BY schema_nome, objeto) AS sk_objeto,
       schema_anon, objeto_anon, tipo_objeto, dominio, exposto_api,
       rls_habilitado, rls_forcado, security_invoker, tem_documentacao,
       schema_nome, objeto
FROM {SILVER}.objeto""")

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.dim_coluna AS
SELECT row_number() OVER (ORDER BY schema_nome, objeto, coluna) AS sk_coluna,
       coluna_anon, tipo_dado, nullable, classe_dado,
       is_dado_pessoal, is_dado_saude, is_dado_sensivel,
       schema_nome, objeto, coluna
FROM {SILVER}.coluna""")

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.dim_role AS
SELECT row_number() OVER (ORDER BY role_nome) AS sk_role, role_nome,
       CASE WHEN role_nome IN ('anon','public')           THEN 'anonima'
            WHEN role_nome = 'authenticated'              THEN 'autenticada'
            WHEN role_nome IN ('service_role','postgres') THEN 'privilegiada'
            ELSE 'outra' END AS tipo_role
FROM (SELECT DISTINCT role_nome FROM {SILVER}.grant_role
      UNION SELECT DISTINCT role_nome FROM {SILVER}.politica)""")

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.dim_tempo AS
SELECT row_number() OVER (ORDER BY d) AS sk_tempo,
       CAST(d AS DATE) AS data_snapshot,
       year(CAST(d AS DATE)) AS ano, month(CAST(d AS DATE)) AS mes,
       date_format(CAST(d AS DATE), 'EEEE') AS dia_semana
FROM (SELECT DISTINCT _snapshot AS d FROM {SILVER}.objeto)""")

# dim_politica entra como dimensao propria porque as perguntas P3 e P8 consultam
# caracteristica de politica sem passar pelo fato
spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.dim_politica AS
SELECT row_number() OVER (ORDER BY schema_nome, objeto, politica, role_nome) AS sk_politica,
       politica, role_nome, comando, permissiva, so_check, libera_tudo,
       filtra_uid, filtra_jwt, filtra_tenant, tem_isolamento,
       schema_nome, objeto
FROM {SILVER}.politica""")

# COMMAND ----------

# MAGIC %md
# MAGIC ## fato_achado
# MAGIC
# MAGIC `score_risco = peso da regra x multiplicador do dado`, com multiplicador 3 para dado
# MAGIC sensivel, 2 para dado pessoal comum e 1 para o resto. Faixa 1 a 30.
# MAGIC
# MAGIC O 3x para dado sensivel nao e arbitrario: reflete que o art. 11 da LGPD impoe base
# MAGIC legal mais estrita ao dado de saude, logo o mesmo defeito tecnico tem consequencia
# MAGIC juridica maior quando atinge prontuario em vez de configuracao.

# COMMAND ----------

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.fato_achado AS
SELECT row_number() OVER (ORDER BY a.id_regra, a.schema_nome, a.objeto) AS sk_achado,
       o.sk_objeto, c.sk_coluna, r.sk_regra, rl.sk_role, t.sk_tempo,
       r.peso * CASE WHEN c.is_dado_sensivel THEN 3
                     WHEN c.is_dado_pessoal  THEN 2
                     ELSE 1 END                        AS score_risco,
       CASE WHEN r.esperado_por_design THEN 0
            ELSE r.peso * CASE WHEN c.is_dado_sensivel THEN 3
                               WHEN c.is_dado_pessoal  THEN 2
                               ELSE 1 END END            AS score_ajustado,
       COALESCE(c.is_dado_pessoal,  false)             AS envolve_dado_pessoal,
       COALESCE(c.is_dado_saude,    false)             AS envolve_dado_saude,
       COALESCE(c.is_dado_sensivel, false)             AS envolve_dado_sensivel,
       a.detalhe,
       current_timestamp()                             AS _processado_em
FROM achados_brutos a
JOIN      {GOLD}.dim_regra  r  ON r.id_regra = a.id_regra
LEFT JOIN {GOLD}.dim_objeto o  ON o.schema_nome = a.schema_nome AND o.objeto = a.objeto
LEFT JOIN {GOLD}.dim_coluna c  ON c.schema_nome = a.schema_nome AND c.objeto = a.objeto
                              AND c.coluna = a.coluna
LEFT JOIN {GOLD}.dim_role   rl ON rl.role_nome = a.role_nome
LEFT JOIN {GOLD}.dim_tempo  t  ON t.data_snapshot = CAST(a._snapshot AS DATE)""")

print(f"fato_achado: {spark.table(f'{GOLD}.fato_achado').count()} linhas")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Tabelas de consumo

# COMMAND ----------

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.backlog_remediacao AS
SELECT row_number() OVER (ORDER BY f.score_ajustado DESC, f.score_risco DESC, r.id_regra) AS prioridade,
       r.id_regra, r.severidade, r.categoria_owasp, r.descricao AS regra, r.escopo_saude,
       r.esperado_por_design, f.score_ajustado,
       o.schema_anon, o.objeto_anon, o.tipo_objeto, o.dominio,
       c.coluna_anon, c.classe_dado,
       f.score_risco, f.envolve_dado_saude, f.envolve_dado_sensivel, f.detalhe
FROM {GOLD}.fato_achado f
JOIN      {GOLD}.dim_regra  r ON r.sk_regra  = f.sk_regra
LEFT JOIN {GOLD}.dim_objeto o ON o.sk_objeto = f.sk_objeto
LEFT JOIN {GOLD}.dim_coluna c ON c.sk_coluna = f.sk_coluna""")

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.postura_por_schema AS
SELECT o.schema_anon, o.dominio,
       count(DISTINCT o.sk_objeto)                                           AS n_objetos,
       count(f.sk_achado)                                                    AS n_achados,
       coalesce(sum(f.score_risco), 0)                                       AS score_total,
       coalesce(sum(f.score_ajustado), 0)                                    AS score_ajustado,
       round(coalesce(sum(f.score_risco), 0)
             / nullif(count(DISTINCT o.sk_objeto), 0), 2)                    AS score_por_objeto,
       sum(CASE WHEN r.severidade = 'Critico' THEN 1 ELSE 0 END)             AS n_criticos,
       sum(CASE WHEN r.escopo_saude THEN 1 ELSE 0 END)                       AS n_achados_saude
FROM {GOLD}.dim_objeto o
LEFT JOIN {GOLD}.fato_achado f ON f.sk_objeto = o.sk_objeto
LEFT JOIN {GOLD}.dim_regra   r ON r.sk_regra  = f.sk_regra
GROUP BY o.schema_anon, o.dominio""")

spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.mapa_exposicao_lgpd AS
SELECT c.classe_dado, c.is_dado_saude, c.is_dado_sensivel,
       count(*)                                                              AS n_colunas,
       sum(CASE WHEN o.rls_habilitado THEN 1 ELSE 0 END)                     AS n_protegidas,
       sum(CASE WHEN NOT o.rls_habilitado AND o.exposto_api THEN 1 ELSE 0 END) AS n_expostas,
       round(100.0 * sum(CASE WHEN NOT o.rls_habilitado AND o.exposto_api THEN 1 ELSE 0 END)
             / count(*), 1)                                                  AS pct_exposta
FROM {GOLD}.dim_coluna c
JOIN {GOLD}.dim_objeto o ON o.schema_nome = c.schema_nome AND o.objeto = c.objeto
WHERE c.is_dado_pessoal AND o.dominio = 'aplicacao'
GROUP BY c.classe_dado, c.is_dado_saude, c.is_dado_sensivel""")

# responde P8: um paciente consegue ler prontuario de outro?
spark.sql(f"""CREATE OR REPLACE TABLE {GOLD}.isolamento_prontuario AS
SELECT o.schema_anon, o.objeto_anon,
       o.rls_habilitado,
       count(p.sk_politica)                                                  AS n_politicas,
       sum(CASE WHEN p.filtra_uid OR p.filtra_tenant THEN 1 ELSE 0 END)      AS n_com_isolamento,
       max(CASE WHEN p.role_nome = 'authenticated'
                 AND NOT p.filtra_uid AND NOT p.filtra_tenant
                THEN 1 ELSE 0 END)                                           AS aberta_a_autenticados,
       count(DISTINCT c.sk_coluna)                                           AS n_colunas_saude
FROM {GOLD}.dim_objeto o
JOIN {GOLD}.dim_coluna c   ON c.schema_nome = o.schema_nome AND c.objeto = o.objeto
                          AND c.is_dado_saude
LEFT JOIN {GOLD}.dim_politica p ON p.schema_nome = o.schema_nome AND p.objeto = o.objeto
WHERE o.dominio = 'aplicacao'
GROUP BY o.schema_anon, o.objeto_anon, o.rls_habilitado""")

display(spark.table(f"{GOLD}.backlog_remediacao").orderBy("prioridade").limit(20))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Catalogo de dados no Unity Catalog

# COMMAND ----------

DOC_TABELA = {
 "dim_regra": "Catalogo das 18 regras de auditoria. Dimensao curada manualmente: traz a severidade, o peso numerico e a categoria do OWASP Top 10:2025. escopo_saude marca as quatro regras especificas de dado de saude.",
 "dim_objeto": "Objetos do banco auditados. Identificadores anonimizados (schema_anon, objeto_anon) porque o Pitaia esta em producao e o repositorio e publico.",
 "dim_coluna": "Colunas com classificacao LGPD. is_dado_saude marca dado referente a saude (art. 11); is_dado_sensivel abrange todo o art. 5, II.",
 "dim_politica": "Politicas de RLS na granularidade politica x role, com flags derivadas da expressao. A expressao SQL literal nao e publicada.",
 "dim_role": "Roles do Postgres agrupadas por nivel de privilegio.",
 "dim_tempo": "Dimensao temporal na granularidade do snapshot do catalogo.",
 "fato_achado": "Tabela fato. Granularidade: um achado = uma regra violada por um objeto num snapshot. score_risco = peso da regra x 3 (dado sensivel), x 2 (dado pessoal) ou x 1.",
 "backlog_remediacao": "Achados ordenados por risco decrescente. Responde a pergunta central do MVP: o que corrigir primeiro.",
 "postura_por_schema": "Score agregado por schema. Permite comparar os schemas da aplicacao com os gerenciados pelo Supabase.",
 "mapa_exposicao_lgpd": "Para cada classe de dado pessoal, quantas colunas estao protegidas por RLS e quantas expostas. Medida de conformidade.",
 "isolamento_prontuario": "Uma linha por tabela que contem dado de saude, com o estado do isolamento entre pacientes. aberta_a_autenticados=1 indica que qualquer usuario logado alcanca o dado.",
}
def sql_txt(t):
    """Aspa simples no texto quebra o literal SQL. Dobrar e o escape."""
    return t.replace("'", "''")

for t, doc in DOC_TABELA.items():
    spark.sql(f"COMMENT ON TABLE {GOLD}.{t} IS '{sql_txt(doc)}'")

# Documentar 20 colunas a mao e deixar 100 sem descricao nao atende o enunciado, que pede
# "nome e descricao do que cada campo representa". Separo em dois dicionarios: COMUM para
# colunas que aparecem em varias tabelas com o mesmo sentido, ESPECIFICO para as que mudam
# de significado conforme a tabela. No fim o loop varre TODAS as colunas e imprime o que
# ficou sem documentacao - o catalogo se audita em vez de eu confiar na minha contagem.

COMUM = {
 "sk_objeto": "Chave substituta de dim_objeto.",
 "sk_coluna": "Chave substituta de dim_coluna. Nula quando o achado nao e por coluna.",
 "sk_regra": "Chave substituta de dim_regra.",
 "sk_role": "Chave substituta de dim_role. Nula quando o achado nao e por role.",
 "sk_tempo": "Chave substituta de dim_tempo.",
 "sk_politica": "Chave substituta de dim_politica.",
 "schema_anon": "Schema anonimizado. Dominio: app_s1..app_sN para a aplicacao, nome real para os schemas gerenciados pelo Supabase.",
 "objeto_anon": "Objeto anonimizado. Formato t_NNN, estavel entre execucoes.",
 "coluna_anon": "Coluna anonimizada. Formato c_ + 8 digitos hexadecimais do SHA-256 de schema|objeto|coluna.",
 "schema_nome": "Nome real do schema. Campo tecnico de join, nao publicado no relatorio.",
 "objeto": "Nome real do objeto. Campo tecnico de join, nao publicado no relatorio.",
 "coluna": "Nome real da coluna. Campo tecnico de join, nao publicado no relatorio.",
 "tipo_objeto": "Tipo do objeto no Postgres. Dominio: tabela, tabela_particionada, view, view_materializada, tabela_estrangeira, outro.",
 "dominio": "Origem do objeto. Dominio: aplicacao, gerenciado_supabase. Separa o que a autora construiu do que a plataforma mantem.",
 "rls_habilitado": "Estado do Row Level Security. Origem: pg_class.relrowsecurity. Dominio: true, false.",
 "severidade": "Nivel de gravidade da regra. Dominio: Critico, Alto, Medio, Baixo.",
 "categoria_owasp": "Categoria do OWASP Top 10:2025. Dominio: A01:2025, A02:2025, A03:2025, A06:2025, A08:2025.",
 "escopo_saude": "True nas regras R15 a R18, especificas de dado referente a saude.",
 "esperado_por_design": "True em R08 e R16. O Supabase concede privilegio amplo a anon e authenticated por padrao e delega a protecao ao RLS; esses achados descrevem a arquitetura da plataforma, nao defeito da aplicacao.",
 "id_regra": "Identificador da regra de auditoria. Dominio: R01 a R18. Chave natural.",
 "role_nome": "Nome da role no Postgres. Dominio observado: anon, authenticated, public, service_role, postgres, supabase_admin e outras.",
 "classe_dado": "Classe de dado pessoal inferida. Dominio: credencial, saude_clinica, saude_metrica, biometrico, documento, prof_saude, financeiro, email, telefone, endereco, nascimento, nome_pessoa, localizacao, nulo.",
 "is_dado_saude": "Dado referente a saude, LGPD art. 11. Inclui metrica corporal por decisao interpretativa documentada no README.",
 "is_dado_sensivel": "Dado pessoal sensivel, LGPD art. 5, II.",
 "is_dado_pessoal": "Dado pessoal, LGPD art. 5, I. True quando classe_dado nao e nula.",
 "envolve_dado_pessoal": "True quando o achado atinge coluna classificada como dado pessoal.",
 "envolve_dado_saude": "True quando o achado atinge coluna de dado referente a saude.",
 "envolve_dado_sensivel": "True quando o achado atinge dado pessoal sensivel. E o que aciona o multiplicador 3 no score.",
 "score_risco": "Metrica de risco. Faixa 1 a 30. Calculo: dim_regra.peso x multiplicador do dado (3 sensivel, 2 pessoal, 1 demais).",
 "score_ajustado": "Score desconsiderando os achados esperados por design (R08, R16). Separa risco introduzido pela aplicacao de caracteristica da plataforma. Faixa 0 a 30.",
 "detalhe": "Descricao textual do achado, gerada pelo motor de regras. Nao contem nome real de objeto.",
 "n_colunas_saude": "Quantidade de colunas de dado de saude na tabela. Faixa observada: 1 a 21.",
 "n_politicas": "Quantidade de politicas de RLS definidas sobre o objeto.",
 "n_com_isolamento": "Quantidade de politicas que referenciam auth.uid(), o JWT ou coluna de tenant.",
}

ESPECIFICO = {
 ("dim_regra", "descricao"): "Enunciado da regra de auditoria, em linguagem de negocio.",
 ("dim_regra", "peso"): "Peso numerico da severidade. Dominio: 10 (Critico), 6 (Alto), 3 (Medio), 1 (Baixo).",
 ("dim_regra", "referencia"): "Nome completo da categoria OWASP correspondente, para citacao no relatorio.",
 ("dim_regra", "sk_regra"): "Chave substituta da regra.",
 ("dim_objeto", "exposto_api"): "True quando o schema e exposto via PostgREST. No Pitaia: public e graphql_public.",
 ("dim_objeto", "rls_forcado"): "True quando o RLS tambem se aplica ao owner da tabela (FORCE ROW LEVEL SECURITY). Origem: pg_class.relforcerowsecurity.",
 ("dim_objeto", "security_invoker"): "True quando a view declara security_invoker=true e portanto respeita o RLS de quem consulta, e nao de quem a criou.",
 ("dim_objeto", "tem_documentacao"): "True quando o objeto possui COMMENT no catalogo de origem do Postgres.",
 ("dim_coluna", "tipo_dado"): "Tipo do dado no Postgres, como retornado por format_type. Exemplos: text, uuid, timestamptz, numeric, jsonb.",
 ("dim_coluna", "nullable"): "True quando a coluna aceita nulo. Derivado de pg_attribute.attnotnull.",
 ("dim_role", "tipo_role"): "Agrupamento da role por nivel de privilegio. Dominio: anonima, autenticada, privilegiada, outra.",
 ("dim_tempo", "data_snapshot"): "Data da coleta do catalogo de seguranca. Granularidade da dimensao.",
 ("dim_tempo", "ano"): "Ano do snapshot. Derivado de data_snapshot.",
 ("dim_tempo", "mes"): "Mes do snapshot. Dominio: 1 a 12.",
 ("dim_tempo", "dia_semana"): "Dia da semana do snapshot, por extenso em ingles.",
 ("dim_politica", "politica"): "Nome da politica de RLS no Postgres.",
 ("dim_politica", "comando"): "Comando SQL coberto pela politica. Dominio: ALL, SELECT, INSERT, UPDATE, DELETE.",
 ("dim_politica", "permissiva"): "True para politica PERMISSIVE (somam-se por OR), false para RESTRICTIVE (somam-se por AND).",
 ("dim_politica", "so_check"): "True quando a politica define apenas WITH CHECK, sem USING. Nesse caso expressao_using vem nula na origem.",
 ("dim_politica", "libera_tudo"): "True quando a expressao da politica reduz a USING(true), concedendo acesso irrestrito.",
 ("dim_politica", "filtra_uid"): "True quando a expressao referencia auth.uid(), amarrando a linha ao usuario autenticado.",
 ("dim_politica", "filtra_jwt"): "True quando a expressao referencia auth.jwt() ou auth.role().",
 ("dim_politica", "filtra_tenant"): "True quando a expressao referencia coluna de tenant, paciente ou profissional.",
 ("dim_politica", "tem_isolamento"): "True quando qualquer uma das tres flags de filtro e verdadeira. E a medida de isolamento entre usuarios.",
 ("fato_achado", "sk_achado"): "Chave substituta do achado. Granularidade da fato: uma regra violada por um objeto, num snapshot.",
 ("fato_achado", "_processado_em"): "Timestamp da execucao do motor de regras. Metadado de controle.",
 ("backlog_remediacao", "prioridade"): "Ordem sugerida de correcao. 1 = mais urgente. Derivada de score_ajustado e score_risco decrescentes.",
 ("backlog_remediacao", "regra"): "Enunciado da regra violada, copiado de dim_regra.descricao para leitura direta.",
 ("postura_por_schema", "n_objetos"): "Quantidade de objetos distintos no schema.",
 ("postura_por_schema", "n_achados"): "Quantidade de achados no schema.",
 ("postura_por_schema", "score_total"): "Soma do score_risco dos achados do schema.",
 ("postura_por_schema", "score_ajustado"): "Soma do score_ajustado. Compare com score_total para ver quanto do risco e caracteristica da plataforma.",
 ("postura_por_schema", "score_por_objeto"): "score_total dividido pelo numero de objetos. Normaliza pelo tamanho do schema, sem o que o schema maior sempre parece o pior.",
 ("postura_por_schema", "n_criticos"): "Quantidade de achados de severidade Critica no schema.",
 ("postura_por_schema", "n_achados_saude"): "Quantidade de achados das regras R15 a R18, especificas de dado de saude.",
 ("mapa_exposicao_lgpd", "n_colunas"): "Total de colunas daquela classe de dado nos schemas da aplicacao.",
 ("mapa_exposicao_lgpd", "n_protegidas"): "Colunas da classe que estao em tabela com RLS habilitado.",
 ("mapa_exposicao_lgpd", "n_expostas"): "Colunas da classe em tabela exposta via API e sem RLS. Medida direta de exposicao regulatoria.",
 ("mapa_exposicao_lgpd", "pct_exposta"): "Percentual de colunas da classe expostas sem RLS. Faixa 0 a 100.",
 ("isolamento_prontuario", "aberta_a_autenticados"): "1 quando existe politica para authenticated sem filtro por usuario ou tenant, ou seja, qualquer conta logada alcanca o dado de qualquer paciente. Dominio: 0, 1.",
}

def sql_txt(t):
    """Aspa simples no texto quebra o literal SQL. Dobrar e o escape."""
    return t.replace("'", "''")

for t, doc in DOC_TABELA.items():
    spark.sql(f"COMMENT ON TABLE {GOLD}.{t} IS '{sql_txt(doc)}'")

documentadas, sem_doc = 0, []
for t in DOC_TABELA:
    for c in spark.table(f"{GOLD}.{t}").columns:
        doc = ESPECIFICO.get((t, c)) or COMUM.get(c)
        if doc:
            spark.sql(f"ALTER TABLE {GOLD}.{t} ALTER COLUMN {c} COMMENT '{sql_txt(doc)}'")
            documentadas += 1
        else:
            sem_doc.append(f"{t}.{c}")

total = documentadas + len(sem_doc)
print(f"Catalogo: {documentadas}/{total} colunas documentadas "
      f"({100*documentadas/total:.0f}%)")
if sem_doc:
    print("Sem descricao:", ", ".join(sem_doc))

print("Catalogo aplicado. Screenshot do Catalog Explorer e da aba Lineage.")
