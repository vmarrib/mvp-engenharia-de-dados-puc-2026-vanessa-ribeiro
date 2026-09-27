# Databricks notebook source
# MAGIC %md
# MAGIC # 02 - Silver | limpeza, padronizacao e classificacao de dado de saude
# MAGIC
# MAGIC O Pitaia armazena prontuario, exame, medicacao e metrica corporal. Isso e dado
# MAGIC pessoal **sensivel** pela LGPD (art. 5, II), com regime proprio no art. 11.
# MAGIC Entao a classificacao aqui nao pode ser genericamente "PII": ela precisa separar
# MAGIC dado pessoal comum de dado de saude, porque o risco e a base legal dos dois sao
# MAGIC diferentes.
# MAGIC
# MAGIC Perfilo a qualidade **antes** de limpar. Medir depois nao prova nada.

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.window import Window

CATALOGO = "workspace"
BRONZE   = f"{CATALOGO}.bronze"
SILVER   = f"{CATALOGO}.silver"

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {SILVER} COMMENT "
          "'Catalogo de seguranca do Pitaia limpo, tipado e com classificacao LGPD. "
          "Identificadores anonimizados para publicacao.'")

def bronze(t):
    return spark.table(f"{BRONZE}.{t}")

def sql_txt(t):
    """Aspa simples no texto quebra o literal SQL. Dobrar e o escape."""
    return t.replace("'", "''")

def salvar(df, nome, doc):
    alvo = f"{SILVER}.{nome}"
    df.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(alvo)
    spark.sql(f"COMMENT ON TABLE {alvo} IS '{sql_txt(doc)}'")
    print(f"{alvo:46s} {spark.table(alvo).count():6d}")
    return spark.table(alvo)

# o export do Supabase devolve booleano como t/f, mas pela UI as vezes vem true/false
def booleano(coluna):
    return F.lower(F.trim(F.col(coluna))).isin("t", "true", "1")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Perfil de qualidade na Bronze

# COMMAND ----------

TABELAS = ["objetos", "politicas", "colunas", "grants", "funcoes",
           "buckets", "extensoes", "constraints"]

perfil = []
for t in TABELAS:
    df = bronze(t)
    total = df.count()
    for c in [x for x in df.columns if not x.startswith("_")]:
        vazio = F.col(c).isNull() | (F.trim(F.col(c)) == "")
        r = df.agg(F.sum(F.when(vazio, 1).otherwise(0)).alias("n"),
                   F.countDistinct(c).alias("d"),
                   F.max(F.length(c)).alias("tam")).collect()[0]
        perfil.append((t, c, total, int(r["n"]),
                       round(100 * r["n"] / total, 2) if total else None,
                       int(r["d"]), r["tam"]))

df_perfil = spark.createDataFrame(perfil, """tabela string, coluna string, n_linhas int,
    n_nulos int, pct_nulo double, n_distintos int, tamanho_max int""")

salvar(df_perfil, "perfil_qualidade",
       "Completude, cardinalidade e tamanho por atributo, medidos na Bronze antes de "
       "qualquer limpeza. Evidencia da etapa 4.5 do MVP.")
display(df_perfil.orderBy(F.desc("pct_nulo")))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Duplicatas por chave natural

# COMMAND ----------

CHAVES = {
    "objetos":     ["schema_nome", "objeto"],
    "politicas":   ["schema_nome", "objeto", "politica"],
    "colunas":     ["schema_nome", "objeto", "coluna"],
    "grants":      ["role_nome", "schema_nome", "objeto", "privilegio"],
    "funcoes":     ["schema_nome", "funcao"],
    "constraints": ["schema_nome", "objeto", "constraint_nome"],
}

dups = []
for t, chave in CHAVES.items():
    n = bronze(t).count()
    u = bronze(t).select(*chave).distinct().count()
    dups.append((t, ",".join(chave), n, u, n - u))

salvar(spark.createDataFrame(dups, """tabela string, chave_natural string,
       n_linhas int, n_unicas int, n_duplicatas int"""),
       "perfil_duplicatas",
       "Duplicatas por chave natural medidas antes da deduplicacao. Dimensao de unicidade.")

display(spark.table(f"{SILVER}.perfil_duplicatas"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Objetos
# MAGIC
# MAGIC Nao removo os schemas internos do Supabase. Marco eles com `dominio` e uso como
# MAGIC grupo de comparacao na analise - sem uma referencia, dizer "tenho 14 achados" nao
# MAGIC significa nada.
# MAGIC
# MAGIC A anonimizacao existe porque o repositorio e publico e o Pitaia esta em producao
# MAGIC com prontuario de gente real. Publicar o nome da tabela vulneravel seria entregar
# MAGIC o caminho pronto.

# COMMAND ----------

SUPABASE = ["auth", "storage", "realtime", "vault", "extensions", "graphql",
            "graphql_public", "supabase_functions", "supabase_migrations",
            "pgbouncer", "cron", "net", "_realtime", "pgsodium", "pgsodium_masks"]
SISTEMA  = ["pg_catalog", "information_schema", "pg_toast"]

# conferir em Supabase > Settings > API > Exposed schemas. O padrao e so public.
EXPOSTOS = ["public", "graphql_public"]

tipo = (F.when(F.col("tipo_bruto") == "r", "tabela")
         .when(F.col("tipo_bruto") == "p", "tabela_particionada")
         .when(F.col("tipo_bruto") == "v", "view")
         .when(F.col("tipo_bruto") == "m", "view_materializada")
         .when(F.col("tipo_bruto") == "f", "tabela_estrangeira")
         .otherwise("outro"))

obj = (bronze("objetos")
       .filter(~F.col("schema_nome").isin(SISTEMA))
       .withColumn("tipo_objeto", tipo)
       .withColumn("rls_habilitado", booleano("rls_habilitado"))
       .withColumn("rls_forcado", booleano("rls_forcado"))
       .withColumn("dominio", F.when(F.col("schema_nome").isin(SUPABASE),
                                     "gerenciado_supabase").otherwise("aplicacao"))
       .withColumn("exposto_api", F.col("schema_nome").isin(EXPOSTOS))
       .withColumn("security_invoker",
                   F.coalesce(F.col("opcoes"), F.lit("")).contains("security_invoker=true"))
       .withColumn("tem_documentacao", F.col("comentario").isNotNull())
       .dropDuplicates(["schema_nome", "objeto"]))

ordem = Window.orderBy("schema_nome", "objeto")
obj = (obj
       .withColumn("objeto_anon",
                   F.concat(F.lit("t_"), F.lpad(F.row_number().over(ordem).cast("string"), 3, "0")))
       .withColumn("schema_anon",
                   F.when(F.col("dominio") == "aplicacao",
                          F.concat(F.lit("app_s"),
                                   F.dense_rank().over(Window.orderBy("schema_nome")).cast("string")))
                    .otherwise(F.col("schema_nome"))))

salvar(obj.select("schema_nome", "schema_anon", "objeto", "objeto_anon", "tipo_objeto",
                  "dominio", "exposto_api", "rls_habilitado", "rls_forcado",
                  "security_invoker", "tem_documentacao", "_snapshot"),
       "objeto",
       "Um registro por objeto do banco. dominio separa o que e da aplicacao do que o "
       "Supabase gerencia. exposto_api indica alcance via PostgREST. Origem: bronze.objetos.")

salvar(obj.select("schema_nome", "objeto", "schema_anon", "objeto_anon"),
       "_de_para_nao_publicar",
       "PRIVADO. De-para entre nome real e anonimizado. Nao versionar.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Colunas e a classificacao LGPD
# MAGIC
# MAGIC Tres niveis, nao dois:
# MAGIC
# MAGIC - `saude` e `biometrico` -> dado sensivel, art. 5 II + art. 11
# MAGIC - `credencial`, `documento`, `financeiro` -> dado pessoal de alto impacto
# MAGIC - `email`, `telefone`, `endereco`, `nome_pessoa` -> dado pessoal comum
# MAGIC
# MAGIC Decisao interpretativa que preciso saber defender: **peso, altura, IMC,
# MAGIC frequencia cardiaca e sono entram como dado de saude.** Isoladamente pareceriam
# MAGIC antropometria banal, mas coletados por uma plataforma de saude, com medico e
# MAGIC educador fisico acessando, sao "dado referente a saude" no sentido do art. 5 II.
# MAGIC Classifiquei pelo contexto de tratamento, nao pelo nome do campo.

# COMMAND ----------

# O schema do Pitaia e em ingles, entao os padroes sao em ingles com alguns termos
# em portugues por seguranca.
#
# Classifico por TABELA e por COLUNA. Isso importa: uma coluna chamada "notes" dentro
# de medical_record_notes e dado clinico; a mesma coluna "notes" em checkin_groups nao
# e. Olhar so o nome da coluna perde a maior parte do dado de saude - na primeira
# versao eu achava 12 colunas em 640, o que era obviamente errado para uma plataforma
# de saude. Com heranca de tabela sao 248.

TABELA_CLASSE = [
    ("saude_clinica", r"medical_record|anamnesis|lab_(result|marker)|medication|menstrual|"
                      r"anxiety|crisis|diagnos|symptom|treatment|prescription|patient_file|"
                      r"diary_entr|self_assessment|questionnaire_answer|prontuario|exame"),
    ("saude_metrica", r"body_measurement|wearable_metric|exercise_log|workout_log|"
                      r"workout_feedback|\bmeals?\b|nutrition|photo_tracking|checkin|"
                      r"\bgoals?\b|alert_completion|assigned_(workout|questionnaire)"),
    ("credencial",    r"ai_keys|otp|trusted_device|unsubscribe_token|invite_link"),
]

COLUNA_CLASSE = [
    ("credencial",    r"senha|password|secret|token|api_?key|otp|refresh"),
    ("saude_clinica", r"diagnos|symptom|medication|dosage|prescri|allerg|anamnes|lab_|marker|"
                      r"clinical|medical|crisis|severity|mood|pain|sleep_quality|cid10"),
    ("saude_metrica", r"weight|height|\bbmi\b|body_fat|muscle|circumference|heart_rate|\bbpm\b|"
                      r"spo2|steps|calories|hydration|glucose|sleep|intensity|reps|duration_min"),
    ("biometrico",    r"biometr|face_|fingerprint"),
    ("documento",     r"\bcpf\b|\bcnpj\b|\brg\b|passport|\bcnh\b|\bcns\b|document_number"),
    ("prof_saude",    r"\bcrm\b|crefito|\bcref\b|council|license_number|specialty"),
    ("financeiro",    r"card_|iban|\bpix\b|bank_|invoice"),
    ("email",         r"e_?mail"),
    ("telefone",      r"phone|whatsapp|mobile_number|telefone|celular"),
    ("endereco",      r"address|zip_?code|postal|street|neighborhood|\bcep\b"),
    ("nascimento",    r"birth|\bdob\b|nascimento|\bage\b"),
    ("nome_pessoa",   r"^name$|full_name|first_name|last_name|display_name|patient_name"),
    ("localizacao",   r"latitude|longitude|\blat\b|\blng\b|geoloc"),
]

# colunas de controle nao herdam a sensibilidade da tabela: um created_at de
# medical_record_notes nao e dado de saude
TECNICAS = r"^(id|created_at|updated_at|deleted_at|.*_id|sort_order|is_active|version|status|type|created_by|updated_by)$"

SAUDE = ["saude_clinica", "saude_metrica"]
SENSIVEIS = SAUDE + ["biometrico", "origem_racial", "religiao"]

col_lower = F.lower(F.col("coluna"))
tab_lower = F.lower(F.col("objeto"))

# classe pela coluna (mais especifica, tem prioridade)
por_coluna = F.lit(None).cast("string")
for nome, padrao in reversed(COLUNA_CLASSE):
    por_coluna = F.when(col_lower.rlike(padrao), F.lit(nome)).otherwise(por_coluna)

# classe herdada da tabela
por_tabela = F.lit(None).cast("string")
for nome, padrao in reversed(TABELA_CLASSE):
    por_tabela = F.when(tab_lower.rlike(padrao), F.lit(nome)).otherwise(por_tabela)

col = (bronze("colunas")
       .filter(~F.col("schema_nome").isin(SISTEMA))
       .withColumn("classe_por_coluna", por_coluna)
       .withColumn("classe_por_tabela", por_tabela)
       .withColumn("coluna_tecnica", col_lower.rlike(TECNICAS))
       .withColumn("classe_dado",
                   F.coalesce(F.col("classe_por_coluna"),
                              F.when(~F.col("coluna_tecnica"), F.col("classe_por_tabela"))))
       .withColumn("origem_classificacao",
                   F.when(F.col("classe_por_coluna").isNotNull(), "coluna")
                    .when(F.col("classe_dado").isNotNull(), "tabela"))
       .withColumn("is_dado_pessoal", F.col("classe_dado").isNotNull())
       .withColumn("is_dado_saude", F.col("classe_dado").isin(SAUDE))
       .withColumn("is_dado_sensivel", F.col("classe_dado").isin(SENSIVEIS))
       .withColumn("nullable", booleano("is_nullable"))
       .withColumn("coluna_anon",
                   F.concat(F.lit("c_"),
                            F.substring(F.sha2(F.concat_ws("|", "schema_nome", "objeto", "coluna"), 256), 1, 8)))
       .dropDuplicates(["schema_nome", "objeto", "coluna"]))

silver_col = salvar(col.select("schema_nome", "objeto", "coluna", "coluna_anon", "tipo_dado",
                              "nullable", "classe_dado", "origem_classificacao",
                              "is_dado_pessoal", "is_dado_saude", "is_dado_sensivel", "_snapshot"),
                    "coluna",
                    "Um registro por coluna, com classificacao LGPD. classe_dado vem do nome da "
                    "coluna quando ha padrao especifico, senao e herdada do nome da tabela - "
                    "colunas tecnicas nao herdam. is_dado_saude marca o art. 11; is_dado_sensivel "
                    "abrange o art. 5, II. Origem: bronze.colunas.")

total = silver_col.count()
pessoais = silver_col.filter("is_dado_pessoal").count()
saude = silver_col.filter("is_dado_saude").count()
print(f"\n{pessoais}/{total} colunas classificadas como dado pessoal ({100*pessoais/total:.1f}%)")
print(f"{saude} colunas de dado de saude, em "
      f"{silver_col.filter('is_dado_saude').select('objeto').distinct().count()} tabelas")
display(silver_col.groupBy("classe_dado", "origem_classificacao").count().orderBy(F.desc("count")))

display(silver_col.groupBy("classe_dado", "is_dado_sensivel").count().orderBy(F.desc("count")))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Acuracia do classificador
# MAGIC Regex sobre nome de coluna erra nos dois sentidos. Amostro 40 colunas para estimar
# MAGIC precisao e recall em vez de apresentar a heuristica como se fosse exata.

# COMMAND ----------

# amostra deterministica: hash estavel da chave em vez de rand(), para que a mesma
# amostra saia em qualquer execucao e o numero do relatorio seja reproduzivel
amostra = (silver_col
           .filter(F.col("schema_nome").isin(EXPOSTOS))
           .withColumn("_ordem", F.sha2(F.concat_ws("|", "objeto", "coluna", F.lit("42")), 256))
           .orderBy("_ordem")
           .select("objeto", "coluna", "tipo_dado", "classe_dado",
                   "origem_classificacao", "is_dado_saude")
           .limit(40))
display(amostra)

# TODO rotular a mao as 40 linhas acima, contar FP e FN, e registrar no README.
# Anotar tambem 2 exemplos de erro para comentar na discussao.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Politicas de RLS
# MAGIC
# MAGIC `pg_policies.roles` vem como array. No CSV virou string separada por `;` porque
# MAGIC usei `array_to_string` na extracao - sem isso o parser de CSV quebrava nas virgulas
# MAGIC internas. Aqui desfaco com split + explode.
# MAGIC
# MAGIC Nao levo a expressao SQL literal para a Silver. Ela revela a estrutura de
# MAGIC multi-tenancy do Pitaia, e o repositorio e publico. Derivo flags e descarto o texto.

# COMMAND ----------

pol = (bronze("politicas")
       .filter(~F.col("schema_nome").isin(SISTEMA))
       # explode precisa vir sozinho: Spark nao aceita gerador aninhado em outra
       # expressao (UNSUPPORTED_GENERATOR.NESTED_IN_EXPRESSIONS). Trim vem na linha seguinte.
       .withColumn("role_nome", F.explode(F.split(F.coalesce(F.col("roles"), F.lit("")), ";")))
       .withColumn("role_nome", F.trim(F.col("role_nome")))
       .filter(F.col("role_nome") != "")
       .withColumn("permissiva", F.upper(F.trim(F.col("permissive"))) == "PERMISSIVE")
       # politica so com WITH CHECK tem qual nulo - uso coalesce em vez de descartar
       .withColumn("expr", F.lower(F.coalesce(F.col("expressao_using"),
                                              F.col("expressao_check"), F.lit(""))))
       .withColumn("so_check", F.col("expressao_using").isNull()
                               & F.col("expressao_check").isNotNull())
       .withColumn("libera_tudo", F.regexp_replace(F.col("expr"), r"[\s()]", "") == "true")
       .withColumn("filtra_uid", F.col("expr").contains("auth.uid()"))
       .withColumn("filtra_jwt", F.col("expr").contains("auth.jwt()")
                                 | F.col("expr").contains("auth.role()"))
       .withColumn("filtra_tenant",
                   F.col("expr").rlike(r"tenant|paciente_id|patient_id|user_id|owner_id|"
                                       r"medico_id|profissional_id|clinica_id|org_id"))
       .withColumn("tem_isolamento", F.col("filtra_uid") | F.col("filtra_jwt") | F.col("filtra_tenant"))
       .dropDuplicates(["schema_nome", "objeto", "politica", "role_nome"]))

salvar(pol.select("schema_nome", "objeto", "politica", "role_nome", "comando", "permissiva",
                  "so_check", "libera_tudo", "filtra_uid", "filtra_jwt", "filtra_tenant",
                  "tem_isolamento", "_snapshot"),
       "politica",
       "Um registro por politica x role (array explodido). tem_isolamento indica se a "
       "expressao amarra a linha ao usuario, ao JWT ou a uma coluna de tenant. libera_tudo "
       "marca USING(true). A expressao literal nao e publicada. Origem: bronze.politicas.")

display(spark.table(f"{SILVER}.politica")
             .groupBy("role_nome", "tem_isolamento").count().orderBy("role_nome"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Grants, funcoes, buckets, extensoes, constraints

# COMMAND ----------

salvar(bronze("grants")
       .filter(~F.col("schema_nome").isin(SISTEMA))
       .select("role_nome", "schema_nome", "objeto", "privilegio", "_snapshot")
       .dropDuplicates(["role_nome", "schema_nome", "objeto", "privilegio"]),
       "grant_role",
       "Um registro por role x objeto x privilegio, deduplicado - heranca de role repete "
       "a mesma tupla. Origem: bronze.grants.")

salvar(bronze("funcoes")
       .withColumn("security_definer", booleano("security_definer"))
       .withColumn("tem_search_path", F.coalesce(F.col("config"), F.lit("")).contains("search_path"))
       .select("schema_nome", "funcao", "security_definer", "tem_search_path", "linguagem", "_snapshot")
       # NAO deduplicar por (schema_nome, funcao). O perfil de duplicatas acusou 30
       # repeticoes, que sao overloads do Postgres: mesma funcao, assinaturas diferentes,
       # cada uma com suas proprias flags. Descartar 30 esconderia um SECURITY DEFINER
       # vulneravel e daria falso negativo na R04. Dedup so de linha integralmente igual.
       .dropDuplicates(),
       "funcao",
       "Uma linha por funcao. Funcoes sobrecarregadas (mesmo nome, assinaturas diferentes) "
       "ficam em linhas distintas de proposito: cada assinatura tem suas proprias flags de "
       "seguranca. security_definer executa com privilegio do criador e contorna RLS; sem "
       "search_path fixado isso viabiliza escalada de privilegio. O corpo da funcao nao foi "
       "coletado. Origem: bronze.funcoes.")

salvar(bronze("buckets").withColumn("publico", booleano("publico"))
       .select("bucket_id", "bucket_nome", "publico", "_snapshot"),
       "bucket",
       "Um registro por bucket do Storage. publico=true libera leitura anonima de todo o "
       "conteudo - critico no Pitaia, onde bucket costuma guardar exame e laudo. "
       "Origem: bronze.buckets.")

salvar(bronze("extensoes").select("extensao", "schema_nome", "versao", "_snapshot"),
       "extensao",
       "Um registro por extensao instalada. Superficie de cadeia de suprimentos, "
       "OWASP A03:2025. Origem: bronze.extensoes.")

salvar(bronze("constraints")
       .filter(~F.col("schema_nome").isin(SISTEMA))
       .select("schema_nome", "objeto", "constraint_nome", "tipo", "_snapshot")
       .dropDuplicates(["schema_nome", "objeto", "constraint_nome"]),
       "constraint_tabela",
       "Um registro por constraint de PK, UNIQUE ou FK. Usada para achar tabela sem chave "
       "primaria. Origem: bronze.constraints.")
