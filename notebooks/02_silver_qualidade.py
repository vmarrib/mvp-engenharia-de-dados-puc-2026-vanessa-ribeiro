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
BRONZE   = f"{CATALOGO}.pitaia_bronze"
SILVER   = f"{CATALOGO}.pitaia_silver"

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {SILVER} COMMENT "
          "'Catalogo de seguranca do Pitaia limpo, tipado e com classificacao LGPD. "
          "Identificadores anonimizados para publicacao.'")

def bronze(t):
    return spark.table(f"{BRONZE}.{t}")

def salvar(df, nome, doc):
    alvo = f"{SILVER}.{nome}"
    df.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(alvo)
    spark.sql(f"COMMENT ON TABLE {alvo} IS '{doc}'")
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
EXPOSTOS = ["public"]

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

# ordem importa: a primeira classe que casar vence
CLASSES = [
    ("credencial",    r"senha|password|passwd|secret|token|api_?key|chave_priv|refresh_token"),
    ("saude",         r"diagnostic|prontuario|\bcid\b|cid10|anamnese|sintoma|doenca|comorbidade|"
                      r"medicament|posologia|prescri|receita|alergia|exame|laudo|hemograma|"
                      r"glicemia|colesterol|pressao_art|vacina|cirurgia|internacao|tratamento|"
                      r"terapia|consulta|atestado|queixa|evolucao_clinica|historico_medico"),
    ("saude_metrica", r"\bpeso\b|\baltura\b|\bimc\b|\bbmi\b|circunferencia|gordura_corp|"
                      r"massa_muscular|batimento|freq_cardiaca|frequencia_card|\bspo2\b|"
                      r"saturacao|\bsono\b|passos|calorias|\bvo2\b|hidratacao|glicose"),
    ("biometrico",    r"biometr|impressao_dig|reconhecimento_fac|facial"),
    ("documento",     r"\bcpf\b|\bcnpj\b|\brg\b|documento|passaporte|\bcnh\b|cartao_sus|\bcns\b"),
    ("prof_saude",    r"\bcrm\b|crefito|\bcref\b|conselho_reg|especialidade|registro_prof"),
    ("financeiro",    r"cartao|\bcard\b|iban|agencia|conta_banc|\bpix\b|boleto|assinatura_valor"),
    ("origem_racial", r"\braca\b|etnia|cor_pele"),
    ("religiao",      r"religi|crenca"),
    ("email",         r"e_?mail"),
    ("telefone",      r"telefone|celular|phone|whats|\bfone\b"),
    ("endereco",      r"endereco|logradouro|\bcep\b|bairro|complemento"),
    ("nascimento",    r"nascimento|birth|\bdob\b|data_nasc|idade"),
    ("nome_pessoa",   r"^nome$|nome_completo|sobrenome|first_name|last_name|full_name|nome_paciente"),
    ("localizacao",   r"latitude|longitude|\blat\b|\blng\b|geoloc|coordenada"),
]

SENSIVEIS = ["saude", "saude_metrica", "biometrico", "origem_racial", "religiao"]

classe = F.lit(None).cast("string")
for nome, padrao in reversed(CLASSES):
    classe = F.when(F.lower(F.col("coluna")).rlike(padrao), F.lit(nome)).otherwise(classe)

col = (bronze("colunas")
       .filter(~F.col("schema_nome").isin(SISTEMA))
       .withColumn("classe_dado", classe)
       .withColumn("is_dado_pessoal", F.col("classe_dado").isNotNull())
       .withColumn("is_dado_saude", F.col("classe_dado").isin("saude", "saude_metrica"))
       .withColumn("is_dado_sensivel", F.col("classe_dado").isin(SENSIVEIS))
       .withColumn("nullable", booleano("is_nullable"))
       .withColumn("coluna_anon",
                   F.concat(F.lit("c_"),
                            F.substring(F.sha2(F.concat_ws("|", "schema_nome", "objeto", "coluna"), 256), 1, 8)))
       .dropDuplicates(["schema_nome", "objeto", "coluna"]))

silver_col = salvar(col.select("schema_nome", "objeto", "coluna", "coluna_anon", "tipo_dado",
                              "nullable", "classe_dado", "is_dado_pessoal", "is_dado_saude",
                              "is_dado_sensivel", "_snapshot"),
                    "coluna",
                    "Um registro por coluna, com classificacao LGPD. is_dado_saude marca dado "
                    "referente a saude (art. 11); is_dado_sensivel abrange todo o art. 5, II. "
                    "Classificacao por heuristica de nome - acuracia estimada por amostra. "
                    "Origem: bronze.colunas.")

total, pessoais = silver_col.count(), silver_col.filter("is_dado_pessoal").count()
print(f"\n{pessoais}/{total} colunas classificadas como dado pessoal ({100*pessoais/total:.1f}%)")
print(f"{silver_col.filter('is_dado_saude').count()} colunas de dado de saude")
display(silver_col.groupBy("classe_dado", "is_dado_sensivel").count().orderBy(F.desc("count")))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Acuracia do classificador
# MAGIC Regex sobre nome de coluna erra nos dois sentidos. Amostro 40 colunas para estimar
# MAGIC precisao e recall em vez de apresentar a heuristica como se fosse exata.

# COMMAND ----------

amostra = (silver_col.select("coluna", "tipo_dado", "classe_dado", "is_dado_saude")
                     .orderBy(F.rand(42)).limit(40))
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
       .withColumn("role_nome", F.trim(F.explode(F.split(F.coalesce(F.col("roles"), F.lit("")), ";"))))
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
       .dropDuplicates(["schema_nome", "funcao"]),
       "funcao",
       "Um registro por funcao. security_definer executa com privilegio do criador e "
       "contorna RLS; sem search_path fixado isso viabiliza escalada de privilegio. "
       "O corpo da funcao nao foi coletado. Origem: bronze.funcoes.")

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
