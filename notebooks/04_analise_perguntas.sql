-- Databricks notebook source
-- MAGIC %md
-- MAGIC # 04 - Analise | as 8 perguntas de negocio
-- MAGIC
-- MAGIC Cada celula traz a query e, no markdown acima dela, **como ler o resultado**:
-- MAGIC o que e esperado, o que seria preocupante e que frase escrever no relatorio.
-- MAGIC Screenshot de cada resultado.

-- COMMAND ----------
USE CATALOG workspace;
USE SCHEMA pitaia_gold;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P1 - Que proporcao das tabelas expostas via API esta sem RLS?
-- MAGIC
-- MAGIC **Como ler:** compare as duas linhas. `aplicacao` e o Pitaia; `gerenciado_supabase`
-- MAGIC e a referencia. O Supabase protege quase tudo por padrao, entao se o seu
-- MAGIC `pct_sem_rls` for maior que o dele, o numero tem contexto e vira argumento.
-- MAGIC
-- MAGIC **O que preocupa:** qualquer tabela em `public` sem RLS e legivel por quem tiver a
-- MAGIC anon key - que e publica por design, embutida no front. Uma tabela sem RLS nao e
-- MAGIC "menos protegida", e aberta.
-- MAGIC
-- MAGIC **Escreva:** "X das Y tabelas expostas do Pitaia (Z%) estao sem RLS, contra W% nos
-- MAGIC schemas gerenciados pelo Supabase."

-- COMMAND ----------
SELECT dominio,
       count(*)                                                           AS n_tabelas,
       sum(CASE WHEN rls_habilitado THEN 1 ELSE 0 END)                    AS com_rls,
       sum(CASE WHEN NOT rls_habilitado THEN 1 ELSE 0 END)                AS sem_rls,
       round(100.0 * sum(CASE WHEN NOT rls_habilitado THEN 1 ELSE 0 END)
             / count(*), 1)                                               AS pct_sem_rls
FROM dim_objeto
WHERE exposto_api AND tipo_objeto IN ('tabela','tabela_particionada')
GROUP BY dominio;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P2 - Quantas tabelas tem RLS habilitado mas ZERO politicas?
-- MAGIC
-- MAGIC **Por que importa:** no Postgres, RLS sem politica **nega tudo**. Passa em qualquer
-- MAGIC checklist ("RLS: ativado") e quebra a aplicacao em silencio. E o inverso do R01:
-- MAGIC aqui o defeito e de disponibilidade, nao de confidencialidade.
-- MAGIC
-- MAGIC **Como ler:** resultado vazio e otimo. Cada linha e uma tabela que provavelmente
-- MAGIC tem uma funcionalidade quebrada no Pitaia que ninguem associou ao RLS.

-- COMMAND ----------
SELECT o.schema_anon, o.objeto_anon, o.tipo_objeto, f.detalhe
FROM fato_achado f
JOIN dim_regra  r ON r.sk_regra  = f.sk_regra
JOIN dim_objeto o ON o.sk_objeto = f.sk_objeto
WHERE r.id_regra IN ('R06','R18')
ORDER BY r.id_regra, o.objeto_anon;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P3 - Das politicas existentes, quantas isolam de fato por usuario ou tenant?
-- MAGIC
-- MAGIC **Como ler:** olhe `pct_com_isolamento` por role. Em `anon` o esperado e baixo (o
-- MAGIC pouco que ela ve deveria ser publico mesmo). Em `authenticated` o esperado e
-- MAGIC **proximo de 100%** - uma politica para authenticated sem `auth.uid()` significa que
-- MAGIC qualquer conta logada alcanca as linhas de todas as outras.
-- MAGIC
-- MAGIC **Escreva:** "de N politicas para authenticated, M (X%) referenciam auth.uid() ou
-- MAGIC coluna de tenant; as demais concedem acesso indiscriminado entre usuarios."

-- COMMAND ----------
SELECT role_nome, comando,
       count(*)                                                            AS n_politicas,
       sum(CASE WHEN tem_isolamento THEN 1 ELSE 0 END)                     AS com_isolamento,
       sum(CASE WHEN libera_tudo THEN 1 ELSE 0 END)                        AS libera_tudo,
       round(100.0 * sum(CASE WHEN tem_isolamento THEN 1 ELSE 0 END)
             / count(*), 1)                                                AS pct_com_isolamento
FROM dim_politica
GROUP BY role_nome, comando
ORDER BY role_nome, comando;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P4 - O que a role anonima consegue escrever?
-- MAGIC
-- MAGIC **Por que importa:** leitura indevida vaza dado; escrita indevida permite inserir
-- MAGIC registro falso no prontuario de alguem. Num sistema de saude o impacto de integridade
-- MAGIC pode ser pior que o de confidencialidade.
-- MAGIC
-- MAGIC **Como ler:** vazio e o resultado correto. Qualquer linha aqui e achado grave.

-- COMMAND ----------
SELECT rl.role_nome, o.schema_anon, o.objeto_anon, f.detalhe, f.score_risco
FROM fato_achado f
JOIN      dim_regra  r  ON r.sk_regra  = f.sk_regra
JOIN      dim_role   rl ON rl.sk_role  = f.sk_role
LEFT JOIN dim_objeto o  ON o.sk_objeto = f.sk_objeto
WHERE r.id_regra IN ('R08','R16')
ORDER BY f.score_risco DESC;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P5 - Onde o risco esta concentrado?
-- MAGIC
-- MAGIC **Como ler:** `score_por_objeto` normaliza pelo tamanho do schema - sem isso o schema
-- MAGIC maior sempre parece o pior. Ordene por ele, nao por `score_total`.
-- MAGIC
-- MAGIC **Escreva:** nomeie o schema com pior densidade de risco e diga se o padrao dos
-- MAGIC achados ali sugere uma causa comum.

-- COMMAND ----------
SELECT * FROM postura_por_schema ORDER BY score_por_objeto DESC;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P6 - Como os achados se distribuem pelo OWASP Top 10:2025?
-- MAGIC
-- MAGIC **Como ler:** a concentracao esperada e em A01 (Broken Access Control) e A02
-- MAGIC (Security Misconfiguration). Vale registrar que A02 subiu de #5 em 2021 para #2 em
-- MAGIC 2025 justamente porque ma configuracao passou a dominar os dados de CVE - o que o seu
-- MAGIC resultado ilustra em escala de uma aplicacao.
-- MAGIC
-- MAGIC **Grafico:** barras horizontais, categoria no eixo Y, score_total no X, cor por severidade.

-- COMMAND ----------
SELECT r.categoria_owasp, r.referencia, r.severidade,
       count(*)                                                            AS n_achados,
       sum(f.score_risco)                                                  AS score_total,
       round(100.0 * count(*) / (SELECT count(*) FROM fato_achado), 1)      AS pct_achados
FROM fato_achado f
JOIN dim_regra r ON r.sk_regra = f.sk_regra
GROUP BY r.categoria_owasp, r.referencia, r.severidade
ORDER BY score_total DESC;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P7 - Quantas colunas com dado de saude estao sem protecao de linha?
-- MAGIC
-- MAGIC **Pergunta ancora.** E a medida direta de conformidade: a LGPD trata dado de saude
-- MAGIC como sensivel (art. 5, II), exige base legal especifica (art. 11) e medidas de
-- MAGIC seguranca proporcionais ao risco (art. 46). Uma coluna de diagnostico em tabela sem
-- MAGIC RLS nao e divida tecnica, e exposicao regulatoria.
-- MAGIC
-- MAGIC **Como ler:** ordene por `pct_exposta`. Qualquer valor acima de zero nas linhas com
-- MAGIC `is_dado_saude = true` e achado critico.

-- COMMAND ----------
SELECT classe_dado, is_dado_saude, is_dado_sensivel,
       n_colunas, n_protegidas, n_expostas, pct_exposta
FROM mapa_exposicao_lgpd
ORDER BY is_dado_saude DESC, pct_exposta DESC, n_colunas DESC;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## P8 - Um usuario autenticado qualquer consegue ler o prontuario de outro paciente?
-- MAGIC
-- MAGIC **A pergunta que mais importa no Pitaia.** O sistema tem tres perfis de acesso -
-- MAGIC paciente, medico e educador fisico. Isolamento entre pacientes e o requisito central.
-- MAGIC
-- MAGIC **Como ler cada coluna:**
-- MAGIC - `rls_habilitado = false` -> a tabela esta aberta, nem ha o que isolar
-- MAGIC - `n_politicas = 0` com RLS ativo -> nega tudo (funcionalidade quebrada)
-- MAGIC - `aberta_a_autenticados = 1` -> **pior caso**: existe politica para authenticated
-- MAGIC   sem filtro por usuario, logo qualquer conta logada le o dado de qualquer paciente
-- MAGIC - `n_com_isolamento = n_politicas` com RLS ativo -> configuracao correta
-- MAGIC
-- MAGIC **Limite desta analise, que preciso declarar:** a query prova que o *banco* permite,
-- MAGIC nao que a *aplicacao* exponha. O front pode filtrar por conta propria. Mas confiar no
-- MAGIC filtro do front e exatamente o que o RLS existe para nao precisar fazer - qualquer
-- MAGIC chamada direta ao PostgREST com um JWT valido contorna o front.

-- COMMAND ----------
SELECT schema_anon, objeto_anon, n_colunas_saude, rls_habilitado,
       n_politicas, n_com_isolamento, aberta_a_autenticados,
       CASE WHEN NOT rls_habilitado           THEN 'ABERTA - sem RLS'
            WHEN n_politicas = 0              THEN 'BLOQUEADA - RLS sem politica'
            WHEN aberta_a_autenticados = 1    THEN 'VAZAMENTO ENTRE PACIENTES'
            WHEN n_com_isolamento = n_politicas THEN 'OK - isolada'
            ELSE 'PARCIAL - revisar' END      AS veredito
FROM isolamento_prontuario
ORDER BY CASE WHEN NOT rls_habilitado THEN 1
              WHEN aberta_a_autenticados = 1 THEN 2
              WHEN n_politicas = 0 THEN 3 ELSE 4 END,
         n_colunas_saude DESC;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## Backlog de remediacao - a entrega do pipeline

-- COMMAND ----------
SELECT prioridade, id_regra, severidade, categoria_owasp, escopo_saude,
       schema_anon, objeto_anon, coluna_anon, classe_dado, score_risco, detalhe
FROM backlog_remediacao
ORDER BY prioridade
LIMIT 40;

-- COMMAND ----------
-- MAGIC %md
-- MAGIC ## Indicadores de resumo
-- MAGIC Numeros para abrir a discussao geral do relatorio.

-- COMMAND ----------
SELECT
  (SELECT count(*) FROM dim_objeto WHERE dominio = 'aplicacao')            AS objetos_pitaia,
  (SELECT count(*) FROM dim_coluna WHERE is_dado_pessoal)                  AS col_dado_pessoal,
  (SELECT count(*) FROM dim_coluna WHERE is_dado_saude)                    AS col_dado_saude,
  (SELECT count(*) FROM fato_achado)                                       AS total_achados,
  (SELECT sum(score_risco) FROM fato_achado)                               AS score_total,
  (SELECT count(*) FROM fato_achado f JOIN dim_regra r ON r.sk_regra = f.sk_regra
    WHERE r.severidade = 'Critico')                                        AS achados_criticos,
  (SELECT count(*) FROM fato_achado f JOIN dim_regra r ON r.sk_regra = f.sk_regra
    WHERE r.escopo_saude)                                                  AS achados_dado_saude,
  (SELECT count(*) FROM isolamento_prontuario
    WHERE aberta_a_autenticados = 1 OR NOT rls_habilitado)                 AS tabelas_saude_vazando;
