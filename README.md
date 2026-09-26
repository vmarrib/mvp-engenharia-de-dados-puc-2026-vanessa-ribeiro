# MVP de Engenharia de Dados — Auditoria de Postura de Segurança da Plataforma Pitaia

**Vanessa Ribeiro** · Pós-graduação PUC-Rio · Sprint de Engenharia de Dados

> Pipeline de dados em nuvem que coleta o catálogo de segurança de uma plataforma de
> saúde em produção, modela os achados em esquema estrela e entrega um **backlog de
> remediação priorizado por risco regulatório**.

| | |
|---|---|
| **Plataforma de nuvem** | Databricks Free Edition — serverless, Unity Catalog, Delta Lake |
| **Arquitetura** | Medalhão: Bronze → Silver → Gold |
| **Fonte** | Catálogo do PostgreSQL do projeto Supabase da plataforma Pitaia (apitaia.com) |
| **Snapshot** | `PREENCHER` |
| **Referenciais** | OWASP Top 10:2025 · LGPD Lei 13.709/2018, arts. 5º, 11 e 46 |

```
extracao/00_queries_supabase.sql        8 extrações via SQL Editor do Supabase
notebooks/01_bronze_ingestao.py         CSV → Delta, sem transformação
notebooks/02_silver_qualidade.py        perfil de qualidade, tipagem, classificação LGPD
notebooks/03_gold_regras_modelagem.py   18 regras + esquema estrela + catálogo
notebooks/04_analise_perguntas.sql      as 8 perguntas de negócio
notebooks/05_visualizacoes.py           painel de indicadores + 4 figuras
docs/governanca_anonimizacao.md         decisões de privacidade do próprio trabalho
docs/catalogo_de_dados.md               catálogo de dados transcrito
```

---

## Contexto de Negócios e Perguntas (Etapas 2 e 4.1)

### O contexto

O **Pitaia** (apitaia.com) é um sistema de inteligência de saúde pessoal. Ele consolida,
num só lugar, dados que hoje vivem espalhados: histórico clínico, exames, medicações,
informações pessoais e métricas corporais. O acesso é compartilhado por três perfis
distintos — **o próprio usuário, médicos e educadores físicos** — cada um devendo alcançar
apenas a fração de informação pertinente ao seu papel.

Essa arquitetura de acesso é o que torna a plataforma útil e, ao mesmo tempo, o que
concentra seu risco. Prontuário é **dado pessoal sensível** na definição do art. 5º, II da
LGPD; seu tratamento exige base legal específica (art. 11) e medidas de segurança
proporcionais ao risco (art. 46). Um defeito de isolamento entre pacientes aqui não é
dívida técnica: é incidente de dados sensíveis.

O Pitaia foi construído com apoio de geração assistida de código sobre Supabase. Esse modo
de construção acelera a entrega, mas desloca as decisões de segurança — sobretudo as
políticas de *Row Level Security* — para configuração implícita, distribuída entre
migrações e raramente auditada de forma sistemática. O resultado típico é uma aplicação
que funciona e cuja postura de segurança ninguém mediu.

### O problema

> **Medir a postura de segurança e a superfície de exposição de dados de saúde da
> plataforma Pitaia, transformando o catálogo do banco em um backlog de remediação
> priorizado por risco — em vez de uma lista desordenada de alertas.**

A decisão de negócio que o pipeline precisa sustentar é concreta: *o que corrigir primeiro,
com tempo limitado de desenvolvimento.*

### As perguntas de negócio

| # | Pergunta | Respondida? |
|---|---|---|
| **P1** | Que proporção das tabelas expostas via API está sem RLS? | `PREENCHER` |
| **P2** | Quantas tabelas têm RLS habilitado mas **zero políticas** — protegidas na aparência, quebradas na prática? | `PREENCHER` |
| **P3** | Das políticas existentes, quantas isolam de fato por usuário ou tenant? | `PREENCHER` |
| **P4** | O que a role anônima consegue **escrever**? | `PREENCHER` |
| **P5** | Onde o risco está concentrado — qual schema tem a pior densidade de achados? | `PREENCHER` |
| **P6** | Como os achados se distribuem pelas categorias do OWASP Top 10:2025? | `PREENCHER` |
| **P7** | **Quantas colunas com dado de saúde estão sem proteção de linha?** (conformidade LGPD art. 11) | `PREENCHER` |
| **P8** | **Um usuário autenticado qualquer consegue ler o prontuário de outro paciente?** | `PREENCHER` |

P7 e P8 são as perguntas-âncora: as duas que um titular de dados faria se pudesse.
Conforme o enunciado, nenhuma pergunta foi removida — o que não foi respondido está
discutido na Autoavaliação.

### Estrutura dos dados brutos

Oito extrações do catálogo do PostgreSQL. **Nenhum dado de paciente foi coletado** —
somente metadados de estrutura e permissão.

Três das oito consultas foram reescritas durante a coleta. As versões iniciais usavam
`information_schema`, cujas views são **filtradas por privilégio**: só retornam o que a role
de execução enxerga. Na prática isso devolveu 164 linhas de grants — todas de uma única role
de sandbox — em vez da ACL real do banco, o que zeraria silenciosamente as regras de
privilégio anônimo. As versões finais leem `pg_attribute`, `aclexplode(pg_class.relacl)` e
`pg_constraint`, que não sofrem esse filtro. Está registrado aqui porque é uma armadilha
real de coleta, não um detalhe de implementação: a consulta *funcionava* e devolvia dados
plausíveis — só que incompletos.

| Arquivo | Origem no PostgreSQL | Granularidade | Linhas |
|---|---|---|---|
| `objetos.csv` | `pg_class` + `pg_namespace` | 1 por objeto do banco | 344 |
| `politicas.csv` | `pg_policies` | 1 por política de RLS | 209 |
| `colunas.csv` | `pg_attribute` | 1 por coluna | `PREENCHER (re-extrair)` |
| `grants.csv` | `aclexplode(pg_class.relacl)` | 1 por role × objeto × privilégio | `PREENCHER (re-extrair)` |
| `funcoes.csv` | `pg_proc` (somente flags) | 1 por função | 195 |
| `buckets.csv` | `storage.buckets` | 1 por bucket de Storage | 7 |
| `extensoes.csv` | `pg_extension` | 1 por extensão instalada | 8 |
| `constraints.csv` | `pg_constraint` | 1 por constraint | `PREENCHER (re-extrair)` |

### Licença e base legal dos dados

Os dados **não vêm de repositório público** e portanto não estão sob licença de terceiros.
São **metadados proprietários** da plataforma Pitaia, de minha autoria e propriedade,
extraídos por mim na condição de titular do projeto Supabase. Não há restrição de terceiros
ao seu uso acadêmico.

O que exigiu decisão explícita foi o oposto: como publicar sem criar risco. O enunciado
determina, no item 4.2, anonimizar informações sensíveis ao usar dados empresariais reais.
Quatro medidas foram aplicadas:

1. **Nenhum dado de paciente foi ingerido.** A auditoria opera sobre a *estrutura* do banco.
   `auth.users` e todas as tabelas de conteúdo clínico ficaram fora do escopo.
2. **Identificadores anonimizados** antes de qualquer publicação — schemas, tabelas e
   colunas viraram `app_s1`, `t_001`, `c_a1b2c3d4`. O mapa reverso não foi versionado.
3. **Nenhuma credencial saiu do Supabase.** A coleta ocorreu dentro do painel, com
   exportação manual em CSV.
4. **Nenhum corpo de função e nenhuma expressão literal de política** foi coletado — apenas
   flags derivadas.

Detalhamento em [`docs/governanca_anonimizacao.md`](docs/governanca_anonimizacao.md).

---

## Carga dos Dados (Etapa 4.2)

`PREENCHER — descreva o caminho: SQL Editor do Supabase → export CSV → upload no Volume do
Unity Catalog → notebook 01. Justifique por que não usei conexão JDBC direta.`

**Scripts:** [`extracao/00_queries_supabase.sql`](extracao/00_queries_supabase.sql) ·
[`notebooks/01_bronze_ingestao.py`](notebooks/01_bronze_ingestao.py)

Três decisões de projeto na camada Bronze:

- **Tudo ingerido como `STRING`** (`inferSchema=False`). A Bronze é cofre de evidências; a
  tipagem é responsabilidade da Silver. Se o export devolveu `t` em vez de `true`, fica
  registrado como veio.
- **Nenhum filtro de schema.** Os schemas gerenciados pelo Supabase (`auth`, `storage`,
  `realtime`) entram junto e servem de **grupo de comparação** na análise. Sem uma
  referência, "14 achados" não significa nada.
- **Metadados de controle** em toda tabela: `_ingerido_em`, `_fonte`, `_snapshot`,
  `_arquivo_origem`.

`SCREENSHOT: Volume com os 8 CSVs · contagens por tabela`

---

## Modelagem e Catálogo de Dados (Etapa 4.3)

### Esquema estrela

```
                    dim_tempo
                        |
   dim_objeto ---- fato_achado ---- dim_regra
                    /      \
            dim_coluna     dim_role        dim_politica
```

**Granularidade do fato:** um achado de segurança — uma regra violada por um objeto
(opcionalmente por coluna ou role) em um snapshot.

Duas escolhas de modelagem que vale explicar:

**`dim_regra` é curada manualmente.** As 18 regras, sua severidade, seu peso numérico e sua
categoria no OWASP Top 10:2025 vivem como uma dimensão do modelo. Isso faz com que o
referencial de segurança seja consultável por SQL, em vez de existir apenas como prosa no
relatório — dá para perguntar "qual categoria do OWASP concentra meu risco?" com um
`GROUP BY`.

**Quatro das 18 regras são específicas de dado de saúde** (R15–R18). Elas existem porque o
Pitaia cai no art. 11 da LGPD: uma tabela de prontuário exposta não tem o mesmo peso que
uma tabela de configuração exposta, e o modelo precisa refletir isso. O `score_risco`
multiplica o peso da regra por 3 quando o achado atinge dado sensível.

### Camadas

| Camada | Schema | Tabelas |
|---|---|---|
| Bronze | `pitaia_bronze` | 8 tabelas cruas |
| Silver | `pitaia_silver` | `objeto`, `coluna`, `politica`, `grant_role`, `funcao`, `bucket`, `extensao`, `constraint_tabela`, `perfil_qualidade`, `perfil_duplicatas` |
| Gold | `pitaia_gold` | `dim_objeto`, `dim_coluna`, `dim_politica`, `dim_role`, `dim_regra`, `dim_tempo`, `fato_achado`, `backlog_remediacao`, `postura_por_schema`, `mapa_exposicao_lgpd`, `isolamento_prontuario` |

### Catálogo de dados

Transcrito em [`docs/catalogo_de_dados.md`](docs/catalogo_de_dados.md) e aplicado no
**Unity Catalog** via `COMMENT ON TABLE` e `ALTER COLUMN … COMMENT` no notebook 03.

`SCREENSHOT: Catalog Explorer com comentários de tabela e de coluna`
`SCREENSHOT: aba Lineage com o grafo Bronze → Silver → Gold`

---

## Pipeline de Dados (Etapa 4.4)

Ramificado em **cinco notebooks**, um por responsabilidade — não em um notebook único, para
que cada etapa possa ser reexecutada isoladamente quando algo precisa de ajuste.

| Notebook | Responsabilidade | Entrada → Saída |
|---|---|---|
| `01_bronze_ingestao.py` | Coleta | 8 CSVs → 8 tabelas Bronze |
| `02_silver_qualidade.py` | Perfil de qualidade, padronização, classificação LGPD | Bronze → 10 tabelas Silver |
| `03_gold_regras_modelagem.py` | Motor de 18 regras, estrela, catálogo | Silver → 11 tabelas Gold |
| `04_analise_perguntas.sql` | As 8 perguntas | Gold → resultados |
| `05_visualizacoes.py` | Figuras do relatório | Gold → PNGs no Volume `pitaia_gold.figuras` |

### Transformações principais

| Transformação | O que foi feito | Por quê | Impacto |
|---|---|---|---|
| Explode de `roles` | `split(';')` + `explode` | `pg_policies.roles` é array; sem explodir não se consulta por role | `PREENCHER` → `PREENCHER` linhas |
| Normalização de booleanos | `t` / `true` / `1` → boolean | O export do Postgres é inconsistente entre colunas | Viabiliza filtro correto de RLS |
| Classificação LGPD | regex sobre nome de coluna, 15 classes | Liga estrutura do banco a risco regulatório | `PREENCHER` colunas classificadas |
| Flags de política | deriva `filtra_uid`, `filtra_tenant`, `libera_tudo` e descarta a expressão | Permite auditar isolamento sem publicar a estrutura de multi-tenancy | Todas as políticas |
| Anonimização | `t_001`, `c_<hash>`, estável e determinística | Repositório público, plataforma de saúde em produção | 100% dos identificadores |
| Motor de regras | 18 `SELECT` em `UNION ALL` sobre a Silver | Converte catálogo em achado acionável | `PREENCHER` achados |
| Score de risco | `peso × 3` (sensível), `× 2` (pessoal), `× 1` | Prioriza o que é regulatoriamente crítico | Ordena o backlog |

`SCREENSHOT: Catalog Explorer com as tabelas persistidas nos três schemas`

---

## Qualidade de Dados (Etapa 4.5)

Perfilamento feito **antes** de qualquer limpeza — medir depois não prova nada. Evidência em
`pitaia_silver.perfil_qualidade` e `pitaia_silver.perfil_duplicatas`.

| # | Problema detectado | Dimensão | Tratamento | Volume |
|---|---|---|---|---|
| 1 | `roles` como array serializado | Consistência | `split` + `explode` | `PREENCHER` |
| 2 | `expressao_using` nula em políticas só com `WITH CHECK` | Completude | flag `so_check` + `coalesce`, em vez de descartar | `PREENCHER` |
| 3 | Booleanos em formatos mistos | Consistência | normalização para boolean | todas as flags |
| 4 | Views presentes em `colunas` mas sem RLS aplicável | Acurácia | separação por `tipo_objeto`, regra própria (R07) | `PREENCHER` |
| 5 | Grants duplicados por herança de role | Unicidade | `dropDuplicates` com contagem prévia | `PREENCHER` |
| 6 | Schemas do Supabase misturados aos da aplicação | Escopo | flag `dominio`, mantidos como comparação | `PREENCHER` |
| 7 | Falso positivo e falso negativo do classificador LGPD | Acurácia | amostra de 40 colunas rotulada à mão | precisão `PREENCHER` · recall `PREENCHER` |

Sobre o item 7: uma heurística de regex sobre nome de coluna erra nos dois sentidos. Em vez
de apresentá-la como exata, 40 colunas foram amostradas e rotuladas manualmente para
estimar precisão e recall. `PREENCHER — comente dois exemplos concretos de erro.`

`SCREENSHOT: perfil_qualidade ordenado por pct_nulo · perfil_duplicatas`

---

## Análise de Dados (Etapa 4.5)

`Para cada pergunta: screenshot do resultado + 2–3 frases de interpretação. O notebook 04
traz, no markdown de cada célula, como ler o resultado e que frase escrever.`

### P1 — Proporção de tabelas expostas sem RLS
`PREENCHER` · `SCREENSHOT`

### P2 — RLS habilitado com zero políticas
`PREENCHER` · `SCREENSHOT`

### P3 — Políticas com isolamento real
`PREENCHER` · `SCREENSHOT`

### P4 — Escrita disponível à role anônima
`PREENCHER` · `SCREENSHOT`

### P5 — Concentração de risco por schema
`PREENCHER` · `SCREENSHOT`

### P6 — Distribuição pelo OWASP Top 10:2025
`PREENCHER` · `SCREENSHOT`

### P7 — Colunas com dado de saúde sem proteção
`PREENCHER` · `SCREENSHOT`

### P8 — Isolamento de prontuário entre pacientes
`PREENCHER` · `SCREENSHOT`

### Discussão geral
`PREENCHER — conecte as oito respostas ao problema original: qual é o veredito sobre a
postura do Pitaia; qual o achado mais grave e por quê; o padrão dos achados revela uma causa
raiz comum (por exemplo, tabela criada antes da política); como a comparação com os schemas
gerenciados pelo Supabase contextualiza os números; o que o backlog manda fazer primeiro.`

---

## Autoavaliação

### O que foi atingido
`PREENCHER`

### O que não foi atingido e por quê
`PREENCHER — candidatos honestos: snapshot único impediu análise de evolução da postura;
a coleta não foi automatizada por decisão de não expor credencial; a classificação LGPD é
heurística de nome, não de conteúdo; a análise prova o que o banco permite, não o que a
aplicação expõe.`

### Dificuldades encontradas
`PREENCHER`

### Trabalhos futuros
- **Lakehouse Federation** (foreign catalog PostgreSQL) substituindo a exportação manual,
  com credencial em Databricks Secrets — habilita execução agendada e histórico de postura.
- **Série temporal de snapshots** para medir a evolução após a remediação, transformando
  `dim_tempo` de uma linha em um eixo de análise real.
- **Classificação de dado de saúde por conteúdo** (amostragem + NER clínico) em vez de nome
  de coluna, elevando precisão e recall.
- **Teste ativo de isolamento**: emitir JWTs de dois pacientes distintos e confirmar
  empiricamente o que a análise estática aponta.
- **Regras de MCP** (tool poisoning, confused deputy, token passthrough) na `dim_regra`,
  relevantes porque a plataforma expõe interface MCP.

---

## Governança e Anonimização

Ver [`docs/governanca_anonimizacao.md`](docs/governanca_anonimizacao.md).

Este repositório é público e o Pitaia está em produção com prontuário de pessoas reais.
Publicar o nome de uma tabela vulnerável seria distribuir o caminho pronto. Por isso todos
os identificadores foram anonimizados, nenhum dado de paciente foi ingerido, nenhuma
credencial trafegou para fora do Supabase e nenhuma expressão de política foi publicada. As
conclusões são estatísticas e não dependem dos nomes reais: *"X% das colunas de dado de
saúde estão em tabelas sem RLS"* tem o mesmo valor informativo com `t_007` ou com o nome
verdadeiro.
