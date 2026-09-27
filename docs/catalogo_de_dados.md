# Catálogo de Dados

> Transcrição do catálogo aplicado no **Unity Catalog** via `COMMENT ON TABLE` e
> `ALTER COLUMN … COMMENT` nos notebooks 01, 02 e 03. Screenshots do Catalog Explorer
> e da aba Lineage estão no README.

## Convenções

- **Linhagem:** toda tabela declara sua origem. Bronze aponta para o objeto do PostgreSQL;
  Silver aponta para a tabela Bronze; Gold aponta para a Silver.
- **Domínio de valores:** declarado na descrição de cada campo categórico; faixa esperada
  nos numéricos.
- **Sufixo `_anon`:** campo anonimizado, seguro para publicação.
- **Prefixo `sk_`:** surrogate key. **Prefixo `_`:** metadado de controle.
- **Prefixo `_` no nome da tabela:** tabela privada, não versionada.

---

# Camada Gold — `gold`

## `fato_achado` — tabela fato

**Contexto.** Cada linha é um achado de segurança: uma das 18 regras de auditoria violada
por um objeto do banco, opcionalmente qualificada por coluna e por role, em um snapshot do
catálogo. É a tabela que sustenta todas as oito perguntas de negócio.

**Granularidade.** Um achado = regra × objeto × (coluna) × (role) × snapshot.
**Linhagem.** Gerada pelo motor de regras do notebook 03 a partir de sete tabelas Silver
(`objeto`, `coluna`, `politica`, `grant_role`, `funcao`, `bucket`, `extensao`,
`constraint_tabela`).

| Campo | Tipo | Descrição | Domínio / faixa |
|---|---|---|---|
| `sk_achado` | int | Surrogate key do achado | ≥ 1 |
| `sk_objeto` | int | FK → `dim_objeto` | — |
| `sk_coluna` | int | FK → `dim_coluna`. Nulo quando o achado não é por coluna | — |
| `sk_regra` | bigint | FK → `dim_regra` | — |
| `sk_role` | int | FK → `dim_role`. Nulo quando o achado não é por role | — |
| `sk_tempo` | int | FK → `dim_tempo` | — |
| `score_risco` | int | `dim_regra.peso` × multiplicador do dado (3 sensível, 2 pessoal, 1 demais) | 1 – 30 |
| `envolve_dado_pessoal` | boolean | Achado atinge coluna com dado pessoal (LGPD art. 5º, I) | true / false |
| `envolve_dado_saude` | boolean | Achado atinge dado referente à saúde (art. 11) | true / false |
| `envolve_dado_sensivel` | boolean | Achado atinge dado sensível (art. 5º, II) | true / false |
| `detalhe` | string | Descrição gerada pelo motor de regras. Não contém nome real de objeto | — |
| `_processado_em` | timestamp | Metadado de controle | — |

## `dim_regra` — dimensão curada manualmente

**Contexto.** As 18 regras de auditoria com severidade, peso e vínculo ao OWASP
Top 10:2025. Curada à mão para que o referencial de segurança seja consultável por SQL em
vez de existir só como texto no relatório. **Linhagem:** literal no notebook 03.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_regra` | bigint | Surrogate key | — |
| `id_regra` | string | Chave natural | `R01` – `R18` |
| `descricao` | string | Enunciado da regra | — |
| `severidade` | string | Nível de gravidade | Critico, Alto, Medio, Baixo |
| `peso` | int | Peso numérico da severidade | 10, 6, 3, 1 |
| `categoria_owasp` | string | Categoria do OWASP Top 10:2025 | A01, A02, A03, A06, A08 (sufixo `:2025`) |
| `referencia` | string | Nome completo da categoria OWASP | — |
| `escopo_saude` | boolean | True em R15–R18, específicas de dado de saúde | true / false |

### As 18 regras

| ID | Regra | Severidade | Peso | OWASP |
|---|---|---|---|---|
| R01 | Tabela exposta via API PostgREST com RLS desabilitado | Crítico | 10 | A01 |
| R02 | Política `USING(true)` concedida a role anônima | Crítico | 10 | A01 |
| R03 | Coluna com dado pessoal em tabela sem RLS | Crítico | 10 | A01 |
| R04 | Função `SECURITY DEFINER` sem `search_path` fixado | Crítico | 10 | A02 |
| R05 | Bucket de Storage público | Crítico | 10 | A02 |
| R06 | RLS habilitado sem nenhuma política definida | Alto | 6 | A06 |
| R07 | View sobre dado protegido sem `security_invoker` | Alto | 6 | A01 |
| R08 | Role anônima com privilégio de escrita | Alto | 6 | A01 |
| R09 | Política sem isolamento por usuário ou tenant | Alto | 6 | A01 |
| R10 | Políticas não cobrem todos os comandos da tabela | Médio | 3 | A06 |
| R11 | Tabela sem chave primária | Médio | 3 | A08 |
| R12 | Extensão instalada fora do schema `extensions` | Médio | 3 | A03 |
| R13 | RLS habilitado mas não forçado para o owner | Baixo | 1 | A02 |
| R14 | Objeto sem `COMMENT`: ausência de documentação | Baixo | 1 | A02 |
| **R15** | **Dado de saúde (art. 11) em tabela sem RLS** | Crítico | 10 | A01 |
| **R16** | **Role anônima com leitura em tabela com dado de saúde** | Crítico | 10 | A01 |
| **R17** | **Tabela de saúde com política para `authenticated` sem filtro de usuário** | Crítico | 10 | A01 |
| **R18** | **Tabela com dado de saúde e nenhuma política de RLS** | Alto | 6 | A06 |

## `dim_objeto`

**Contexto.** Um registro por objeto do banco auditado. Identificadores anonimizados porque
o Pitaia está em produção e o repositório é público. **Linhagem:** `silver.objeto` ←
`bronze.objetos` ← `pg_class` + `pg_namespace`.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_objeto` | int | Surrogate key | — |
| `schema_anon` | string | Schema anonimizado | `app_s1`… ou nome do schema Supabase |
| `objeto_anon` | string | Objeto anonimizado | `t_001`… |
| `tipo_objeto` | string | Tipo do objeto | tabela, tabela_particionada, view, view_materializada, tabela_estrangeira, outro |
| `dominio` | string | Origem do objeto | aplicacao, gerenciado_supabase |
| `exposto_api` | boolean | Alcançável via PostgREST | true / false |
| `rls_habilitado` | boolean | Estado do RLS (`pg_class.relrowsecurity`) | true / false |
| `rls_forcado` | boolean | `pg_class.relforcerowsecurity` | true / false |
| `security_invoker` | boolean | View com `security_invoker=true` | true / false |
| `tem_documentacao` | boolean | Objeto possui `COMMENT` no PostgreSQL | true / false |
| `schema_nome`, `objeto` | string | Campos técnicos de join. Não publicados | — |

## `dim_coluna`

**Contexto.** Um registro por coluna, com a classificação LGPD em três níveis. A
classificação é heurística sobre o nome da coluna; a acurácia foi estimada por amostra
rotulada à mão e está declarada no README. **Linhagem:** `silver.coluna` ←
`bronze.colunas` ← `information_schema.columns`.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_coluna` | int | Surrogate key | — |
| `coluna_anon` | string | Coluna anonimizada | `c_` + 8 hex |
| `tipo_dado` | string | Tipo PostgreSQL | text, uuid, timestamptz, numeric, … |
| `nullable` | boolean | Aceita nulo | true / false |
| `classe_dado` | string | Classe de dado pessoal inferida | credencial, saude, saude_metrica, biometrico, documento, prof_saude, financeiro, origem_racial, religiao, email, telefone, endereco, nascimento, nome_pessoa, localizacao, nulo |
| `is_dado_pessoal` | boolean | LGPD art. 5º, I | true / false |
| `is_dado_saude` | boolean | Dado referente à saúde, art. 11. Inclui métrica corporal por decisão interpretativa documentada | true / false |
| `is_dado_sensivel` | boolean | LGPD art. 5º, II | true / false |

## `dim_politica`

**Contexto.** Uma linha por política × role. Existe como dimensão própria porque P3 e P8
consultam característica de política sem passar pelo fato. A expressão SQL literal **não**
é publicada — só as flags derivadas dela. **Linhagem:** `silver.politica` ←
`bronze.politicas` ← `pg_policies`.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_politica` | int | Surrogate key | — |
| `politica` | string | Nome da política no PostgreSQL | — |
| `role_nome` | string | Role à qual a política se aplica | anon, authenticated, public, service_role, … |
| `comando` | string | Comando coberto | ALL, SELECT, INSERT, UPDATE, DELETE |
| `permissiva` | boolean | `PERMISSIVE` (true) ou `RESTRICTIVE` (false) | true / false |
| `so_check` | boolean | Política define apenas `WITH CHECK`, sem `USING` | true / false |
| `libera_tudo` | boolean | Expressão reduz a `USING(true)` | true / false |
| `filtra_uid` | boolean | Expressão referencia `auth.uid()` | true / false |
| `filtra_jwt` | boolean | Expressão referencia `auth.jwt()` ou `auth.role()` | true / false |
| `filtra_tenant` | boolean | Expressão referencia coluna de tenant/paciente | true / false |
| `tem_isolamento` | boolean | Qualquer uma das três flags acima | true / false |

## `dim_role`

**Linhagem:** união de `silver.grant_role` e `silver.politica`.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_role` | int | Surrogate key | — |
| `role_nome` | string | Nome da role no PostgreSQL | — |
| `tipo_role` | string | Agrupamento por nível de privilégio | anonima, autenticada, privilegiada, outra |

## `dim_tempo`

**Linhagem:** distintos de `silver.objeto._snapshot`.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_tempo` | int | Surrogate key | — |
| `data_snapshot` | date | Data da coleta do catálogo | — |
| `ano` | int | Derivado | 2026 |
| `mes` | int | Derivado | 1 – 12 |
| `dia_semana` | string | Derivado | Monday – Sunday |

## Tabelas Gold de consumo

| Tabela | Granularidade | Responde | Campo-chave |
|---|---|---|---|
| `backlog_remediacao` | 1 achado, ordenado por risco | *O que corrigir primeiro* | `prioridade` (1 = mais urgente) |
| `postura_por_schema` | 1 schema | P5 | `score_por_objeto` (score normalizado pelo tamanho do schema) |
| `mapa_exposicao_lgpd` | 1 classe de dado pessoal | P7 | `pct_exposta` (0 – 100) |
| `isolamento_prontuario` | 1 tabela que contém dado de saúde | P8 | `aberta_a_autenticados` (0 ou 1) |

`isolamento_prontuario.aberta_a_autenticados = 1` significa que existe política para
`authenticated` sem filtro por usuário ou tenant — ou seja, qualquer conta logada alcança o
dado de saúde de qualquer paciente. É o pior caso detectável estaticamente.

---

# Camada Silver — `silver`

| Tabela | Granularidade | Origem | Principais derivações |
|---|---|---|---|
| `objeto` | 1 por objeto do banco | `bronze.objetos` | `tipo_objeto`, `dominio`, `exposto_api`, `security_invoker`, anonimização |
| `coluna` | 1 por coluna | `bronze.colunas` | `classe_dado`, `is_dado_pessoal`, `is_dado_saude`, `is_dado_sensivel` |
| `politica` | 1 por política × role | `bronze.politicas` | explode do array `roles`; flags `libera_tudo`, `filtra_uid`, `filtra_tenant`, `tem_isolamento`, `so_check` |
| `grant_role` | 1 por role × objeto × privilégio | `bronze.grants` | deduplicação por herança de role |
| `funcao` | 1 por função | `bronze.funcoes` | `security_definer`, `tem_search_path` |
| `bucket` | 1 por bucket de Storage | `bronze.buckets` | `publico` tipado |
| `extensao` | 1 por extensão instalada | `bronze.extensoes` | — |
| `constraint_tabela` | 1 por constraint | `bronze.constraints` | filtro de schemas de sistema |
| `perfil_qualidade` | 1 por tabela × coluna da Bronze | as 8 tabelas Bronze | `pct_nulo`, `n_distintos`, `tamanho_max` |
| `perfil_duplicatas` | 1 por tabela Bronze | as 8 tabelas Bronze | `n_duplicatas` por chave natural |
| `_de_para_nao_publicar` | 1 por objeto | `silver.objeto` | **privada**, não versionada |

### `perfil_qualidade`

| Campo | Tipo | Descrição | Faixa |
|---|---|---|---|
| `tabela`, `coluna` | string | Atributo perfilado | — |
| `n_linhas` | int | Total de linhas da tabela Bronze | ≥ 0 |
| `n_nulos` | int | Nulos ou strings vazias | 0 – `n_linhas` |
| `pct_nulo` | double | Completude | 0 – 100 |
| `n_distintos` | int | Cardinalidade | 0 – `n_linhas` |
| `tamanho_max` | int | Maior comprimento observado | ≥ 0 |

---

# Camada Bronze — `bronze`

Oito tabelas. **Todas as colunas de negócio como `string`** por decisão de projeto: a
Bronze preserva o dado como veio, e a tipagem é responsabilidade da Silver.

Metadados de controle presentes em todas: `_arquivo_origem`, `_fonte`, `_snapshot`,
`_ingerido_em`.

| Tabela | Origem no PostgreSQL | Observação |
|---|---|---|
| `objetos` | `pg_class` + `pg_namespace` | inclui `reloptions` para detectar `security_invoker` |
| `politicas` | `pg_policies` | `roles` serializado com `;`; `expressao_using` nula em políticas só com `WITH CHECK` |
| `colunas` | `information_schema.columns` | — |
| `grants` | `information_schema.role_table_grants` | maior volume da extração |
| `funcoes` | `pg_proc` | **somente flags** — corpo da função não coletado |
| `buckets` | `storage.buckets` | — |
| `extensoes` | `pg_extension` | cadeia de suprimentos, OWASP A03:2025 |
| `constraints` | `information_schema.table_constraints` | PK, UNIQUE e FK |
