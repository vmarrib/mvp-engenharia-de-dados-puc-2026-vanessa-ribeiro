# Catálogo de Dados

> Transcrição do catálogo aplicado no **Unity Catalog** (`COMMENT ON TABLE` e
> `ALTER COLUMN ... COMMENT` no notebook `03_gold_regras_modelagem.py`).
> Screenshots do Catalog Explorer e da aba Lineage no README.

## Convenções

- **Linhagem:** toda tabela declara sua origem. Bronze aponta para o objeto do
  Postgres; Silver aponta para a tabela Bronze; Gold aponta para a Silver.
- **Domínio de valores:** declarado na descrição de cada campo categórico e nas
  faixas esperadas dos numéricos.
- **Sufixo `_anon`:** campo anonimizado, seguro para publicação.
- **Prefixo `sk_`:** surrogate key. **Prefixo `_`:** metadado de controle.

---

## Camada Gold — `pitaia_gold`

### `fato_achado` — tabela fato
Granularidade: **um achado de segurança** = uma violação de uma regra por um objeto
(opcionalmente por coluna ou role) em um snapshot. Origem: `pitaia_silver.*` via o
motor de regras do notebook 03.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_achado` | bigint | Surrogate key do achado | ≥ 1 |
| `sk_objeto` | int | FK para `dim_objeto` | — |
| `sk_coluna` | int | FK para `dim_coluna`; nulo quando o achado não é por coluna | — |
| `sk_regra` | bigint | FK para `dim_regra` | — |
| `sk_role` | int | FK para `dim_role`; nulo quando não é por role | — |
| `sk_tempo` | int | FK para `dim_tempo` | — |
| `score_risco` | int | `dim_regra.peso` × 2 quando envolve dado pessoal | 1–20 |
| `envolve_dado_pessoal` | boolean | Achado atinge coluna com dado pessoal | true/false |
| `envolve_dado_sensivel` | boolean | Dado pessoal sensível, LGPD art. 5 II | true/false |
| `detalhe` | string | Descrição textual gerada pelo motor de regras | — |
| `_processado_em` | timestamp | Metadado de controle | — |

### `dim_regra` — dimensão curada manualmente
As 14 regras de auditoria, com severidade e vínculo ao OWASP Top 10:2025.

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_regra` | bigint | Surrogate key | — |
| `id_regra` | string | Chave natural | `R01`–`R14` |
| `descricao` | string | Enunciado da regra | — |
| `severidade` | string | Nível de gravidade | Crítico, Alto, Médio, Baixo |
| `peso` | int | Peso numérico da severidade | 10, 6, 3, 1 |
| `categoria_owasp` | string | Categoria OWASP Top 10:2025 | A01, A02, A03, A06, A08 |
| `referencia` | string | Fonte normativa ou documental | — |

### `dim_objeto`

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_objeto` | int | Surrogate key | — |
| `schema_anon` | string | Schema anonimizado | `app_s1`… ou nome do schema Supabase |
| `objeto_anon` | string | Objeto anonimizado | `t_001`… |
| `tipo_objeto` | string | Tipo do objeto | tabela, tabela_particionada, view, view_materializada, tabela_estrangeira |
| `dominio` | string | Origem do objeto | aplicacao, gerenciado_supabase |
| `exposto_api` | boolean | Alcançável via PostgREST | true/false |
| `rls_habilitado` | boolean | `pg_class.relrowsecurity` | true/false |
| `rls_forcado` | boolean | `pg_class.relforcerowsecurity` | true/false |
| `security_invoker` | boolean | View com `security_invoker=true` | true/false |
| `tem_documentacao` | boolean | Objeto possui COMMENT no Postgres | true/false |

### `dim_coluna`

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_coluna` | int | Surrogate key | — |
| `coluna_anon` | string | Coluna anonimizada | `c_<8 hex>` |
| `tipo_dado` | string | Tipo Postgres | text, uuid, timestamptz, … |
| `nullable` | boolean | Aceita nulo | true/false |
| `classe_dado` | string | Classe de dado pessoal inferida | credencial, documento, financeiro, saude, biometrico, origem_racial, religiao, email, telefone, endereco, nascimento, nome_pessoa, localizacao, nulo |
| `is_dado_pessoal` | boolean | LGPD art. 5, I | true/false |
| `is_dado_sensivel` | boolean | LGPD art. 5, II | true/false |

### `dim_role`

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_role` | int | Surrogate key | — |
| `role_nome` | string | Nome da role no Postgres | anon, authenticated, service_role, … |
| `tipo_role` | string | Agrupamento por privilégio | anonima, autenticada, privilegiada, outra |

### `dim_tempo`

| Campo | Tipo | Descrição | Domínio |
|---|---|---|---|
| `sk_tempo` | int | Surrogate key | — |
| `data_snapshot` | date | Data da coleta do catálogo | — |
| `ano` / `mes` | int | Derivados | 2026 / 1–12 |
| `dia_semana` | string | Derivado | Monday–Sunday |

### Tabelas Gold de consumo

| Tabela | Granularidade | Responde |
|---|---|---|
| `backlog_remediacao` | 1 achado, ordenado por risco | *O que corrigir primeiro* |
| `postura_por_schema` | 1 schema | P5 — concentração de risco |
| `mapa_exposicao_lgpd` | 1 classe de dado pessoal | P7 — exposição regulatória |

---

## Camada Silver — `pitaia_silver`

`PREENCHER — replique o formato acima para: objeto, coluna, politica, grant_role,
funcao, bucket, extensao, constraint_tabela, perfil_qualidade, perfil_duplicatas.
Os COMMENT de tabela já estão no notebook 02; transcreva-os aqui com os campos.`

## Camada Bronze — `pitaia_bronze`

Oito tabelas, todas as colunas de negócio como `string` por decisão de projeto
(a Bronze preserva o dado como veio). Metadados de controle em todas:
`_arquivo_origem`, `_fonte`, `_snapshot`, `_ingerido_em`.

| Tabela | Origem no Postgres |
|---|---|
| `objetos` | `pg_class` + `pg_namespace` |
| `politicas` | `pg_policies` |
| `colunas` | `information_schema.columns` |
| `grants` | `information_schema.role_table_grants` |
| `funcoes` | `pg_proc` (somente flags) |
| `buckets` | `storage.buckets` |
| `extensoes` | `pg_extension` |
| `constraints` | `information_schema.table_constraints` |
