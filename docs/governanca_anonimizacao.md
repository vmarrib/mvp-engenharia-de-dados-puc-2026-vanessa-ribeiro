# Governança e Anonimização

## Por que este documento existe

Este MVP audita uma aplicação **em produção**, com usuários reais, e o código está
em um repositório **público**, exigência do item 3 do enunciado. Essas duas coisas
juntas criam um risco que a maioria dos trabalhos não enfrenta: um relatório de
vulnerabilidades publicado abertamente é um mapa de ataque.

O enunciado já prevê isso no item 4.2: *"se optar por dados da empresa onde
trabalha, anonimize informações sensíveis antes de subir para qualquer ambiente
externo."* As medidas abaixo cumprem essa exigência.

## Medidas aplicadas

### 1. Nenhum dado pessoal foi ingerido
A auditoria opera sobre **estrutura**, não sobre registros. `auth.users` e todas as
tabelas de conteúdo ficaram fora do escopo. Nenhum e-mail, nome ou identificador de
usuário final entrou no pipeline.

### 2. Nenhuma credencial saiu do Supabase
A coleta foi feita pelo SQL Editor dentro do próprio painel do Supabase, com
exportação manual em CSV. Nenhuma connection string, senha, `service_role key` ou
token foi gravada em notebook, variável de ambiente ou arquivo versionado.

Consequência assumida: a coleta não é automatizada neste MVP. Registrado em
Trabalhos Futuros como Lakehouse Federation com credencial em Databricks Secrets.

### 3. Nenhum corpo de função foi coletado
`pg_get_functiondef()` retornaria a lógica completa das funções, que pode conter
regras de negócio e segredos embutidos. A extração lê apenas as flags
`prosecdef` (SECURITY DEFINER) e `proconfig` (search_path).

### 4. Identificadores anonimizados antes da publicação

| Objeto real | Publicado como | Método |
|---|---|---|
| nome do schema da aplicação | `app_s1`, `app_s2` | `dense_rank` por ordem alfabética |
| nome da tabela | `t_001`, `t_002` | `row_number` por ordem alfabética |
| nome da coluna | `c_<8 hex>` | `sha2(schema\|objeto\|coluna, 256)` truncado |

A anonimização é **estável** (a mesma tabela recebe sempre o mesmo código) e
**determinística**, o que preserva a capacidade de join entre as camadas.

O mapeamento reverso vive em `silver._de_para_nao_publicar`, existe apenas
dentro do workspace do Databricks e **não é versionado**. O prefixo `_` e o sufixo
`nao_publicar` sinalizam a intenção no próprio nome.

### 5. Expressões SQL das políticas não são publicadas
A coluna `qual` de `pg_policies` contém a expressão literal da política, que
frequentemente revela nomes de colunas de controle de acesso e estrutura de
multi-tenancy. A Silver deriva dela apenas **flags booleanas**
(`filtra_uid`, `filtra_tenant`, `expressao_permissiva_total`) e descarta o texto.

## O que a anonimização NÃO compromete

Todas as conclusões analíticas são estatísticas e independem dos nomes reais:
*"38% das tabelas expostas não têm RLS"* e *"12 colunas com dado pessoal estão em
tabelas sem proteção de linha"* têm exatamente o mesmo valor informativo com
`t_007` ou com o nome verdadeiro. O backlog de remediação é reidentificável por
mim, via o `de_para` privado, sem que o repositório exponha nada.

## Ordem de execução adotada

Auditar primeiro, corrigir depois. As vulnerabilidades detectadas **não** foram
corrigidas antes da entrega, por duas razões: manter a integridade do snapshot que
o pipeline documenta, e não misturar remediação com prazo de entrega. A correção é
trabalho posterior, e o backlog gerado é exatamente o insumo para ela.
