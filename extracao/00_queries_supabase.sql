-- =====================================================================
-- MVP Engenharia de Dados | Auditoria de Postura de Seguranca - Pitaia
-- ETAPA 4.2 COLETA - Extracao do catalogo de seguranca do Postgres
--
-- COMO USAR:
--   1. Painel do Supabase > SQL Editor
--   2. Rode UMA query por vez (cada bloco abaixo)
--   3. Baixe o resultado em CSV com o nome indicado em "SALVAR COMO"
--   4. Suba os 8 CSVs para o Volume do Databricks
--
-- PRINCIPIO: nao filtramos nada aqui. A camada Bronze guarda o dado como
-- ele veio (cofre de evidencias). Todo recorte de escopo acontece na Silver
-- e fica documentado.
--
-- SEGURANCA: nenhuma destas queries le dados de usuario. Extraimos APENAS
-- metadados de estrutura e permissao. A query E extrai somente FLAGS das
-- funcoes (nunca o corpo), para nao vazar logica ou segredo no repo publico.
-- =====================================================================


-- ---------------------------------------------------------------------
-- QUERY A  |  SALVAR COMO: objetos.csv
-- Objetos do banco e estado do Row Level Security.
-- reloptions carrega security_invoker das views (regra R07).
-- ---------------------------------------------------------------------
select
    n.nspname                as schema_nome,
    c.relname                as objeto,
    c.relkind                as tipo_bruto,
    c.relrowsecurity         as rls_habilitado,
    c.relforcerowsecurity    as rls_forcado,
    array_to_string(c.reloptions, ';') as opcoes,
    obj_description(c.oid)   as comentario
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p','v','m','f')
order by n.nspname, c.relname;


-- ---------------------------------------------------------------------
-- QUERY B  |  SALVAR COMO: politicas.csv
-- Politicas de RLS. O CORACAO da auditoria.
-- ATENCAO: a coluna "roles" vem como array Postgres -> {anon,authenticated}
-- e sera explodida na Silver. "qual" vem NULL em politicas so com WITH CHECK.
-- ---------------------------------------------------------------------
select
    schemaname  as schema_nome,
    tablename   as objeto,
    policyname  as politica,
    permissive,
    array_to_string(roles, ';') as roles,
    cmd         as comando,
    qual        as expressao_using,
    with_check  as expressao_check
from pg_policies
order by schemaname, tablename, policyname;


-- ---------------------------------------------------------------------
-- QUERY C  |  SALVAR COMO: colunas.csv
-- Todas as colunas. Base da classificacao de dado de saude (LGPD art. 11).
-- ATENCAO: NAO usar information_schema.columns aqui. Aquela view e filtrada
-- por privilegio: so mostra o que a role corrente enxerga, e no SQL Editor
-- isso devolve um subconjunto silencioso. pg_attribute nao filtra.
-- ---------------------------------------------------------------------
select
    n.nspname                                   as schema_nome,
    c.relname                                   as objeto,
    a.attname                                   as coluna,
    format_type(a.atttypid, a.atttypmod)        as tipo_dado,
    case when a.attnotnull then 'NO' else 'YES' end as is_nullable,
    a.attnum                                    as ordinal_position,
    pg_get_expr(d.adbin, d.adrelid)             as column_default
from pg_attribute a
join pg_class c     on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace
left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
where a.attnum > 0 and not a.attisdropped
  and c.relkind in ('r','p','v','m','f')
order by n.nspname, c.relname, a.attnum;


-- ---------------------------------------------------------------------
-- QUERY D  |  SALVAR COMO: grants.csv
-- Privilegios por role. E aqui que se ve o que "anon" e "authenticated" alcancam.
-- ATENCAO: information_schema.role_table_grants SO mostra grants em que a role
-- corrente e concedente, beneficiaria ou membro da role beneficiaria. Rodando no
-- SQL Editor ela devolve apenas os grants da propria role de execucao - inutil
-- para auditoria. aclexplode() sobre pg_class.relacl le a ACL real.
-- grantee = 0 significa PUBLIC (todo mundo).
-- ---------------------------------------------------------------------
select
    case when a.grantee = 0 then 'PUBLIC'
         else pg_get_userbyid(a.grantee) end    as role_nome,
    n.nspname                                   as schema_nome,
    c.relname                                   as objeto,
    a.privilege_type                            as privilegio,
    case when a.is_grantable then 'YES' else 'NO' end as is_grantable
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
cross join lateral aclexplode(
    coalesce(c.relacl, acldefault('r', c.relowner))) a
where c.relkind in ('r','p','v','m','f')
order by role_nome, n.nspname, c.relname, a.privilege_type;


-- ---------------------------------------------------------------------
-- QUERY E  |  SALVAR COMO: funcoes.csv
-- Funcoes: SOMENTE FLAGS, nunca o corpo (pg_get_functiondef fica de fora
-- de proposito - poderia vazar logica/segredo no repositorio publico).
-- prosecdef = SECURITY DEFINER | proconfig contem o search_path fixado.
-- ---------------------------------------------------------------------
select
    n.nspname   as schema_nome,
    p.proname   as funcao,
    p.prosecdef as security_definer,
    array_to_string(p.proconfig, ';') as config,
    l.lanname   as linguagem
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
join pg_language l on l.oid = p.prolang
where n.nspname not in ('pg_catalog','information_schema')
order by n.nspname, p.proname;


-- ---------------------------------------------------------------------
-- QUERY F  |  SALVAR COMO: buckets.csv
-- Buckets do Supabase Storage. public = true significa leitura anonima.
-- ---------------------------------------------------------------------
select
    id        as bucket_id,
    name      as bucket_nome,
    public    as publico,
    file_size_limit,
    created_at
from storage.buckets
order by name;


-- ---------------------------------------------------------------------
-- QUERY G  |  SALVAR COMO: extensoes.csv
-- Extensoes instaladas = cadeia de suprimentos (OWASP A03:2025).
-- Extensao fora do schema "extensions" e desvio de boa pratica.
-- ---------------------------------------------------------------------
select
    e.extname                        as extensao,
    n.nspname                        as schema_nome,
    e.extversion                     as versao
from pg_extension e
join pg_namespace n on n.oid = e.extnamespace
order by e.extname;


-- ---------------------------------------------------------------------
-- QUERY H  |  SALVAR COMO: constraints.csv
-- Chaves primarias, unicas e estrangeiras. Tabela sem PK impede deduplicacao
-- confiavel (OWASP A08:2025). pg_constraint tambem evita o filtro por privilegio
-- do information_schema.
-- ---------------------------------------------------------------------
select
    n.nspname   as schema_nome,
    c.relname   as objeto,
    con.conname as constraint_nome,
    case con.contype when 'p' then 'PRIMARY KEY'
                     when 'u' then 'UNIQUE'
                     when 'f' then 'FOREIGN KEY' end as tipo
from pg_constraint con
join pg_class c     on c.oid = con.conrelid
join pg_namespace n on n.oid = c.relnamespace
where con.contype in ('p','u','f')
order by n.nspname, c.relname, con.conname;
