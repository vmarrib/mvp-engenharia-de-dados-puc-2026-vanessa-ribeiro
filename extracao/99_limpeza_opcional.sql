-- Limpeza de tabelas remanescentes de um projeto anterior no mesmo workspace.
-- Nao faz parte do pipeline; existe so para deixar o catalogo legivel nos screenshots.
-- Rode numa celula SQL do Databricks (ou no SQL Editor) ANTES de capturar as telas
-- do Catalog Explorer.

DROP TABLE IF EXISTS workspace.bronze.bureau_responses;
DROP TABLE IF EXISTS workspace.silver.normalized_signals;
DROP TABLE IF EXISTS workspace.gold.dossies;

-- Confira o que sobrou em cada camada:
SHOW TABLES IN workspace.bronze;
SHOW TABLES IN workspace.silver;
SHOW TABLES IN workspace.gold;
