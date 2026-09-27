# Apresentação

Exportações dos notebooks executados no **Databricks Free Edition**, no formato `.ipynb`,
incluídas porque o GitHub renderiza esse formato de forma nativa — código, markdown e
**saídas** aparecem inline, sem precisar abrir a plataforma.

O pipeline **não** foi executado em Google Colab. Toda a execução ocorreu no Databricks,
conforme o item 2 do enunciado; estes arquivos são apenas o registro dessa execução.

| arquivo | o que mostra |
|---|---|
| `01_bronze_ingestao.ipynb` | leitura dos 8 CSVs e as contagens da camada Bronze |
| `02_silver_qualidade.ipynb` | perfil de qualidade, duplicatas e classificação LGPD |
| `03_gold_regras_modelagem.ipynb` | as 18 regras, o esquema estrela e o catálogo |
| `04_analise_perguntas.ipynb` | as 8 perguntas de negócio respondidas |
| `05_visualizacoes.ipynb` | o painel de indicadores e as 4 figuras |
