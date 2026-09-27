# Apresentação

Exportações dos notebooks executados no **Databricks Free Edition**, no formato `.ipynb`,
incluídas porque o GitHub renderiza esse formato de forma nativa — código, markdown e
saídas aparecem inline, sem precisar abrir a plataforma.

O pipeline **não** foi executado em Google Colab. Toda a execução ocorreu no Databricks,
conforme o item 2 do enunciado; estes arquivos são apenas o registro dessa execução.

| arquivo | o que mostra | saídas no `.ipynb` |
|---|---|---|
| `01_bronze_ingestao.ipynb` | leitura dos 8 CSVs e contagens da Bronze | ✅ completas |
| `02_silver_qualidade.ipynb` | perfil de qualidade, duplicatas, classificação LGPD | ✅ completas |
| `03_gold_regras_modelagem.ipynb` | as 18 regras, esquema estrela e catálogo | ✅ completas |
| `04_analise_perguntas.ipynb` | as 8 perguntas de negócio | ⚠️ só o código |
| `05_visualizacoes.ipynb` | painel de indicadores e as 4 figuras | ⚠️ só o código |

**Sobre os dois últimos.** A exportação do Databricks preserva a saída de `print()`, mas não
a de células SQL nem a de `display()` e `plt.show()`, que são renderizadas pela interface da
plataforma e não gravadas no formato `nbformat`. Por isso `04` e `05` aparecem aqui apenas
com o código.

Os resultados dessas duas etapas estão registrados como evidência em
[`../evidencias/`](../evidencias) e embutidos no [README principal](../README.md): as oito
respostas em `p1.png` a `p8.png`, e as cinco figuras em `00_indicadores.png` a
`04_backlog.png`.
