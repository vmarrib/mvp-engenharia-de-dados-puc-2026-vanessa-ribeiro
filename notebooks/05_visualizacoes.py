# Databricks notebook source
# MAGIC %md
# MAGIC # 05 - Visualizacoes
# MAGIC
# MAGIC Quatro figuras + um painel de indicadores, salvos em PNG num Volume para eu baixar
# MAGIC e colar no relatorio.
# MAGIC
# MAGIC Duas decisoes de cor que vale registrar, porque testei antes de escolher:
# MAGIC
# MAGIC - **Protegida x exposta nao usa verde e vermelho.** O par verde/vermelho tem
# MAGIC   separacao de apenas 4.1 em deuteranopia - quem tem a forma mais comum de
# MAGIC   daltonismo nao distingue as duas barras. Troquei por azul x vermelho, que separa
# MAGIC   23.8 e passa em todas as checagens.
# MAGIC - **Severidade usa rampa ordinal de um hue, nao quatro cores de status.** Severidade
# MAGIC   e ordenada (Critico > Alto > Medio > Baixo), entao rampa clara->escura comunica a
# MAGIC   ordem; quatro matizes distintas nao comunicam nada e a paleta de status
# MAGIC   amarelo/laranja fica indistinguivel (13.6, abaixo do piso de 15 mesmo com visao
# MAGIC   normal de cores).
# MAGIC
# MAGIC Valores sempre impressos nas barras e nas celulas, para que a informacao nunca
# MAGIC dependa so da cor.

# COMMAND ----------

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

CATALOGO = "workspace"
GOLD     = f"{CATALOGO}.gold"
FIGURAS  = f"/Volumes/{CATALOGO}/gold/figuras"

spark.sql(f"CREATE VOLUME IF NOT EXISTS {CATALOGO}.gold.figuras")

SUPERFICIE = "#fcfcfb"
TINTA      = "#0b0b0b"
TINTA_2    = "#52514e"
GRADE      = "#e6e5e1"

AZUL     = "#2a78d6"
VERMELHO = "#d03b3b"

# rampa ordinal: mais escuro = mais grave
SEVERIDADE = {"Critico": "#0d366b", "Alto": "#256abf", "Medio": "#5598e7", "Baixo": "#86b6ef"}
ORDEM_SEV  = ["Critico", "Alto", "Medio", "Baixo"]

plt.rcParams.update({
    "figure.facecolor": SUPERFICIE, "axes.facecolor": SUPERFICIE,
    "text.color": TINTA, "axes.labelcolor": TINTA_2,
    "xtick.color": TINTA_2, "ytick.color": TINTA_2,
    "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "semibold",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.edgecolor": GRADE, "grid.color": GRADE, "grid.linewidth": 0.8,
})

def limpar(ax, eixo_valor="x"):
    ax.grid(axis=eixo_valor, alpha=0.9, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)
    for lado in ("left", "bottom"):
        ax.spines[lado].set_visible(False)

def salvar(fig, nome):
    caminho = f"{FIGURAS}/{nome}.png"
    fig.savefig(caminho, dpi=150, bbox_inches="tight", facecolor=SUPERFICIE)
    print(f"salvo em {caminho}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Painel de indicadores
# MAGIC Os quatro numeros que abrem o relatorio. Numero grande le melhor que grafico quando
# MAGIC a informacao e um valor unico.

# COMMAND ----------

ind = spark.sql(f"""
SELECT (SELECT count(*) FROM {GOLD}.fato_achado)                                   AS achados,
       (SELECT count(*) FROM {GOLD}.fato_achado f
          JOIN {GOLD}.dim_regra r ON r.sk_regra = f.sk_regra
         WHERE r.severidade = 'Critico')                                           AS criticos,
       (SELECT count(*) FROM {GOLD}.dim_coluna WHERE is_dado_saude)                AS col_saude,
       (SELECT count(*) FROM {GOLD}.isolamento_prontuario
         WHERE aberta_a_autenticados = 1 OR NOT rls_habilitado)                     AS vazando
""").collect()[0]

cartoes = [
    (f"{ind['achados']}",  "achados de segurança",          TINTA),
    (f"{ind['criticos']}", "de severidade crítica",         VERMELHO),
    (f"{ind['col_saude']}", "colunas com dado de saúde",     AZUL),
    (f"{ind['vazando']}",  "tabelas de saúde sem isolamento", VERMELHO),
]

fig, eixos = plt.subplots(1, 4, figsize=(13, 2.4))
for ax, (valor, rotulo, cor) in zip(eixos, cartoes):
    ax.text(0.5, 0.62, valor, ha="center", va="center", fontsize=42, fontweight="bold", color=cor)
    ax.text(0.5, 0.18, rotulo, ha="center", va="center", fontsize=10, color=TINTA_2, wrap=True)
    ax.axis("off")
fig.suptitle("Pitaia — postura de segurança do banco de dados", fontsize=13,
             fontweight="semibold", y=1.06)
salvar(fig, "00_indicadores")
plt.show()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Figura 1 - risco por categoria do OWASP Top 10:2025 (P6)

# COMMAND ----------

df = spark.sql(f"""
SELECT r.categoria_owasp, r.severidade, sum(f.score_risco) AS score
FROM {GOLD}.fato_achado f JOIN {GOLD}.dim_regra r ON r.sk_regra = f.sk_regra
GROUP BY r.categoria_owasp, r.severidade
""").toPandas()

pivo = (df.pivot_table(index="categoria_owasp", columns="severidade",
                       values="score", aggfunc="sum", fill_value=0)
          .reindex(columns=[s for s in ORDEM_SEV if s in df.severidade.unique()], fill_value=0))
pivo = pivo.loc[pivo.sum(axis=1).sort_values().index]

fig, ax = plt.subplots(figsize=(9, 0.7 * len(pivo) + 1.6))
base = np.zeros(len(pivo))
for sev in pivo.columns:
    ax.barh(pivo.index, pivo[sev], left=base, height=0.6, color=SEVERIDADE[sev],
            label=sev, edgecolor=SUPERFICIE, linewidth=1.6, zorder=3)
    base += pivo[sev].values

for y, total in enumerate(pivo.sum(axis=1)):
    ax.text(total + max(base) * 0.015, y, f"{int(total)}", va="center",
            fontsize=10, color=TINTA_2)

ax.set_xlabel("Score de risco acumulado")
ax.set_title("Onde o risco se concentra nas categorias do OWASP Top 10:2025")
ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
ax.legend(title="Severidade", frameon=False, loc="lower right", fontsize=9, title_fontsize=9)
limpar(ax)
salvar(fig, "01_owasp")
plt.show()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Figura 2 - exposicao de dado pessoal e de saude (P7)
# MAGIC As classes de dado de saude aparecem marcadas com asterisco no eixo - sao as que
# MAGIC caem no art. 11 da LGPD.

# COMMAND ----------

df = spark.sql(f"""
SELECT classe_dado, is_dado_saude, n_protegidas, n_expostas, n_colunas
FROM {GOLD}.mapa_exposicao_lgpd
""").toPandas().sort_values("n_colunas")

rotulos = [f"{c} *" if s else c for c, s in zip(df.classe_dado, df.is_dado_saude)]

fig, ax = plt.subplots(figsize=(9, 0.55 * len(df) + 1.8))
ax.barh(rotulos, df.n_protegidas, height=0.6, color=AZUL, label="protegida por RLS",
        edgecolor=SUPERFICIE, linewidth=1.6, zorder=3)
ax.barh(rotulos, df.n_expostas, left=df.n_protegidas, height=0.6, color=VERMELHO,
        label="exposta sem RLS", edgecolor=SUPERFICIE, linewidth=1.6, zorder=3)

for y, (p, e) in enumerate(zip(df.n_protegidas, df.n_expostas)):
    if e > 0:
        ax.text(p + e + max(df.n_colunas) * 0.02, y, f"{int(e)} exposta(s)",
                va="center", fontsize=9, color=VERMELHO, fontweight="semibold")

ax.set_xlabel("Colunas")
ax.set_title("Exposição por classe de dado pessoal  (* dado de saúde, LGPD art. 11)")
ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
ax.legend(frameon=False, loc="lower right", fontsize=9)
limpar(ax)
salvar(fig, "02_exposicao_lgpd")
plt.show()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Figura 3 - densidade de achados por schema e severidade (P5)

# COMMAND ----------

df = spark.sql(f"""
SELECT o.schema_anon, r.severidade, count(*) AS n
FROM {GOLD}.fato_achado f
JOIN {GOLD}.dim_regra  r ON r.sk_regra  = f.sk_regra
JOIN {GOLD}.dim_objeto o ON o.sk_objeto = f.sk_objeto
GROUP BY o.schema_anon, r.severidade
""").toPandas()

m = (df.pivot_table(index="schema_anon", columns="severidade", values="n",
                    aggfunc="sum", fill_value=0)
       .reindex(columns=ORDEM_SEV, fill_value=0))
m = m.loc[m.sum(axis=1).sort_values(ascending=False).index]

fig, ax = plt.subplots(figsize=(7, 0.5 * len(m) + 2))
im = ax.imshow(m.values, cmap="Blues", aspect="auto", vmin=0)

ax.set_xticks(range(len(m.columns)), m.columns)
ax.set_yticks(range(len(m.index)), m.index)
ax.set_title("Achados por schema e severidade")

# valor impresso em toda celula: a leitura nao depende da cor
limite = m.values.max() * 0.55 if m.values.max() else 1
for i in range(m.shape[0]):
    for j in range(m.shape[1]):
        v = m.values[i, j]
        ax.text(j, i, int(v), ha="center", va="center", fontsize=10,
                color="#ffffff" if v > limite else TINTA_2)

cb = fig.colorbar(im, ax=ax, shrink=0.7, pad=0.03)
cb.set_label("nº de achados", color=TINTA_2, fontsize=9)
cb.outline.set_visible(False)
ax.tick_params(length=0)
for s in ax.spines.values():
    s.set_visible(False)
salvar(fig, "03_heatmap_schema")
plt.show()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Figura 4 - top 15 do backlog de remediacao
# MAGIC A entrega do pipeline: o que corrigir primeiro.

# COMMAND ----------

df = spark.sql(f"""
SELECT prioridade, id_regra, severidade, objeto_anon, coluna_anon, detalhe, score_risco
FROM {GOLD}.backlog_remediacao
ORDER BY prioridade LIMIT 15
""").toPandas().iloc[::-1]

# funcoes e buckets nao sao tabelas, entao nao tem objeto_anon - uso o detalhe curto
def alvo(o, c, d):
    if o:  return o + (f" · {c}" if c else "")
    return (d or "")[:34]

rotulos = [f"{p:>2}. {r} · {alvo(o, c, d)}"
           for p, r, o, c, d in zip(df.prioridade, df.id_regra, df.objeto_anon,
                                    df.coluna_anon, df.detalhe)]

fig, ax = plt.subplots(figsize=(10, 0.45 * len(df) + 1.8))
ax.barh(rotulos, df.score_risco, height=0.6,
        color=[SEVERIDADE[s] for s in df.severidade],
        edgecolor=SUPERFICIE, linewidth=1.6, zorder=3)

for y, v in enumerate(df.score_risco):
    ax.text(v + 0.4, y, str(int(v)), va="center", fontsize=9, color=TINTA_2)

ax.set_xlabel("Score de risco  (peso da regra × 3 se dado sensível, × 2 se pessoal)")
ax.set_title("Backlog de remediação — 15 itens mais urgentes")
ax.tick_params(axis="y", labelsize=9)
handles = [plt.Rectangle((0, 0), 1, 1, color=SEVERIDADE[s])
           for s in ORDEM_SEV if s in set(df.severidade)]
ax.legend(handles, [s for s in ORDEM_SEV if s in set(df.severidade)],
          title="Severidade", frameon=False, loc="lower right", fontsize=9, title_fontsize=9)
limpar(ax)
salvar(fig, "04_backlog")
plt.show()

# COMMAND ----------

# MAGIC %md
# MAGIC Os PNGs ficam no Volume `gold.figuras`. Baixo pelo Catalog Explorer
# MAGIC (Catalog > gold > figuras > download) e coloco em `evidencias/` no repositorio.
