#!/bin/bash
# Confere se os 23 arquivos de evidencia estao presentes com os nomes exatos
# que o README referencia. Rode dentro da pasta do projeto:  bash evidencias/conferir.sh
cd "$(dirname "$0")"
ESPERADOS=(
  00_indicadores.png 01_owasp.png 02_exposicao_lgpd.png 03_heatmap_schema.png 04_backlog.png
  01_volume_csvs.png 02_ingestao_contagens.png 03_perfil_qualidade.png
  04_perfil_duplicatas.png 05_classe_dado.png 06_catalogo_tabela.png
  07_catalogo_coluna.png 08_lineage.png 09_dim_regra.png 10_backlog.png 11_catalogo_cobertura.png
  11_catalogo_cobertura.png
  p1.png p2.png p3.png p4.png p5.png p6.png p7.png p8.png
)
faltam=0
for f in "${ESPERADOS[@]}"; do
  if [ -f "$f" ]; then printf "  ok      %s\n" "$f"
  else printf "  FALTA   %s\n" "$f"; faltam=$((faltam+1)); fi
done
echo ""
extras=$(ls *.png 2>/dev/null | grep -vxF "$(printf '%s\n' "${ESPERADOS[@]}")" || true)
[ -n "$extras" ] && { echo "Arquivos com nome fora da lista (renomeie ou remova):"; echo "$extras" | sed 's/^/  /'; echo ""; }
if [ $faltam -eq 0 ]; then echo ">> Os 23 estao no lugar. Pode commitar."
else echo ">> Faltam $faltam arquivo(s)."; fi
