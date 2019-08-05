echo '>> Building charts...'
find "$HELM_CHARTS_SOURCE" -mindepth 1 -maxdepth 1 -type d | while read chart; do
  echo ">>> helm lint $chart"
  helm lint "$chart"
  chart_name=$HELM_CHART_DEST/"`basename "$chart"`"
  #chart_name="$HELM_CHART_DEST/$chart"
  echo ">>> helm package -d $chart_name $chart"
  mkdir -p "$chart_name"
  helm package -d "$chart_name" "$chart"
done
echo '>>> helm repo index'
helm repo index --url https://$(dirname $GITHUB_PAGES_REPO).github.io/$(basename $GITHUB_PAGES_REPO) $HELM_CHART_DEST