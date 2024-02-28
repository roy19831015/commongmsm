DATE=$(date +%Y%m%d%H%M%S)
echo "git commit -a -m '第v1.0.$DATE版本'"
git commit -a -m "第v1.0.$DATE版本"
echo "git checkout -b release/v1.0.$DATE"
git checkout -b release/v1.0.$DATE
echo "git push -u fork release/v1.0.$DATE"
git push -u fork release/v1.0.$DATE
echo "git tag v1.0.$DATE"
git tag v1.0.$DATE
echo "git push --tags"
git push --tags
git checkout main
echo "git checkout main"
echo "goreleaser release --snapshot --rm-dist"
goreleaser release --snapshot --rm-dist
sed -i "1i//go:build !amd64 && !arm64 || purego" ./internal/sm2ec/sm2p256.go
