git -C $GITHUB_PAGES_DIR config user.email "$redhat-cop@users.noreply.github.com"
git -C $GITHUB_PAGES_DIR config user.name $GIT_USERNAME
git -C $GITHUB_PAGES_DIR add .
git -C $GITHUB_PAGES_DIR status
git -C $GITHUB_PAGES_DIR commit -m "Published by Travis"
git -C $GITHUB_PAGES_DIR push origin "$GITHUB_PAGES_BRANCH"