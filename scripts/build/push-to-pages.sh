git config user.email "$CIRCLE_USERNAME@users.noreply.github.com"
git config user.name CircleCI
git add .
git status
git commit -m "Published by CircleCI $CIRCLE_BUILD_URL"
git push origin "$GITHUB_PAGES_BRANCH"