mkdir -p $GITHUB_PAGES_DIR
echo ">> Checking out $GITHUB_PAGES_BRANCH branch from $GITHUB_PAGES_REPO"
#cd $GITHUB_PAGES_DIR
mkdir -p "$HOME/.ssh"
ssh-keyscan -H github.com >> "$HOME/.ssh/known_hosts"
git -C $GITHUB_PAGES_DIR clone -b "$GITHUB_PAGES_BRANCH" "git@github.com:$GITHUB_PAGES_REPO.git" .
git -C $GITHUB_PAGES_DIR fetch origin
git -C $GITHUB_PAGES_DIR rebase origin/$TRAVIS_TAG