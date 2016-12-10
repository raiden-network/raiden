#!/usr/bin/env bash

set -e

echo "Creating a release branch"

NEW_VERSION=$(bumpversion patch --dry-run --verbose 2>&1|grep current_version|tail -n1|cut -d' ' -f3)
RELEASE_BRANCH="poc_release_$NEW_VERSION"

echo "Will create $NEW_VERSION on $RELEASE_BRANCH"

git checkout -b $RELEASE_BRANCH

echo "Bumping the version"

bumpversion patch

git push --set-upstream git@github.com:raiden-network/raiden.git $RELEASE_BRANCH

echo "Querying your github user"

GH_USER=$(ssh git@github.com 2>&1|grep "Hi"|cut -d' ' -f2|rev|cut --complement -b-1|rev)

echo "Your github user seems to be $GH_USER"

read -s -p "Enter github password for $GH_USER: " GH_PASSWORD

# github doesn't issue OTP for all API requests, but this request works:
curl -u $GH_USER:$GH_PASSWORD https://api.github.com/authorizations -d '{
    "scopes": ["invalid"],
    "note": "just query OTP"
}'

read -s -p "Enter your github one time password: " GH_OTP

echo "\nCreating a pull request"

RESULT=$(curl -u $GH_USER:$GH_PASSWORD -XPOST -H "X-GitHub-OTP: $GH_OTP" \
https://api.github.com/repos/raiden-network/raiden/pulls -d'{
    "title": "Release '"$NEW_VERSION"'",
    "body": "automated PR!",
    "base": "master",
    "head": "'"$RELEASE_BRANCH"'"
}')

echo $RESULT
echo "--^ This should have created a pull request titled '$RELEASE_BRANCH'."

echo "If there is no PR, you should rollback your changes and start over."

GH_OTP=""

PR_URL=$(echo $RESULT|cut -d' ' -f 3|cut -b2-|rev|cut -b3-|rev)

# https://developer.github.com/early-access/platform-roadmap/  # see Pull Request Review REST API
echo "Since approving PRs is not supported yet, you have to proceed manually from here:"

echo "1) Get $PR_URL approved & merged"
echo "2) 'git checkout master && git pull --rebase'"
echo "3) 'git tag v$NEW_VERSION'"
echo "4) 'git push --tags'"
