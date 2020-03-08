hugo -t hello-friend-ng
git checkout master
cp public/* ./
rm -r public/

git push origin master

git checkout develop
git submodule update