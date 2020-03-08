hugo -t hello-friend-ng
git checkout master
cp -r spublic/* ./
rm -r public/

git add .
git commit -m "Update"
git push origin master

git checkout develop
git submodule update