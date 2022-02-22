start_docker:
	sudo /etc/init.d/docker start

login:
	docker run --rm -it -v `pwd`/:/app/blog -v ~/.ssh:/root/.ssh -p 8000:8000 kashiwabayuki/gatsby-env

develop:
	make force_pull
	docker run --rm -v `pwd`/:/app/blog kashiwabayuki/gatsby-env gatsby clean
	docker run --rm -v `pwd`/:/app/blog -p 8000:8000 kashiwabayuki/gatsby-env gatsby develop -H 0.0.0.0

deploy:
	make force_pull
	docker run --rm -v `pwd`/:/app/blog -v ~/.ssh:/root/.ssh kashiwabayuki/gatsby-env npm run deploy

chown:
	sudo chown ubuntu:ubuntu ./* -R

day := `date +"%Y_%m_%d"`
m := autopush ${day}
branch := origin main
autopush: ## This is auto push module, need commit message(default=autopush)
	git add .
	git commit -m "${m}"
	git push ${branch}

pull:
	git pull ${branch}

force_pull:
	git fetch ${branch}
	git reset --hard origin/main