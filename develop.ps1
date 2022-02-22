$pwddir = (Get-Location -PSProvider FileSystem).Path
docker run --rm -v $pwddir\:/app/blog -p 8000:8000 kashiwabayuki/gatsby-env gatsby develop -H 0.0.0.0