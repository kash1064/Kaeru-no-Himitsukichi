$pwddir = (Get-Location -PSProvider FileSystem).Path
docker run --rm -v $pwddir\:/app/blog kashiwabayuki/gatsby-env gatsby clean