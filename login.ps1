$pwddir = (Get-Location -PSProvider FileSystem).Path
docker run -it --rm -v $pwddir\:/app/blog -p 8000:8000 kashiwabayuki/gatsby-env