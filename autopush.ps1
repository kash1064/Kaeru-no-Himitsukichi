Param(
    [parameter(mandatory=$true)][String]$comment
)
git add .
git commit -m $comment
git push origin main