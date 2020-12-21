name = "githubsub"
type = "ext"

function start( )
    setratelimit(1)
end

function vertical( ctx,domain )
    local cmd = outputdir(ctx) .. "/bin/github-subdomains -t 6c5ed8ab7b7c4b9232fcaea5c051b8977a624012 -d " .. domain

    local data = assert(io.popen(cmd))
    for line in data.lines() do
        checkratelimit()
        newname(ctx,line)
    end
    data.close()
end
