name = "finddomain"
type = "ext"

function vertical( ctx,domain )
    local cmd = outputdir(ctx) .. "/bin/findomain -r --quiet -c  /bin/config.json -t " .. domain

    local data = assert(io.popen(cmd))
    for line in data.lines() do
        newname(ctx,line)
    end
    data.close()
end
