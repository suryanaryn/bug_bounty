name = "assetfinder"
type = "ext"

function vertical( ctx,domain )
    local cmd = outputdir(ctx) .. "/bin/assetfinder --subs-only " .. domain

    local data = assert(io.popen(cmd))
    for line in data.lines() do
        newname(ctx,line)
    end
    data.close()
end
