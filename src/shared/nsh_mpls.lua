-- Wireshark Lua script to decode NSH over MPLS directly
-- Maps the project's transit MPLS labels to the built-in NSH dissector.

local mpls_table = DissectorTable.get("mpls.label")
local nsh_dissector = Dissector.get("nsh")

if mpls_table and nsh_dissector then
    -- List of MPLS labels used in the lab
    local labels = { 101, 102, 103, 104, 105, 106, 107, 201, 202 }
    for _, label in ipairs(labels) do
        mpls_table:add(label, nsh_dissector)
    end
    print("NSH-over-MPLS Lua Dissector loaded successfully.")
else
    print("Error: Could not retrieve mpls.label table or nsh dissector.")
end
