rule itroublveTSC{
    meta:
        author = "R00T - 0MrR00T0"
        description = "Detect itroublveTSC Discord Token & Passwords Stealer"
        hash = "F11665C8721466F78A96C106B08F17FC29A12F6C"
    strings:
        $Properties = "idk.Properties"
        $resources = "idk.Properties.Resources.resources"
        $config = "idk.Binaries.config"
        $windefDisable = "idk.Binaries.whysosad"
        $droppedstealer = "RtkBtManServ.exe"
        $hexify = "hexify"
    condition: all of them    
}