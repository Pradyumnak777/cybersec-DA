rule EICAR_Test_File {
    meta:
        description = "will detect EICAR test file"
        author = "pradyumna"
        date = "2024-10-06"

    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIV>

    condition:
        $eicar_string
}


