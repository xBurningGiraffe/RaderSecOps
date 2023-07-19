function Invoke-RandomString {
    param (
        [Parameter(Mandatory=$true)]
        [int]$length
    )

    $randomString = ""
    for($i=0; $i -lt 10; $i++) { 
        $randomString += -join (((33..47)+(48..57)+(58..64)+(65..90)+(91..96)+(97..122)+(123..126)) * 80 | Get-Random -Count 20 | % {[char]$_})
    }

    # Remove random characters until only $length characters remain
    while($randomString.Length -gt $length) {
        $removeIndex = Get-Random -Minimum 0 -Maximum $randomString.Length
        $randomString = $randomString.Remove($removeIndex, 1)
    }

    $randomString
}
