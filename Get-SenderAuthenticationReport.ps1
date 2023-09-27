function Get-SenderAuthenticationReport {

    param(
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$DomainList)

    $authreport = New-Object System.Collections.ArrayList
    foreach ($domain in $domainlist) {
        Write-Verbose "Processing $($domain)"
        #Get SPF
        try {
            $txtrecords = Resolve-DnsName $domain -Type TXT -ErrorAction Stop
        }
        catch {
            $authprop = @{
                "Domain" = $Domain;
                "HasSPF" = $false;
            }
        }
        if ($txtrecords -ne $null) {
            $hasspf = $false
            foreach ($record in $txtrecords) {
                If ($record.Strings -match "v=spf") {
                    $hasspf = $true
                }
            }
            $authprop = @{
                "Domain" = $Domain;
                "HasSPF" = $hasspf;
            }
        }
        #Get DMARC
        try {
            $dmarcrecords = Resolve-DnsName ("_dmarc." + $domain) -Type TXT -ErrorAction Stop
        }
        catch {
            $authprop.Add("HasDmarc", $false)
            $authprop.Add("DMARCPolicy", "NA")
            $dmarcrecords = $Null
        }
        if ($dmarcrecords -ne $null) {
            $hasdmarc = $false
            foreach ($record in $dmarcrecords) {
                if (($record.strings -match "v=DMARC1")) {
                    $authprop.Add("HasDmarc", $true)
                    if ($record.strings -match "p=reject") {
                        $authprop.Add("DMARCPolicy", "Reject")
                    }
                    elseif ($record.strings -match "p=quarantine") {
                        $authprop.Add("DMARCPolicy", "Quarantine")
                    }
                    elseif ($record.strings -match "p=none") {
                        $authprop.Add("DMARCPolicy", "None")
                    }
                    else {
                        $authprop.Add("DMARCPolicy", "Error")
                    }
                    $hasdmarc = $true
                }
                if ($record.Type -eq "SOA") {
                    $orgrecord = Resolve-DnsName ("_dmarc." + $record.name) -Type TXT -ErrorAction Stop
                    if (($orgrecord.strings -match "v=DMARC1")) {
                        $authprop.Add("HasDmarc", $true)
                        if ($orgrecord.strings -match "p=reject") {
                            $authprop.Add("DMARCPolicy", "Reject")
                        }
                        elseif ($record.strings -match "p=quarantine") {
                            $authprop.Add("DMARCPolicy", "Quarantine")
                        }
                        elseif ($record.strings -match "p=none") {
                            $authprop.Add("DMARCPolicy", "None")
                        }
                        else {
                            $authprop.Add("DMARCPolicy", "Error")
                        }                      
                        $authprop.Add("DMARCPolicy", "NA")
                        $hasdmarc = $true
                    }
                }
            }
            if ($hasdmarc -eq $false) {
                $authprop.Add("HasDmarc", $false)
                $authprop.Add("DMARCPolicy", "NA")
            }
        }
        $authobj = New-Object psobject -Property $authprop
        [void]$authreport.Add($authobj)
    }

    return $authreport
}