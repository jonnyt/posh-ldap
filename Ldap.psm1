
Function Find-LdapObject 
{ 
    Param ( 
        [parameter(Mandatory = $true)] 
        [String]  
            #Search filter in LDAP syntax 
        $searchFilter, 
         
        [parameter(Mandatory = $true)] 
        [String]  
            #DN of container where to search 
        $searchBase, 
         
        [parameter(Mandatory = $false)] 
        [String]  
            #LDAP server name 
            #Default: local machine 
        $LdapServer=$env:computername, 
         
        [parameter(Mandatory = $false)] 
        [Int32]  
            #LDAP server port 
            #Default: 389 
        $Port=389, 
         
        [parameter(Mandatory = $false)] 
        [System.DirectoryServices.Protocols.LdapConnection] 
            #existing LDAPConnection object. 
            #When we perform many searches, it is more effective to use the same connection rather than create new connection for each search request. 
            #Default: $null, which means that connection is created automatically using information in LdapServer and Port parameters 
        $LdapConnection, 
         
        [parameter(Mandatory = $false)] 
        [System.DirectoryServices.Protocols.SearchScope] 
            #Search scope 
            #Default: Subtree 
        $searchScope="Subtree", 
         
        [parameter(Mandatory = $false)] 
        [String[]] 
            #List of properties we want to return for objects we find. 
            #Default: distinguishedName 
        $PropertiesToLoad=@("distinguishedName"), 
         
        [parameter(Mandatory = $false)] 
        [UInt32] 
            #Page size for paged search. Zero means that paging is disabled 
            #Default: 100 
        $PageSize=100, 
         
        [parameter(Mandatory = $false)] 
        [String[]] 
            #List of properties that we want to load as byte stream. 
            #Note: Those properties must also be present in PropertiesToLoad parameter. Properties not listed here are loaded as strings 
            #Default: empty list, which means that all properties are loaded as strings 
        $BinaryProperties=@(), 
 
        [parameter(Mandatory = $false)] 
        [UInt32] 
            #Number of seconds before connection times out. 
            #Default: 120 seconds 
        $TimeoutSeconds = 120, 
        

        [parameter(Mandatory = $false)] 
        [Boolean] 
            #Type of encryption to use. 
            #Applies only when existing connection is not passed 
        $SecureSocketsLayer=$false,

        [parameter(Mandatory = $false)] 
        [String] 
            #Use different credentials when connecting 
        $UserName=$null, 
 
        [parameter(Mandatory = $false)] 
        [String] 
            #Use different credentials when connecting 
        $Password=$null 
    ) 
 
    Process { 
        #we want dispose LdapConnection we create 
        [Boolean]$bDisposeConnection=$false 
        #range size for ranged attribute retrieval 
        #Note that default in query policy is 1500; we set to 1000 
        $rangeSize=100
 
        try 
        { 
            if($LdapConnection -eq $null) 
            { 
                [System.Net.NetworkCredential]$cred=$null 
                if(-not [String]::IsNullOrEmpty($userName))
                { 
                    if([String]::IsNullOrEmpty($password))
                    { 
                        $securePwd=Read-Host -AsSecureString -Prompt:"Enter password" 
                        $cred=new-object System.Net.NetworkCredential($userName,$securePwd) 
                    }
                    else
                    { 
                        $cred=new-object System.Net.NetworkCredential($userName,$Password) 
                    } 
                    $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection((new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port)), $cred) 
                }
                else
                { 
                    $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection(new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port)) 
                }

                # Need to have this as a parameter
                $LdapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]'Basic'
                $bDisposeConnection=$true
                if($SecureSocketsLayer)
                { 
                        $options=$LdapConnection.SessionOptions
                        $options.ProtocolVersion=3
                        $options.SecureSocketLayer = $true
                        #$options.StartTransportLayerSecurity($null)
                }

            } 
            if($pageSize -gt 0)
            { 
                #paged search silently fails when chasing referrals 
                $LdapConnection.SessionOptions.ReferralChasing="None" 
            } 
 
            #build request 
            $rq=new-object System.DirectoryServices.Protocols.SearchRequest 
             
            #search base 
            $rq.DistinguishedName=$searchBase 
 
            #search filter in LDAP syntax 
            $rq.Filter=$searchFilter 
 
            #search scope 
            $rq.Scope=$searchScope 
 
            #attributes we want to return - distinguishedName now, and then use ranged retrieval for the propsToLoad 
            # JT - Range retrieval needs some trouble-shooting
            $rq.Attributes.Add("distinguishedName") | Out-Null 
            foreach($prop in $PropertiesToLoad)
            {
                $rq.Attributes.Add($prop) | Out-Null
            }
            
            #paged search control for paged search 
            if($pageSize -gt 0)
            { 
                [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize) 
                $rq.Controls.Add($pagedRqc) | Out-Null 
            } 
 
            #server side timeout 
            $rq.TimeLimit=(new-object System.Timespan(0,0,$TimeoutSeconds)) 
            #process paged search in cycle or go through the processing at least once for non-paged search 
            while ($true) 
            { 
                $rsp = $LdapConnection.SendRequest($rq, (new-object System.Timespan(0,0,$TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse]; 
                 
                #for paged search, the response for paged search result control - we will need a cookie from result later 
                if($pageSize -gt 0) { 
                    [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null; 
                    if ($rsp.Controls.Length -gt 0) 
                    { 
                        foreach ($ctrl in $rsp.Controls) 
                        { 
                            if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) 
                            { 
                                $prrc = $ctrl; 
                                break; 
                            } 
                        } 
                    } 
                    if($prrc -eq $null) 
                    { 
                        #server was unable to process paged search 
                        throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter" 
                    } 
                } 
                #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval 
                foreach ($sr in $rsp.Entries) 
                {
                    #create empty custom object for result 
                    $propDef=@{} 
                    foreach($prop in $PropertiesToLoad) { 
                        $propDef.Add($prop,@()) 
                    } 
                    $data=new-object PSObject -Property $propDef

                    #fill properties of custom object
                    $dn=$sr.DistinguishedName

                    if($sr.Attributes -ne $null)
                    {
                        foreach($attrName in $PropertiesToLoad)
                        {
                            if($sr.Attributes.Contains($attrName))
                            {
                                if($BinaryProperties -contains $attrName) 
                                { 
                                    $vals=$sr.Attributes[$attrName].GetValues([byte[]]) 
                                } 
                                else
                                { 
                                    $vals = $sr.Attributes[$attrName].GetValues(([string])) # -as [string[]]; 
                                } 
                                $data.$attrName+=$vals

                                #return single value as value, multiple values as array 
                                if($data.$attrName.Length -eq 1) 
                                { 
                                    $data.$attrName = $data.$attrName[0] 
                                }
                            }
                            else
                            {
                                $data.$attrName = $null
                            }
                        }
                    }
                    
                    <#
                    #we return results as powershell custom objects to pipeline 
                    #initialize members of result object (server response does not contain empty attributes, so classes would not have the same layout 
                    #initialize via hashtable --> faster than add-member 
                    $propDef=@{} 
                    foreach($prop in $PropertiesToLoad) { 
                        $propDef.Add($prop,@()) 
                    } 
                    #create empty custom object for result 
                    $data=new-object PSObject -Property $propDef 
 
                    #fill properties of custom object 
                    #here is going to be a distinguishedName only 
                    #$dn=($sr.Attributes["distinguishedname"].GetValues(([string])) -as [string[]])[0] 
                    $dn=$sr.DistinguishedName

                    
                    foreach ($attrName in $PropertiesToLoad) { 
                        $rqAttr=new-object System.DirectoryServices.Protocols.SearchRequest 
                        $rqAttr.DistinguishedName=$dn 
                        $rqAttr.Scope="Base" 

                        # add by me
                        $rqAttr.Filter="(objectClass=*)"
                         
                        $start=-$rangeSize 
                        $lastRange=$false 
                        while ($lastRange -eq $false) { 
                            $start += $rangeSize 
                            $rng = "$($attrName.ToLower());range=$start`-$($start+$rangeSize-1)" 
                            $rqAttr.Attributes.Clear() | Out-Null 
                            $rqAttr.Attributes.Add($rng) | Out-Null 
                            $rspAttr = $LdapConnection.SendRequest($rqAttr) 
                            foreach ($sr in $rspAttr.Entries) { 
                                if($sr.Attributes.AttributeNames -ne $null) { 
                                    #LDAP server changes upper bound to * on last chunk 
                                    $returnedAttrName=$($sr.Attributes.AttributeNames) 
                                    #load binary properties as byte stream, other properties as strings 
                                    if($BinaryProperties -contains $attrName) { 
                                        $vals=$sr.Attributes[$returnedAttrName].GetValues([byte[]]) 
                                    } else { 
                                        $vals = $sr.Attributes[$returnedAttrName].GetValues(([string])) # -as [string[]]; 
                                    } 
                                    $data.$attrName+=$vals 
                                    if($returnedAttrName.EndsWith("-*")) { 
                                        #last chunk arrived 
                                        $lastRange = $true 
                                    } 
                                } 
                                else 
                                { 
                                    #nothing was found 
                                    $lastRange = $true 
                                } 
                            } 
                        } 
 
                        #return single value as value, multiple values as array 
                        if($data.$attrName.Count -eq 1) { 
                            $data.$attrName = $data.$attrName[0] 
                        } 
                    }
                    #>
                    
                    #return result to pipeline 
                    $data 
                } 
                if($pageSize -gt 0) 
                { 
                    if ($prrc.Cookie.Length -eq 0) 
                    { 
                        #last page --> we're done 
                        break; 
                    } 
                    #pass the search cookie back to server in next paged request 
                    $pagedRqc.Cookie = $prrc.Cookie; 
                } else
                { 
                    #exit the processing for non-paged search 
                    break; 
                } 
            } 
        } 
        finally { 
            if($bDisposeConnection) { 
                #if we created the connection, dispose it here 
                $LdapConnection.Dispose() 
            } 
        } 
    } 
}

Export-ModuleMember Find-LdapObject