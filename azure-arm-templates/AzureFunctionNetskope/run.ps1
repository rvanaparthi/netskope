# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}


# Function to convery Html to text

function Html-ToText {
 param([System.String] $html)

 # remove line breaks, replace with spaces
 $html = $html -replace "(`r|`n|`t)", " "
 # write-verbose "removed line breaks: `n`n$html`n"

 # remove invisible content
 @('head', 'style', 'script', 'object', 'embed', 'applet', 'noframes', 'noscript', 'noembed') | % {
  $html = $html -replace "<$_[^>]*?>.*?</$_>", ""
 }
 # write-verbose "removed invisible blocks: `n`n$html`n"

 # Condense extra whitespace
 $html = $html -replace "( )+", " "
 # write-verbose "condensed whitespace: `n`n$html`n"

 # Add line breaks
 @('div','p','blockquote','h[1-9]') | % { $html = $html -replace "</?$_[^>]*?>.*?</$_>", ("`n" + '$0' )} 
 # Add line breaks for self-closing tags
 @('div','p','blockquote','h[1-9]','br') | % { $html = $html -replace "<$_[^>]*?/>", ('$0' + "`n")} 
 # write-verbose "added line breaks: `n`n$html`n"

 #strip tags 
 $html = $html -replace "<[^>]*?>", ""
 # write-verbose "removed tags: `n`n$html`n"
  
 # replace common entities
 @( 
  @("&amp;bull;", " * "),
  @("&amp;lsaquo;", "<"),
  @("&amp;rsaquo;", ">"),
  @("&amp;(rsquo|lsquo);", "'"),
  @("&amp;(quot|ldquo|rdquo);", '"'),
  @("&amp;trade;", "(tm)"),
  @("&amp;frasl;", "/"),
  @("&amp;(quot|#34|#034|#x22);", '"'),
  @('&amp;(amp|#38|#038|#x26);', "&amp;"),
  @("&amp;(lt|#60|#060|#x3c);", "<"),
  @("&amp;(gt|#62|#062|#x3e);", ">"),
  @('&amp;(copy|#169);', "(c)"),
  @("&amp;(reg|#174);", "(r)"),
  @("&amp;nbsp;", " "),
  @("&amp;(.{2,6});", "")
 ) | % { $html = $html -replace $_[0], $_[1] }
 # write-verbose "replaced entities: `n`n$html`n"

 return $html

}


# Function for alerts and events from netskop apis 

function netskope ()
{
$customerId = $env:workspaceId
$sharedKey = $env:workspacekey
$apikey = $env:apikey
$LogType = $env:tablename
$timeperiod = $env:timeperiod
$uri = "$env:uri"
$netskopeevents = @()
$apitypes = @("alert","page","application","audit","infrastructure","network")
    
    
     foreach($type in $apitypes){   
            if("$type" -eq "alert") 
            { 

                       $Url = "$uri/api/v1/alerts?token=$apikey&timeperiod=$timeperiod"
                       Write-Output $Url
                       $alerts = Invoke-RestMethod $URL -Method 'GET' -Headers $headers -Body $body -ErrorVariable RestError
                       if ($RestError )
                       {
                            Write-Output "Error Please check the API request"
                       }
                       elseif([string]::IsNullOrWhiteSpace($alerts.data.type))
                       {
                            Write-Output "$type event type Data is Empty on Request"
                       }
                       else
                       {
                            Write-Output " event $type data is available"
                            $netskopeevents += $alerts.data     
                       }
                                            
            } 
            else {
            
                     $Url = "$uri/api/v1/events?token=$apikey&type=$type&timeperiod=$timeperiod"
            
                     $events = Invoke-RestMethod $URL -Method 'GET' -Headers $headers -Body $body -ErrorVariable RestError
                      if ($RestError )
                       {
                          Write-Output "Error Please check the API request"
                       }
                      elseif([string]::IsNullOrWhiteSpace($events.data.type))
                       {
                          Write-Output "$type event type Data is Empty on Request"
                       }
                      else
                       {
                          Write-Output " event $type data is available"
                          $netskopeevents += $events.data     
                       }
                    }
 
           }


if (-not ($netskopeevents -eq $null))
{
       
        Write-Output 'Loading Data to Log Analytics'
        $event = $netskopeevents
        $event | ForEach-Object {
        $eventobjs = New-Object -TypeName PSObject
        if ($_._id) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Id" -Value $_._id}
        if ($_.activity) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Activity" -Value $_.Activity}
        if ($_.src_region) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SourceRegion" -Value $_.src_region}
        if ($_._insertion_epoch_timestamp) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "EpochTimeStamp" -Value $_._insertion_epoch_timestamp}
        if ($_.access_method) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AccessMethod" -Value $_.access_method}
        if ($_.alert) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Alert" -Value $_.alert}
        if ($_.app) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AppName" -Value $_.app}
        if ($_.app_session_id) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AppSessionId" -Value $_.app_session_id}
        if ($_.appcategory) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AppCategory" -Value $_.appcategory}
        if ($_.browser) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Browser" -Value $_.browser}
        if ($_.browser_version) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "BrowserVersion" -Value $_.browser_version}
        if ($_.category) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "BrowserSessionId" -Value $_.browser_session_id}
        if ($_.category) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Category" -Value $_.category}
        if ($_.ccl) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Ccl" -Value $_.ccl}                      
        if ($_.cci) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Cci" -Value $_.cci}
        if ($_.count) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Count" -Value $_.count}
        if ($_.device_classification) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DeviceClassification" -Value $_.device_classification}
        if ($_.device) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Dvc" -Value $_.device}
        if ($_.dst_country) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstCountry" -Value $_.dst_country}
        if ($_.dstip) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstIpAddr" -Value $_.dstip}
        if ($_.dst_longitude) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstGeoLongitude" -Value $_.dst_longitude}     
        if ($_.dst_latitude) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstGeoLatitude" -Value $_.dst_latitude                
        if ($_.dst_location) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstGeoLocation" -Value $_.dst_location}         
        if ($_.dst_zipcode) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstGeoZipCode" -Value $_.dst_zipcode} 
        if ($_.dst_region) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DstGeoRegion" -Value $_.dst_region}
        if ($_.from_user) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "FromUser" -Value $_.from_user}
        if ($_.hostname) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DvcHostname" -Value $_.hostname}
        if ($_.managementID) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "ManagedId" -Value $_.managementID}
        if ($_.managed_app) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "ManagedApp" -Value $_.managed_app}
        if ($_.os) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcOs" -Value $_.os}
        if ($_.os_version) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "OsVersion" -Value $_.os_version}
        if ($_.object_type) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "ObjectType" -Value $_.object_type}
        if ($_.organization_unit) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Org" -Value $_.organization_unit} 
        if ($_.page_id) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "PageId" -Value $_.page_id}
        if ($_.page) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Page" -Value $_.page}
        if ($_.page_site) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "PageSite" -Value $_.page_site}
        if ($_.referer) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Referer" -Value $_.referer}                     
        if ($_.site) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Site" -Value $_.site}                            
        if ($_.src_time) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcTime" -Value $_.src_time}                                                           
        if ($_.src_zipcode) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcGeoZipCode" -Value $_.src_zipcode}                                                                     
        if ($_.src_region) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcGeoRegion" -Value $_.src_region}                                              
        if ($_.src_location) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcGeoLocation" -Value $_.src_location}            
        if ($_.src_country) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcCountry" -Value $_.src_country}
        if ($_.srcip) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcIpAddr" -Value $_.srcip}
        if ($_.sv) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SV" -Value $_.sv} 
        if ($_.src_timezone) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcGeoTimeZone" -Value $_.src_timezone}
        if ($_.src_longitude) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcLongitude" -Value $_.src_longitude}       
        if ($_.src_latitude) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcLatitude" -Value $_.src_latitude}
        if ($_.telemetry_app) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "TelemetryApp" -Value $_.telemetry_app}
        if ($_.type) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Type" -Value $_.type}                    
        if ($_.timestamp) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "TimeStamp" -Value $_.timestamp}               
        if ($_.traffic_type) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "TrafficType" -Value $_.traffic_type}            
        if ($_.transaction_id) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "TransactionId" -Value $_.transaction_id}                
        if ($_.user) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcUserName" -Value $_.user}                            
        if ($_.userip) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcUserIp" -Value $_.userip}                             
        if ($_._instance_id) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "InstanceId" -Value $_._instance_id}                                     
        if ($_.url) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Url" -Value $_.url}                                           
        if ($_.nsdeviceuid) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DeviceId" -Value $_.nsdeviceuid}                             
        if ($_.userkey) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SrcUserKey" -Value $_.userkey}                 
        if ($_.ur_normalized) {Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Normalized" -Value $_.ur_normalized}
        if ($_.severity) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Severity" -Value $_.severity}
        if ($_.iaas_remediated) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "IaasRemediated" -Value $_.iaas_remediated}
        if ($_.asset_object_id) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AssetObjectId" -Value $_.asset_object_id}
        if ($_.account_name) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AccountName" -Value $_.account_name}
        if ($_.account_id) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AccountId" -Value $_.account_id}
        if ($_.resource_category) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "ResourceCategory" -Value $_.resource_category}
        if ($_.sa_rule_severity) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SaRuleSeverity" -Value $_.sa_rule_severity}
        if ($_.sa_rule_id) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SaRuleId" -Value $_.sa_rule_id}
        if ($_.sa_rule_name) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SaRuleName" -Value $_.sa_rule_name}
        if ($_.region_id) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "RegionId" -Value $_.region_id}
        if ($_.region_name) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "RegionName" -Value $_.region_name}
        if ($_.action) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Action" -Value $_.action}
        if ($_.alert_type) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AlertType" -Value $_.alert_type}
        if ($_.alert_name) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "AlertName" -Value $_.alert_name}
        if ($_.acked) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Acked" -Value $_.acked}
        if ($_.src_geoip_src) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SourceGeoIpSrc" -Value $_.src_geoip_src}
        if ($_.dst_geoip_src) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "DestGeoIpSrc" -Value $_.dst_geoip_src}
        if ($_.os) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "OperatingSystem" -Value $_.os}
        if ($_.org) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Organization" -Value $_.org}
        if ($_.to_user) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "ToUser" -Value $_.alert
        if ($_.object) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Object" -Value $_.object}
        if ($_.policy) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "Policy" -Value $_.policy}
        if ($_.policy_id) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "PolicyId" -Value $_.policy_id}
        $categories = @()
        foreach($category in $_.other_categories){   

            $customobject = New-Object -TypeName PSObject
            Add-Member -InputObject $customobject -MemberType NoteProperty -Name "Category" -Value $category
            $categories += $customobject.Category
        }
        if($categories){Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "OtherCategories" -Value $categories}
        $ruleremediation = Html-ToText($_.sa_rule_remediation)
        if ($_.sa_rule_remediation) { Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "SaRuleRemedaiton" -Value $ruleremediation }
        $assets = @()
        foreach($asset in $_.iaas_asset_tags){   
            $customobject = New-Object -TypeName PSObject
            Add-Member -InputObject $customobject -MemberType NoteProperty -Name "Name" -Value $asset.name
            Add-Member -InputObject $customobject -MemberType NoteProperty -Name "Value" -Value $asset.value
            Write-Output "$type"
            $assets += $customobject        
        }
        if ($assets){ Add-Member -InputObject $eventobjs -MemberType NoteProperty -Name "IaasAssetTags" -Value $assets }    
       
        }
     }
      Write-Output $eventobjs
        $jsonPayload = $eventobjs | ConvertTo-Json
        $mbyte = ([System.Text.Encoding]::UTF8.GetBytes($jsonPayload)).Count/1024/1024  
         # if the detections object has payload Less than 30MB will POST the payload.
            if (($mbytes -le 30)){                                
                $responseCode = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonPayload)) -logType $LogType
                if ($responseCode -ne 200){
                    Write-Host "ERROR: Log Analytics POST, Status Code: $responseCode, Not able to Log."
                }else {
                    $LOGGED += $mbyte
                    Write-Host "SUCCESS: Log Analytics POST, Status Code: $responseCode.Loaded succefully.Logged"
                }
               
            }
            else {
                   Write-Host "NOT SUCCESS: Log Analytics POST failed as the PayLoad is more than 30Mb: $mbyte"

            } 
            
          } 
   }
}
 

# Create the function to create the authorization signature
function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date;
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource;
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash);
    $keyBytes = [Convert]::FromBase64String($sharedKey);
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $sha256.Key = $keyBytes;
    $calculatedHash = $sha256.ComputeHash($bytesToHash);
    $encodedHash = [Convert]::ToBase64String($calculatedHash);
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash;
    return $authorization;
}

# Create the function to create and post the request
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $TimeStampField = "DateValue"
    $method = "POST";
    $contentType = "application/json";
    $resource = "/api/logs";
    $rfc1123date = [DateTime]::UtcNow.ToString("r");
    $contentLength = $body.Length;
    $signature = Build-Signature -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource;
    $uri = "https://$($customerId).ods.opinsights.azure.com$($resource)?api-version=2016-04-01";
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    };
    $response = Invoke-WebRequest -Body $body -Uri $uri -Method $method -ContentType $contentType -Headers $headers -UseBasicParsing
    return $response.StatusCode
}

# Execute the Function to Pull Netskope events data and Post to the Log Analytics Workspace

netskope






# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"
