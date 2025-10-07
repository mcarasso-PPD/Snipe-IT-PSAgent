# Define the necessary variables
  $SnipeItApiUrl = "https://ppd-prod-inv01.psnet.phila.local/api/v1"
    $SnipeItApiToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNTViOGQ5ZTk0NWEzZTA0NDlmM2Y3MmFhN2ZlZDI3NDk5ZjE3ZThjMzZmMTA5ZmM2OTExMjgxYThiMzFlN2ExM2YzNzJjNWIzYjQ0YTk0ZDMiLCJpYXQiOjE3NDYxOTYzNDYuOTcwODY5LCJuYmYiOjE3NDYxOTYzNDYuOTcwODcyLCJleHAiOjIyMTk1ODE5NDYuOTY2Nzk1LCJzdWIiOiI5NjIyIiwic2NvcGVzIjpbXX0.NSiAaVJnrY0O-jR7e2arfHB5FN_Gx4w71MxV26IPpApZrWeqbt2uOYFuBaiQuMQqJF_xw1LAmfyUMRug2dRWOQHwms8_GS9LuMqaVipeWUmp19m2d6XyGvaX828wzcfG1z9Eb0IMNT1e74TpiHn8Z0aYIjP4v3Gdq0WEt1Nenf4PBpx44lV9D_NIGm0PCQwr-ogvuS8QV9OMtxy3VkKnqG_yVml_Hql5GbijDHie4YxggQV_MDEuh98dnOC0-9AE89FXgMKb2GC1oKutidbfnhBBulGReumTQyFeobe1x_6w0Q-VnXfpGxSO9_8TueIbpS-pzFVKrVNpS8opiEyXYWp9p08qJO8L2XHBTIso85pkyQVLlkKF_8pjVLQZxesz_2rkUxrMVmad3Eblcn8dXAD_w6aFmBZF-C1kyCn1Gx0y4w0CQj-z4qyKlpqdpBSRUXxHPlpBm8oaScRciA_44P0abWO1j5YiNebycPLKwTOv_BW46gn_GYNcyh_ehTFszUJqM8eOkD2mMJ4HSV9au3NIgfIgPNIqj9V6MRBgfqDByCyuS7cA-TfvrZRV7DPwNDzMencJfwRtQoJ1IabRSCzKwYfUb_HPvXQ6LlfOPO84irj0vtEEsWYdAcLNdZy4WD2QorxSbGOyEbIJRkIv22Jp1O3NxiwFYsP0NV_0DPA"


# Static fields for asset creation
$status_id = 2  # Change this to the appropriate status ID for your assets
$fieldset_id = 2  # Change this to the appropriate fieldset ID for your models (Custom Fields)

# Function to load the necessary assembly for System.Web.HttpUtility
function Load-HttpUtilityAssembly {
    Add-Type -AssemblyName "System.Web"
}

# Function to check if Hyper-V is installed and list VMs
function Get-HyperVVMs {
    if (Get-Module -ListAvailable -Name "Hyper-V") {
        try {
            $vms = Get-VM | Select-Object -ExpandProperty Name
            if ($vms) {
                return $vms -join ", "
            } else {
                return ""
            }
        } catch {
            return ""
        }
    } else {
        return ""
    }
}

# Function to determine if the computer is a laptop or desktop
function Get-ComputerType {
    $battery = Get-WmiObject -Class Win32_Battery

    if ($battery) {
        return "Laptop"
    } else {
        return "Desktop"
    }
}

# Function to get the category ID based on computer type
function Get-CategoryId {
    $computerType = Get-ComputerType

    switch ($computerType) {
        "Laptop" { return 2 }
        "Desktop" { return 3 }
        default { return 3 }
    }
}

# Function to get the computer model number (e.g., "7440", "T14", "840 G9")
function Get-ComputerModelNumber {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    
    if ($manufacturer -match "Lenovo") {
        $fullModel = (Get-WmiObject -Class Win32_BIOS).Description
    } else {
        $fullModel = (Get-WmiObject -Class Win32_ComputerSystem).Model
    }
    
    # Get everything after the first word
    $parts = $fullModel -split '\s+', 2
    if ($parts.Count -gt 1) {
        return $parts[1].Trim()
    } else {
        return ""
    }
}

# Keep the original function for backward compatibility if needed
function Get-ComputerModel {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    
    if ($manufacturer -match "Lenovo") {
        $model = (Get-WmiObject -Class Win32_BIOS).Description
    } else {
        $model = (Get-WmiObject -Class Win32_ComputerSystem).Model
    }
    
    return $model
}


# # Function to get the computer model
# function Get-ComputerModel {
#     $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    
#     if ($manufacturer -match "Lenovo") {
#         $model = (Get-WmiObject -Class Win32_BIOS).Description
#     } else {
#         $model = (Get-WmiObject -Class Win32_ComputerSystem).Model
#     }
    
#     # Trim whitespace and return as string
#     return $model.ToString().Trim()
# }

# Function to get the computer serial number
function Get-ComputerSerialNumber {
    $serialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    return $serialNumber
}

# Function to get all MAC addresses of the computer
function Get-MacAddresses {
    $macAddresses = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null } | Select-Object -ExpandProperty MACAddress
    return $macAddresses -join ", "
}

# Function to get the RAM amount in GB
function Get-RAMAmount {
    $ramAmount = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    return $ramAmount
}

# Function to get the CPU information
function Get-CPUInfo {
    $cpuInfo = (Get-WmiObject -Class Win32_Processor | Select-Object -First 1).Name
    return $cpuInfo
}

# Function to get the currently logged-on user
function Get-CurrentUser {
    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
    return $currentUser
}

# Function to get the OS information
function Get-OSInfo {
    $osInfo = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    
    # Remove any non-alphanumeric characters and spaces
    $osInfo = ($osInfo -replace '[^\w\s]', '').Trim()
    
    # Replace non-breaking spaces (U+00A0) with a normal space (U+0020)
    $osInfo = $osInfo -replace '\u00A0', ' '

    # Trim leading and trailing spaces
    $osInfo = $osInfo.Trim()
    
    return $OsInfo
}

# Function to get the Windows version
function Get-WindowsVersion {
    $windowsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
    return $windowsVersion
}

# Function to get the build number
function Get-BuildNumber {
    $buildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    return $buildNumber
}

# Function to get the kernel version
function Get-KernelVersion {
    $kernelVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
    return $kernelVersion
}

# Function to get the current active IP address
function Get-ActiveIPAddress {
    # Get all IP-enabled network adapters and extract the IPv4 address, excluding VMware adapters
    $ipAddress = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
        Where-Object { 
            $_.IPEnabled -eq $true -and 
            $_.Description -notlike "VMware*" -and 
            $_.ServiceName -notlike "VMnet*"
        } |
        ForEach-Object { $_.IPAddress -match '\d{1,3}(\.\d{1,3}){3}' } |
        Select-Object -First 1
    
    return $ipAddress
}

# Function to get storage type (SSD or HDD) and capacity
function Get-StorageInfo {
    $physicalDisks = Get-PhysicalDisk
    $storageInfo = @()
    foreach ($disk in $physicalDisks) {
        $type = if ($disk.MediaType -eq 'Unspecified' -or $disk.MediaType -eq $null) { 
            'Unknown' 
        } else { 
            $disk.MediaType 
        }
        $size = [math]::Round($disk.Size / 1GB, 2)
        $storageInfo += [PSCustomObject]@{
            Type = $type
            Capacity = "$size GB"
        }
    }
    return $storageInfo
}

# Gather information for custom fields
function Get-CustomFields {
    $macAddresses = Get-MacAddresses
    $ramAmount = Get-RAMAmount
    $cpuInfo = Get-CPUInfo
    $currentUser = Get-CurrentUser
    $osInfo = Get-OSInfo
    $windowsVersion = Get-WindowsVersion
    $buildNumber = Get-BuildNumber
    $kernelVersion = Get-KernelVersion
    $ipAddress = Get-ActiveIPAddress
    $storageInfo = Get-StorageInfo
    $hyperVVMs = Get-HyperVVMs

    $storageType = ($storageInfo | ForEach-Object { $_.Type }) -join ", "
    $storageCapacity = ($storageInfo | ForEach-Object { $_.Capacity }) -join ", "

    $dbFields = @{
        #"_snipeit_adresse_mac_1"   = if ($macAddresses) { $macAddresses } else { "" }
        #"_snipeit_ram_5"           = if ($ramAmount) { $ramAmount } else { "" }
        "_snipeit_cpu_13"           = if ($cpuInfo) { $cpuInfo } else { "" }
        #"_snipeit_utilisateur_11"  = if ($currentUser) { $currentUser } else { "" }
        "_snipeit_os_12"           = if ($osInfo) { $osInfo } else { "" }
        "_snipeit_version_11"      = if ($windowsVersion) { $windowsVersion } else { "" }
        #"_snipeit_build_43"        = if ($buildNumber) { $buildNumber } else { "" }
        #"_snipeit_kernel_42"       = if ($kernelVersion) { $kernelVersion } else { "" }
        #"_snipeit_type_stockage_7" = if ($storageType) { $storageType } else { "" }
        #"_snipeit_capacitac_stockage_8" = if ($storageCapacity) { $storageCapacity } else { "" }
        #"_snipeit_vm_28"           = if ($hyperVVMs) { $hyperVVMs } else { "" }
        "_snipeit_ip_address_2" = if ($ipAddress) { $ipAddress } else { "" }
    }

    return $dbFields
}

# Function to search for a model in Snipe-IT
function Search-ModelInSnipeIt {
    param (
        [string]$ModelName
    )
    
    Load-HttpUtilityAssembly
    $encodedModelName = [System.Web.HttpUtility]::UrlEncode($ModelName)
    $url = "$SnipeItApiUrl/models?limit=50&offset=0&search=$encodedModelName&sort=created_at&order=asc"
    $headers = @{
        "Authorization" = "Bearer $SnipeItApiToken"
        "accept"        = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        
        if ($response.total -gt 0) {
            foreach ($model in $response.rows) {
                if ($model.name -eq $ModelName) {
                    return $model.id
                }
            }
        }
    } catch {
        Write-Output "Error during search: $_"
    }

    return $null
}

# Function to create a model in Snipe-IT
function Create-ModelInSnipeIt {
    param (
        [string]$ModelName,
        [int]$CategoryId
    )

    $url = "$SnipeItApiUrl/models"
    $headers = @{
        "Authorization" = "Bearer $SnipeItApiToken"
        "accept"        = "application/json"
        "content-type"  = "application/json"
    }

    # Start with the required fields
    $body = @{
        category_id = $CategoryId
        name        = $ModelName
    }

    # Conditionally add fieldset_id if it is set
    if ($fieldset_id -ne $null -and $fieldset_id -ne 0) {
        $body.fieldset_id = $fieldset_id
    }

    $bodyJson = $body | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $bodyJson
        return $response.payload.id
    } catch {
    Write-Output "Error during asset update: $_"
    Write-Output "Response: $($_.Exception.Response)"
    Write-Output "Body sent: $body"
}
    }


# Function to search for an asset in Snipe-IT
function Search-AssetInSnipeIt {
    param (
        [string]$SerialNumber
    )

    $encodedSerialNumber = $SerialNumber
    $url = "$SnipeItApiUrl/hardware?limit=50&offset=0&search=$encodedSerialNumber&sort=created_at&order=asc"
    $headers = @{
        "Authorization" = "Bearer $SnipeItApiToken"
        "accept"        = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        
        if ($response.total -gt 0) {
            foreach ($asset in $response.rows) {
                if ($asset.serial -eq $SerialNumber) {
                    return $asset
                }
            }
        }
    } catch {
        Write-Output "Error during asset search: $_"
    }

    return $null
}

# Function to create an asset in Snipe-IT
function Create-AssetInSnipeIt {
    param (
        [string]$ModelId,
        [string]$SerialNumber,
        [string]$AssetName,
        [hashtable]$CustomFields
    )

    $url = "$SnipeItApiUrl/hardware"
    $headers = @{
        "Authorization" = "Bearer $SnipeItApiToken"
        "accept"        = "application/json"
        "content-type"  = "application/json"
    }
    $body = @{
        model_id  = $ModelId
        serial    = $SerialNumber
        name      = $AssetName
        status_id = $status_id
    } + $CustomFields | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
        return $response.payload.id
    } catch {
        Write-Output "Error during asset creation: $_"
    }
}

# Function to update an asset in Snipe-IT
function Update-AssetInSnipeIt {
    param (
        [string]$AssetId,
        [string]$AssetName,
        [hashtable]$CustomFields
    )

    $url = "$SnipeItApiUrl/hardware/$AssetId"
    $headers = @{
        "Authorization" = "Bearer $SnipeItApiToken"
        "accept"        = "application/json"
        "content-type"  = "application/json"
    }
    
    # Build body properly
    $body = @{
        name = $AssetName
    }
    
    # Add custom fields to body
    foreach ($key in $CustomFields.Keys) {
        $body[$key] = $CustomFields[$key]
    }
    
    $bodyJson = $body | ConvertTo-Json
    
    # Debug output
    Write-Output "DEBUG: Updating Asset ID: $AssetId"
    Write-Output "DEBUG: URL: $url"
    Write-Output "DEBUG: Body: $bodyJson"

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Patch -Body $bodyJson
        Write-Output "DEBUG: Response: $($response | ConvertTo-Json -Depth 5)"
        return $response.payload.id
    } catch {
        Write-Output "Error during asset update: $_"
        Write-Output "ERROR Details: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $responseBody = $reader.ReadToEnd()
            Write-Output "ERROR Response Body: $responseBody"
        }
        return $null
    }
}

# Main script logic
$computerModel = Get-ComputerModel
$serialNumber = Get-ComputerSerialNumber

if ($serialNumber) {
    $asset = Search-AssetInSnipeIt -SerialNumber $serialNumber

    $assetName = $env:COMPUTERNAME
    $customFields = Get-CustomFields

    if ($asset) {
        $assetId = $asset.id
        $updateRequired = $false

        if ($asset.name -ne $assetName) {
            Write-Output "Asset name requires update: '$($asset.name)' -> '$assetName'"
            $updateRequired = $true
        }

        foreach ($key in $customFields.Keys) {
            foreach ($field in $asset.custom_fields.PSObject.Properties) {
                if ($field.Value.field -eq $key -and $field.Value.value -ne $customFields[$key]) {
                    Write-Output "Custom field '$key' requires update: '$($field.Value.value)' -> '$($customFields[$key])'"
                    $updateRequired = $true
                    break
                }
            }
        }

        if ($updateRequired) {
            $updatedAssetId = Update-AssetInSnipeIt -AssetId $assetId -AssetName $assetName -CustomFields $customFields
            Write-Output "Asset updated with ID: $updatedAssetId"
        } else {
            Write-Output "No update required for asset with ID: $assetId"
        }
    } else {
        $modelId = Search-ModelInSnipeIt -ModelName $computerModel

        if (-not $modelId) {
            $categoryId = Get-CategoryId
            $modelId = Create-ModelInSnipeIt -ModelName $computerModel -CategoryId $categoryId
        }

        $newAssetId = Create-AssetInSnipeIt -ModelId $modelId -SerialNumber $serialNumber -AssetName $assetName -CustomFields $customFields
        Write-Output "New Asset ID: $newAssetId"
    }
} else {
    Write-Output "No serial number found on this computer."
}
## Debug
<#Write-Output "Current asset name: $($asset.name)"
Write-Output "New asset name: $assetName"
Write-Output "Custom fields to update:"
$customFields | ConvertTo-Json | Write-Output
Write-Output "Current custom fields:"
$asset.custom_fields | ConvertTo-Json | Write-Output#>

