<#

    https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-overview#overview

    Follow these steps to set up Azure Files for AD DS authentication:

    Enable AD DS authentication on your storage account

        function JoinAzStorageAccount

    Assign share-level permissions to the Microsoft Entra identity (a user, group, or service principal) that is in sync with the target AD identity

        function SetShareLvlPermissions

    Configure Windows ACLs over SMB for directories and files

    Mount an Azure file share to a VM joined to your AD DS

        function MountDrive

    Update the password of your storage account identity in AD DS

#>
param (
    [switch]$Mount,
    [switch]$Debug
)

$CsvFilePath = "creds.csv"

function ImportParams {
    try {
        $params = Import-Csv $CsvFilePath
    } catch {
        Write-Host "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-enable?WT.mc_id=Portal-Microsoft_Azure_FileStorage#option-one-recommended-use-azfileshybrid-powershell-module"
        Write-Host "Please review this article on enabling Active Directory Domain Services authentication for Azure file shares"
        $params = New-Object PSObject -Property @{
            SubscriptionId = Read-Host -Prompt "Subscription ID"
            ResourceGroupName = Read-Host -Prompt "Resource Group name"
            StorageAccountName = Read-Host -Prompt "Storage Account name"
            SamAccountName = Read-Host -Prompt "SAM account name"
            DomainAccountType = Read-Host -Prompt "Domain account type"
            OuDistinguishedName = Read-Host -Prompt "OU Distinguished Name"
            FileShare = Read-Host -Prompt "Azure Files fileshare"
        }
        Export-Csv -Path $CsvFilePath -NoTypeInformation
    }
    return $params
}

Write-Host "Your input:"
$params | Format-List

$Params = ImportParams
$SubscriptionId = $Params.SubscriptionId
$ResourceGroupName = $Params.ResourceGroupName
$StorageAccountName = $Params.StorageAccountName
$SamAccountName = $Params.SamAccountName
$DomainAccountType = $Params.DomainAccountType
$OuDistinguishedName = $Params.OuDistinguishedName
$FileShare = $Params.FileShare

function SetShareLvlPermissions {

    # When you set a default share-level permission, all authenticated users and groups will have the same permission. 
    # https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-assign-share-level-permissions?tabs=azure-powershell#share-level-permissions-for-all-authenticated-identities

    $defaultPermission = "StorageFileDataSmbShareElevatedContributor" # Set the default permission of your choice
    $account = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName -DefaultSharePermission $defaultPermission
    $account.AzureFilesIdentityBasedAuth
}

function AddPrivateLink {

    # When setting up Azure Files as a file server accessed over SMB on an internal domain, public access should be disabled.
    # Because of this, some stipulations arise:

    # Azure Private Link establishes a connection between an Azure Storage Account and a virtual network
    # that can be accessible from an on-prem domain. It gives Azure Storage a vNIC and a private IP address.

    # This vNIC will connect directly to a Service Endpoint (an endpoint for multiple services located on the vNET).
    # By only allowing traffic from the vNET through firewall configuration, the security posture is improved.

}

function Debug {

    # Feature rich debug

    $trySubscription = Select-AzSubscription -SubscriptionId $SubscriptionId
    if ( $trySubscription ) {
        Debug-AzStorageAccountAuth -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName -Verbose
        Test-AzStorageAccountADObjectPasswordIsKerbKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Verbose
    }
}
function JoinAzStorageAccount {

    # Enable Active Directory Domain Services authentication for Azure file shares

    Join-AzStorageAccount `
        -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccountName `
        -SamAccountName $SamAccountName `
        -DomainAccountType $DomainAccountType `
        -OrganizationalUnitDistinguishedName $OuDistinguishedName
}

function TestStorageAccount {
    Test-AzStorageAccountADObjectPasswordIsKerbKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Verbose
}

function AddRole {

    $userUpn = Read-Host -Prompt "User UPN for role add"

    # We are using "default share-level permission" but this function is available for testing

    # Get the name of the custom role
    # Use one of the built-in roles: Storage File Data SMB Share Reader, Storage File Data SMB Share Contributor, Storage File Data SMB Share Elevated Contributor
    $fileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor" 

    # Constrain the scope to the target file share
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$FileShare"

    # Assign the custom role to the target identity with the specified scope.
    New-AzRoleAssignment -SignInName $userUpn -RoleDefinitionName $fileShareContributorRole.Name -Scope $scope
}

function MountDrive {

    # Mount Azure Files to SMB

    $publicEndpoint = $StorageAccountName + ".file.core.windows.net"

    Write-Host $publicEndpoint

    try {
        $connectTestResult = Test-NetConnection -ComputerName $publicEndpoint -Port 445
        if ($connectTestResult.TcpTestSucceeded) {
            New-PSDrive -Name R -PSProvider FileSystem -Root "\\$publicEndpoint\$FileShare" -Persist
    }
    } catch {
        return $_.Exception
    }
}

if ($Mount) { MountDrive }
if ($Debug) { Debug }