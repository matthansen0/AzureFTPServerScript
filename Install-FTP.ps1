##Format data disk 
diskperf -y
get-disk | where partitionstyle -EQ 'raw' | `
Initialize-Disk -PartitionStyle MBR -PassThru | `
New-Partition -DriveLetter "F" -UseMaximumSize | `
Format-Volume -FileSystem NTFS -NewFileSystemLabel "FTPData" -Confirm:$false

##Make FTP Root Directory
mkdir F:\FTPRoot

#Install Needed Roles and Features
Add-WindowsFeature Web-Server -IncludeAllSubFeature -IncludeManagementTools
Add-WindowsFeature Web-FTP-Server -IncludeAllSubFeature

Import-Module WebAdministration


#Create Self-Signed Certificate 
$newCert = New-SelfSignedCertificate -FriendlyName "SelfSignedCert" -dnsname "hostname" -KeyLength 2048 -CertStoreLocation cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(20)

# Create the FTP site
$FTPSiteName = 'Default FTP Site'
$FTPRootDir = 'F:\FTPRoot'
$FTPPort = 21
New-WebFtpSite -Name $FTPSiteName -Port $FTPPort -PhysicalPath $FTPRootDir

# Create the local Windows group
$FTPUserGroupName = "FTP Users"
$ADSI = [ADSI]"WinNT://$env:ComputerName"
$FTPUserGroup = $ADSI.Create("Group", "$FTPUserGroupName")
$FTPUserGroup.SetInfo()
$FTPUserGroup.Description = "Members of this group can connect through FTP"
$FTPUserGroup.SetInfo()

# Create an FTP user
$FTPUserName = "FTPUser"
$FTPPassword = 'P@ssw0rd'
$CreateUserFTPUser = $ADSI.Create("User", "$FTPUserName")
$CreateUserFTPUser.SetInfo()
$CreateUserFTPUser.SetPassword("$FTPPassword")
$CreateUserFTPUser.SetInfo()

# Add an FTP user to the group FTP Users
$UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserName")
$SID = $UserAccount.Translate([System.Security.Principal.SecurityIdentifier])
$Group = [ADSI]"WinNT://$env:ComputerName/$FTPUserGroupName,Group"
$User = [ADSI]"WinNT://$SID"
$Group.Add($User.Path)


# Enable basic authentication on the FTP site

$FTPSitePath = "IIS:\Sites\$FTPSiteName"
$BasicAuth = 'ftpServer.security.authentication.basicAuthentication.enabled'
Set-ItemProperty -Path $FTPSitePath -Name $BasicAuth -Value $True

# Add an authorization read rule for FTP Users.
$Param = @{
    Filter   = "/system.ftpServer/security/authorization"
    Value    = @{
        accessType  = "Allow"
        roles       = "$FTPUserGroupName"
        permissions = 'Read, Write'
    }
    PSPath   = 'IIS:\'
    Location = $FTPSiteName
}
Add-WebConfiguration @param

# Change from require to allow SSL 
$SSLPolicy = @(
    'ftpServer.security.ssl.controlChannelPolicy',
    'ftpServer.security.ssl.dataChannelPolicy',
    'ftpServer.security.ssl.serverCertHash'
)
Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0] -Value 1
Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[1] -Value 1
Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[2] -Value $newCert.GetCertHashString()

#Set NTFS Permissions on FTP Root 
$UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserGroupName")
$AccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($UserAccount,
    'ReadAndExecute',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow'
)
$ACL = Get-Acl -Path $FTPRootDir
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $FTPRootDir

##Set FTP Data Channel Port Range
Set-WebConfiguration "/system.ftpServer/firewallSupport" -PSPath "IIS:\" -Value @{lowDataChannelPort="1025";highDataChannelPort="1026";} 

Restart-WebItem "IIS:\Sites\$FTPSiteName" -Verbose