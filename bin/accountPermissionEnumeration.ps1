<#
.SYNOPSIS
Queries Active Directory Objects for their SDDL permissions and then formats the data to be human readable to be consumed in Splunk or anything for that matter :).


.DESCRIPTION
Querying Permissions of Active Directory has been a long standing issue. This script aims to reduce the complexity of auditing and rather than present a set of defined permissions back to you, allow you to review all of the permissions.


.NOTES
There is a $exclude variable that allows you to remove certain groups from being presented.  No switches are required to be parsed into this script.  Modification
You can pipe the results to a txt file for manual import into Splunk
.\accountPermissionEnumeration.ps1 > ADPermissions.txt
#>


<#


List of Common Groups that you can remove from your results by adding the 2 letter acronym to the $exclude variable.

Use the following values to help remove noise
“AO”	Account operators
“RU”	Alias to allow previous Windows 2000
“AN”	Anonymous logon
“AU”	Authenticated users
“BA”	Built-in administrators
“BG”	Built-in guests
“BO”	Backup operators
“BU”	Built-in users
“CA”	Certificate server administrators
“CG”	Creator group
“CO”	Creator owner
“DA”	Domain administrators
“DC”	Domain computers
“DD”	Domain controllers
“DG”	Domain guests
“DU”	Domain users
“EA”	Enterprise administrators
“ED”	Enterprise domain controllers
“WD”	Everyone
“PA”	Group Policy administrators
“IU”	Interactively logged-on user
“LA”	Local administrator
“LG”	Local guest
“LS”	Local service account
“SY”	Local system
“NU”	Network logon user
“NO”	Network configuration operators
“NS”	Network service account
“PO”	Printer operators
“PS”	Personal self
“PU”	Power users
“RS”	RAS servers group
“RD”	Terminal server users
“RE”	Replicator
“RC”	Restricted code
“SA”	Schema administrators
“SO”	Server operators
“SU”	Service logon user
#>


#Start Functions for Converting GUIDS http://myitpath.blogspot.com.au/2012/04/
#region Convert-ADACL 

function Convert-ADACL
{
        
    <#
        .Synopsis 
            Translates the AD Object ACL to a more readable format by converting SID and GUID values to text
            
        .Description
            Translates the AD Object ACL to a more readable format by converting SID and GUID values to tex
            
        .Parameter ACL
            ACL Object to Apply
            
        .OUTPUTS
            Object
            
    #>
        [cmdletbinding()]
        Param(
    
            [Parameter(ValueFromPipeline=$true)]
            [System.DirectoryServices.ActiveDirectoryAccessRule]$ACL
            
        )

  Begin {
   $results = @()
  }
  
  process {
   if ($_.ActiveDirectoryRights -eq "ExtendedRight") {
    $myresult = New-Object PSobject -Property @{
     ActiveDirectoryRights = $_.ActiveDirectoryRights
     InheritanceType = $_.InheritanceType
     ObjectType = Convert-GUIDToName -guid $_.objecttype -extended
     InheritedObjectType = Convert-GUIDToName -guid $_.inheritedobjecttype
     ObjectFlags = $_.ObjectFlags
     AccessControlType = $_.accesscontroltype
     IdentityReference = ConvertTo-Name -sid $_.identityReference
     IsInherited = $_.isinherited
     InheritanceFlags = $_.InheritanceFlags
     PropagationFlags = $_.PropagationFlags
    }
   } else {
          $myresult = New-Object PSobject -Property @{
     ActiveDirectoryRights = $_.ActiveDirectoryRights
     InheritanceType = $_.InheritanceType
     ObjectType = Convert-GUIDToName -guid $_.objecttype
     InheritedObjectType = Convert-GUIDToName -guid $_.inheritedobjecttype
     ObjectFlags = $_.ObjectFlags
     AccessControlType = $_.accesscontroltype
     IdentityReference = ConvertTo-Name -sid $_.identityReference
     IsInherited = $_.isinherited
     InheritanceFlags = $_.InheritanceFlags
     PropagationFlags = $_.PropagationFlags
    }  
   }
   $results += $Myresult

  }
  end {
   $results |Select-Object ActiveDirectoryRights,InheritanceType,ObjectType,InheritedObjectType,ObjectFlags,`
    AccessControlType,IdentityReference,IsInherited,InheritanceFlags,PropagationFlags
  }
}
    
#endregion 


#region ConvertTo-Name 

function ConvertTo-Name
{
    param($sid)
 Write-Verbose $sid
 try {
     $ID = New-Object System.Security.Principal.SecurityIdentifier($sid)
     $User = $ID.Translate( [System.Security.Principal.NTAccount])
     $User.Value
 } catch {
  switch($sid) {
   #Reference http://support.microsoft.com/kb/243330
   "S-1-0" { "Null Authority" }
   "S-1-0-0" { "Nobody" }
   "S-1-1" {"World Authority" }
   "S-1-1-0" { "Everyone" }
   "S-1-2" { "Local Authority" }
   "S-1-2-0" { "Local" }
   "S-1-2-1" { "Console Logon" }
   "S-1-3" { "Creator Authority" }
   "S-1-3-0" { "Creator Owner" }
   "S-1-3-1" { "Creator Group" }
   "S-1-3-4" { "Owner Rights" }
   "S-1-5-80-0" {"All Services" }
   "S-1-4" { "Non Unique Authority" }
   "S-1-5" { "NT Authority" }
   "S-1-5-1" { "Dialup" }
   "S-1-5-2" { "Network" }
   "S-1-5-3" { "Batch" }
   "S-1-5-4" { "Interactive" }
   "S-1-5-6" { "Service" }
   "S-1-5-7" { "Anonymous" }
   "S-1-5-9" { "Enterprise Domain Controllers"}
   "S-1-5-10" { "Self" }
   "S-1-5-11" { "Authenticated Users" }
   "S-1-5-12" { "Restricted Code" }
   "S-1-5-13" { "Terminal Server Users" }
   "S-1-5-14" { "Remote Interactive Logon" }
   "S-1-5-15" { "This Organization" }
   "S-1-5-17" { "This Organization" }
   "S-1-5-18" { "Local System" }
   "S-1-5-19" { "NT Authority Local Service" }
   "S-1-5-20" { "NT Authority Network Service" }
   "S-1-5-32-544" { "Administrators" }
   "S-1-5-32-545" { "Users"}
   "S-1-5-32-546" { "Guests" }
   "S-1-5-32-547" { "Power Users" }
   "S-1-5-32-548" { "Account Operators" }
   "S-1-5-32-549" { "Server Operators" }
   "S-1-5-32-550" { "Print Operators" }
   "S-1-5-32-551" { "Backup Operators" }
   "S-1-5-32-552" { "Replicators" }
   "S-1-5-32-554" { "Pre-Windows 2000 Compatibility Access"}
   "S-1-5-32-555" { "Remote Desktop Users"}
   "S-1-5-32-556" { "Network Configuration Operators"}
   "S-1-5-32-557" { "Incoming forest trust builders"}
   "S-1-5-32-558" { "Performance Monitor Users"}
   "S-1-5-32-559" { "Performance Log Users" }
   "S-1-5-32-560" { "Windows Authorization Access Group"}
   "S-1-5-32-561" { "Terminal Server License Servers"}
   "S-1-5-32-561" { "Distributed COM Users"}
   "S-1-5-32-569" { "Cryptographic Operators" }
   "S-1-5-32-573" { "Event Log Readers" }
   "S-1-5-32-574" { "Certificate Services DCOM Access" }
   "S-1-5-32-575" { "RDS Remote Access Servers" }
   "S-1-5-32-576" { "RDS Endpoint Servers" }
   "S-1-5-32-577" { "RDS Management Servers" }
   "S-1-5-32-575" { "Hyper-V Administrators" }
   "S-1-5-32-579" { "Access Control Assistance Operators" }
   "S-1-5-32-580" { "Remote Management Users" }
   
   default {$sid}
  }
 }
}
    
#endregion 

#region Convert-GUIDToName

 #helper module to convert schema GUID's to readable names

function Convert-GUIDToName
{
 param(
  [parameter(mandatory=$true)][string]$guid,
  [switch]$extended
 )
 
 $guidval = [Guid]$guid
 $bytearr = $guidval.tobytearray()
    $bytestr = ""
    
 foreach ($byte in $bytearr) {
          $str = "\" + "{0:x}" -f $byte
          $bytestr += $str
    }
 
 if ($extended) {
  #for extended rights, we can check in the configuration container
  $de = new-object directoryservices.directoryentry("LDAP://" + ([adsi]"LDAP://rootdse").psbase.properties.configurationnamingcontext)
  $ds = new-object directoryservices.directorysearcher($de)
  $ds.propertiestoload.add("displayname")|Out-Null
  $ds.filter = "(rightsguid=$guid)"
  $result = $ds.findone()
 } else {
  #Search schema for possible matches for this GUID
  $de = new-object directoryservices.directoryentry("LDAP://" + ([adsi]"LDAP://rootdse").psbase.properties.schemanamingcontext)
  $ds = new-object directoryservices.directorysearcher($de)
  $ds.filter = "(|(schemaidguid=$bytestr)(attributesecurityguid=$bytestr))"
  $ds.propertiestoload.add("ldapdisplayname")|Out-Null
  $result = $ds.findone()
 } 
 if ($result -eq $null) {
  $guid
 } else {
  if ($extended) {
   $result.properties.displayname
  } else {
   $result.properties.ldapdisplayname 
  }
 }
 
}
#endregion

#Update: 1/29/2013 
#End Functions for Converting GUIDS http://myitpath.blogspot.com.au/2012/04/

$server = "mickeyslab.local"

if($server.length -eq 0){
'Please enter a domain into the $server parameter'
exit
}

#Import Module of Active Directory
Import-Module activedirectory

#Format Date
$datetime = Get-Date -UFormat "%Y/%m/%d %H:%M:%S"

#LDAP Filter to Use - This one specifies enabled user accounts, Security groups, computers and Organisational Units
$ldapfilter = "(|(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))(|(groupType:1.2.840.113556.1.4.803:=2147483648)(objectCategory=organizationalUnit)(objectClass=computer)(objectClass=groupPolicyContainer)))" 

#Get Results from AD
try{
$list = Get-ADObject -LDAPFilter $ldapfilter -server $server
}
catch{
'Error with LDAP Lookup, please check permission or script'
break 
}

#Exclude Certain SDDL Permissions from being retrieved.  List above
$exclude = "RU|AN|BG|DG|ED|LG|NS|PS"

#Iterate through all the lists
foreach ($object in $list)
{
#Declare a variable for Distinguished Name
 $distinguishedname = $object.distinguishedname

#Create a path variable for AD and distinguished name
$path = "AD:\" + $distinguishedname

#Get the ACL for the Object
try{
$acl = Get-Acl  -path $path | select  @{N="DateTime";e={$datetime}},@{N="pspath";e={($_.pspath).split("/")[3]}},Sddl
}

catch{
"Error with getting ACLs of each distinguished object"
}
#Split the ACL by open bracket and remove the trailing bracket
$acl_split = $acl.sddl.split("(").trimend(")")

$acl_split_count = $acl_split.length

#Foreach SDDL from Array number 1 -> End of Array
$acl_split[1..$acl_split_count] | % {

#Specify the date time
"DateTime: " + $acl.datetime 
#Specify the distinguished name
"PSPath: " + $acl.pspath
#Specify the Object Class
"ObjectClass: " + $object.ObjectClass
#Specify the SDDL Header
"SDDLHeader: " + $acl_split[0] 

#Split ACL by ;
$ace_split = ($_).split(";")

#Exclude Permissions we don't care about
if($ace_split[5] -match $exclude)
{
#Do Nothing
}

#Otherwise, Select first column of Split Array.
else{
switch($ace_split[0]){
    'A'{ 'ACEType: Access Allowed'}
 'D'{ 'ACEType: Access Denied'}
 'OA'{ 'ACEType: Object Access Allowed'}
 'OD'{ 'ACEType: Object Access Denied'}
 'AU'{ 'ACEType: System Audit'}
 'AL'{ 'ACEType: System Alarm'}
 'OU'{ 'ACEType: Object System Audit'}
 'OL'{ 'ACEType: Object System Alarm'}
 }

#Initialise ACE Flags Array
$ace_flags = @()

#Select second object in array of the ACE Split 
$ace_flag_arr = $ace_split[1]

if($ace_flag_arr.length -gt 0){
$ace_flag_arr -split "([A-Z]{2})"| %{

#Use switch as a pseudo replace function
switch($_){
'CI' {$ace_flags += 'Container Inherit'}
'OI' {$ace_flags += 'Object Inherit'}
'NP' {$ace_flags += 'No Propagate'}
'IO' {$ace_flags += 'Inheritence Only'}
'ID' {$ace_flags += 'Ace Is Inherited'}
'SA' {$ace_flags += 'Successful Access Audit'}
'FA' {$ace_flags += 'Failed Access Audit'}
 }
 }
 $ace_flags_join = ($ace_flags | ?{$_}) -join ","
  "ACEFlags: " + $ace_flags_join
 }
 else {"ACEFlags: empty"}


#Initialise ACE Permissions Array
$ace_permissions = @()

#Select third object in array of the ACE Split 
$ace_perm_arr = $ace_split[2]

#Use switch as a pseudo replace function
if($ace_perm_arr.length -gt 0){
$ace_perm_arr -split "([A-Z]{2})"| %{
switch($_){
'GA'	{$ace_permissions +='Generic All'}
'GR'	{$ace_permissions +='Generic Read'}
'GW'	{$ace_permissions +='Generic Write'}
'GX'	{$ace_permissions +='Generic Execute'}
'RC'	{$ace_permissions +='Read Permissions'}
'SD'	{$ace_permissions +='Delete'}
'WD'	{$ace_permissions +='Modify Permissions'}
'WO'	{$ace_permissions +='Modify Owner'}
'RP'	{$ace_permissions +='Read All Properties'}
'WP'	{$ace_permissions +='Write All Properties'}
'CC'	{$ace_permissions +='Create All Child Objects'}
'DC'	{$ace_permissions +='Delete All Child Objects'}
'LC'	{$ace_permissions +='List Contents'}
'SW'	{$ace_permissions +='All Validated Writes'}
'LO'	{$ace_permissions +='List Object'}
'DT'	{$ace_permissions +='Delete Subtree'}
'CR'	{$ace_permissions +='All Extended Rights'}
'FA'	{$ace_permissions +='File All Access'}
'FR'	{$ace_permissions +='File Generic Read'}
'FW'	{$ace_permissions +='File Generic Write'}
'FX'	{$ace_permissions +='File Generic Execute'}
'KA'	{$ace_permissions +='Key All Access'}
'KR'	{$ace_permissions +='Key Read'}
'KW'	{$ace_permissions +='Key Write'}
'KX'	{$ace_permissions +='Key Execute'}
 }
 }

 $ace_permissions_join = ($ace_permissions | ?{$_}) -join ","
  "ACEPermissions: " + $ace_permissions_join
 }
 else {"ACEPermissions: empty"}
 

#Select fourth object in array of the ACE Split 
$ace_obj_type = $ace_split[3]

if($ace_obj_type.length -gt 0){
	"ACEObjectType: " +  (Convert-GUIDToName -guid $ace_obj_type)
	"ACEObjectTypeGuid: " +  $ace_obj_type
 }
 else {"ACEObjectType: empty"}

#Select fifth object in array of the ACE Split 
$ace_inobj_type = $ace_split[4]

if($ace_inhobj_type.length -gt 0){
	"ACEInheritedObjectTypeGuid: " +  $ace_inhobj_type
	"ACEInheritedObjectType: " + (Convert-GUIDToName -guid $ace_inhobj_type)
 }
 else {"ACEInheritedObjectType: empty"}

#Use switch as a pseudo replace function
if($ace_split[5].length -gt 0){
switch($ace_split[5]){
'AO'	{'ACETrustee: Account operators'}
'RU'	{'ACETrustee: Alias to allow previous Windows 2000'}
'AN'	{'ACETrustee: Anonymous logon'}
'AU'	{'ACETrustee: Authenticated users'}
'BA'	{'ACETrustee: Built-in administrators'}
'BG'	{'ACETrustee: Built-in guests'}
'BO'	{'ACETrustee: Backup operators'}
'BU'	{'ACETrustee: Built-in users'}
'CA'	{'ACETrustee: Certificate server administrators'}
'CG'	{'ACETrustee: Creator group'}
'CO'	{'ACETrustee: Creator owner'}
'DA'	{'ACETrustee: Domain administrators'}
'DC'	{'ACETrustee: Domain computers'}
'DD'	{'ACETrustee: Domain controllers'}
'DG'	{'ACETrustee: Domain guests'}
'DU'	{'ACETrustee: Domain users'}
'EA'	{'ACETrustee: Enterprise administrators'}
'ED'	{'ACETrustee: Enterprise domain controllers'}
'WD'	{'ACETrustee: Everyone'}
'PA'	{'ACETrustee: Group Policy administrators'}
'IU'	{'ACETrustee: Interactively logged-on user'}
'LA'	{'ACETrustee: Local administrator'}
'LG'	{'ACETrustee: Local guest'}
'LS'	{'ACETrustee: Local service account'}
'SY'	{'ACETrustee: Local system'}
'NU'	{'ACETrustee: Network logon user'}
'NO'	{'ACETrustee: Network configuration operators'}
'NS'	{'ACETrustee: Network service account'}
'PO'	{'ACETrustee: Printer operators'}
'PS'	{'ACETrustee: Personal self'}
'PU'	{'ACETrustee: Power users'}
'RS'	{'ACETrustee: RAS servers group'}
'RD'	{'ACETrustee: Terminal server users'}
'RE'	{'ACETrustee: Replicator'}
'RC'	{'ACETrustee: Restricted code'}
'SA'	{'ACETrustee: Schema administrators'}
'SO'	{'ACETrustee: Server operators'}
'SU'	{'ACETrustee: Service logon user'}
}
}
else{'ACETrustee: empty'}
}
  }}

