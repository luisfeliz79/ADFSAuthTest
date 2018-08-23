###############################################################
#
#This Sample Code is provided for the purpose of illustration only
#and is not intended to be used in a production environment.  THIS
#SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED AS IS
#WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
#INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
#MERCHANTABILITY ANDOR FITNESS FOR A PARTICULAR PURPOSE.  We
#grant You a nonexclusive, royalty-free right to use and modify
#the Sample Code and to reproduce and distribute the object code
#form of the Sample Code, provided that You agree (i) to not use
#Our name, logo, or trademarks to market Your software product in
#which the Sample Code is embedded; (ii) to include a valid
#copyright notice on Your software product in which the Sample
#
#Code is embedded; and (iii) to indemnify, hold harmless, and
#defend Us and Our suppliers from and against any claims or
#lawsuits, including attorneys’ fees, that arise or result from
#the use or distribution of the Sample Code.
#Please note None of the conditions outlined in the disclaimer
#above will supersede the terms and conditions contained within
#the Premier Customer Services Description.
#
###############################################################

#Version 1.1

<#

.SYNOPSIS
AD FS command line authentication testing kit

.DESCRIPTION
A script that allows you test oAuth, SAML, WSFed authentications.

.EXAMPLE
.

Obtain token using Kerberos for AD FS Server sts.contoso.com, using RPT EntityID urn:federation:MicrosoftOnline
    ./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline" -AuthType Kerberos

Obtain token using Credentials for AD FS Server sts.contoso.com, using RPT EntityID urn:federation:MicrosoftOnline
    ./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline" -AuthType Credentials -Credentials (Get-Credential)

Obtain a token using oAuth / ADAL Library
    ./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID https://contoso.com/SPNative -AuthType oAuth -ClientID e0ffffcb-5b30-4a07-b544-c75fffff66f0

Obtain a SAMLversion 2 Token, and using TLS mode 1.2
    ./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline","urn:saml:app" -AuthType Kerberos -SAMLVersion 2 -TLSMode tls1.2

Obtain a token and on failure, notify a webhook
    ./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline","urn:saml:app" -AuthType Kerberos -NotifyURLOnFail "https://web.contoso.com/webhook"

Obtain a token and on Success, send out an email.
    ./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline","urn:saml:app" -AuthType Kerberos -NotifyEmailOnSuccess admin@contoso.com

.NOTES
Kerberos authentication requires the host name of the STS to be added to the Intranet zone - trusted sites.
For oAuth, the Azure PowerShell module is required.  use "Install-Module Azure" to install it.

.LINK
https://github.com/luisfeliz79/ADFSAuthTest

#>



param(


    #The AD FS Url
    [Parameter(mandatory=$true)][string] $ADFSUrl="",
    
    #The EntityID to attempt authentication against. CASE SENSTIVE!
    [Parameter(mandatory=$true)][Array] $EntityID=@(),
      

    [Parameter(mandatory=$true)][ValidateSet('Kerberos','Credentials','oAuth')] $AuthType="Kerberos",

    #When using Oauth, must pass a clientID
    [Parameter()] [String] $ClientID="",

    [Parameter()] $Credentials,

    #Defaults to SAML 2
    [Parameter()][ValidateSet('1','2')] $SAMLVersion = 2,


    #Defaults to TLS 1.2
    [Parameter()][ValidateSet('tls1.0','tls1.1','tls1.2')] $TLSMode="tls1.2",

    #Notify options
    [Parameter()] [String] $NotifyEmailOnFail,
    [Parameter()] [String] $NotifyEmailOnSuccess,
    [Parameter()] [String] $NotifyURLOnFail,
    [Parameter()] [String] $NotifyURLOnSuccess,

    #Configure an SMTP Server here
    $SMTPServer="",
    $SMTPfrom = "User01 <user01@example.com>"



    )




#validate ADFSURL
if ($adfsurl -notlike "*https://*") {$ADFSUrl="https://$ADFSUrl"}

#Some credential validation, first ask, and then check again just in case of cancel
if ($AuthType -eq "Credentials" -and $Credentials.count -lt 1) { $Credentials=Get-Credential -Message "Enter Credentials #$($count+1)$([char]13)$([char]10)Username should be in DOMAIN\User format"}
if ($AuthType -eq "Credentials" -and $Credentials.count -lt 1) { "No credentials specified.  Provide credentials, or use Kerberos/oAuth";break } 

if ($AuthType -eq "oAuth" -and $ClientID -eq "") { $ClientID=Read-Host -Prompt "ClientID"  }


#TLS mode
switch ($TLSMode) {
"tls1.2" {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
"tls1.1" {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11}
"tls1.0" {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls}
}


Function Send-Notification ($Type,$Address,$Subject,$Body){
                   
    Switch ($Type) { 

        Email { Send-MailMessage -From $SMTPfrom  -To $Address -Subject $subject -Body $Body -SmtpServer $smtpserver }
        URL   { $json=@{
                   'Subject'=$subject
                   'Message'=$Body
                    } | ConvertTo-Json -Compress
                
                #Invoke-WebRequest -Uri $Address -UseBasicParsing 
                Invoke-RestMethod -Uri $Address -UseBasicParsing -Body $json -Method Post -ContentType  'application/json'
                }
    }
}

                  
function Invoke-ADFSSecurityTokenRequest {
param(
    [Parameter()][ValidateSet('Kerberos','Credentials','oAuth')] $ClientCredentialType,
    [Parameter()] $ADFSBaseUri,
    [Parameter()] $AppliesTo,
    [Parameter()] $Username,
    [Parameter()] $Password,
    [Parameter()][ValidateSet('1','2')] $SAMLVersion = 2,
    [Parameter()][ValidateSet('Token','RSTR')] $OutputType = 'Token',
    [Parameter()][Switch] $IgnoreCertificateErrors,
    [Parameter()] $ClientID="",
    [Parameter()] $ServerName

)

#Load needed .NET types
Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'


#WSTrust configuration
$ADFSTrustPath = 'adfs/services/trust/2005'
$SecurityMode = 'TransportWithMessageCredential'
$ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')


switch ($ClientCredentialType) {


        'oAuth' {

        Import-Module Azure
  
        
        $resourceAppIdURI = $AppliesTo
        $authority = $ADFSBaseUri+"/adfs/oauth2/authorize"
        $validateAuthority=$false
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority,$validateAuthority
        
          
        #$AADCredential = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential" -ArgumentList $Username,$Password
        #Token = $authContext.AcquireToken($resourceAppIdURI, $ClientID,$AADCredential )
    
       try { 
        $Token = $authContext.AcquireToken($resourceAppIdURI, $ClientID,$AppliesTo,"Auto" )
                
        #https://msdn.microsoft.com/en-us/library/microsoft.identitymodel.clients.activedirectory.authenticationcontext.acquiretoken.aspx
        #AcquireToken(Resource,ClientID,RedirectURI, PromptBehavior)
        #PromptBehavior https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        
        "Tokens"
        "------"
        $Token
        
        "Token Properties"
        "----------------"
        [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($($tmpToken=($token.AccessToken -split "\.")[0]; while ($tmpToken.Length % 4) { $tmpToken += "=" };$tmpToken))) | ConvertFrom-Json

        "Login Info"
        "-----------"
        [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($($tmpToken=($token.AccessToken -split "\.")[1]; while ($tmpToken.Length % 4) { $tmpToken += "=" };$tmpToken))) | ConvertFrom-Json

        "Claims"
        "-------"
        [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($($tmpToken=($token.IdToken -split "\.")[1]; while ($tmpToken.Length % 4) { $tmpToken += "=" };$tmpToken))) | ConvertFrom-Json
  
     }

     Catch { Write-Error $_.Exception }






    }


    

    'Kerberos' {
        $MessageCredential = 'Windows'
        $ADFSTrustEndpoint = 'windowstransport'
        $Binding = new-object -typename System.ServiceModel.WShttpbinding -ArgumentList ([System.ServiceModel.BasicHttpsSecurityMode] $SecurityMode)
        $Binding.Security.Transport.ClientCredentialType = $MessageCredential
        $EP = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ('{0}/{1}/{2}' -f $ADFSBaseUri,$ADFSTrustPath,$ADFSTrustEndpoint)
        $WSTrustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $Binding, $EP
        $WSTrustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrustFeb2005
        $WSTrustChannelFactory.Credentials.Windows.ClientCredential = [System.Net.CredentialCache]::DefaultNetworkCredentials
        $WSTrustChannelFactory.Credentials.Windows.AllowedImpersonationLevel = [System.Security.Principal.TokenImpersonationLevel]::Impersonation
    }
    'Credentials' {
        $MessageCredential = 'UserName'
        $ADFSTrustEndpoint = 'usernamemixed'
        $Binding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode] $SecurityMode)
        $Binding.Security.Message.EstablishSecurityContext = $false
        $Binding.Security.Message.ClientCredentialType = $MessageCredential
        $Binding.Security.Transport.ClientCredentialType = 'None'
        $EP = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ('{0}/{1}/{2}' -f $ADFSBaseUri,$ADFSTrustPath,$ADFSTrustEndpoint)
        $WSTrustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $Binding, $EP
        $WSTrustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrustFeb2005
        $Credential = New-Object System.Net.NetworkCredential -ArgumentList $Username,$Password
        $WSTrustChannelFactory.Credentials.Windows.ClientCredential = $Credential
        $WSTrustChannelFactory.Credentials.UserName.UserName = $Credential.UserName
        $WSTrustChannelFactory.Credentials.UserName.Password = $Credential.Password
        

    }


} # end Switch


#Do this only if Auth type is Kerb or creds
if ($AuthType -eq "Kerberos" -or $AuthType -eq "Credentials") {

   try {
    $Channel = $WSTrustChannelFactory.CreateChannel()


    $TokenType = @{
        SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion'
        SAML2 = 'urn:oasis:names:tc:SAML:2.0:assertion'
    }

    $RST = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityToken -Property @{
        RequestType   = [System.IdentityModel.Protocols.WSTrust.RequestTypes]::Issue
        AppliesTo     = $AppliesTo
        KeyType       = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer
        TokenType     = if ($SAMLVersion -eq '2') {$TokenType.SAML2} else {$TokenType.SAML11}
    }
 
    #Request the Token
    $RSTR = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse

 
        $OriginalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        if ($IgnoreCertificateErrors.IsPresent) {[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {return $true}}
        $Token = $Channel.Issue($RST, [ref] $RSTR)
    }

    catch {

        Write-Error $_.Exception.message

        if ($NotifyEmailOnFail) {Send-Notification -Type Email -Address $NotifyEmailOnFail -Subject "Login failure for: $AppliesTo" -Body $_.Exception.message }
        if ($NotifyURLOnFail) {Send-Notification -Type URL -Address $NotifyURLOnFail -Subject "Login failure for: $AppliesTo" -Body $_.Exception.message}


    }


    finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $OriginalCallback
    }


    #If we got a token, lets crack it open
    if ($Token) {

        $obj=new-object PSObject -property ([ordered]@{
 
          #Select-XML allows you to address XML elements as they appear on the file
          "Identifier"  = $AppliesTo
          "Lifetime"    = $Token.ValidTo.ToLocalTime()  
          "Token"       = $Token.TokenXML
     
        }) #new-object

        #If the claims are encrypted, skip adding claims to the list.
        if (-Not $Token.TokenXML.EncryptedData -and -Not $Token.TokenXML.CipherData) {

         $obj | add-member -MemberType NoteProperty -Name "Issuer" -Value $Token.Tokenxml.Issuer
         
         $NameID=$(try{if ($Token.TokenXML.Subject.NameID.GetType().Name -eq "XmlElement") {$Token.TokenXML.Subject.NameID.'#text'} else {$Token.TokenXML.Subject.NameID}} catch {})
         if ($NameID) { $obj | add-member -MemberType NoteProperty -Name "NameID" -Value $NameID }

         $NameIDFormat=$(try{if ($SamlVersion -eq 2) {$Token.TokenXML.Subject.NameID.Format} else {$Token.TokenXML.AttributeStatement.Subject.NameIdentifier.Format}} catch {})
         if ($NameIDFormat) {$obj | add-member -MemberType NoteProperty -Name "NameIDFormat" -Value $NameIDFormat }
  

         $token.tokenXML.AttributeStatement.attribute | foreach {

            $Name=""
            $Value=""
            $Entry=$_

            Switch ($SAMLVersion) {
        
                #SAML 1.1 uses AttributeName 
                1 { $Name=$Entry.AttributeName    }
                #SAML 2.0 uses Name 
                2 { $Name=$Entry.Name             }
            }
    

            Switch ($Entry.AttributeValue.GetType().Name) {

                #Some elemetics are nested deeper in Token XML
                "XmlElement"  { $Value= $Entry.AttributeValue.'#text' }
                #But for everything else, just look at AttributeValue
                Default       { $Value=$Entry.AttributeValue          }
            }
    
            $obj | add-member -MemberType NoteProperty -Name $Name -Value $Value
        }

        } #end if not encrypted
        
        #output the object
        $obj

        
        if ($NotifyEmailOnSuccess) {Send-Notification -Type Email -Address $NotifyEmailOnSuccess -Subject "Login success for: $AppliesTo" -Body $obj}
        if ($NotifyURLOnSuccess) {Send-Notification -Type URL -Address $NotifyURLOnSuccess -Subject "Login success for: $AppliesTo" -Body $obj}


       } #end if token
}     

} #End function

$EntityID | Foreach {

Invoke-ADFSSecurityTokenRequest `
-ClientCredentialType $AuthType `
-ADFSBaseUri $ADFSUrl `
-AppliesTo $_ `
-ClientID $ClientID `
-UserName $Credentials.Username `
-Password $Credentials.Password `
-OutputType Token `
-SAMLVersion $SamlVersion `
-IgnoreCertificateErrors 

}





      