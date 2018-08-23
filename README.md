# ADFSAuthTest
AD FS Authentication testing kit


# Prerequisites
- The Azure PowerShell module is required.  To install it:
```sh
Install-Module Azure
```
- Kerberos authentication requires the host name of the STS to be added to the Intranet zone - trusted sites.


# Examples
Obtain token using Kerberos for AD FS Server sts.contoso.com, using RPT EntityID urn:federation:MicrosoftOnline
```sh
./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline" -AuthType Kerberos
```

Obtain token using Credentials for AD FS Server sts.contoso.com, using RPT EntityID urn:federation:MicrosoftOnline
```sh
./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline" -AuthType Credentials -Credentials (Get-Credential)
```

Obtain a token using oAuth / ADAL Library
```sh
./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID https://contoso.com/SPNative -AuthType oAuth -ClientID e0ffffcb-5b30-4a07-b544-c75fffff66f0
```

Obtain a SAMLversion 2 Token, and using TLS mode 1.2
```sh
./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline","urn:saml:app" -AuthType Kerberos -SAMLVersion 2 -TLSMode tls1.2
```

Obtain a token and on failure, notify a webhook
```sh
./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline","urn:saml:app" -AuthType Kerberos -NotifyURLOnFail "https://web.contoso.com/webhook"
```

Obtain a token and on Success, send out an email.
```sh
./ADFSAuthTest.ps1 -ADFSUrl sts.contoso.com -EntityID "urn:federation:MicrosoftOnline","urn:saml:app" -AuthType Kerberos -NotifyEmailOnSuccess admin@contoso.com
```

