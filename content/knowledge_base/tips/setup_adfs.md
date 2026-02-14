# How to set up OIDC authentication using ADFS

This guide walks you through the configuration of Microsoft ADFS as an OIDC
authentication provider for Velociraptor.

{{% notice warning "Environment" %}}
This procedure has been tested with Windows Server 2022 and ADFS 4.0
Velociraptor has been deployed using self signed certificate

ADFS OpenID Configuration can be read with https://auth.domain.local/adfs/.well-known/openid-configuration
SSL certificate on ADFS is provided by Let's Encrypt.
Velociraptor Server is on velociraptor.local
{{% /notice %}}

![setup_adfs](network_overview.png)

The high-level steps of this setup process are:

1. Deploy Velociraptor using Self Signed Certificates.
2. Create a new Application Group in ADFS.
3. Add the authenticator settings to your Velociraptor config.
4. Start Velociraptor
5. Add test users to Velociraptor.
6. Test the authentication process.


## 1. Deploy Velociraptor using Self Signed Certificates

Velociraptor quickstart > https://docs.velociraptor.app/docs/deployment/quickstart/


## 2. Create a new Application Group in ADFS
**1. Open ADFS Management**
Open Server Manager > Tool > AD FS Management
![](adfs1.png)

**2. Create a New Application Group**
Select Application Groups and create a new one
![](adfs2.png)

**3. Welcome**
Enter a name and select Server Application accessing a web API
![](adfs3.png)

**4. Server application**
Enter your Redirect URI : https://velociraptor.local:8889/auth/oidc/callback and add it
Save your client identifier, we will use it on velociraptor config file
![](adfs4.png)

**5. Configure Application Credentials**
Generate a shared secret and save it
![](adfs5.png)

**6. Configure WEB API**
Enter your application identifier and add it
![](adfs6.png)

**7. Access Control Policy**
On next window, Choose Access Control Policy and filter as needed
![](adfs7.png)

**8. Configure Application Permissions**
Select email, openid, profile
![](adfs8.png)

**9. Summary**
Validate your summary and click Next, then complete.
![](adfs9.png)

## 3. Add the authenticator settings to your Velociraptor config
In the `GUI` section of your Velociraptor config you should have the following
authenticator settings by default:

```yaml
  authenticator:
    type: Basic
```

We no longer want Basic auth and instead want SSO, so replace that with these
new settings to match our Keycloak configuration:

```yaml
    type: oidc
    oidc_issuer: https://domain.local/adfs
    oidc_name: adfs
    oauth_client_id: e49d074b-c157-40cd-a1b4-0a863bac99aa
    oauth_client_secret: scwp-348TOdnNJ7hzP3pKGXcYS4Ohu2q0JMCyDT0
    # uncommment below if you want a full debug
    # oidc_debug: true
```

The `oauth_client_secret` is the value we obtained at the end of step 5. The
`oauth_client_id` is the name we used for the OIDC Client ID in that same
section in step 4.

## 4. Start Velociraptor

The server should now start cleanly and continue running. In the log messages
you should see `GUI will use the oidc authenticator`. That means everything is
OK with the authenticator config.

{{% notice tip %}}

While configuring, testing and potentially troubleshooting problems, it's
easier if you can see Velociraptor's log messages. You can stop the server
service and then run the server manually on the command line by using the
following commands:

```bash
sudo systemctl stop velociraptor_server
sudo -u velociraptor bash
velociraptor -c /etc/velociraptor/server.config.yaml frontend -v
```

This will display the log messages in the terminal.

{{% /notice %}}


## 5. Add Users

Even if you have added groups/users through Access Control Policy in step 7, you have
to create users in Velociraptor. Users can be created using VQL in Velociraptor
notebooks but since we have now switched authentication providers we no longer
have access to the GUI. Of course we could have added the users before we
switched but let's pretend we didn't and instead do it from the command line.

We will make `bob@domain.local` a server admin and grant `fred@domain.local` the "reader"
role, which provides minimal access to Velociraptor's GUI. Note that you have to use the user
email field in Active Directory. The following two commands will create these users:

```sh
velociraptor --config server.config.yaml user add --role administrator bob@domain.local
velociraptor --config server.config.yaml user add --role reader fred@domain.local
```

NOTE: We provide the `--config` flag so that this invocation of the velociraptor
binary knows which datastore to add the new users to. This can be done while the
server service is running or not running, but either way the service will need
to be restarted to update itself with the datastore changes.

Because of our OIDC authenticator config, when adding each user we will receive
an acknowledgement message saying
`"Authentication will occur via oidc - therefore no password needs to be set."`

## 6. Test authentication process

Test the authentication process by going to `https://velociraptor.local:8889/`

You will be presented with the choice to log in with Keycloak (multiple
authentication providers are supported but we only have one configured).

![](adfs10.png)

Enter initial credentials using DOMAIN\bob or bob@domain.local


Tags: #configuration #sso #deployment
