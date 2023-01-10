# oauthRefreshToken
For use with [aerc](https://git.sr.ht/~rjarry/aerc).

Fetches refresh token for office365 email. no additional hassle.

## Usage

Just run the script, and input your password. In the end, it will spit out a refresh token, which you can save in a file.

## Aerc

As mentioned before, get your refresh token, and save it in a file. Adapt your configuration like so (only change the `change these`):

```conf
[exchange]
outgoing-cred-cmd = cat path/to/refresh/token/or/use/password/manager
# change these: --------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
source-cred-cmd   = cat path/to/refresh/token/or/use/password/manager
# change these: --------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
source            = imaps+xoauth2://<username>%40<hostname>@outlook.office365.com:993?token_endpoint=https://login.microsoftonline.com/common/oauth2/v2.0/token&client_id=08162f7c-0fd2-4200-a84a-f25a4db0b584&client_secret=TxRBilcHdC6WGBee]fs?QR:SJ8nI[g82&scope=offline_access https://outlook.office.com/IMAP.AccessAsUser.All
# change these: --------------------^^^^^^^^^^---^^^^^^^^^^
outgoing          = smtp+xoauth2://<username>%40<hostname>@smtp.office365.com:587?token_endpoint=https://login.microsoftonline.com/common/oauth2/v2.0/token&client_id=08162f7c-0fd2-4200-a84a-f25a4db0b584&client_secret=TxRBilcHdC6WGBee]fs?QR:SJ8nI[g82&scope=offline_access https://outlook.office.com/IMAP.AccessAsUser.All
# change these: -------------------^^^^^^^^^^---^^^^^^^^^^
smtp-starttls     = yes
default           = INBOX
from              = My Name <username@hostname>
# change these: ----^^^^^^^-^^^^^^^^^^^^^^^^^^^
copy-to           = Sent
```
