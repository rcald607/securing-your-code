# Password Vault

A command-line password vault for Windows and Python 3.12. Credential passwords
are encrypted with Fernet. A 16-byte random salt is generated once per database
and persisted in SQLite; PBKDF2-HMAC-SHA256 derives the Fernet key from that
salt and the `VAULT_MASTER_PASSWORD` environment variable. The master password
is never written to the database or application logs. A keyed HMAC verifier
is persisted to reject an incorrect master password at startup and compared
in constant time. On an older database without a verifier, startup verifies
the candidate key by decrypting every existing credential before saving one;
an empty database initializes its verifier on first launch.

## Setup and run

From the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r password_vault\requirements-dev.txt
$securePassword = Read-Host "Choose a strong vault master password" -AsSecureString
$env:VAULT_MASTER_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
python password_vault\app.py
```

The database and log default to `password_vault\vault.db` and
`password_vault\vault.log` regardless of the current directory. Set
`VAULT_DB_PATH` to select another database location, for example:

```powershell
$env:VAULT_DB_PATH = "$PWD\password_vault\vault.db"
python password_vault\app.py
```

Keep the master password safe. Losing it makes encrypted credentials
unrecoverable; changing it requires decrypting and re-encrypting each entry.
The first launch initializes a new database. Back up the database securely
while the master password is stored separately.

The list and CSV report show service, username, and creation time, never
password values. The explicit retrieve menu action displays the requested
password. Activity logs record actions and service names, but never credential
passwords.

## Checks

Run the same checks as CI from the repository root:

```powershell
Set-Location password_vault
python -m pylint .
python -m bandit -r .
python -m pytest -q
```

Each command exits unsuccessfully if it finds an issue; Pylint prints its score
at the end. The workflow is the repository-root
`.github/workflows/python-ci.yml`. After pushing a normal, non-vulnerable
change or opening a pull request, use the repository's **Actions** tab, open
**Password Vault Python CI**, and capture its green completed run for the CI
screenshot. No GitHub run or screenshot is included in this repository.

## Screenshot guide

Start the app in a PowerShell terminal with a test-only master password and a
temporary database path. Capture the terminal for each item, using fake
credentials only:

```powershell
$env:VAULT_DB_PATH = "$env:TEMP\password-vault-demo.db"
python password_vault\app.py
```

1. Select no menu item yet to show the main menu.
2. Select **1** and enter a test service, username, and password (password
   input is hidden); capture the confirmation.
3. Select **2** to capture the stored service list.
4. Select **3** and enter the service name to capture retrieval.
5. Select **4**, enter the service name, and confirm deletion.
6. Select **5** and enter a length of at least 12 to capture password
   generation.
7. Select **6** and enter a sample password to capture strength checking.
8. Select **7** and a report filename to capture report export.
9. Capture the terminal after `python -m pytest -q` reports all tests passing.
10. Capture the terminal after `python -m pylint .` reports `10.00/10`.
11. Capture the terminal after `python -m bandit -r .` reports no issues.
12. Capture the successful workflow run in GitHub Actions as described above.

The repository does not contain screenshots; capture them locally after
running the commands so the images reflect actual output.

## Safe scanner-failure demonstrations

Do not add intentionally vulnerable samples to tracked source or push them.
To demonstrate scanner behavior, create a temporary Python file outside the
repository, run the scanner against only that file, then remove the file:

```powershell
$sample = Join-Path $env:TEMP "vault-bandit-demo.py"
Set-Content -Path $sample -Value 'password = "Admin123"'
python -m bandit $sample
Remove-Item -LiteralPath $sample
```

For Pylint, use a separate temporary file, run the scanner, then remove it:

```powershell
$sample = Join-Path $env:TEMP "vault-pylint-demo.py"
Set-Content -Path $sample -Value 'x = 5'
python -m pylint $sample
Remove-Item -LiteralPath $sample
```

Pylint's typical finding for this sample is the unused-variable warning.
Neither demonstration is a CI change, and no failing sample should be pushed.
