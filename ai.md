#####


## 1. Remote Code Execution via Insecure Deserialization
**Location:** `/reports/generate` function

* **Vulnerability:** The application uses the `pickle` module to deserialize a base64-encoded string provided by the user in the `filter_config` field.


---

## 2. OS Command Injection
**Location:** `/diagnostics/ping` function

* **Vulnerability:** The `host` parameter is directly interpolated into a shell command string executed via `subprocess.check_output(..., shell=True)`.

---

## 3. SQL Injection
**Location:** `/assets/search` function

* **Vulnerability:** The `term` query parameter is inserted directly into the SQL query string using an f-string.

---

## 4. Hardcoded & Weak Default Secrets
**Location:** `JWT_SECRET` and `INTERNAL_API_KEY` assignments

* **Vulnerability:** Both secrets provide a fallback to the weak default string `"1234567890"` if the environment variables are not set.

---

## 5. Timing Attack on API Key Validation
**Location:** `/internal/validate-key` function

* **Vulnerability:** The application uses the standard `==` operator to compare the provided key with the `INTERNAL_API_KEY`.

---

## 6. Improper Access Control (Hardcoded User List)
**Location:** `AUTHORIZED_EMAILS` list

* **Vulnerability:** The list of authorized users is hardcoded directly into the script.


---
