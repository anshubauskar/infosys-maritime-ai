# FreightQuote AI — Milestone 2

**Infosys Springboard Internship 7.0 · Batch 4 · Milestone 2**

FreightQuote AI is a freight operations demonstration application. The project combines a FastAPI backend, SQLite data store, browser-based interface, role-based access control (RBAC), and an AI Copilot that is intended to answer operational questions from database evidence.

> **Submission note:** This repository contains the Colab notebook used to create and run the application. Verify each feature in the running app and add only genuine screenshots/test results before final submission. This is an academic demo, not a production deployment.

## Repository contents

```text
Milestone2/
├── README.md
├── FreightQuote_Milestone2.ipynb
└── screenshots/
    └── README.md
```

The notebook writes the application source files into `/content/app` when run in Google Colab. Runtime data (SQLite database, logs and generated files) is stored separately under `/content/app_data`.

## Technology stack

- Python
- FastAPI and Uvicorn
- SQLite
- JWT-based authentication
- Password hashing with bcrypt
- Role-based access control (RBAC)
- HTML, CSS and JavaScript frontend
- Google Colab for the demonstration runtime
- ngrok as an optional public-link fallback

The notebook installs the Python dependencies required by the project.

## Run in Google Colab

1. Open `FreightQuote_Milestone2.ipynb` in Google Colab.
2. Open the **Secrets** panel (key icon).
3. Add the following secrets and enable notebook access:

   | Secret name | Purpose |
   |---|---|
   | `JWT_SECRET` | Signs authentication tokens |
   | `ADMIN_EMAIL_ID` | Initial administrator email |
   | `ADMIN_PASSWORD` | Initial administrator password |
   | `NGROK_AUTHTOKEN` | Optional fallback public URL |
   | `EMAIL_ADDRESS` | Optional sender address for recovery emails |
   | `EMAIL_PASSWORD` | Optional email app password |

4. Do not paste secrets into notebook code or commit them to GitHub.
5. Select **Runtime → Run all**.
6. Wait for the server cell to print `FreightQuote AI is running`.
7. Open the `Open the app` link printed by the notebook.
8. Sign in with the administrator account configured through Colab Secrets.

If startup fails, read the traceback in the server cell and correct the configuration before testing the app. The email secrets are optional if email-based password recovery is not being demonstrated. `NGROK_AUTHTOKEN` is only needed when the Colab proxy link is unavailable.

## Roles and access matrix

The following is the target access matrix specified in the Milestone 2 mentor instructions. Confirm each permission against the running application and update this table if the implementation differs.

| Feature / page | Admin | Operations Manager | Freight Broker | Auditor | Customer |
|---|:---:|:---:|:---:|:---:|:---:|
| AI Copilot | ✓ | ✓ | ✓ | ✓ | ✓* |
| Route AI | ✓ | ✓ | — | Read-only | — |
| Spot Quotes | ✓ | — | ✓ | Read-only | Own quotes* |
| Carriers | ✓ | ✓ | ✓ | Read-only | — |
| Weather Risk | ✓ | ✓ | — | Read-only | — |
| Margin | ✓ | — | ✓ | Read-only | — |
| Customs | ✓ | ✓ | — | Read-only | — |
| Admin dashboard / user management | ✓ | — | — | — | — |
| Profile | ✓ | ✓ | ✓ | ✓ | ✓ |

- `✓` = allowed.
- `Read-only` = view access; no changes or agent actions.
- `—` = not allowed.
- `*` Customers must be restricted to their own records and quotes.

The backend must enforce authorization as well as hiding unavailable menu items in the frontend. Restricted direct API/page requests should return HTTP `403`.

## Authentication and administration

The Milestone 2 brief calls for:

- Signup, login, forgot-password and reset-password endpoints.
- Password hashing and JWT authentication.
- A profile page with account information and password/username update.
- Five roles: Admin, Operations Manager, Freight Broker, Auditor and Customer.
- Admin user management: create, role update, lock/unlock and delete users.
- Protection against deleting or locking the last active administrator.
- Immediate rejection of locked users, including requests made with an earlier token.
- An activity/audit trail for administrator actions.

Test these flows with dummy accounts before recording screenshots. Never show real passwords, password hashes, recovery secrets or personal user data.

## AI Copilot

The Copilot is designed to answer freight-operation questions using database-backed results rather than invented figures. The mentor brief requires at least 15 additional question patterns, role-aware data access, and display of the SQL/query evidence and row count where applicable.

Suggested prompts to validate in the application:

1. Show me the top 5 carriers by reliability.
2. Which port has the highest congestion?
3. How many shipments are delayed?
4. Which quotes have a low margin?
5. Which shipments are on customs hold?
6. Which carrier is least reliable?
7. Show shipments arriving this week.
8. Which customers have high-priority accounts?

Record the actual response and evidence for each prompt you test. A greeting such as `hello` should receive a polite response without fabricating operational statistics.

## Screenshots

Add screenshots only after testing the corresponding feature. Use dummy accounts and blur personal information.


## GitHub safety checklist

Do **not** commit:

- SQLite database files (`*.db`, `*.sqlite`, `*.sqlite3`) or SQLite WAL/SHM files.
- `.env` files, passwords, API keys, JWT secrets, ngrok tokens or email app passwords.
- Runtime logs (`*.log`), cache folders or Python bytecode.
- Notebook outputs containing credentials, OTPs, personal data or temporary runtime links.

Before pushing an updated notebook, clear outputs using **Edit → Clear all outputs** in Colab/Jupyter and inspect the notebook diff.

## Current verification status

This README documents the project structure and the mentor's required behavior. It does not claim that every checklist item has passed testing. Maintain a test record here after verifying each feature in the live Colab application, including the role used, expected result, actual result and screenshot filename.
