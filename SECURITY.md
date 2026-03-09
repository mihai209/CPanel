# CPanel Update & Compatibility Policy

## Platform Compatibility

CPanel is designed to run on **any environment capable of running Node.js**.
This makes the panel highly portable and easy to deploy on a wide range of systems.

Supported environments include:

| Environment                  | Status    |
| ---------------------------- | --------- |
| Linux (Ubuntu, Debian, etc.) | Supported |
| Windows (via WSL)            | Supported |
| Any Node.js capable system   | Supported |

Because CPanel only depends on **Node.js**, it can generally run on most modern server environments.

---

## Version Policy

CPanel does **not maintain legacy versions**.

The project follows a **rolling update model**, meaning:

* there is **only one maintained version**
* the panel is always **kept up-to-date**
* security patches and improvements are delivered through updates

Older versions are not supported and should not be used.

---

## Updating the Panel

Updating CPanel is simple and requires only a single command:

```
npm run update-panel
```

This command will:

* fetch the latest changes from the repository
* update modified files
* install any required dependencies
* update the panel to the newest version

No manual intervention is required besides running the command.

---

## Recommendation

Administrators should periodically run the update command to ensure their installation remains **secure, stable, and up to date**.
