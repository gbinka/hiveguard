# detector.path_probe

Detects requests to suspicious paths like `/wp-login.php` and `/.env`.

## Config example

```yaml
plugins:
  - id: detector.path_probe
    name: web-probe
    config:
      paths: ["/wp-login.php", "/xmlrpc.php", "/.env", "/phpmyadmin", "/wp-admin"]
      ban_duration_secs: 259200
```
