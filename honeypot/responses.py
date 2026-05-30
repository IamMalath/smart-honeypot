"""Fake response generators - the bait the honeypot serves to attackers."""
from __future__ import annotations

FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Sign in - Admin Panel</title></head>
<body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Admin sign-in</h2>
<form method="POST" action="/login">
  <p><label>Username<br><input name="username" autofocus></label></p>
  <p><label>Password<br><input name="password" type="password"></label></p>
  <p><button type="submit">Sign in</button></p>
</form>
<small>v3.4.1</small>
</body></html>
"""

FAKE_LOGIN_FAIL_HTML = """<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Sign-in failed</h2>
<p>Invalid username or password.</p>
<p><a href="/login">Try again</a></p>
</body></html>
"""

FAKE_WP_LOGIN = """<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8">
<title>Log In &lsaquo; My Blog &#8212; WordPress</title></head>
<body class="login login-action-login wp-core-ui">
<div id="login"><h1><a href="/">My Blog</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p><label for="user_login">Username or Email Address</label>
  <input type="text" name="log" id="user_login"></p>
  <p><label for="user_pass">Password</label>
  <input type="password" name="pwd" id="user_pass"></p>
  <p class="submit"><input type="submit" name="wp-submit" value="Log In"></p>
</form></div></body></html>
"""

FAKE_PHPMYADMIN = """<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
<body><h1>phpMyAdmin 4.8.5</h1>
<form method="POST" action="/phpmyadmin/index.php">
  Server: <input name="pma_servername" value="localhost"><br>
  User: <input name="pma_username"><br>
  Password: <input name="pma_password" type="password"><br>
  <button>Go</button></form></body></html>
"""

FAKE_ENV = """APP_NAME=Acme
APP_ENV=production
APP_KEY=base64:7N3wL5z9aQ8pXrV2cYbWuT0sJ4kE6mGhI1oP3qRfStU=
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=10.0.12.7
DB_PORT=3306
DB_DATABASE=acme_prod
DB_USERNAME=acme_app
DB_PASSWORD=hunter2
REDIS_HOST=10.0.12.8
MAIL_HOST=smtp.acme.example
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEFAKEFAKE
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://github.example/acme/internal-billing.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

FAKE_ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /private/
Disallow: /.git/
Disallow: /api/internal/
"""

FAKE_INDEX = """<!DOCTYPE html>
<html><head><title>Acme Internal Tools</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:60px auto">
<h1>Acme Internal Tools</h1>
<p>Authorised personnel only.</p>
<ul>
  <li><a href="/login">Sign in</a></li>
  <li><a href="/api/v1/status">API status</a></li>
</ul>
</body></html>
"""

FAKE_API_STATUS = '{"status":"ok","version":"3.4.1","uptime":48311}'

FAKE_404 = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server</address></body></html>
"""

FAKE_500 = """<!DOCTYPE html>
<html><head><title>500 Internal Server Error</title></head>
<body><h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.</p>
</body></html>
"""
