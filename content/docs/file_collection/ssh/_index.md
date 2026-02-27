---
title: "File Acquisition Over SSH"
menutitle: "Acquisition over SSH"
date: 2025-11-06
last_reviewed: 2026-01-27
draft: true
weight: 30
---

The ssh accessor is used to read remote files - it can not execute arbitrary
tools on the endpoint - UAC collector is a shell script which is pushed to the
endpoint normally so it can not be used via the ssh accessor.


```yaml
name: SSH.Upload
description: |
  Uploads files from a remote host via the SSH accessor.
  The remote host and access credentials are defined in a server secret.

type: CLIENT

sources:
  - query: |
      LET SSH_CONFIG <= dict(secret="alpine")

      SELECT OSPath,
             Mtime,
             Size,
             upload(file=OSPath, accessor="ssh") AS FilePreview
      FROM glob(globs='/var/log/*', accessor='ssh')

column_types:
  - name: FilePreview
    type: preview_upload
  - name: Size
    type: mb
```
