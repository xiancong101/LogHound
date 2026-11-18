#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 git 历史里所有 commit 的作者/提交者改成新身份，保留原始提交日期与提交信息。"""
import os
import subprocess
import sys

os.chdir(r'E:\LogHawk')

NAME = '花放'
EMAIL = '2971421830@qq.com'

# 用 git filter-branch 的环境变量方式最稳：不改时间戳，只改身份
env = dict(os.environ)
env['GIT_AUTHOR_NAME'] = NAME
env['GIT_AUTHOR_EMAIL'] = EMAIL
env['GIT_COMMITTER_NAME'] = NAME
env['GIT_COMMITTER_EMAIL'] = EMAIL

cmd = [
    'git', 'filter-branch', '-f',
    '--env-filter',
    'export GIT_AUTHOR_NAME="%s"; export GIT_AUTHOR_EMAIL="%s"; '
    'export GIT_COMMITTER_NAME="%s"; export GIT_COMMITTER_EMAIL="%s";'
    % (NAME, EMAIL, NAME, EMAIL),
    '--', '--all',
]
print('running:', ' '.join(cmd))
r = subprocess.run(cmd, env=env, capture_output=True, text=True, encoding='utf-8', errors='replace')
print('rc =', r.returncode)
if r.stdout.strip():
    print(r.stdout[-2000:])
if r.stderr.strip():
    print(r.stderr[-2000:])
