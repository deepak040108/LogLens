"""
parser/nginx_parser.py
------------------------------------------------------------------------
Nginx's default `combined` log format string is byte-for-byte the same
Combined Log Format Apache uses:

  log_format combined '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $body_bytes_sent '
                       '"$http_referer" "$http_user_agent"';

So rather than duplicating (and risking drifting) the same regex in a
second file, this module re-exports the Apache parser under the Nginx
name. If a project later needs to support a *customized* Nginx
log_format (many ops teams change it), that's where this file would
diverge and gain its own pattern -- the two-module split exists so
that can happen without touching apache_parser.py.
------------------------------------------------------------------------
"""

from .apache_parser import parse_line, parse_timestamp, stream_parse_file, CLF_PATTERN  # noqa: F401
