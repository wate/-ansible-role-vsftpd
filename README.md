vsftpd
=========

[![Build Status](https://travis-ci.org/wate/ansible-role-vsftpd.svg?branch=master)](https://travis-ci.org/wate/ansible-role-vsftpd)

[vsftpd](https://security.appspot.com/vsftpd.html)のインストールとセットアップを行います。

Role Variables
--------------

### vsftpd_cfg

vsftpdの設定内容を指定します。

```yml
vsftpd_cfg:
  listen: yes
  # listen_address: ""
  listen_ipv6: no
  # listen_address6: ""
  tcp_wrappers: yes
  # banner_file: ""
  # ftpd_banner: ""
  # max_clients: 0
  # max_per_ip: 0
  # delay_failed_login: 1
  # max_login_fails: 3
  # delay_successful_login: 0
  pam_service_name: vsftpd
  nopriv_user: ftp
  # port_enable: yes
  # port_promiscuous: no
  # connect_timeout: 60
  # accept_timeout: 60
  # data_connection_timeout: 300
  # idle_session_timeout: 300
  # async_abor_enable: yes
  # session_support: no
  # setproctitle_enable: no
  # download_enable: yes
  write_enable: yes
  # lock_upload_files: yes
  # chmod_enable: yes
  # dirlist_enable: yes
  # file_open_mode: "0666"
  ls_recurse_enable: yes
  ascii_download_enable: yes
  ascii_upload_enable: yes
  # mdtm_write: yes
  # tilde_user_enable: no
  # delete_failed_uploads: no
  # cmds_allowed: ""
  # cmds_denied: ""
  # deny_file: ""
  # hide_file: ""
  # hide_ids: no
  # background: no
  # check_shell: yes
  # dirmessage_enable: no
  # message_file: .message
  # force_dot_files: no
  # text_userdb_names: no
  # use_localtime: no
  # use_sendfile: yes
  # virtual_use_local_privs: no
  # listen_port: 21
  # connect_from_port_20: no
  # ftp_data_port: 20
  # guest_enable: no
  # guest_username: ftp
  # one_process_model: no
  # trans_chunk_size: 0
  # secure_chroot_dir: /usr/share/empty
  # user_config_dir: ""
  # user_sub_token: ""
  # run_as_launching_user: no
  # require_cert: no
  # validate_cert: no
  # ca_certs_file: ""
  ## --------------------
  ## PASV
  ## --------------------
  # pasv_enable: yes
  # pasv_addr_resolve: no
  # pasv_promiscuous: no
  pasv_min_port: 65000
  pasv_max_port: 65535
  # pasv_address: ""
  ## --------------------
  ## Anonymous User setting
  ## --------------------
  anonymous_enable: no
  # anon_root: ""
  # anon_mkdir_write_enable: no
  # anon_other_write_enable: no
  # anon_upload_enable: no
  # anon_world_readable_only: yes
  # anon_max_rate: 0
  # anon_umask: "077"
  # ftp_username: ftp
  # chown_uploads: no
  # chown_username: root
  # chown_upload_mode: "0600"
  # secure_email_list_enable: no
  # no_anon_password: no
  # email_password_file: /etc/vsftpd/email_passwords
  # deny_email_enable: no
  # banned_email_file: /etc/vsftpd/banned_emails
  ## --------------------
  ## Local User Setting
  ## --------------------
  local_enable: yes
  # local_root: ""
  # local_max_rate: 0
  local_umask: "022"
  userlist_enable: yes
  userlist_deny: yes
  userlist_file: /etc/vsftpd/user_list
  chroot_local_user: yes
  chroot_list_enable: yes
  allow_writeable_chroot: yes
  chroot_list_file: /etc/vsftpd/chroot_list
  # passwd_chroot_enable: no
  ## --------------------
  ## SSL Setting
  ## --------------------
  # ssl_enable: no
  # ssl_ciphers: DES-CBC3-SHA
  # ssl_request_cert: yes
  ssl_sslv2: no
  ssl_sslv3: no
  ssl_tlsv1: yes
  # allow_anon_ssl: no
  # force_anon_data_ssl: no
  # force_anon_logins_ssl: no
  # force_local_data_ssl: yes
  # force_local_logins_ssl: yes
  # rsa_cert_file: /usr/share/ssl/certs/vsftpd.pem
  # rsa_private_key_file: ""
  # dsa_cert_file: ""
  # dsa_private_key_file: ""
  require_ssl_reuse: no
  # debug_ssl: no
  # implicit_ssl: no
  # strict_ssl_read_eof: no
  # strict_ssl_write_shutdown: no
  ## --------------------
  ## Logging
  ## --------------------
  # log_ftp_protocol: no
  # dual_log_enable: no
  # vsftpd_log_file: /var/log/vsftpd.log
  # xferlog_enable: no
  # xferlog_std_format: no
  # xferlog_file: /var/log/xferlog
  # no_log_lock: no
  # syslog_enable: no
  # extra_setting:
```

### vsftpd_chroot_list

```yml
vsftpd_chroot_list: []
```

### vsftpd_banned_emails

```yml
vsftpd_banned_emails: []
```

### vsftpd_email_passwords

```yml
vsftpd_email_passwords: []
```

### vsftpd_userlist

```yml
vsftpd_userlist:
  - root
  - bin
  - daemon
  - adm
  - lp
  - sync
  - shutdown
  - halt
  - mail
  - news
  - uucp
  - operator
  - games
  - nobody
```

Example Playbook
----------------

```yml
- hosts: servers
  roles:
     - role: vsftpd
```

License
-------

MIT
