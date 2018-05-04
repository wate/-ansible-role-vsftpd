require 'spec_helper'

describe package('vsftpd') do
  it { should be_installed }
end

describe file('/etc/vsftpd/vsftpd.conf') do
  it { should exist }
  it { should be_file }
  vsftpd_cfg = property['vsftpd_cfg']

  if vsftpd_cfg.key?('anonymous_enable')
    anonymous_enable = vsftpd_cfg['banned_email_file'] ? 'YES' : 'NO'
    its(:content) { should match(/anonymous_enable=#{e(anonymous_enable)}/) }
  end
  if vsftpd_cfg.key?('allow_anon_ssl')
    allow_anon_ssl = vsftpd_cfg['allow_anon_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/allow_anon_ssl=#{e(allow_anon_ssl)}/) }
  end
  if vsftpd_cfg.key?('anon_mkdir_write_enable')
    anon_mkdir_write_enable = vsftpd_cfg['anon_mkdir_write_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/anon_mkdir_write_enable=#{e(anon_mkdir_write_enable)}/) }
  end
  if vsftpd_cfg.key?('anon_other_write_enable')
    anon_other_write_enable = vsftpd_cfg['anon_other_write_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/anon_other_write_enable=#{e(anon_other_write_enable)}/) }
  end
  if vsftpd_cfg.key?('anon_upload_enable')
    anon_upload_enable = vsftpd_cfg['anon_upload_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/anon_upload_enable=#{e(anon_upload_enable)}/) }
  end
  if vsftpd_cfg.key?('anon_world_readable_only')
    anon_world_readable_only = vsftpd_cfg['anon_world_readable_only'] ? 'YES' : 'NO'
    its(:content) { should match(/anon_world_readable_only=#{e(anon_world_readable_only)}/) }
  end

  if vsftpd_cfg.key?('ascii_download_enable')
    ascii_download_enable = vsftpd_cfg['ascii_download_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/ascii_download_enable=#{e(ascii_download_enable)}/) }
  end
  if vsftpd_cfg.key?('ascii_upload_enable')
    ascii_upload_enable = vsftpd_cfg['ascii_upload_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/ascii_upload_enable=#{e(ascii_upload_enable)}/) }
  end
  if vsftpd_cfg.key?('async_abor_enable')
    async_abor_enable = vsftpd_cfg['async_abor_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/async_abor_enable=#{e(async_abor_enable)}/) }
  end
  if vsftpd_cfg.key?('background')
    background = vsftpd_cfg['background'] ? 'YES' : 'NO'
    its(:content) { should match(/background=#{e(background)}/) }
  end
  if vsftpd_cfg.key?('check_shell')
    check_shell = vsftpd_cfg['check_shell'] ? 'YES' : 'NO'
    its(:content) { should match(/check_shell=#{e(check_shell)}/) }
  end
  if vsftpd_cfg.key?('chmod_enable')
    chmod_enable = vsftpd_cfg['chmod_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/chmod_enable=#{e(chmod_enable)}/) }
  end
  if vsftpd_cfg.key?('chown_uploads')
    chown_uploads = vsftpd_cfg['chown_uploads'] ? 'YES' : 'NO'
    its(:content) { should match(/chown_uploads=#{e(chown_uploads)}/) }
  end
  if vsftpd_cfg.key?('chroot_list_enable')
    chroot_list_enable = vsftpd_cfg['chroot_list_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/chroot_list_enable=#{e(chroot_list_enable)}/) }
  end
  if vsftpd_cfg.key?('chroot_local_user')
    chroot_local_user = vsftpd_cfg['chroot_local_user'] ? 'YES' : 'NO'
    its(:content) { should match(/chroot_local_user=#{e(chroot_local_user)}/) }
  end
  if vsftpd_cfg.key?('connect_from_port_20')
    connect_from_port_twenty = vsftpd_cfg['connect_from_port_20'] ? 'YES' : 'NO'
    its(:content) { should match(/connect_from_port_20=#{e(connect_from_port_twenty)}/) }
  end
  if vsftpd_cfg.key?('debug_ssl')
    debug_ssl = vsftpd_cfg['debug_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/debug_ssl=#{e(debug_ssl)}/) }
  end
  if vsftpd_cfg.key?('delete_failed_uploads')
    delete_failed_uploads = vsftpd_cfg['delete_failed_uploads'] ? 'YES' : 'NO'
    its(:content) { should match(/delete_failed_uploads=#{e(delete_failed_uploads)}/) }
  end
  if vsftpd_cfg.key?('deny_email_enable')
    deny_email_enable = vsftpd_cfg['deny_email_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/deny_email_enable=#{e(deny_email_enable)}/) }
  end
  if vsftpd_cfg.key?('dirlist_enable')
    dirlist_enable = vsftpd_cfg['dirlist_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/dirlist_enable=#{e(dirlist_enable)}/) }
  end
  if vsftpd_cfg.key?('dirmessage_enable')
    dirmessage_enable = vsftpd_cfg['dirmessage_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/dirmessage_enable=#{e(dirmessage_enable)}/) }
  end
  if vsftpd_cfg.key?('download_enable')
    download_enable = vsftpd_cfg['download_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/download_enable=#{e(download_enable)}/) }
  end
  if vsftpd_cfg.key?('dual_log_enable')
    dual_log_enable = vsftpd_cfg['dual_log_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/dual_log_enable=#{e(dual_log_enable)}/) }
  end
  if vsftpd_cfg.key?('force_dot_files')
    force_dot_files = vsftpd_cfg['force_dot_files'] ? 'YES' : 'NO'
    its(:content) { should match(/force_dot_files=#{e(force_dot_files)}/) }
  end
  if vsftpd_cfg.key?('force_anon_data_ssl')
    force_anon_data_ssl = vsftpd_cfg['force_anon_data_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/force_anon_data_ssl=#{e(force_anon_data_ssl)}/) }
  end
  if vsftpd_cfg.key?('force_anon_logins_ssl')
    force_anon_logins_ssl = vsftpd_cfg['force_anon_logins_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/force_anon_logins_ssl=#{e(force_anon_logins_ssl)}/) }
  end
  if vsftpd_cfg.key?('force_local_data_ssl')
    force_local_data_ssl = vsftpd_cfg['force_local_data_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/force_local_data_ssl=#{e(force_local_data_ssl)}/) }
  end
  if vsftpd_cfg.key?('force_local_logins_ssl')
    force_local_logins_ssl = vsftpd_cfg['force_local_logins_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/force_local_logins_ssl=#{e(force_local_logins_ssl)}/) }
  end
  if vsftpd_cfg.key?('guest_enable')
    guest_enable = vsftpd_cfg['guest_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/guest_enable=#{e(guest_enable)}/) }
  end
  if vsftpd_cfg.key?('hide_ids')
    hide_ids = vsftpd_cfg['hide_ids'] ? 'YES' : 'NO'
    its(:content) { should match(/hide_ids=#{e(hide_ids)}/) }
  end
  if vsftpd_cfg.key?('implicit_ssl')
    implicit_ssl = vsftpd_cfg['implicit_ssl'] ? 'YES' : 'NO'
    its(:content) { should match(/implicit_ssl=#{e(implicit_ssl)}/) }
  end
  if vsftpd_cfg.key?('listen')
    listen = vsftpd_cfg['listen'] ? 'YES' : 'NO'
    its(:content) { should match(/listen=#{e(listen)}/) }
  end
  if vsftpd_cfg.key?('listen_ipv6')
    listen_ipv6 = vsftpd_cfg['listen_ipv6'] ? 'YES' : 'NO'
    its(:content) { should match(/listen_ipv6=#{e(listen_ipv6)}/) }
  end
  if vsftpd_cfg.key?('local_enable')
    local_enable = vsftpd_cfg['local_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/local_enable=#{e(local_enable)}/) }
  end
  if vsftpd_cfg.key?('lock_upload_files')
    lock_upload_files = vsftpd_cfg['lock_upload_files'] ? 'YES' : 'NO'
    its(:content) { should match(/lock_upload_files=#{e(lock_upload_files)}/) }
  end
  if vsftpd_cfg.key?('log_ftp_protocol')
    log_ftp_protocol = vsftpd_cfg['log_ftp_protocol'] ? 'YES' : 'NO'
    its(:content) { should match(/log_ftp_protocol=#{e(log_ftp_protocol)}/) }
  end
  if vsftpd_cfg.key?('ls_recurse_enable')
    ls_recurse_enable = vsftpd_cfg['ls_recurse_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/ls_recurse_enable=#{e(ls_recurse_enable)}/) }
  end
  if vsftpd_cfg.key?('mdtm_write')
    mdtm_write = vsftpd_cfg['mdtm_write'] ? 'YES' : 'NO'
    its(:content) { should match(/mdtm_write=#{e(mdtm_write)}/) }
  end
  if vsftpd_cfg.key?('no_anon_password')
    no_anon_password = vsftpd_cfg['no_anon_password'] ? 'YES' : 'NO'
    its(:content) { should match(/no_anon_password=#{e(no_anon_password)}/) }
  end
  if vsftpd_cfg.key?('no_log_lock')
    no_log_lock = vsftpd_cfg['no_log_lock'] ? 'YES' : 'NO'
    its(:content) { should match(/no_log_lock=#{e(no_log_lock)}/) }
  end
  if vsftpd_cfg.key?('one_process_model')
    one_process_model = vsftpd_cfg['one_process_model'] ? 'YES' : 'NO'
    its(:content) { should match(/one_process_model=#{e(one_process_model)}/) }
  end
  if vsftpd_cfg.key?('passwd_chroot_enable')
    passwd_chroot_enable = vsftpd_cfg['passwd_chroot_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/passwd_chroot_enable=#{e(passwd_chroot_enable)}/) }
  end
  if vsftpd_cfg.key?('pasv_enable')
    pasv_enable = vsftpd_cfg['pasv_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/pasv_enable=#{e(pasv_enable)}/) }
  end
  if vsftpd_cfg.key?('pasv_addr_resolve')
    pasv_addr_resolve = vsftpd_cfg['pasv_addr_resolve'] ? 'YES' : 'NO'
    its(:content) { should match(/pasv_addr_resolve=#{e(pasv_addr_resolve)}/) }
  end
  if vsftpd_cfg.key?('pasv_promiscuous')
    pasv_promiscuous = vsftpd_cfg['pasv_promiscuous'] ? 'YES' : 'NO'
    its(:content) { should match(/pasv_promiscuous=#{e(pasv_promiscuous)}/) }
  end
  if vsftpd_cfg.key?('port_enable')
    port_enable = vsftpd_cfg['port_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/port_enable=#{e(port_enable)}/) }
  end
  if vsftpd_cfg.key?('port_promiscuous')
    port_promiscuous = vsftpd_cfg['port_promiscuous'] ? 'YES' : 'NO'
    its(:content) { should match(/port_promiscuous=#{e(port_promiscuous)}/) }
  end
  if vsftpd_cfg.key?('require_cert')
    require_cert = vsftpd_cfg['require_cert'] ? 'YES' : 'NO'
    its(:content) { should match(/require_cert=#{e(require_cert)}/) }
  end
  if vsftpd_cfg.key?('require_ssl_reuse')
    require_ssl_reuse = vsftpd_cfg['require_ssl_reuse'] ? 'YES' : 'NO'
    its(:content) { should match(/require_ssl_reuse=#{e(require_ssl_reuse)}/) }
  end
  if vsftpd_cfg.key?('run_as_launching_user')
    run_as_launching_user = vsftpd_cfg['run_as_launching_user'] ? 'YES' : 'NO'
    its(:content) { should match(/run_as_launching_user=#{e(run_as_launching_user)}/) }
  end
  if vsftpd_cfg.key?('secure_email_list_enable')
    secure_email_list_enable = vsftpd_cfg['secure_email_list_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/secure_email_list_enable=#{e(secure_email_list_enable)}/) }
  end
  if vsftpd_cfg.key?('session_support')
    session_support = vsftpd_cfg['session_support'] ? 'YES' : 'NO'
    its(:content) { should match(/session_support=#{e(session_support)}/) }
  end
  if vsftpd_cfg.key?('setproctitle_enable')
    setproctitle_enable = vsftpd_cfg['setproctitle_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/setproctitle_enable=#{e(setproctitle_enable)}/) }
  end
  if vsftpd_cfg.key?('ssl_enable')
    ssl_enable = vsftpd_cfg['ssl_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/ssl_enable=#{e(ssl_enable)}/) }
  end
  if vsftpd_cfg.key?('ssl_request_cert')
    ssl_request_cert = vsftpd_cfg['ssl_request_cert'] ? 'YES' : 'NO'
    its(:content) { should match(/ssl_request_cert=#{e(ssl_request_cert)}/) }
  end
  if vsftpd_cfg.key?('ssl_sslv2')
    ssl_sslv2 = vsftpd_cfg['ssl_sslv2'] ? 'YES' : 'NO'
    its(:content) { should match(/ssl_sslv2=#{e(ssl_sslv2)}/) }
  end
  if vsftpd_cfg.key?('ssl_sslv3')
    ssl_sslv3 = vsftpd_cfg['ssl_sslv3'] ? 'YES' : 'NO'
    its(:content) { should match(/ssl_sslv3=#{e(ssl_sslv3)}/) }
  end
  if vsftpd_cfg.key?('ssl_tlsv1')
    ssl_tlsv1 = vsftpd_cfg['ssl_tlsv1'] ? 'YES' : 'NO'
    its(:content) { should match(/ssl_tlsv1=#{e(ssl_tlsv1)}/) }
  end
  if vsftpd_cfg.key?('strict_ssl_read_eof')
    strict_ssl_read_eof = vsftpd_cfg['strict_ssl_read_eof'] ? 'YES' : 'NO'
    its(:content) { should match(/strict_ssl_read_eof=#{e(strict_ssl_read_eof)}/) }
  end
  if vsftpd_cfg.key?('strict_ssl_write_shutdown')
    strict_ssl_write_shutdown = vsftpd_cfg['strict_ssl_write_shutdown'] ? 'YES' : 'NO'
    its(:content) { should match(/strict_ssl_write_shutdown=#{e(strict_ssl_write_shutdown)}/) }
  end
  if vsftpd_cfg.key?('syslog_enable')
    syslog_enable = vsftpd_cfg['syslog_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/syslog_enable=#{e(syslog_enable)}/) }
  end
  if vsftpd_cfg.key?('tcp_wrappers')
    tcp_wrappers = vsftpd_cfg['tcp_wrappers'] ? 'YES' : 'NO'
    its(:content) { should match(/tcp_wrappers=#{e(tcp_wrappers)}/) }
  end
  if vsftpd_cfg.key?('text_userdb_names')
    text_userdb_names = vsftpd_cfg['text_userdb_names'] ? 'YES' : 'NO'
    its(:content) { should match(/text_userdb_names=#{e(text_userdb_names)}/) }
  end
  if vsftpd_cfg.key?('tilde_user_enable')
    tilde_user_enable = vsftpd_cfg['tilde_user_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/tilde_user_enable=#{e(tilde_user_enable)}/) }
  end
  if vsftpd_cfg.key?('use_localtime')
    use_localtime = vsftpd_cfg['use_localtime'] ? 'YES' : 'NO'
    its(:content) { should match(/use_localtime=#{e(use_localtime)}/) }
  end
  if vsftpd_cfg.key?('use_sendfile')
    use_sendfile = vsftpd_cfg['use_sendfile'] ? 'YES' : 'NO'
    its(:content) { should match(/use_sendfile=#{e(use_sendfile)}/) }
  end
  if vsftpd_cfg.key?('userlist_deny')
    userlist_deny = vsftpd_cfg['userlist_deny'] ? 'YES' : 'NO'
    its(:content) { should match(/userlist_deny=#{e(userlist_deny)}/) }
  end
  if vsftpd_cfg.key?('userlist_enable')
    userlist_enable = vsftpd_cfg['userlist_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/userlist_enable=#{e(userlist_enable)}/) }
  end
  if vsftpd_cfg.key?('validate_cert')
    validate_cert = vsftpd_cfg['validate_cert'] ? 'YES' : 'NO'
    its(:content) { should match(/validate_cert=#{e(validate_cert)}/) }
  end
  if vsftpd_cfg.key?('virtual_use_local_privs')
    virtual_use_local_privs = vsftpd_cfg['virtual_use_local_privs'] ? 'YES' : 'NO'
    its(:content) { should match(/virtual_use_local_privs=#{e(virtual_use_local_privs)}/) }
  end
  if vsftpd_cfg.key?('write_enable')
    write_enable = vsftpd_cfg['write_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/write_enable=#{e(write_enable)}/) }
  end
  if vsftpd_cfg.key?('xferlog_enable')
    xferlog_enable = vsftpd_cfg['xferlog_enable'] ? 'YES' : 'NO'
    its(:content) { should match(/xferlog_enable=#{e(xferlog_enable)}/) }
  end
  if vsftpd_cfg.key?('xferlog_std_format')
    xferlog_std_format = vsftpd_cfg['xferlog_std_format'] ? 'YES' : 'NO'
    its(:content) { should match(/xferlog_std_format=#{e(xferlog_std_format)}/) }
  end

  if vsftpd_cfg.key?('accept_timeout')
    its(:content) { should match(/accept_timeout=#{e(vsftpd_cfg['accept_timeout'])}/) }
  end
  its(:content) { should match(/anon_max_rate=#{e(vsftpd_cfg['anon_max_rate'])}/) } if vsftpd_cfg.key?('anon_max_rate')
  its(:content) { should match(/anon_umask=#{e(vsftpd_cfg['anon_umask'])}/) } if vsftpd_cfg.key?('anon_umask')
  if vsftpd_cfg.key?('chown_upload_mode')
    its(:content) { should match(/chown_upload_mode=#{e(vsftpd_cfg['chown_upload_mode'])}/) }
  end
  if vsftpd_cfg.key?('connect_timeout')
    its(:content) { should match(/connect_timeout=#{e(vsftpd_cfg['connect_timeout'])}/) }
  end
  if vsftpd_cfg.key?('data_connection_timeout')
    its(:content) { should match(/data_connection_timeout=#{e(vsftpd_cfg['data_connection_timeout'])}/) }
  end
  if vsftpd_cfg.key?('delay_failed_login')
    its(:content) { should match(/delay_failed_login=#{e(vsftpd_cfg['delay_failed_login'])}/) }
  end
  if vsftpd_cfg.key?('delay_successful_login')
    its(:content) { should match(/delay_successful_login=#{e(vsftpd_cfg['delay_successful_login'])}/) }
  end
  if vsftpd_cfg.key?('file_open_mode')
    its(:content) { should match(/file_open_mode=#{e(vsftpd_cfg['file_open_mode'])}/) }
  end
  its(:content) { should match(/ftp_data_port=#{e(vsftpd_cfg['ftp_data_port'])}/) } if vsftpd_cfg.key?('ftp_data_port')
  if vsftpd_cfg.key?('idle_session_timeout')
    its(:content) { should match(/idle_session_timeout=#{e(vsftpd_cfg['idle_session_timeout'])}/) }
  end
  its(:content) { should match(/listen_port=#{e(vsftpd_cfg['listen_port'])}/) } if vsftpd_cfg.key?('listen_port')
  if vsftpd_cfg.key?('local_max_rate')
    its(:content) { should match(/local_max_rate=#{e(vsftpd_cfg['local_max_rate'])}/) }
  end
  its(:content) { should match(/local_umask=#{e(vsftpd_cfg['local_umask'])}/) } if vsftpd_cfg.key?('local_umask')
  its(:content) { should match(/max_clients=#{e(vsftpd_cfg['max_clients'])}/) } if vsftpd_cfg.key?('max_clients')
  if vsftpd_cfg.key?('max_login_fails')
    its(:content) { should match(/max_login_fails=#{e(vsftpd_cfg['max_login_fails'])}/) }
  end
  its(:content) { should match(/max_per_ip=#{e(vsftpd_cfg['max_per_ip'])}/) } if vsftpd_cfg.key?('max_per_ip')
  its(:content) { should match(/pasv_max_port=#{e(vsftpd_cfg['pasv_max_port'])}/) } if vsftpd_cfg.key?('pasv_max_port')
  its(:content) { should match(/pasv_min_port=#{e(vsftpd_cfg['pasv_min_port'])}/) } if vsftpd_cfg.key?('pasv_min_port')
  if vsftpd_cfg.key?('trans_chunk_size')
    its(:content) { should match(/trans_chunk_size=#{e(vsftpd_cfg['trans_chunk_size'])}/) }
  end

  its(:content) { should match(/anon_root=#{e(vsftpd_cfg['anon_root'])}/) } if vsftpd_cfg.key?('anon_root')
  if vsftpd_cfg.key?('banned_email_file')
    its(:content) { should match(/banned_email_file=#{e(vsftpd_cfg['banned_email_file'])}/) }
  end
  its(:content) { should match(/banner_file=#{e(vsftpd_cfg['banner_file'])}/) } if vsftpd_cfg.key?('banner_file')
  its(:content) { should match(/ca_certs_file=#{e(vsftpd_cfg['ca_certs_file'])}/) } if vsftpd_cfg.key?('ca_certs_file')
  if vsftpd_cfg.key?('chown_username')
    its(:content) { should match(/chown_username=#{e(vsftpd_cfg['chown_username'])}/) }
  end
  if vsftpd_cfg.key?('chroot_list_file')
    its(:content) { should match(/chroot_list_file=#{e(vsftpd_cfg['chroot_list_file'])}/) }
  end
  its(:content) { should match(/cmds_allowed=#{e(vsftpd_cfg['cmds_allowed'])}/) } if vsftpd_cfg.key?('cmds_allowed')
  its(:content) { should match(/cmds_denied=#{e(vsftpd_cfg['cmds_denied'])}/) } if vsftpd_cfg.key?('cmds_denied')
  its(:content) { should match(/deny_file=#{e(vsftpd_cfg['deny_file'])}/) } if vsftpd_cfg.key?('deny_file')
  its(:content) { should match(/dsa_cert_file=#{e(vsftpd_cfg['dsa_cert_file'])}/) } if vsftpd_cfg.key?('dsa_cert_file')
  if vsftpd_cfg.key?('dsa_private_key_file')
    its(:content) { should match(/dsa_private_key_file=#{e(vsftpd_cfg['dsa_private_key_file'])}/) }
  end
  if vsftpd_cfg.key?('email_password_file')
    its(:content) { should match(/email_password_file=#{e(vsftpd_cfg['email_password_file'])}/) }
  end
  its(:content) { should match(/ftp_username=#{e(vsftpd_cfg['ftp_username'])}/) } if vsftpd_cfg.key?('ftp_username')
  its(:content) { should match(/ftpd_banner=#{e(vsftpd_cfg['ftpd_banner'])}/) } if vsftpd_cfg.key?('ftpd_banner')
  if vsftpd_cfg.key?('guest_username')
    its(:content) { should match(/guest_username=#{e(vsftpd_cfg['guest_username'])}/) }
  end
  its(:content) { should match(/hide_file=#{e(vsftpd_cfg['hide_file'])}/) } if vsftpd_cfg.key?('hide_file')
  if vsftpd_cfg.key?('listen_address')
    its(:content) { should match(/listen_address=#{e(vsftpd_cfg['listen_address'])}/) }
  end
  if vsftpd_cfg.key?('listen_address6')
    its(:content) { should match(/listen_address6=#{e(vsftpd_cfg['listen_address6'])}/) }
  end
  its(:content) { should match(/local_root=#{e(vsftpd_cfg['local_root'])}/) } if vsftpd_cfg.key?('local_root')
  its(:content) { should match(/message_file=#{e(vsftpd_cfg['message_file'])}/) } if vsftpd_cfg.key?('message_file')
  its(:content) { should match(/nopriv_user=#{e(vsftpd_cfg['nopriv_user'])}/) } if vsftpd_cfg.key?('nopriv_user')
  if vsftpd_cfg.key?('pam_service_name')
    its(:content) { should match(/pam_service_name=#{e(vsftpd_cfg['pam_service_name'])}/) }
  end
  its(:content) { should match(/pasv_address=#{e(vsftpd_cfg['pasv_address'])}/) } if vsftpd_cfg.key?('pasv_address')
  its(:content) { should match(/rsa_cert_file=#{e(vsftpd_cfg['rsa_cert_file'])}/) } if vsftpd_cfg.key?('rsa_cert_file')
  if vsftpd_cfg.key?('rsa_private_key_file')
    its(:content) { should match(/rsa_private_key_file=#{e(vsftpd_cfg['rsa_private_key_file'])}/) }
  end
  if vsftpd_cfg.key?('secure_chroot_dir')
    its(:content) { should match(/secure_chroot_dir=#{e(vsftpd_cfg['secure_chroot_dir'])}/) }
  end
  its(:content) { should match(/ssl_ciphers=#{e(vsftpd_cfg['ssl_ciphers'])}/) } if vsftpd_cfg.key?('ssl_ciphers')
  if vsftpd_cfg.key?('user_config_dir')
    its(:content) { should match(/user_config_dir=#{e(vsftpd_cfg['user_config_dir'])}/) }
  end
  if vsftpd_cfg.key?('user_sub_token')
    its(:content) { should match(/user_sub_token=#{e(vsftpd_cfg['user_sub_token'])}/) }
  end
  its(:content) { should match(/userlist_file=#{e(vsftpd_cfg['userlist_file'])}/) } if vsftpd_cfg.key?('userlist_file')
  if vsftpd_cfg.key?('vsftpd_log_file')
    its(:content) { should match(/vsftpd_log_file=#{e(vsftpd_cfg['vsftpd_log_file'])}/) }
  end
  its(:content) { should match(/xferlog_file=#{e(vsftpd_cfg['xferlog_file'])}/) } if vsftpd_cfg.key?('xferlog_file')
end

describe service('vsftpd') do
  it { should be_enabled }
  it { should be_running }
end

# describe port(80) do
#   it { should be_listening }
# end
