package ProFTPD::Tests::Modules::mod_tar;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Archive::Tar;
use Archive::Tar::File;
use Archive::Zip qw(:ERROR_CODES :CONSTANTS);
use Cwd;
use Digest::MD5;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Zlib;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  tar_retr_file => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_tar => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_tar_already_exists => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_tar_symlinks => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # XXX tar_retr_tar_subdirs

  # XXX Need test for absolute symlinks, and chrooted session
  tar_retr_tar_symlinks_opt_dereference => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_enable_off => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_notar => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_tar_gz => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_tgz => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_tar_bz2 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_xferlog_retr_tar => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_tmp_path_cleanup_on_abort => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  # XXX tar_tmp_path_dev_full (on Linux), to test out-of-space handling

  tar_retr_tar_2gb_single_file => {
    order => ++$order,
    test_class => [qw(forking slow)],
  },

   # XXX tar_retr_tar_2gb_many_files

  tar_retr_zip => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub tar_retr_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$home_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("test.txt.tar");
      if ($conn) {
        die("RETR test.txt.tar succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'test.txt.tar: No such file or directory';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar");
      unless ($conn) {
        die("RETR subdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $tar = Archive::Tar->new($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 2;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'subdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      $expected = 'subdir/test.txt';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      # Make sure the file contents have not been corrupted in transit

      $ctx = Digest::MD5->new();
      $ctx->add($tar->get_content('subdir/test.txt')); 

      my $test_md5 = $ctx->hexdigest();

      $self->assert($test_md5 eq $expected_md5,
        test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar_already_exists {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $archive = File::Spec->rel2abs("t/etc/modules/mod_tar/subdir.tar");
  my $test_file = File::Spec->rel2abs("$tmpdir/subdir.tar");
  unless (copy($archive, $test_file)) {
    die("Can't copy $archive to $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  $ctx->add("Hello, World!\n");
  my $expected_md5 = $ctx->hexdigest();

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar");
      unless ($conn) {
        die("RETR subdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $tar = Archive::Tar->new($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 2;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'subdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      $expected = 'subdir/test.txt';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      # Make sure the file contents have not been corrupted in transit

      $ctx = Digest::MD5->new();
      $ctx->add($tar->get_content('subdir/test.txt')); 

      my $test_md5 = $ctx->hexdigest();

      $self->assert($test_md5 eq $expected_md5,
        test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar_symlinks {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Create three files in subdir
  for (my $i = 0; $i < 3; $i++) {
    my $test_file = File::Spec->rel2abs("$sub_dir/test" . ($i + 1) . ".txt");
    if (open(my $fh, "> $test_file")) {
      print $fh "Hello, World!\n";
      unless (close($fh)) {
        die("Can't write $test_file: $!");
      }

    } else {
      die("Can't open $test_file: $!");
    }
  }

  my $symlink_dir = File::Spec->rel2abs("$tmpdir/symlinkdir");
  mkpath($symlink_dir);

  # Create three symlinks in symlinkdir to the files in subdir (using
  # relative paths).

  my $cwd = getcwd();

  unless (chdir($symlink_dir)) {
    die("Can't chdir to $symlink_dir: $!");
  }

  # Create three files in subdir
  for (my $i = 0; $i < 3; $i++) {
    my $symlink_src = "../subdir/test" . ($i + 1) . ".txt";
    my $symlink_dst = "./test" . ($i + 1) . ".lnk";

    unless (symlink($symlink_src, $symlink_dst)) {
      die("Can't symlink '$symlink_src' to '$symlink_dst': $!");
    }
  }

  unless (chdir($cwd)) {
    die("Can't chdir to $cwd: $!");
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("symlinkdir.tar");
      unless ($conn) {
        die("RETR symlinkdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $tar = Archive::Tar->new($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 4;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'symlinkdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      for (my $i = 0; $i < 3; $i++) {
        $expected = "symlinkdir/test" . ($i + 1) . '.lnk';
        $self->assert(defined($entries->{$expected}),
          test_msg("Expected entry for '$expected', did not see one"));

        my $ent = ($tar->get_files($expected))[0];
        $self->assert(defined($ent),
          test_msg("Unable to get info for $expected from archive"));

        $self->assert($ent->is_symlink(),
          test_msg("File $expected is not a symlink as expected"));

        $expected = '../subdir/test' . ($i + 1) . '.txt';
        my $ent_linkname = $ent->linkname();
        $self->assert($ent_linkname eq $expected,
          test_msg("Expected linkname '$expected', got '$ent_linkname'"));
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar_symlinks_opt_dereference {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Create three files in subdir
  for (my $i = 0; $i < 3; $i++) {
    my $test_file = File::Spec->rel2abs("$sub_dir/test" . ($i + 1) . ".txt");
    if (open(my $fh, "> $test_file")) {
      print $fh "Hello, World!\n";
      unless (close($fh)) {
        die("Can't write $test_file: $!");
      }

    } else {
      die("Can't open $test_file: $!");
    }
  }

  my $symlink_dir = File::Spec->rel2abs("$tmpdir/symlinkdir");
  mkpath($symlink_dir);

  # Create three symlinks in symlinkdir to the files in subdir (using
  # relative paths).

  my $cwd = getcwd();

  unless (chdir($symlink_dir)) {
    die("Can't chdir to $symlink_dir: $!");
  }

  # Create three files in subdir
  for (my $i = 0; $i < 3; $i++) {
    my $symlink_src = "../subdir/test" . ($i + 1) . ".txt";
    my $symlink_dst = "./test" . ($i + 1) . ".lnk";

    unless (symlink($symlink_src, $symlink_dst)) {
      die("Can't symlink '$symlink_src' to '$symlink_dst': $!");
    }
  }

  unless (chdir($cwd)) {
    die("Can't chdir to $cwd: $!");
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
        TarOptions => 'dereference',
#        TarOptions => 'FollowSymlinks',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("symlinkdir.tar");
      unless ($conn) {
        die("RETR symlinkdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $tar = Archive::Tar->new($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 4;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'symlinkdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      for (my $i = 0; $i < 3; $i++) {
        $expected = "symlinkdir/test" . ($i + 1) . '.lnk';
        $self->assert(defined($entries->{$expected}),
          test_msg("Expected entry for '$expected', did not see one"));

        my $ent = ($tar->get_files($expected))[0];
        $self->assert(defined($ent),
          test_msg("Unable to get info for $expected from archive"));

        $self->assert($ent->is_file(),
          test_msg("File $expected is not a symlink as expected"));

        $expected = 14;
        my $ent_sz = $ent->size();
        $self->assert($ent_sz == $expected,
          test_msg("Expected file size $expected, got $ent_sz"));
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_enable_off {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # MacOSX-specific hack
  if ($^O eq 'darwin') {
    $sub_dir = ('/private' . $sub_dir);
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    Directory => {
      $sub_dir => {
        TarEnable => 'off',
      },
    },

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      # This should fail, since the file doesn't exist, and we configured
      # "TarEnable off" in that directory.
      my $conn = $client->retr_raw("subdir.tar");
      if ($conn) {
        die("RETR subdir.tar succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'subdir.tar: No such file or directory';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_notar {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $notar_file = File::Spec->rel2abs("$sub_dir/.notar");
  if (open(my $fh, "> $notar_file")) {
    unless (close($fh)) {
      die("Can't write $notar_file: $!");
    }

  } else {
    die("Can't open $notar_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      # This should fail, since the file doesn't exist, and we configured
      # a .notar file in that directory.
      my $conn = $client->retr_raw("subdir.tar");
      if ($conn) {
        die("RETR subdir.tar succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'subdir.tar: No such file or directory';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar_gz {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar.gz");
      unless ($conn) {
        die("RETR subdir.tar.gz failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $zio = IO::Zlib->new($conn, 'rb');
      my $tar = Archive::Tar->new($zio);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 2;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'subdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      $expected = 'subdir/test.txt';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      # Make sure the file contents have not been corrupted in transit

      $ctx = Digest::MD5->new();
      $ctx->add($tar->get_content('subdir/test.txt')); 

      my $test_md5 = $ctx->hexdigest();

      $self->assert($test_md5 eq $expected_md5,
        test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tgz {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tgz");
      unless ($conn) {
        die("RETR subdir.tgz failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $zio = IO::Zlib->new($conn, 'rb');
      my $tar = Archive::Tar->new($zio);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 2;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'subdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      $expected = 'subdir/test.txt';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      # Make sure the file contents have not been corrupted in transit

      $ctx = Digest::MD5->new();
      $ctx->add($tar->get_content('subdir/test.txt')); 

      my $test_md5 = $ctx->hexdigest();

      $self->assert($test_md5 eq $expected_md5,
        test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar_bz2 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $src_file = File::Spec->rel2abs("$sub_dir/src.bin");
  if (open(my $fh, "> $src_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $src_file: $!");
    }

  } else {
    die("Can't open $src_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $src_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $src_file: $!");
  }

  my $dst_bz2_file = File::Spec->rel2abs("$tmpdir/dst.tar.bz2");
  my $dst_tar_file = File::Spec->rel2abs("$tmpdir/dst.tar");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar.bz2");
      unless ($conn) {
        die("RETR subdir.tar.bz2 failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      # Download the data to a separate bunzipped file, and let Archive::Tar
      # work on that.

      my $dstfh;
      unless (open($dstfh, "> $dst_bz2_file")) {
        die("Can't open $dst_bz2_file: $!");
      }
      binmode($dstfh);

      my $buf;
      my $buflen = 16384;
      while ($conn->read($buf, $buflen, 25)) {
        print $dstfh $buf;
      }

      unless (close($dstfh)) {
        die("Can't write $dst_bz2_file: $!");
      }

      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    # Uncompress the file
    `bunzip2 -q $dst_bz2_file`;

    my $dstfh;
    unless (open($dstfh, "< $dst_tar_file")) {
      die("Can't read $dst_tar_file: $!");
    }
    binmode($dstfh);

    my $tar = Archive::Tar->new($dstfh);
    unless (defined($tar)) {
      die("Can't read tar file from $dst_tar_file: " . $Archive::Tar::error);
    }

    my $entries = { map { $_ => 1 } $tar->list_files() };

    # Make sure the hashref contains the entries we expect
    my $expected = 2;
    my $nents = scalar(keys(%$entries));
    $self->assert($nents == $expected,
      test_msg("Expected $expected entries, found $nents"));

    $expected = 'subdir/';
    $self->assert(defined($entries->{$expected}),
      test_msg("Expected entry for '$expected', did not see one"));

    $expected = 'subdir/src.bin';
    $self->assert(defined($entries->{$expected}),
      test_msg("Expected entry for '$expected', did not see one"));

    # Make sure the file contents have not been corrupted in transit

    $ctx = Digest::MD5->new();
    $ctx->add($tar->get_content('subdir/src.bin')); 

    my $test_md5 = $ctx->hexdigest();

    $self->assert($test_md5 eq $expected_md5,
      test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));

    close($dstfh);
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_xferlog_retr_tar {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $xfer_log = File::Spec->rel2abs("$tmpdir/xfer.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    TransferLog => $xfer_log,

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar");
      unless ($conn) {
        die("RETR subdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $tar = Archive::Tar->new($conn);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 2;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'subdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      $expected = 'subdir/test.txt';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      # Make sure the file contents have not been corrupted in transit

      $ctx = Digest::MD5->new();
      $ctx->add($tar->get_content('subdir/test.txt')); 

      my $test_md5 = $ctx->hexdigest();

      $self->assert($test_md5 eq $expected_md5,
        test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    # Now read in the TransferLog, make sure that the filename is the originally
    # requested name, not the name as modified by mod_tar.

    if (open(my $fh, "< $xfer_log")) {
      my $line = <$fh>;
      chomp($line);
      close($fh);

      my $expected = '^\S+\s+\S+\s+\d+\s+\d+:\d+:\d+\s+\d+\s+\d+\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+_\s+o\s+r\s+(\S+)\s+ftp\s+0\s+\*\s+c$';

      $self->assert(qr/$expected/, $line,
        test_msg("Expected '$expected', got '$line'"));

      if ($line =~ /$expected/) {
        my $remote_host = $1;
        my $filesz = $2;
        my $filename = $3;
        my $xfer_type = $4;
        my $user_name = $5;

        $expected = '127.0.0.1';
        $self->assert($expected eq $remote_host,
          test_msg("Expected '$expected', got '$remote_host'"));

        # The original filename, sans .tar extension
        $expected = $sub_dir;

        if ($^O eq 'darwin') {
          # MacOSX-specific hack dealing with their tmp filesystem shenanigans
          $expected = ('/private' . $expected);
        }

        $self->assert($expected eq $filename,
          test_msg("Expected '$expected', got '$filename'"));

        $expected = 'b';
        $self->assert($expected eq $xfer_type,
          test_msg("Expected '$expected', got '$xfer_type'"));

        $expected = $user;
        $self->assert($expected eq $user_name,
          test_msg("Expected '$expected', got '$user_name'"));

      } else {
        die("Can't read $xfer_log: $!");
      }
    }
  };

  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_tmp_path_cleanup_on_abort {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $tmp_path = File::Spec->rel2abs("$tmpdir/tarwork");
  mkpath($tmp_path);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
        TarTempPath => $tmp_path,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar");
      unless ($conn) {
        die("RETR subdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      # Read in a couple of bytes, then abort the connection.
      my $buf;
      $conn->read($buf, 4, 25);
      $conn->abort();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Abort successful';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      # Scan the TarTempPath, make sure there are no files in there.
      my $dirh;
      unless (opendir($dirh, $tmp_path)) {
        die("Can't open directory '$tmp_path': $!");
      }

      my $tmp_files = [grep { !/^\.$/ && !/^\.\.$/ } readdir($dirh)];
      closedir($dirh);

      my $nfiles = scalar(@$tmp_files);
      $self->assert($nfiles == 0,
        test_msg("Expected no tmp files, found $nfiles"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_tar_2gb_single_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $src_file = File::Spec->rel2abs("$sub_dir/src.bin");

  # Create a file that is 2GB.
  my $src_len = (2 ** 31);
  if (open(my $fh, "> $src_file")) {

    if ($ENV{TEST_VERBOSE}) {
      print STDOUT "# Creating test file of $src_len bytes\n";
    }

    my $nchunks = 64;
    my $chunklen = ($src_len / $nchunks);

    for (my $i = 0; $i < $nchunks; $i++) {
      print $fh "A" x $chunklen;
    }

    unless (close($fh)) {
      die("Can't write $src_file: $!");
    }

  } else {
    die("Can't open $src_file: $!");
  }

  my $dst_file = File::Spec->rel2abs("$tmpdir/dst.tar");

  # This test could run for a while, since mod_tar has to read in the large
  # file.  So give the test time to run.
  my $timeout_idle = 1800;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0,
        10, $timeout_idle);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.tar");
      unless ($conn) {
        die("RETR subdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      # I'm not sure why, but Archive::Tar does not like reading tar data
      # directly from the $conn if that tar data contains large files.
      #
      # To work around this, read the data from $conn into a local temp
      # file, then set Archive::Tar to work on that local file.

      my $dstfh;
      unless (open($dstfh, "> $dst_file")) {
        die("Can't write $dst_file: $!");
      }
      binmode($dstfh);

      my $buf;
      my $buflen = 16384;

      while ($conn->read($buf, $buflen, 25)) {
        print $dstfh $buf;
      }

      unless (close($dstfh)) {
        die("Can't write $dst_file: $!");
      }

      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      unless (open($dstfh, "< $dst_file")) {
        die("Can't read $dst_file: $!");
      }
      binmode($dstfh);

      if ($ENV{TEST_VERBOSE}) {
        print STDOUT "# Finished downloading to $dst_file, verifying tar format\n";
      }

      my $tar = Archive::Tar->new($dstfh);
      my $entries = { map { $_ => 1 } $tar->list_files() };

      # Make sure the hashref contains the entries we expect
      $expected = 2;
      my $nents = scalar(keys(%$entries));
      $self->assert($nents == $expected,
        test_msg("Expected $expected entries, found $nents"));

      $expected = 'subdir/';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      $expected = 'subdir/src.bin';
      $self->assert(defined($entries->{$expected}),
        test_msg("Expected entry for '$expected', did not see one"));

      my $ent = ($tar->get_files($expected))[0];
      $self->assert(defined($ent),
        test_msg("Expected entry for '$expected', did not see one"));

      my $ent_len = $ent->size();
      $self->assert($ent_len eq $src_len,
        test_msg("Expected file length $src_len, got $ent_len"));

      close($dstfh);
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 10) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub tar_retr_zip {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/tar.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/tar.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/tar.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/tar.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/tar.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$tmpdir/subdir");
  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$sub_dir/src.bin");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $dst_zip_file = File::Spec->rel2abs("$tmpdir/dst.zip");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 tar:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_tar.c' => {
        TarEngine => 'on',
        TarLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->retr_raw("subdir.zip");
      unless ($conn) {
        die("RETR subdir.tar failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $dstfh;
      unless (open($dstfh, "> $dst_zip_file")) {
        die("Can't open $dst_zip_file: $!");
      }

      my $buf;
      my $buflen = 16384;
      while ($conn->read($buf, $buflen, 25)) {
        print $dstfh $buf;
      }

      unless (close($dstfh)) {
        die("Can't write $dst_zip_file: $!");
      }

      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    my $zip = Archive::Zip->new($dst_zip_file);

    my $entries = [$zip->members()];

    # Make sure the arrayref contains the entries we expect
    my $expected = 2;
    my $nents = scalar(@$entries);
    $self->assert($nents == $expected,
      test_msg("Expected $expected entries, found $nents"));

    $expected = 'subdir/';
    my $ent = $zip->memberNamed($expected);
    $self->assert(defined($ent),
      test_msg("Expected entry for '$expected', did not see one"));

    $expected = 'subdir/src.bin';
    $ent = $zip->memberNamed($expected);
    $self->assert(defined($ent),
      test_msg("Expected entry for '$expected', did not see one"));

    # Make sure the file contents have not been corrupted in transit

    $ctx = Digest::MD5->new();
    my $data = $zip->contents('subdir/src.bin');
    $ctx->add($data);

    my $test_md5 = $ctx->hexdigest();

    $self->assert($test_md5 eq $expected_md5,
      test_msg("Expected MD5 checksum '$expected_md5', got '$test_md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

1;
