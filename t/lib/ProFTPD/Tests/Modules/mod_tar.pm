package ProFTPD::Tests::Modules::mod_tar;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Archive::Tar;
use Archive::Tar::File;
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

  # XXX Need a working IO::Compress installion for this
#  tar_retr_tar_bz2 => {
#    order => ++$order,
#    test_class => [qw(forking)],
#  },

  tar_retr_2gb => {
    order => ++$order,
    test_class => [qw(forking slow)],
  },

  # tar_temp_path, aborted downloads and cleanup

  # tar_xferlog, making sure the originally requested name is logged
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
#  return testsuite_get_runnable_tests($TESTS);
  return qw(
    tar_notar
  );
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

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

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

1;
