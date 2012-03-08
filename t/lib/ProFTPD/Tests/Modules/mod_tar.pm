package ProFTPD::Tests::Modules::mod_tar;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Archive::Tar;
use Cwd;
use Digest::MD5;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

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

  tar_retr_symlinks => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  tar_retr_symlinks_followed => {
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

  tar_retr_4gb => {
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

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
#  return testsuite_get_runnable_tests($TESTS);
  return qw(
    tar_retr_tar_gz
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

sub tar_retr_symlinks {
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

use Data::Dumper;
print STDERR "entries: ", Dumper($entries), "\n";

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
