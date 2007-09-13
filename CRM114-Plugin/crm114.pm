# CRM114 Plugin for SpamAssassin
#
# Features:
# - optionally use static or dynamic spam-/ham-scores
# - adds template tags for custom header lines
# - trains CRM114 on "spamassassin --report/--revoke"
#
# Notes:
# - Training is now faster. I read the CRM114 README again
#   and removed the unnecessary checking.
#   (Quote: "It is safe to run mailtrainer.crm repeatedly [...];
#   if the data doesn't need to be trained in, it won't be.")
# - Do not worry too much about performance and CPU costs, unless
#   you know you are really CPU bound. (And not just waiting for
#   your slow DNS server to reply.)
#   
# Problems/ToDo:
# - I still want to convert the comments into a POD documentation.
# - I usually use sa-learn to train my filter an would like to have sa-learn
#   call this plugin as well. But the used callback bayes_learn() 
#   does not seem to give access to the full message.
# - If you use CRM114's cache then note that SA will only write headers
#   beginning with "X-Spam-" but CRM114 looks for "X-CRM114-CacheID".
#   Training with "spamassassin --report/--revoke" should work
#   (because this plugin handles the renaming) but otherwise
#   you will have to change that line before training from cache.
#
# Amavis-Notes:
# I use Amavis to call SpamAssassin. Here are patches to include the
# additional CRM114-Headers into every Mail:
# against amavisd-new-2.4.5: http://mschuette.name/files/amavisd.245.patch
# against amavisd-new-2.5.2: http://mschuette.name/files/amavisd.252.patch
#
#############################################################################
#
# Version: 0.1, 070406
# Version: 0.2, 070408
# Version: 0.3, 070409
# Version: 0.3.1, 070412 (fixed typo)
# Version: 0.3.2, 070414 (checked documentation)
# Version: 0.4, 070421 (added crm114_autolearn)
# Version: 0.4.1, 070430 (fixed crm114_autolearn)
# Version: 0.4.2, 070501 (fixed crm114_autolearn again)
# Version: 0.4.3, 070506 (fixed crm114_autolearn again, now tested)
# Version: 0.5, 070507 (works with SA 3.2.0)
# Version: 0.6, 070514 (crm114_autodisable_score, omit test before learning)
# Version: 0.6.1, 070516 (adjusted 'CRM and SA disagree' condition)
# Version: 0.6.2, 070802 (fixed small bug, thanks to Rick Cooper)
# Version: 0.6.3, 070815 (now trying to prevent zombie processes)
# Version: 0.6.4, 070819 (use helper_app_pipe_open-code from Plugin::Pyzor)
# Version: 0.6.5, 070821 (fixed bug in pipe_open-code, thanks to Robert Horton)
# Version: 0.6.6, 070913 (fixed crm114_use_cacheid, added debug-tag)
# 
# Thanks to Tomas Charvat for testing.
#
# Initially based on plugin by Eugene Morozov:
#   http://eugene.renice.org/spamassassin/crm114.pm
# 
# Also borrowing from the Mail::SpamAssassin::Plugin-modules.
#
# Everything else is
#   Copyright 2007, Martin Schütte <info@mschuette.name>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#       http://www.apache.org/licenses/LICENSE-2.0
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#############################################################################

package crm114;

use strict;
use warnings "all";
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;

  # the usual perlobj boilerplate to create a subclass object
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  # then register an eval rule
  $self->register_eval_rule ("check_crm");

  $self->set_config($mailsa->{conf});

  # uncomment to always get debugging output on stderr
  #Mail::SpamAssassin::Logger::add_facilities('crm114');

  # and return the new plugin object
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'crm114_command',
    default => 'crm -u ~/.crm114 mailreaver.crm',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });
  push (@cmds, {
    setting => 'crm114_learn',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });
  push (@cmds, {
    setting => 'crm114_autolearn',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });
  push (@cmds, {
    setting => 'crm114_remove_existing_spam_headers',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });
  push (@cmds, {
    setting => 'crm114_remove_existing_virus_headers',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });
  push (@cmds, {
    setting => 'crm114_staticscore_good',
    default => -3,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_staticscore_unsure',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_staticscore_spam',
    default => 3,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_dynscore',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });
  # compute default crm114_dynscore_factor
  # so that CRM score 25 yields SA required_score
  my $default_crm114_dynscore_factor = $conf->{required_score} / -25;
  push (@cmds, {
    setting => 'crm114_dynscore_factor',
    default => $default_crm114_dynscore_factor,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_use_cacheid',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });
  push (@cmds, {
    setting => 'crm114_autodisable_negative_score',
    default => -999,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_autodisable_score',
    default => 999,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_timeout',
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub call_crm {
  my ($self, $status, $action) = @_;
  my $crm114_score = "0";
  my $crm114_status = "UNKNOWN";

  my $crm114_command = $self->{main}->{conf}->{crm114_command};
  my $crm114_remove_existing_spam_headers =
            $self->{main}->{conf}->{crm114_remove_existing_spam_headers};
  my $crm114_remove_existing_virus_headers =
            $self->{main}->{conf}->{crm114_remove_existing_virus_headers};
  my $crm114_use_cacheID = $self->{main}->{conf}->{crm114_use_cacheid};
  my $crm114_timeout = $self->{main}->{conf}->{crm114_timeout};

  # get seperate header und body, because we filter the headers
  my $hdr = $status->get_message()->get_pristine_header();
  #my $bdy = $status->get_message()->get_pristine_body();
  my $fullref = \$status->get_message()->get_pristine();

  # if a Cache is used and the CacheID is included in every mail,
  # then it should be used. the renaming is necessary because
  # a) CRM114 looks only for "X-CRM114-CacheID"
  # b) that way we easily pass the spam header removing below
  if ($crm114_use_cacheID && ($action ne "check")) {
    $hdr =~ s/^X-Spam-CRM114-CacheID: (.*)$/X-CRM114-CacheID: $1/;
  }
  if ($crm114_remove_existing_spam_headers) {
    $hdr =~ s/^X-Spam-[^:]*:.*(\n\s.*)*\n//mg;
  }
  if ($crm114_remove_existing_virus_headers) {
    $hdr =~ s/^X-Virus-[^:]*:.*(\n\s.*)*\n//mg;
  }

  my $crm114_option;
  $crm114_option = "" if ($action eq "check");
  $crm114_option = "--spam" if ($action eq "train_spam");
  $crm114_option = "--good" if ($action eq "train_good");
  my $crm114_cmdline = join(" ", ($crm114_command, $crm114_option));

  dbg(sprintf("crm114: call_crm() called, action: %s", $action));

  # Step 1: call CRM114
  # code copied from Plugin::Pyzor
  my ($pid, @response);
  my $tmpf = $status->create_fulltext_tmpfile($fullref);
  $status->enter_helper_run_mode();
  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $crm114_timeout });
  
  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };
    dbg("crm114: opening pipe: $crm114_cmdline < $tmpf");
    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(
                                  *CRM_OUT,	$tmpf, 1, $crm114_cmdline);
    $pid or die "crm114: $!\n";
    
    @response = <CRM_OUT>;
    close CRM_OUT
      or dbg(sprintf("crm114: [%s] finished: %s exit=0x%04x",$pid,$!,$?));
      
    if (!@response) {
      die("no response\n");
    }
  });
  
  if (defined(fileno(*CRM_OUT))) {  # still open
    if ($pid) {
      if (kill('TERM',$pid)) { dbg("crm114: killed stale helper [$pid]") }
      else { dbg("crm114: killing helper application [$pid] failed: $!") }
    }
    close CRM_OUT
      or dbg(sprintf("crm114: [%s] terminated: %s exit=0x%04x",$pid,$!,$?));
  }
  $status->leave_helper_run_mode();
  if ($timer->timed_out()) {
    dbg("crm114: check timed out after timeout seconds");
    return 0;
  }
  if ($err) {
    chomp $err;
    if ($err eq "__brokenpipe__ignore__") {
      dbg("crm114: check failed: broken pipe");
    } elsif ($err eq "no response") {
      dbg("crm114: check failed: no response");
    } else {
      warn("crm114: check failed: $err\n");
    }
  }
  
  # Step 2: parse output
  # we only look for the bits we're going to return to SA
  # and ignore everything else (just like Amavis does when calling SA)
  my $line;
  foreach $_ (@response) {
    if (/^X-CRM114-Version: (.+)$/) {
      $status->set_tag("CRM114VERSION", $1);
      dbg(sprintf("crm114: found version %s", $1));
    }
    elsif (/^X-CRM114-CacheID: (.+)$/) {
      $status->set_tag("CRM114CACHEID", $1);
      dbg(sprintf("crm114: found CacheID %s", $1));
    }
    elsif (/^X-CRM114-Notice: (.+)$/) {
      $status->set_tag("CRM114NOTICE", $1);
      dbg(sprintf("crm114: found Notice %s", $1));
    }
    elsif (/^X-CRM114-Status: ([A-Z]+)\s+\(\s+([-\d\.]+)\s+\)/) {
      $crm114_status = $1;
      $crm114_score = $2;
      $status->set_tag("CRM114STATUS", $crm114_status);
      $status->set_tag("CRM114SCORE", $crm114_score);
      dbg(sprintf("crm114: found status %s and score %s",
                  $crm114_status, $crm114_score));
    }
    elsif (/^X-CRM114-Action: (.+)$/) {
      $status->set_tag("CRM114ACTION", $1);
      dbg(sprintf("crm114: found Action %s", $1));
    }
    elsif (/(^X-CRM114.*$)/) {
      dbg(sprintf("crm114: found unknown CRM114-header '%s", $1));
    }
  }

  # for debugging: this lets us include original crm114-output into the mail  
  $status->set_tag("CRM114DEBUG", join("|", @response[0 .. 10]));

  dbg(sprintf("crm114: call_crm returns (%s, %s)",
                       $crm114_status, $crm114_score));
  return ($crm114_status, $crm114_score);
}

sub check_crm {
  my ($self, $status) = @_;

  # Step 0: get options
  my $crm114_staticscore_good =
          $self->{main}->{conf}->{crm114_staticscore_good};
  my $crm114_staticscore_unsure =
          $self->{main}->{conf}->{crm114_staticscore_unsure};
  my $crm114_staticscore_spam =
          $self->{main}->{conf}->{crm114_staticscore_spam};
  my $crm114_dynscore = $self->{main}->{conf}->{crm114_dynscore};
  my $crm114_dynscore_factor =
          $self->{main}->{conf}->{crm114_dynscore_factor};
  my $crm114_autodisable_negative_score =
          $self->{main}->{conf}->{crm114_autodisable_negative_score};
  my $crm114_autodisable_score =
          $self->{main}->{conf}->{crm114_autodisable_score};

  # init SA template tags, in case we cannot find real values
  $status->set_tag("CRM114VERSION", "UNKNOWN");
  $status->set_tag("CRM114CACHEID", "UNKNOWN");
  $status->set_tag("CRM114STATUS",  "UNKNOWN");
  $status->set_tag("CRM114ACTION",  "UNKNOWN");
  $status->set_tag("CRM114SCORE",   "0");
  # and one additional for debugging
  $status->set_tag("CRM114DEBUG",  "");

  # check if message already classified and CRM114 disabled
  my $sa_prevscore = $status->get_score();
  if (($sa_prevscore < $crm114_autodisable_negative_score)
   || ($sa_prevscore > $crm114_autodisable_score)) {
    warn("crm114: skip test because score=$sa_prevscore");
    return 0;
  }

  # Step 2: call CRM114
  my ($crm114_status, $crm114_score) = $self->call_crm($status, "check");

  # Step 3: return vales to SA
  if ("UNKNOWN" eq $crm114_status) {
    # Error --> no score returned
    warn("crm114: Error. Failed to get CRM114-Status.");
  }
  else {
    # OK, got my score
    
    # first check if CRM and SA scores differ too much
    my $sa_reqscore = $status->get_required_score();
    if (((($sa_prevscore + $crm114_score) > $sa_reqscore) && ($crm114_status eq "GOOD"))
     || ((($sa_prevscore + $crm114_score) < 0) && ($crm114_status eq "SPAM"))) {
      warn ("crm114: CRM and SA disagree over message status");
    }

    # and now return something to SA
    my $description = sprintf("message is %s with crm114-score %3.4f",
                      $crm114_status, $crm114_score);
    if ($crm114_dynscore) {
      # return dynamic score --> normalize CRM114-score to SA-score
      my $sa_score = $crm114_dynscore_factor * $crm114_score;
      for my $set (0..3) {
        $status->{conf}->{scoreset}->[$set]->{"CRM114_CHECK"} = 
                                              sprintf("%0.3f", $sa_score);
      }

      # Set dynamic description
      $status->{conf}->{descriptions}->{CRM114_CHECK} = 
                                                           $description;
      # Set dynamic score
      $status->got_hit("CRM114_CHECK", "CRM114: ",
                       score => $sa_score, ruletype => "full");
      dbg(sprintf("crm114: score is %3.4f, translated to SA score: %3.4f, linear factor was %3.4f",
                  $crm114_score, $sa_score, $crm114_dynscore_factor));
    }
    else {
      # no dynamic score --> return status
      if ($crm114_status eq "GOOD") {
        $status->{conf}->{descriptions}->{CRM114_GOOD} = 
                                                           $description;
        $status->{conf}->{scores}->{"CRM114_GOOD"} = $crm114_staticscore_good;
        $status->got_hit("CRM114_GOOD", "CRM114: ",
                       score => $crm114_staticscore_good, ruletype => "full");
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_GOOD", 
                               $crm114_score));
      }
      elsif ($crm114_status eq "UNSURE") {
        $status->{conf}->{descriptions}->{CRM114_UNSURE} = 
                                                           $description;
        $status->{conf}->{scores}->{"CRM114_UNSURE"} = $crm114_staticscore_unsure;
        $status->got_hit("CRM114_UNSURE", "CRM114: ",
                       score => $crm114_staticscore_unsure, ruletype => "full");
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_UNSURE", 
                               $crm114_score));
      }
      elsif ($crm114_status eq "SPAM") {
        $status->{conf}->{descriptions}->{CRM114_SPAM} = 
                                                           $description;
        $status->{conf}->{scores}->{"CRM114_SPAM"} = $crm114_staticscore_spam;
        $status->got_hit("CRM114_SPAM", "CRM114: ",
                       score => $crm114_staticscore_spam, ruletype => "full");
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_SPAM",
                               $crm114_score));
      }
      else {  # status UNKNOWN --> no score
        0;
      }
    }
  }
  return 0;
}

sub plugin_report {
  my ($self, $options) = @_;

  dbg("crm114: plugin_report() called");
  return unless $self->{main}->{conf}->{crm114_learn};

  # call_crm() needs a PerMsgStatus object
  my $pms = Mail::SpamAssassin::PerMsgStatus->new($self, $options->{msg});
  $self->call_crm($pms, "train_spam");
  if ("LEARNED AND CACHED SPAM" eq $pms->get_tag("CRM114ACTION")) {
    $options->{report}->{report_available} = 1;
    $options->{report}->{report_return} = 1;
    dbg("crm114: trained spam message");
  }
  else {
    warn(sprintf("crm114: error in training, unexpected Action: %s",
            $pms->get_tag("CRM114ACTION")));
  }
}

sub plugin_revoke {
  my ($self, $options) = @_;

  dbg("crm114: plugin_revoke() called");
  return unless $self->{main}->{conf}->{crm114_learn};

  # call_crm() needs a PerMsgStatus object
  my $pms = Mail::SpamAssassin::PerMsgStatus->new($self, $options->{msg});
  $self->call_crm($pms, "train_good");
  if ("LEARNED AND CACHED GOOD" eq $pms->get_tag("CRM114ACTION")) {
    $options->{revoke}->{revoke_available} = 1;
    $options->{revoke}->{revoke_return} = 1;
    dbg("crm114: trained ham/good message");
  } else {
    warn(sprintf("crm114: error in training, unexpected Action: %s",
            $pms->get_tag("CRM114ACTION")));
  }
}

sub autolearn {
  my ($self, $options) = @_;

  dbg("crm114: autolearn() called");
  return unless $self->{main}->{conf}->{crm114_autolearn};

  if ($options->{isspam} == 1) {
    $self->call_crm($options->{permsgstatus}, "train_spam");
    if ("LEARNED AND CACHED SPAM" eq $options->{permsgstatus}->get_tag("CRM114ACTION")) {
      dbg("crm114: trained spam message");
    }
    else {
      warn(sprintf("crm114: error in training, unexpected Action: %s",
              $options->{permsgstatus}->get_tag("CRM114ACTION")));
    }
  }
  else {
    $self->call_crm($options->{permsgstatus}, "train_good");
    if ("LEARNED AND CACHED GOOD" eq $options->{permsgstatus}->get_tag("CRM114ACTION")) {
      dbg("crm114: trained spam message");
    }
    else {
      warn(sprintf("crm114: error in training, unexpected Action: %s",
              $options->{permsgstatus}->get_tag("CRM114ACTION")));
    }
  }
}

1;
