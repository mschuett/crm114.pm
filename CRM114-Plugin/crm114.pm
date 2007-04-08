#
# SpamAssassin Plugin for CRM114
#
#   Copyright 2007, Martin Sch�tte <info@mschuette.name>
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
#
# initially based on plugin by Eugene Morozov:
#   http://eugene.renice.org/spamassassin/crm114.pm
#
# Features:
# - optionally use static or dynamic spam-/ham-scores
# - adds template tags for custom header lines
#
# Problems/ToDo:
# - Convert comments into a POD documentation.
# - I tried to convert the open2() into
#   Mail::SpamAssassin::Util::helper_app_pipe_open()
#   like in Mail::SpamAssassin::Plugin::DCC, Pyzor et al
#   but I failed because I did not get the output
# - I would like to implement some methods to train the filter, so that
#   sa-learn would train the CRM114-database as well (while adopting
#   CRM114's TOE-model by skipping messages already correctly classified).
#   But I could not figure out the SA interface, because the
#   callback bayes_learn() does not provide the fulltext of the message
#   and plugin_report()/plugin_revoke() are not called.
#
# Amavis-Notes:
# - Is there some easy way to pass additional information from SA to Amavis?
#   In order to add an additional Header I had to change the whole callstack
#   to add new return-values. Ist there no easier way?
#   At least the SA-functions should use and return some SA-Info-object.
#   The you only had to change call_spamassassin() to write it and
#   add_forwarding_header_edits_per_recip() to use it (and not every step
#   inbetween as well :-/ )
# - That Problem also involves caching. I did not add cache-field and now
#   I get mails with an empty X-Spam-CRM114-Status because the SA-field are
#   looked up in the cache and the CRM fields stay empty.
#
# Version: 0.1, 070406
# Version: 0.2, 070408
# 
package crm114;

use strict;
use warnings "all";
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use IPC::Open2;
our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;

  # the usual perlobj boilerplate to create a subclass object
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->{crm114_command} = 
                "/usr/local/bin/crm -u /var/amavis/.crm114 mailreaver.crm";

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
    default => 'crm mailreaver.crm',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });
  push (@cmds, {
    setting => 'crm114_learn',
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
  # so that CRM score 40 yields SA required_score
  my $default_crm114_dynscore_factor = $conf->{required_score} / -40;
  push (@cmds, {
    setting => 'crm114_dynscore_factor',
    default => $default_crm114_dynscore_factor,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_fulldebug',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
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
  my $crm114_fulldebug = $self->{main}->{conf}->{crm114_fulldebug};

  # get seperate header und body, because we filter the headers
  my $hdr = $status->get_message()->get_pristine_header();
  my $bdy = $status->get_message()->get_pristine_body();

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

  dbg(sprintf("crm114: call_crm() called, crm114_command set to: %s, status: %s, action: %s", $crm114_cmdline, $status, $action));

  # Step 1: call CRM114
  #$status->enter_helper_run_mode();
  #my $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*CRM,
            #$tmpf, 1, $crm114_command, $crm114_option);
  #if (!$pid) { warn(sprintf("crm114: $!\n")); return; }

  $status->enter_helper_run_mode();
  my $pid = open2(\*CRM_OUT, \*CRM_IN, $crm114_cmdline);
  dbg(sprintf("crm114: crm114_command run"));
  print CRM_IN $hdr;
  print CRM_IN $bdy;
  close CRM_IN;

  # Step 2: parse output
  # we only look for the bits we're going to return to SA
  # and ignore everything else (just like Amavis does when calling SA)
  while(<CRM_OUT>) {
    if (/^(open2: .*)/) {
      warn(sprintf("crm114: Error: %s"), $1);
    }
    elsif (/^X-CRM114-Version: (.+)$/) {
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
      dbg(sprintf("crm114: found status %s and score %s", $crm114_status, $crm114_score));
    }
    elsif (/^X-CRM114-Action: (.+)$/) {
      $status->set_tag("CRM114ACTION", $1);
      dbg(sprintf("crm114: found Action %s", $1));
    }
    elsif (/(^X-CRM114.*$)/) {
      dbg(sprintf("crm114: found unknown CRM114-header '%s", $1));
    }
  }
  close CRM_OUT;
  waitpid $pid, 0;
  $status->leave_helper_run_mode();
  
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
  my $crm114_fulldebug = $self->{main}->{conf}->{crm114_fulldebug};

  # init SA template tags, in case we cannot find real values
  $status->set_tag("CRM114VERSION", "UNKNOWN");
  $status->set_tag("CRM114CACHEID", "UNKNOWN");
  $status->set_tag("CRM114STATUS",  "UNKNOWN");
  $status->set_tag("CRM114ACTION",  "UNKNOWN");
  $status->set_tag("CRM114SCORE",   "0");

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
    my $sa_prevscore = $status->get_score();
    my $sa_reqscore = $status->get_required_score();
    if ((($sa_prevscore > $sa_reqscore) && ($crm114_status eq "GOOD"))
     || (($sa_prevscore < 0) && ($crm114_status eq "SPAM"))) {
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

      #The magic call to set dynamic score
      $status->_handle_hit("CRM114_CHECK", $sa_score, 
                             "CRM114: ", $description);
      dbg(sprintf("crm114: score is %3.4f, translated to SA score: %3.4f, linear factor was %3.4f", $crm114_score, $sa_score, $crm114_dynscore_factor));
    }
    else {
      # no dynamic score --> return status
      if ($crm114_status eq "GOOD") {
        $status->_handle_hit("CRM114_GOOD", $crm114_staticscore_good,
                               "CRM114: ", $description);
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_GOOD", 
                               $crm114_score));
      }
      elsif ($crm114_status eq "UNSURE") {
        $status->_handle_hit("CRM114_UNSURE", $crm114_staticscore_unsure,
                               "CRM114: ", $description);
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_UNSURE", 
                               $crm114_score));
      }
      elsif ($crm114_status eq "SPAM") {
        $status->_handle_hit("CRM114_SPAM", $crm114_staticscore_spam,
                               "CRM114: ", $description);
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

1;
