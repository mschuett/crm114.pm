# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Plugin::CRM114 - use CRM114 with SpamAssassin

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::CRM114

=head1 DESCRIPTION

This plugin uses the external program crm114 for classification.

=head1 FEATURES

=over 4

=item *

adds template tags for custom header lines

=item *

trains CRM114 on C<spamassassin --report/--revoke>

=item *

optionally use static or dynamic spam-/ham-scores

=back

=head1 NOTES/PROBLEMS/TODO

If you use CRM114's cache then note that SA will only write headers
beginning with C<X-Spam-> but CRM114 looks for C<X-CRM114-CacheID>.
Training with C<spamassassin --report>/C<--revoke> should work
(because this plugin handles the renaming) but otherwise
you will have to change that line before training from cache.

Amavis-Notes:
I use Amavis to call SpamAssassin. Here are patches to include the
additional CRM114-Headers into every Mail:
against amavisd-new-2.4.5: L<http://mschuette.name/files/amavisd.245.patch>,
against amavisd-new-2.5.2: L<http://mschuette.name/files/amavisd.252.patch>.

=head1 AUTHOR & ACKNOWLEDGEMENT

Thanks to Tomas Charvat for testing.

Initially based on plugin by Eugene Morozov:
L<http://eugene.renice.org/spamassassin/crm114.pm>

Also borrowing from the C<Mail::SpamAssassin::Plugin>-modules.

Everything else is
Copyright 2007, Martin Schuette <info@mschuette.name>

=head1 CRM114 INSTALLATION & CONFIGURATION

To use this plugin you have to set up CRM114 so that you have these files:
F<mailreaver.crm>, F<mailfilter.cf>, F<rewrites.mfp>, F<priolist.mfp>, and F<.CSS> files
(see L<http://crm114.sourceforge.net/CRM114_Mailfilter_HOWTO.txt> for details).

The most important steps are:

    mkdir ~/.crm114
    cp mailfilter.cf rewrites.mfp *.crm ~/.crm114
    cd ~/.crm114
    cssutil -b -r spam.css
    cssutil -b -r nonspam.css
    touch priolist.mfp
    $EDITOR mailfilter.cf
    $EDITOR rewrites.mfp

In F<mailfilter.cf> check the option C<:add_headers: /yes/>!
(and do not bother to change the C<flag_subject_string> options --
this plugin ignores them anyway)

=cut

package Mail::SpamAssassin::Plugin::CRM114;

use strict;
use warnings "all";
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
our @ISA = qw(Mail::SpamAssassin::Plugin);
our $crm114_plugin_version = "0.7.1";

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

=head1 PLUGIN CONFIGURATION

To use this plugin you probably have to set the C<crm114_command>.

All other settings should have working default values,
which are chosen to be cautionary and nonintrusive.

=over 4

=item crm114_command string		(default: C<crm -u ~/.crm114 mailreaver.crm>)

The commandline used to execute CRM114.
It is recommendet to run mailreaver.crm and to use absolute paths only.

=cut

  push (@cmds, {
    setting => 'crm114_command',
    default => 'crm -u ~/.crm114 mailreaver.crm',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=item crm114_learn	(0|1)	(default: 0)

Set this if CRM114 should be trained by SA.

If enabled, then a call to C<Mail::SpamAssassin-E<gt>learn()> or
C<spamassassin --report>/C<--revoke> also calls the CRM114 plugin
and lets CRM114 learn the mail as spam/ham.

=cut

  push (@cmds, {
    setting => 'crm114_learn',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_autolearn	(0|1)	(default: 0)

Set this if CRM114 should be trained by SA's autolearn function.

NB: This is different from C<:automatic_training:> in CRM114's C<mailfilter.cf>
because SA's score is influenced by several different factors while
CRM114 has to rely on its own classification. 

But anyway: Only activate this if you know what you are doing!

=cut

  push (@cmds, {
    setting => 'crm114_autolearn',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_remove_existing_spam_headers	(0|1)	(default: 0)

=item crm114_remove_existing_virus_headers	(0|1)	(default: 0)

Set whether existing X-Spam or X-Virus headers are to be removed before classification.

If SpamAssassin is called by Amavis then set the same value as Amavis does.
That way a SA-check from Amavis and one from the command line both see the same Headers.

=cut

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

=item crm114_dynscore	(0|1)	(default: 0)

Set to use a dynamic score, i.e. calculate a SA score from the CRM114 score.
Otherwise the static scores are used.

=cut

  push (@cmds, {
    setting => 'crm114_dynscore',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_dynscore_factor		(default: depends on SA C<required_score>)

Dynamic score normalization factor.

With dynamic scoring the SA score is calculated by: CRM score * C<crm114_dynscore_factor>

Notes: 

=over 8

=item *

Keep in mind that CRM score have much higher absolute values
and different signs than SA scores (usual ham-scores are between
15 and 40, scores from -10 to 10 are undecided, previously seen
spam easily gets -200).

=item *

Thus this has to be a negative number!

=item *

Thus the absolute value should be quite low (certainly E<lt>.3, probably E<lt>=.2),
otherwise the returned score would override all other tests.

=back

The default is to calculate this factor so that a CRM-score of -25 yields
the SA required spam threshold (C<required_score>).

=cut

  # compute default crm114_dynscore_factor
  # so that CRM score 25 yields SA required_score
  my $default_crm114_dynscore_factor = $conf->{required_score} / -25;
  push (@cmds, {
    setting => 'crm114_dynscore_factor',
    default => $default_crm114_dynscore_factor,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item crm114_staticscore_good	n	(default: -3)

=item crm114_staticscore_prob_good	n	(default: -0.5)

=item crm114_staticscore_unsure	n	(default: 0)

=item crm114_staticscore_prob_spam	n	(default: 0.5)

=item crm114_staticscore_spam	n	(default: 3)

Static scores for different classifications and scores.

Scores for good/spam are used according to CRM114's classification.

On very short messages CRM114 often returns scores with
the right sign (for spam/ham) but with a low absolute value
because there are not enough tokens for sufficiently certain classification.

The prob_good/prob_spam were introduced to benefit from these cases as well.
The basic assumption is that CRM114 uses the default C<:thick_threshold:> of 10
(i.e. classify if |crm-score| E<gt>= 10). The prob_good/prob_spam scores
are used if 5 E<lt>= |crm-score| E<lt>= 10, leaving the unsure score
for |crm-score| E<lt> 5.

=cut

  push (@cmds, {
    setting => 'crm114_staticscore_good',
    default => -3,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_staticscore_prob_good',
    default => -0.5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_staticscore_unsure',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_staticscore_prob_spam',
    default => 0.5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_staticscore_spam',
    default => 3,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item crm114_use_cacheid		(default: 0)


Set to preserve the CRM114-CacheID for training.

To use the cache enable it in F<mailfilter.cf>, set this option, and 
include the CacheID into all Mails with
C<add_header all CRM114-CacheID _CRM114CACHEID_>

=cut

  push (@cmds, {
    setting => 'crm114_use_cacheid',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_autodisable_score		(default: 999)

=item crm114_autodisable_negative_score		(default: -999)

Skip CRM114 check if a message already has
a score E<gt>= C<crm114_autodisable_score> or
a score E<lt>= C<crm114_autodisable_negative_score>
from other tests.

This can be used if you think you have to save some CPU cycles.

In that case you will also want to set a priority for CRM114
(e.g. C<priority  CRM114_CHECK  899>). This ensures that other
(less expensive) tests run first and accumulate some points.
899 is recommended as an optimization because FuzzyOCR runs at 900;
thus if CRM114 already yields a high SA score, then FuzzyOCR will decide
to skip its tests (just like CRM114 might skip if the previous tests
already got us C<crm114_autodisable_score>).

NB: Do not worry too much about performance and CPU costs, unless
you know you are really CPU bound. (And not just waiting for
your slow DNS server to reply.)

=cut

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

=item crm114_timeout	n	(default: 10)

Set timeout of I<n> seconds to cancel a unresponsive CRM114 process. 

=back

=cut

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
      our $crm114_plugin_version;
      $status->set_tag("CRM114VERSION", $1." (SA plugin v$crm114_plugin_version)");
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
  # also make sure that 40 or 20 lines present -- otherwise no output
  my @response_part = defined @response[0..40] ? @response[0..40] :
      (defined @response[0..20] ? @response[0..20] : ());
  $status->set_tag("CRM114DEBUG", join("| ", @response_part));

  dbg(sprintf("crm114: call_crm returns (%s, %s)",
                       $crm114_status, $crm114_score));
  return ($crm114_status, $crm114_score);
}

sub check_crm {
  my ($self, $status) = @_;

  # Step 0: get options
  my $crm114_staticscore_good =
          $self->{main}->{conf}->{crm114_staticscore_good};
  my $crm114_staticscore_prob_good =
          $self->{main}->{conf}->{crm114_staticscore_prob_good};
  my $crm114_staticscore_unsure =
          $self->{main}->{conf}->{crm114_staticscore_unsure};
  my $crm114_staticscore_prob_spam =
          $self->{main}->{conf}->{crm114_staticscore_prob_spam};
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
      $status->{conf}->{descriptions}->{CRM114_CHECK} = $description;
      # Set dynamic score
      $status->got_hit("CRM114_CHECK", "CRM114: ",
                       score => $sa_score, ruletype => "full");
      dbg(sprintf("crm114: score is %3.4f, translated to SA score: %3.4f, linear factor was %3.4f",
                  $crm114_score, $sa_score, $crm114_dynscore_factor));
    }
    else {
      # no dynamic score --> return status
      if ($crm114_status eq "GOOD") {
        $status->{conf}->{descriptions}->{CRM114_GOOD} = $description;
        $status->{conf}->{scores}->{"CRM114_GOOD"} = $crm114_staticscore_good;
        $status->got_hit("CRM114_GOOD", "CRM114: ",
                       score => $crm114_staticscore_good, ruletype => "full");
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_GOOD", 
                               $crm114_score));
      }
      elsif ($crm114_status eq "SPAM") {
        $status->{conf}->{descriptions}->{CRM114_SPAM} = $description;
        $status->{conf}->{scores}->{"CRM114_SPAM"} = $crm114_staticscore_spam;
        $status->got_hit("CRM114_SPAM", "CRM114: ",
                       score => $crm114_staticscore_spam, ruletype => "full");
        dbg(sprintf("crm114: score is %3.4f, returned CRM114_SPAM",
                               $crm114_score));
      }
      elsif ($crm114_status eq "UNSURE") {
        $status->{conf}->{descriptions}->{CRM114_UNSURE} = $description;
        # basic assumption for 'probably'-cases: CRM114 unsure-threshold of +/- 10
        if ($crm114_score <= -5) {
          $status->{conf}->{scores}->{"CRM114_PROB_SPAM"} = $crm114_staticscore_prob_spam;
          $status->got_hit("CRM114_PROB_SPAM", "CRM114: ",
                       score => $crm114_staticscore_prob_spam, ruletype => "full");
          dbg(sprintf("crm114: score is %3.4f, returned CRM114_PROB_SPAM", $crm114_score));
        }
        elsif ($crm114_score >= 5) {
          $status->{conf}->{scores}->{"CRM114_PROB_GOOD"} = $crm114_staticscore_prob_good;
          $status->got_hit("CRM114_PROB_GOOD", "CRM114: ",
                       score => $crm114_staticscore_prob_good, ruletype => "full");
          dbg(sprintf("crm114: score is %3.4f, returned CRM114_PROB_GOOD", $crm114_score));
        }
        else {
          $status->{conf}->{scores}->{"CRM114_UNSURE"} = $crm114_staticscore_unsure;
          $status->got_hit("CRM114_UNSURE", "CRM114: ",
                       score => $crm114_staticscore_unsure, ruletype => "full");
          dbg(sprintf("crm114: score is %3.4f, returned CRM114_UNSURE", $crm114_score));
        }
      }
      else {  # status UNKNOWN --> error, no score
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

=head1 VERSIONS

 Version: 0.1, 070406
 Version: 0.2, 070408
 Version: 0.3, 070409
 Version: 0.3.1, 070412 (fixed typo)
 Version: 0.3.2, 070414 (checked documentation)
 Version: 0.4, 070421 (added crm114_autolearn)
 Version: 0.4.1, 070430 (fixed crm114_autolearn)
 Version: 0.4.2, 070501 (fixed crm114_autolearn again)
 Version: 0.4.3, 070506 (fixed crm114_autolearn again, now tested)
 Version: 0.5, 070507 (works with SA 3.2.0)
 Version: 0.6, 070514 (crm114_autodisable_score, omit test before learning)
 Version: 0.6.1, 070516 (adjusted 'CRM and SA disagree' condition)
 Version: 0.6.2, 070802 (fixed small bug, thanks to Rick Cooper)
 Version: 0.6.3, 070815 (now trying to prevent zombie processes)
 Version: 0.6.4, 070819 (use helper_app_pipe_open-code from Plugin::Pyzor)
 Version: 0.6.5, 070821 (fixed bug in pipe_open-code, thanks to Robert Horton)
 Version: 0.6.6, 070913 (fixed crm114_use_cacheid, added debug-tag)
 Version: 0.6.7, 070927 (add score for unsure but probably spam/good, fix possibly uninitialized value)
 Version: 0.7, 070928 (add POD documentation, considered stable)
 Version: 0.7.1, 071230 (fix prob-cases, where score did not appear in Spam-Status)
 
=cut

