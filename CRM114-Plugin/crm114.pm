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

=over 1

=item against amavisd-new-2.4.5: L<http://mschuette.name/files/amavisd.245.patch>,

=item against amavisd-new-2.5.2: L<http://mschuette.name/files/amavisd.252.patch>,

=item against amavisd-new-2.6.1: L<http://mschuette.name/files/amavisd.261.patch> (thanks to Jules M),

=item against amavisd-new-2.6.2: L<http://mschuette.name/files/amavisd.262.patch> (thanks to Mark M).

=item amavisd-new-2.6.3 no longer requires these patches

=back

=head1 AUTHOR & ACKNOWLEDGEMENT

Thanks to Tomas Charvat for testing.

Initially based on plugin by Eugene Morozov.

Also borrowing from the C<Mail::SpamAssassin::Plugin>-modules.

C<lookup_crm114_cacheid()> contributed by Thomas Mueller <thomas@chaschperli.ch>

Many improvements contributed by Mark Martinec <Mark.Martinec@ijs.si>

Everything else is
Copyright 2007-2008, Martin Schuette <info@mschuette.name>

=head1 CRM114 INSTALLATION & CONFIGURATION

To use this plugin you have to set up CRM114 so that you have these files:
F<mailreaver.crm>, F<mailfilter.cf>, F<rewrites.mfp>, F<priolist.mfp>, and F<.CSS> files
(see L<http://crm114.sourceforge.net/docs/CRM114_Mailfilter_HOWTO.txt> for details).

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
use re 'taint';
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_file_path
                                proc_status_ok exit_status_str);
our @ISA = qw(Mail::SpamAssassin::Plugin);
our $crm114_plugin_version = "0.8.0";

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

To use this plugin you probably have to adjust the C<crm114_command>.

All other settings should have working default values,
which are chosen to be cautionary and nonintrusive.

=over 4

=item crm114_command string		(default: C<crm -u ~/.crm114 mailreaver.crm>)

The commandline used to execute CRM114.
It is recommended to run mailreaver.crm and to use absolute paths only.

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
In other words: it makes sense to enable autolearning only if non-learning
SpamAssassin rules (without AWL and Bayes) are already well tuned and are
known to provide good results,

=cut

  push (@cmds, {
    setting => 'crm114_autolearn',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_remove_existing_spam_headers	(0|1)	(default: 0)

=item crm114_remove_existing_virus_headers	(0|1)	(default: 0)

Set whether existing X-Spam or X-Virus headers are to be removed
before classification.

If SpamAssassin is called by Amavis then set the same value as Amavis does.
That way a SA-check from Amavis and one from the command line both see
the same headers.

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

Dynamic score scaling factor.

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

Thus the absolute value should be quite low (certainly E<lt>0.3, probably E<lt>=0.2),
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


=item crm114_staticscore_good   n   (default: -3)

=item crm114_staticscore_prob_good  n   (default: -0.5)

=item crm114_staticscore_unsure n   (default: 0)

=item crm114_staticscore_prob_spam  n   (default: 0.5)

=item crm114_staticscore_spam   n   (default: 3)

Static scores for different classifications and scores.

Scores for good/spam are used according to CRM114's classification.

On very short messages CRM114 often returns scores with
the right sign (for spam/ham) but with a low absolute value
because there are not enough tokens for sufficiently certain classification.
The prob_good/prob_spam were introduced to benefit from these cases as well.

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

=item crm114_good_threshold n   (default: 10)

=item crm114_spam_threshold n   (default: -10)

The good/spam thresholds as used by CRM114.

mailreaver.crm allows one to set different thresholds for classification.
crm114_good_threshold should be set to C<:good_threshold:> and
crm114_spam_threshold to C<:spam_threshold:>.
This plugin does not need these values to detect classified good/spam mails;
but will use them only to determine its additional classes prob_good/prob_spam.

These settings override variables :good_threshold: and :spam_threshold:
as used by mailreaver.crm and have their defaults set in mailfilter.cf.
Thresholds delimit classification regions SPAM / UNSURE / GOOD based on
CRM114 score (either by crm itself or by this plugin when --stats_only
is used which only provides a score but not a status to the plugin).
They are also used to determine additional classes prob_good/prob_spam
when crm114_dynscore is false.
default values are +10 for good threshold and -10 for spam threshold

=cut

  push (@cmds, {
    setting => 'crm114_good_threshold',
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'crm114_spam_threshold',
    default => -10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item crm114_use_cacheid		(default: 0)

Set to preserve the CRM114-CacheID for later training and store
messages in a reaver cache.

Enabling this adds additional processing as crm114 is expected to provide
a rewritten message, and also causes reaver cache to grow, requiring periodic
purging (not provided by the CRM114 system or this plugin).

To use the cache enable it in F<mailfilter.cf>, set this option, and
include the CacheID into all Mails with
C<add_header all CRM114-CacheID _CRM114CACHEID_>

=cut

  push (@cmds, {
    setting => 'crm114_use_cacheid',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_lookup_cacheid                (default: 0)

If crm114_use_cacheid is true and CRM114-CacheID is not found
in the message, do a lookup in the reaver_cache/texts directory.

Note that this can be expensive as the lookup needs to read mail header
section from files in the cache directory successively until a message
is found, so keep the number of files small by regularly purging a cache
directory if you use this option.

You also need to set crm114_cache_dir

=cut

  push (@cmds, {
    setting => 'crm114_lookup_cacheid',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item crm114_cache_dir                (default: ~/.crm114/reaver_cache)

Used to lookup cacheid if set crm114_lookup_cacheid. Needs to be set to
reaver_cache/texts directory.

=cut

  push (@cmds, {
    setting => 'crm114_cache_dir',
    default => '~/.crm114/reaver_cache',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=item crm114_autodisable_score		(default: 999)

=item crm114_autodisable_negative_score		(default: -999)

Skip CRM114 check if a message already has
a score E<gt>= C<crm114_autodisable_score> or
a score E<lt>= C<crm114_autodisable_negative_score>
from other tests.

This can be used if you think you have to save some CPU cycles and
the number of messages reaching very high (or very low) SA scores is
non-negligible, e.g. when white- or blacklisting is extensively used.

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

Set timeout of I<n> seconds to cancel an unresponsive CRM114 process.

=back

=cut

  push (@cmds, {
    setting => 'crm114_timeout',
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

#
# <cacheid> $self->lookup_crm114_cacheid(<messageid>)
#

sub lookup_crm114_cacheid($) {
  my ($self, $msgid) = @_;
  my $cacheid = 0;

  my $crm114_cache_dir = $self->{main}->{conf}->{crm114_cache_dir};
  my @files;

  dbg("crm114: lookup_crm114_cacheid: $msgid");

  local *DIR;
  if (!opendir(DIR, "$crm114_cache_dir/texts")) {
      warn("crm114: lookup_crm114_cacheid: can't open directory $crm114_cache_dir/texts: $!");
      return 0;
  }

  foreach (readdir(DIR)) {
    if (-f "$crm114_cache_dir/texts/$_") {
      # Reverse directory listing, to read newest to oldest
      unshift(@files,$_);
    }
  }
  closedir DIR or die "cannot close directory $crm114_cache_dir/texts: $!";

  foreach my $file (@files) {
    my $header = "";
    local *FILE;
    if (open(FILE, "< $crm114_cache_dir/texts/$file")) {
      { local $/ = "\n\n"; # to read the whole header
        $header = <FILE>;
      }
      close FILE or die "cannot close $crm114_cache_dir/texts/$file: $!";
      if ($header =~ /^(:?(?i)Message-ID):\s*<\Q$msgid\E>/m) {
        $cacheid = "sfid-$file";
        last;
      }
    } else {
      warn("crm114: lookup_crm114_cacheid: can't open $crm114_cache_dir/texts/$file: $!");
    }
  }

  return $cacheid;
}

sub call_crm {
  my ($self, $pms, $action) = @_;
  my $crm114_score;
  my $crm114_status;

  my $crm114_command = $self->{main}->{conf}->{crm114_command};
  my $crm114_remove_existing_spam_headers =
            $self->{main}->{conf}->{crm114_remove_existing_spam_headers};
  my $crm114_remove_existing_virus_headers =
            $self->{main}->{conf}->{crm114_remove_existing_virus_headers};
  my $crm114_use_cacheID = $self->{main}->{conf}->{crm114_use_cacheid};
  my $crm114_timeout = $self->{main}->{conf}->{crm114_timeout};
  my $crm114_lookup_cacheid = $self->{main}->{conf}->{crm114_lookup_cacheid};

  my $fullref;
  # if we do not edit header section, just get whole mail as plaintext
  if (!($crm114_use_cacheID && $action ne "check")
    && !$crm114_remove_existing_spam_headers
    && !$crm114_remove_existing_virus_headers) {
    $fullref = \$pms->get_message()->get_pristine();
  }
  else {  # otherwise get seperate header and body to modify first
    my $hdr = $pms->get_message()->get_pristine_header();
    my $bdy = $pms->get_message()->get_pristine_body();

    # if a Cache is used and the CacheID is included in every mail,
    # then it should be used. the renaming is necessary because
    # a) CRM114 looks only for "X-CRM114-CacheID"
    # b) that way we easily pass the spam header removing below
    if ($crm114_use_cacheID && $action ne "check") {
      local $1;
      $hdr =~ s/^X-Spam-CRM114-CacheID: (.*)$/X-CRM114-CacheID: $1/m;
    }

    if ($action ne "check") {
      # when autolearning, cache ID may be available from checking time
      my $cacheid_from_check = $pms->get_tag("CRM114CACHEID");
      if (defined $cacheid_from_check) {
        dbg("crm114: supplying CacheID from check time: $cacheid_from_check");
        $hdr = "X-CRM114-CacheID: $cacheid_from_check\n" . $hdr;
      }
    }

    # Some mail systems don't preserve all original mail header fields
    # (except a few like Message-ID, From, Subject).  So lookup the
    # message-id in a reaver_cache directory and insert the CRM114 CacheID
    if ($crm114_use_cacheID && $crm114_lookup_cacheid && $action ne "check"
        && $hdr !~ /^X-CRM114-CacheID/m)
    { local $1;
      if ($hdr =~ m/^Message-ID:\s*<(.*)>/mi) {
        my $msgid = $1;
        my $cacheid = $self->lookup_crm114_cacheid($msgid);

        if ($cacheid) {
          dbg("crm114: found CRM114-CacheID ($cacheid)");
          # Prepend the CRM114 CacheID to the header
          $hdr = "X-CRM114-CacheID: $cacheid\n" . $hdr;
        } else {
          warn("crm114: CRM114-CacheID not found (msgid: $msgid / cacheid: $cacheid)");
        }
      } else {
        warn("crm114: No Message-Id found");
      }
    }

    if ($crm114_remove_existing_spam_headers) {
      $hdr =~ s/^X-Spam-[^:]*:.*(?:\n[ \t].*)*\n//mg;
    }
    if ($crm114_remove_existing_virus_headers) {
      $hdr =~ s/^X-Virus-[^:]*:.*(?:\n[ \t].*)*\n//mg;
    }
	# NOTE: quite ugly, but we need a reference
    my $fullref2 = $hdr.$bdy;
    $fullref = \$fullref2;
  }

  my $crm114_good_threshold = $self->{main}->{conf}->{crm114_good_threshold};
  my $crm114_spam_threshold = $self->{main}->{conf}->{crm114_spam_threshold};
  my $ditch_cache_file = $action eq "check" && !$crm114_use_cacheID;
  my @crm114_options;
  push(@crm114_options, '--spam')  if $action eq "train_spam";
  push(@crm114_options, '--good')  if $action eq "train_good";
  #push(@crm114_options, '--report_only');  # versions cca. 20081111 and later
  push(@crm114_options, '--dontstore', '--stats_only')  if $ditch_cache_file;
  push(@crm114_options, '--good_threshold='.$crm114_good_threshold);
  push(@crm114_options, '--spam_threshold='.$crm114_spam_threshold);

  my $crm114_cmdline = join(' ', untaint_file_path($crm114_command),
                                 @crm114_options);

  dbg("crm114: call_crm() called, action: %s", $action);

  # Step 1: call CRM114
  # code copied from Plugin::Pyzor
  my ($pid, @response);
  # TODO: elimininate tmpfile, use pipe instead
  #       (but impossible with helper_app_pipe_open)
  my $tmpf = $pms->create_fulltext_tmpfile($fullref);
  $pms->enter_helper_run_mode();
  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $crm114_timeout });

  local *CRM_OUT;
  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };
    dbg("crm114: opening pipe: $crm114_cmdline < $tmpf");
    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(
                                  *CRM_OUT,	$tmpf, 1, $crm114_cmdline);
    $pid or die "crm114: starting subprocess failed: error msg=$!\n";

    # read+split avoids a Perl I/O bug (Bug 5985)
    my($inbuf,$nread,$resp); $resp = '';
    while ( $nread=read(CRM_OUT,$inbuf,8192) ) { $resp .= $inbuf }
    defined $nread  or die "error reading from pipe: $!";
    @response = split(/^/m, $resp, -1);  undef $resp;

    my $errno = 0;  close CRM_OUT or $errno = $!;
    if (proc_status_ok($?,$errno)) {
      dbg("crm114: [%s] finished successfully", $pid);
    } else {
      info("crm114: [%s] error: %s", $pid, exit_status_str($?,$errno));
      if (!@response) {
        dbg("crm114: no response");
      } else {
        my(@resp) = @response <= 6 ? @response : (@response[0..4], '[...]');
        chomp for @resp;
        dbg("crm114: got response: %s", join('\\n', @resp));
      }
    }

    if (!@response) {
      die("no response\n");
    }

  });

  # IMHO not strictly necessary, but be nice and clean
  $pms->delete_fulltext_tmpfile();

  if (defined(fileno(*CRM_OUT))) {  # still open
    if ($pid) {
      if (kill('TERM',$pid)) { dbg("crm114: killed stale helper [$pid]") }
      else { dbg("crm114: killing helper application [$pid] failed: $!") }
    }
    my $errno = 0;  close CRM_OUT or $errno = $!;
    proc_status_ok($?,$errno)
      or info("crm114: [%s] error: %s", $pid, exit_status_str($?,$errno));
  }
  $pms->leave_helper_run_mode();
  if ($timer->timed_out()) {
    dbg("crm114: check timed out after $crm114_timeout seconds");
  # return 0;  # do not bail out here, still has to store results
  }
  if ($err) {
    chomp $err;
    warn("crm114: check failed: $err\n");
  }

  # Step 2: parse output
  # we only look for the bits we're going to return to SA
  # and ignore everything else (just like Amavis does when calling SA)

  if ($ditch_cache_file) {  # only a single line with score is expected
    local $1;
    if (@response == 1 && $response[0] =~ /^\s*([+-]?\d*(?:\.\d*)?)\s*$/) {
      $crm114_score = $1;
      dbg("crm114: found score %s", $crm114_score);
    }
    @response = ();  # skip the following loop
  }

  foreach $_ (@response) {
    local($1,$2);
    if (/^X-CRM114-Version: (.+)$/) {
      our $crm114_plugin_version;
      $pms->set_tag("CRM114VERSION",
                    $1." (SA plugin v$crm114_plugin_version)");
      dbg("crm114: found version ".$1);
    }
    elsif (/^X-CRM114-CacheID: (.+)$/) {
      if ($action eq "check" && $1 ne 'sfid-') {  # don't keep null CacheID
        $pms->set_tag("CRM114CACHEID", $1);
      }
      dbg("crm114: found CacheID ".$1);
    }
    elsif (/^X-CRM114-Notice: (.+)$/) {
      $pms->set_tag("CRM114NOTICE", $1);
      dbg("crm114: found Notice ".$1);
    }
    elsif (/^X-CRM114-Status: ([A-Z]+)\s+\(\s+([-\d\.]+)\s+\)/) {
      if ($action eq "check") {
      	$crm114_status = $1;
      	$crm114_score = $2;
      }
      dbg("crm114: found status %s and score %s", $1, $2);
    }
    elsif (/^X-CRM114-Action: (.+)$/) {
      $pms->set_tag("CRM114ACTION", $1);
      dbg("crm114: found Action ".$1);
    }
    elsif (/^(X-CRM114.*)$/) {
      dbg("crm114: found unknown CRM114-header '$1'");
    }
    elsif (/^$/) {  # end of header section
      last;
    }
  }

  if (!defined $crm114_status && defined $crm114_score) {
    # presumably using --stats_only
    $crm114_status = $crm114_score <= $crm114_spam_threshold ? "SPAM"
                   : $crm114_score >= $crm114_good_threshold ? "GOOD"
                                                             : "UNSURE";
  }
  $pms->set_tag("CRM114STATUS", $crm114_status)  if defined $crm114_status;
  $pms->set_tag("CRM114SCORE",  $crm114_score)   if defined $crm114_score;

  # for debugging: this lets us include original crm114-output into the mail
  # also make sure that 40 or 20 lines are present -- otherwise no output
  my @response_part = @response > 40 ? @response[0..40] :
                      @response > 20 ? @response[0..20] : ();
  $pms->set_tag("CRM114DEBUG", join("| ", @response_part));

  $crm114_score  = 0          if !defined $crm114_score;
  $crm114_status = "UNKNOWN"  if !defined $crm114_status;
  dbg("crm114: call_crm returns (%s, %s)", $crm114_status, $crm114_score);

  return ($crm114_status, $crm114_score);
}

sub check_crm {
  my ($self, $pms) = @_;

  my $timing = $self->{main}->UNIVERSAL::can("time_method") &&
               $self->{main}->time_method("check_crm114");

  # Step 0: get options
  my $crm114_good_threshold =
          $self->{main}->{conf}->{crm114_good_threshold};
  my $crm114_spam_threshold =
          $self->{main}->{conf}->{crm114_spam_threshold};
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

  # check if message already classified by SA and CRM114 is to be skipped
  my $sa_prevscore = $pms->get_score();
  if (($sa_prevscore < $crm114_autodisable_negative_score)
   || ($sa_prevscore > $crm114_autodisable_score)) {
    dbg("crm114: skip test because score=$sa_prevscore");
    return 0;
  }

  # Step 2: call CRM114
  # no need to preserve a message in reaver_cache at this point,
  # and no need to let crm114 waste time in rewriting a message,
  # all we really need is a score
  my ($crm114_status, $crm114_score) = $self->call_crm($pms, "check");

  # Step 3: return vales to SA
  if ($crm114_status eq "UNKNOWN") {
    # Error --> no score returned
    warn("crm114: Error. Failed to get CRM114-Status.");
  }
  else {
    # OK, got my score

    # return something to SA
    my $description = sprintf("message is %s with crm114-score %3.4f",
                              $crm114_status, $crm114_score);
    my $tflags = $pms->{conf}->{tflags};
    my $sa_score;
    if ($crm114_dynscore) {
      # return dynamic score --> normalize CRM114-score to SA-score
      $sa_score = $crm114_dynscore_factor * $crm114_score;
      for my $set (0..3) {
        $pms->{conf}->{scoreset}->[$set]->{"CRM114_CHECK"} =
                                              sprintf("%0.3f", $sa_score);
      }

      # Set dynamic description
      $pms->{conf}->{descriptions}->{CRM114_CHECK} = $description;

      # Set 'learn' tflag to prevent feedback, and 'nice' as appropriate
      $_ = join(' ', !defined $_ ? () : split(' '), 'learn',
           $crm114_status eq "GOOD" ? 'nice' : ()) for $tflags->{CRM114_CHECK};

      # Set dynamic score
      $pms->got_hit("CRM114_CHECK", "CRM114: ",
                    score => $sa_score, ruletype => "full");
      dbg("crm114: score is %3.4f, translated to SA score: %3.4f, ".
          "linear factor was %3.4f",
          $crm114_score, $sa_score, $crm114_dynscore_factor);
    }
    else {
      # no dynamic score --> return status
      if ($crm114_status eq "GOOD") {
        $sa_score = $crm114_staticscore_good;
        $pms->{conf}->{descriptions}->{CRM114_GOOD} = $description;
        $pms->{conf}->{scores}->{"CRM114_GOOD"} = $sa_score;
        $_ = join(' ', !defined $_ ? () : split(' '), 'learn', 'nice')
          for $tflags->{CRM114_GOOD};
        $pms->got_hit("CRM114_GOOD", "CRM114: ",
                      score => $sa_score, ruletype => "full");
        dbg("crm114: score is %3.4f, returned CRM114_GOOD", $crm114_score);
      }
      elsif ($crm114_status eq "SPAM") {
        $sa_score = $crm114_staticscore_spam;
        $pms->{conf}->{descriptions}->{CRM114_SPAM} = $description;
        $pms->{conf}->{scores}->{"CRM114_SPAM"} = $sa_score;
        $_ = join(' ', !defined $_ ? () : split(' '), 'learn')
          for $tflags->{CRM114_SPAM};
        $pms->got_hit("CRM114_SPAM", "CRM114: ",
                      score => $sa_score, ruletype => "full");
        dbg("crm114: score is %3.4f, returned CRM114_SPAM", $crm114_score);
      }
      elsif ($crm114_status eq "UNSURE") {
        $pms->{conf}->{descriptions}->{CRM114_UNSURE} = $description;
        # 'probably'-cases: 0.5*$threshold <= x < $threshold
        if ($crm114_score <= 0.5*$crm114_spam_threshold) {
          $sa_score = $crm114_staticscore_prob_spam;
          $pms->{conf}->{scores}->{"CRM114_PROB_SPAM"} = $sa_score;
          $_ = join(' ', !defined $_ ? () : split(' '), 'learn')
            for $tflags->{CRM114_PROB_SPAM};
          $pms->got_hit("CRM114_PROB_SPAM", "CRM114: ",
                        score => $sa_score, ruletype => "full");
          dbg("crm114: score is %3.4f, returned CRM114_PROB_SPAM",
              $crm114_score);
        }
        elsif ($crm114_score >= 0.5*$crm114_good_threshold) {
          $sa_score = $crm114_staticscore_prob_good;
          $pms->{conf}->{scores}->{"CRM114_PROB_GOOD"} = $sa_score;
          $_ = join(' ', !defined $_ ? () : split(' '), 'learn', 'nice')
            for $tflags->{CRM114_PROB_GOOD};
          $pms->got_hit("CRM114_PROB_GOOD", "CRM114: ",
                        score => $sa_score, ruletype => "full");
          dbg("crm114: score is %3.4f, returned CRM114_PROB_GOOD",
              $crm114_score);
        }
        else {
          $sa_score = $crm114_staticscore_unsure;
          $pms->{conf}->{scores}->{"CRM114_UNSURE"} = $sa_score;
          $_ = join(' ', !defined $_ ? () : split(' '), 'learn')
            for $tflags->{CRM114_UNSURE};
          $pms->got_hit("CRM114_UNSURE", "CRM114: ",
                        score => $sa_score, ruletype => "full");
          dbg("crm114: score is %3.4f, returned CRM114_UNSURE", $crm114_score);
        }
      }
      else {  # status UNKNOWN --> error, no score
        return 0;
      }
    }
    $pms->set_tag("CRM114SCORESA", $sa_score)  if defined $sa_score;

    # check if CRM and SA scores differ too much
    my $sa_reqscore = $pms->get_required_score();
    if ($sa_prevscore + $sa_score > $sa_reqscore && $crm114_status eq "GOOD" ||
        $sa_prevscore + $sa_score < 0            && $crm114_status eq "SPAM") {
      dbg("crm114: CRM and SA disagree, crm says %s, sa %.3f",
          $crm114_status, $sa_prevscore);
    }

  }
  return 0;
}

sub plugin_report {
  my ($self, $options) = @_;

  dbg("crm114: plugin_report() called");
  return unless $self->{main}->{conf}->{crm114_learn};

  my $timing = $self->{main}->UNIVERSAL::can("time_method") &&
               $self->{main}->time_method("crm114_report");

  my $pms = Mail::SpamAssassin::PerMsgStatus->new($self, $options->{msg});

  $self->call_crm($pms, "train_spam");

  my $action = $pms->get_tag("CRM114ACTION");
  if ($action eq "LEARNED AND CACHED SPAM") {
    $options->{report}->{report_available} = 1;
    $options->{report}->{report_return} = 1;
    dbg("crm114: trained spam message");
  }
  else {
    warn("crm114: error in training, unexpected Action: ".$action);
  }
}

sub plugin_revoke {
  my ($self, $options) = @_;

  dbg("crm114: plugin_revoke() called");
  return unless $self->{main}->{conf}->{crm114_learn};

  my $timing = $self->{main}->UNIVERSAL::can("time_method") &&
               $self->{main}->time_method("crm114_revoke");

  my $pms = Mail::SpamAssassin::PerMsgStatus->new($self, $options->{msg});

  $self->call_crm($pms, "train_good");

  my $action = $pms->get_tag("CRM114ACTION");
  if ($action eq "LEARNED AND CACHED GOOD") {
    $options->{revoke}->{revoke_available} = 1;
    $options->{revoke}->{revoke_return} = 1;
    dbg("crm114: trained ham/good message");
  } else {
    warn("crm114: error in training, unexpected Action: ".$action);
  }
}

sub autolearn {
  my ($self, $options) = @_;
  my $pms = $options->{permsgstatus};

  my $autolearn_enabled = $self->{main}->{conf}->{crm114_autolearn};
  my $isspam = $options->{isspam};
  my $sa_verdict = $isspam ? 'SPAM' : 'GOOD';
  my $crm114_status = $pms->get_tag("CRM114STATUS");
  my $crm114_scoresa = $pms->get_tag("CRM114SCORESA");
  $crm114_status = ''  if !defined $crm114_status;
  $crm114_scoresa = '' if !defined $crm114_scoresa;

  # training only on errors yields best results according to crm114 docs
  my $will_autolearn = $autolearn_enabled && $crm114_status ne $sa_verdict;

  dbg("crm114: %sautolearn%s, crm: %s %.3f, sa: %s %.3f al=%.3f",
      $will_autolearn    ? '' : 'no ',
      $autolearn_enabled ? '' : ', disabled',
      $crm114_status, $crm114_scoresa,
      $sa_verdict, $pms->get_score, $pms->get_autolearn_points);

  return if !$will_autolearn;

  my $timing = $self->{main}->UNIVERSAL::can("time_method") &&
               $self->{main}->time_method("crm114_autolearn");

  if ($isspam) {
    $self->call_crm($pms, "train_spam");
    my $action = $pms->get_tag("CRM114ACTION");
    if (defined $action && $action eq "LEARNED AND CACHED SPAM") {
      dbg("crm114: trained spam message: %s -> %s",
          $crm114_status, $sa_verdict);
    }
    else {
      $action = '-'  if !defined $action;
      warn("crm114: error in training, unexpected Action: ".$action);
    }
  }
  else {
    $self->call_crm($pms, "train_good");
    my $action = $pms->get_tag("CRM114ACTION");
    if (defined $action && $action eq "LEARNED AND CACHED GOOD") {
      dbg("crm114: trained good message: %s -> %s",
          $crm114_status, $sa_verdict);
    }
    else {
      $action = '-'  if !defined $action;
      warn("crm114: error in training, unexpected Action: ".$action);
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
 Version: 0.7.2, 071230 (hopefully better error messages in case of process failure)
 Version: 0.7.3, 080127 (typo in autolearn)
 Version: 0.7.4, 080301 (CLT08-Edition, fixed header filter, thanks to Thomas Mueller)
 Version: 0.7.5, 080421 (added lookup_crm114_cacheid, thanks to Thomas Mueller)
 Version: 0.7.6, 081217 (added crm114_{good,spam}_threshold)
 Version: 0.8.0, 090418 (lots of improvements, thanks to Mark Martinec)

=cut
