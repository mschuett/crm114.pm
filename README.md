# NAME

Mail::SpamAssassin::Plugin::CRM114 - use CRM114 with SpamAssassin

# SYNOPSIS

    loadplugin     Mail::SpamAssassin::Plugin::CRM114

# DESCRIPTION

This plugin uses the external program crm114 for classification.

# FEATURES

- adds template tags for custom header lines
- trains CRM114 on `spamassassin --report/--revoke`
- optionally use static or dynamic spam-/ham-scores

# NOTES/PROBLEMS/TODO

If you use CRM114's cache then note that SA will only write headers
beginning with `X-Spam-` but CRM114 looks for `X-CRM114-CacheID`.
Training with `spamassassin --report`/`--revoke` should work
(because this plugin handles the renaming) but otherwise
you will have to change that line before training from cache.

Amavis-Notes:
I use Amavis to call SpamAssassin. Here are patches to include the
additional CRM114-Headers into every Mail:

- against amavisd-new-2.4.5: [http://mschuette.name/files/amavisd.245.patch](http://mschuette.name/files/amavisd.245.patch),
- against amavisd-new-2.5.2: [http://mschuette.name/files/amavisd.252.patch](http://mschuette.name/files/amavisd.252.patch),
- against amavisd-new-2.6.1: [http://mschuette.name/files/amavisd.261.patch](http://mschuette.name/files/amavisd.261.patch) (thanks to Jules M),
- against amavisd-new-2.6.2: [http://mschuette.name/files/amavisd.262.patch](http://mschuette.name/files/amavisd.262.patch) (thanks to Mark M).
- amavisd-new-2.6.3 no longer requires these patches

# AUTHOR & ACKNOWLEDGEMENT

Thanks to Tomas Charvat for testing.

Initially based on plugin by Eugene Morozov.

Also borrowing from the `Mail::SpamAssassin::Plugin`\-modules.

`lookup_crm114_cacheid()` contributed by Thomas Mueller <thomas@chaschperli.ch>

Many improvements contributed by Mark Martinec <Mark.Martinec@ijs.si>

Everything else is
Copyright 2007-2010, Martin Schuette <info@mschuette.name>

# CRM114 INSTALLATION & CONFIGURATION

To use this plugin you have to set up CRM114 so that you have these files:
`mailreaver.crm`, `mailfilter.cf`, `rewrites.mfp`, `priolist.mfp`, and `.CSS` files
(see [http://crm114.sourceforge.net/docs/CRM114_Mailfilter_HOWTO.txt](http://crm114.sourceforge.net/docs/CRM114_Mailfilter_HOWTO.txt) for details).

The most important steps are:

    mkdir ~/.crm114
    cp mailfilter.cf rewrites.mfp *.crm ~/.crm114
    cd ~/.crm114
    cssutil -b -r spam.css
    cssutil -b -r nonspam.css
    touch priolist.mfp
    $EDITOR mailfilter.cf
    $EDITOR rewrites.mfp

In `mailfilter.cf` check the option `:add_headers: /yes/`!
(and do not bother to change the `flag_subject_string` options --
this plugin ignores them anyway)

# PLUGIN CONFIGURATION

To use this plugin you probably have to adjust the `crm114_command`.

All other settings should have working default values,
which are chosen to be cautionary and nonintrusive.

- crm114\_command string		(default: `crm -u ~/.crm114 mailreaver.crm`)

    The commandline used to execute CRM114.
    It is recommended to run mailreaver.crm and to use absolute paths only.

- crm114\_learn	(0|1)	(default: 0)

    Set this if CRM114 should be trained by SA.

    If enabled, then a call to `Mail::SpamAssassin->learn()` or
    `spamassassin --report`/`--revoke` also calls the CRM114 plugin
    and lets CRM114 learn the mail as spam/ham.

- crm114\_autolearn	(0|1)	(default: 0)

    Set this if CRM114 should be trained by SA's autolearn function.

    NB: This is different from `:automatic_training:` in CRM114's `mailfilter.cf`
    because SA's score is influenced by several different factors while
    CRM114 has to rely on its own classification.

    But anyway: Only activate this if you know what you are doing!
    In other words: it makes sense to enable autolearning only if non-learning
    SpamAssassin rules (without AWL and Bayes) are already well tuned and are
    known to provide good results,

- crm114\_remove\_existing\_spam\_headers	(0|1)	(default: 0)
- crm114\_remove\_existing\_virus\_headers	(0|1)	(default: 0)

    Set whether existing X-Spam or X-Virus headers are to be removed
    before classification.

    If SpamAssassin is called by Amavis then set the same value as Amavis does.
    That way a SA-check from Amavis and one from the command line both see
    the same headers.

- crm114\_dynscore	(0|1)	(default: 0)

    Set to use a dynamic score, i.e. calculate a SA score from the CRM114 score.
    Otherwise the static scores are used.

- crm114\_dynscore\_factor		(default: depends on SA `required_score`)

    Dynamic score scaling factor.

    With dynamic scoring the SA score is calculated by: CRM score \* `crm114_dynscore_factor`

    Notes:

    - Keep in mind that CRM score have much higher absolute values
    and different signs than SA scores (usual ham-scores are between
    15 and 40, scores from -10 to 10 are undecided, previously seen
    spam easily gets -200).
    - Thus this has to be a negative number!
    - Thus the absolute value should be quite low (certainly <0.3, probably <=0.2),
    otherwise the returned score would override all other tests.

    The default is to calculate this factor so that a CRM-score of -25 yields
    the SA required spam threshold (`required_score`).

- crm114\_staticscore\_good   n   (default: -3)
- crm114\_staticscore\_prob\_good  n   (default: -0.5)
- crm114\_staticscore\_unsure n   (default: 0)
- crm114\_staticscore\_prob\_spam  n   (default: 0.5)
- crm114\_staticscore\_spam   n   (default: 3)

    Static scores for different classifications and scores.

    Scores for good/spam are used according to CRM114's classification.

    On very short messages CRM114 often returns scores with
    the right sign (for spam/ham) but with a low absolute value
    because there are not enough tokens for sufficiently certain classification.
    The prob\_good/prob\_spam were introduced to benefit from these cases as well.

- crm114\_good\_threshold n   (default: 10)
- crm114\_spam\_threshold n   (default: -10)

    The good/spam thresholds as used by CRM114.

    mailreaver.crm allows one to set different thresholds for classification.
    crm114\_good\_threshold should be set to `:good_threshold:` and
    crm114\_spam\_threshold to `:spam_threshold:`.
    This plugin does not need these values to detect classified good/spam mails;
    but will use them only to determine its additional classes prob\_good/prob\_spam.

    These settings override variables :good\_threshold: and :spam\_threshold:
    as used by mailreaver.crm and have their defaults set in mailfilter.cf.
    Thresholds delimit classification regions SPAM / UNSURE / GOOD based on
    CRM114 score (either by crm itself or by this plugin when --stats\_only
    is used which only provides a score but not a status to the plugin).
    They are also used to determine additional classes prob\_good/prob\_spam
    when crm114\_dynscore is false.
    default values are +10 for good threshold and -10 for spam threshold

- crm114\_use\_cacheid		(default: 0)

    Set to preserve the CRM114-CacheID for later training and store
    messages in a reaver cache.

    Enabling this adds additional processing as crm114 is expected to provide
    a rewritten message, and also causes reaver cache to grow, requiring periodic
    purging (not provided by the CRM114 system or this plugin).

    To use the cache enable it in `mailfilter.cf`, set this option, and
    include the CacheID into all Mails with
    `add_header all CRM114-CacheID _CRM114CACHEID_`

- crm114\_lookup\_cacheid                (default: 0)

    If crm114\_use\_cacheid is true and CRM114-CacheID is not found
    in the message, do a lookup in the reaver\_cache/texts directory.

    Note that this can be expensive as the lookup needs to read mail header
    section from files in the cache directory successively until a message
    is found, so keep the number of files small by regularly purging a cache
    directory if you use this option.

    You also need to set crm114\_cache\_dir

- crm114\_cache\_dir                (default: ~/.crm114/reaver\_cache)

    Used to lookup cacheid if set crm114\_lookup\_cacheid. Needs to be set to
    reaver\_cache/texts directory.

- crm114\_autodisable\_score		(default: 999)
- crm114\_autodisable\_negative\_score		(default: -999)

    Skip CRM114 check if a message already has
    a score >= `crm114_autodisable_score` or
    a score <= `crm114_autodisable_negative_score`
    from other tests.

    This can be used if you think you have to save some CPU cycles and
    the number of messages reaching very high (or very low) SA scores is
    non-negligible, e.g. when white- or blacklisting is extensively used.

    In that case you will also want to set a priority for CRM114
    (e.g. `priority  CRM114_CHECK  899`). This ensures that other
    (less expensive) tests run first and accumulate some points.
    899 is recommended as an optimization because FuzzyOCR runs at 900;
    thus if CRM114 already yields a high SA score, then FuzzyOCR will decide
    to skip its tests (just like CRM114 might skip if the previous tests
    already got us `crm114_autodisable_score`).

    NB: Do not worry too much about performance and CPU costs, unless
    you know you are really CPU bound. (And not just waiting for
    your slow DNS server to reply.)

- crm114\_timeout	n	(default: 10)

    Set timeout of _n_ seconds to cancel an unresponsive CRM114 process.

# VERSIONS

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
    Version: 0.8.1, 100607 (fix CRM114-Status regexp, thanks to Kevin Chua Soon Jia)
