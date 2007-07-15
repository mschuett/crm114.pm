# <@LICENSE>
# 
# Private Use Only - Non-Redistributable until public release.
#
# </@LICENSE>
#
# -------------------------------------------------------
# PDFInfo Plugin for SpamAssassin
# Version: 0.4
# Current Home: http://www.rulesemporium.com/plugins.htm#pdfinfo
# Created: 2007-06-25
# Modified: 2007-07-13
# By: Dallas Engelken <dallase@uribl.com>
#
# Changes: 
#   0.4 - added pdf_is_encrypted() function
#       - added option to look for image HxW on same line
#   0.3 - added 2nd fuzzy md5 which uses pdf tag layout as data
#       - renamed pdf_image_named() to pdf_named()
#          - PDF images are encapsulated and have no names.  We are matching the PDF file name.
#       - renamed pdf_image_name_regex() to pdf_name_regex()
#          - PDF images are encapsulated and have no names.  We are matching the PDF file name.
#       - changed pdf_image_count() a bit and added pdf_count().
#          - pdf_count() checks how many pdf attachments there are on the mail
#          - pdf_image_count() checks how many images are found within all pdfs in the mail.
#       - removed the restriction of the pdf containing an image in order to md5 it.
#       - added pdf_match_details() function to check the following 'details'
#          - author: Author of PDF if specified
#          - producer: Software used to produce PDF
#          - creator: Software used to produce PDF, usually similar to producer
#          - title: Title of PDF
#          - created: Creation Date
#          - modified: Last Modified
#   0.2 - support PDF octet-stream
#   0.1 - just ported over the imageinfo code, and renamed to pdfinfo.  
#         - removed all support for png, gif, and jpg from the code.
#         - prepended pdf_ to all function names to avoid conflicts with ImageInfo in SA 3.2.
#
# Files:
#
#   PDFInfo.pm (plugin)  - http://www.rulesemporium.com/plugins/private/PDFInfo.pm
#   pdfinfo.cf (ruleset) - http://www.rulesemporium.com/plugins/private/pdfinfo.cf
#   
# Installation:
#
#   1) place ruleset in your local config dir
#   2) place plugin in your plugins dir 
#   3) add to init.pre (or v310.pre) the following line
#      loadplugin Mail::SpamAssassin::Plugin::PDFInfo
#           or if not in plugin dir..
#      loadplugin Mail::SpamAssassin::Plugin::PDFInfo /path/to/plugin
#    4) restart spamd (if necessary)
#
# Usage:
#
#  pdf_count()
#
#     body RULENAME  eval:pdf_count(<min>,[max]) 
#        min: required, message contains at least x pdf mime parts
#        max: optional, if specified, must not contain more than x pdf mime parts
#
#  pdf_image_count()
#
#     body RULENAME  eval:pdf_image_count(<min>,[max]) 
#        min: required, message contains at least x images in pdf attachments.
#        max: optional, if specified, must not contain more than x pdf images
#
#  pdf_pixel_coverage()
#
#     body RULENAME  eval:pdf_pixel_coverage(<min>,[max])
#        min: required, message contains at least this much pixel area
#        max: optional, if specified, message must not contain more than this much pixel area
#
#  pdf_named()
# 
#     body RULENAME  eval:pdf_named(<string>) 
#        string: exact file name match, if you need partial match, see pdf_name_regex()
#
#  pdf_name_regex()
# 
#     body RULENAME  eval:pdf_name_regex(<regex>) 
#        regex: regular expression, see examples in ruleset
#
#  pdf_match_md5()
#
#     body RULENAME  eval:pdf_match_md5(<string>)
#        string: 32-byte md5 hex
#
#  pdf_match_fuzzy_md5()
#
#     body RULENAME  eval:pdf_match_md5(<string>)
#        string: 32-byte md5 hex - see ruleset for obtaining the fuzzy md5
#
#  pdf_match_details()
#
#     body RULENAME  eval:pdf_match_details(<detail>,<regex>);
#        detail: author, creator, created, modified, producer, title
#        regex: regular expression, see examples in ruleset
#
#  pdf_is_encrypted()
#
#     body RULENAME eval:pdf_is_encrypted()
#
#  NOTE: See the ruleset for more examples that are not documented here.
#
# -------------------------------------------------------

package Mail::SpamAssassin::Plugin::PDFInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;
use Digest::MD5 qw(md5_hex);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);
  
  $self->register_eval_rule ("pdf_count");
  $self->register_eval_rule ("pdf_image_count");
  $self->register_eval_rule ("pdf_pixel_coverage");
  $self->register_eval_rule ("pdf_image_size_exact");
  $self->register_eval_rule ("pdf_image_size_range");
  $self->register_eval_rule ("pdf_named");
  $self->register_eval_rule ("pdf_name_regex");
  $self->register_eval_rule ("pdf_image_to_text_ratio");
  $self->register_eval_rule ("pdf_match_md5");
  $self->register_eval_rule ("pdf_match_fuzzy_md5");
  $self->register_eval_rule ("pdf_match_details");
  $self->register_eval_rule ("pdf_is_encrypted");

  return $self;
}

# -----------------------------------------

my %get_details = (
  'pdf' => sub {
    my ($pms, $part) = @_;
    my $data = $part->decode();

    my $index = substr($data, 0, 8);

    return unless ($index =~ /.PDF\-(\d\.\d)/);
    my $version = $1;
    # dbg("pdfinfo: pdf version = $version");

    my ($height, $width, $fuzzy_data, $pdf_tags);
    my ($producer, $created, $modified, $title, $creator, $author) = ('unknown','0','0','untitled','unknown','unknown');
    my ($md5, $fuzzy_md5) = ('', '');
    my ($total_height, $total_width, $total_area, $line_count) = (0,0,0,0);

    my $name = $part->{'name'};
    my $no_more_fuzzy = 0;
    my $got_image = 0;
    my $encrypted = 0;

    while($data =~ /([^\n]+)/g) {
      # dbg("pdfinfo: line=$1");
      my $line = $1;

      $line_count++;

      # lines containing high bytes will have no data we need, so save some cycles
      next if ($line =~ /[\x80-\xff]/);

      if (!$no_more_fuzzy && $line_count < 70) {
        if ($line !~ m/^\%/ && $line !~ m/^\/(?:Height|Width|(?:(?:Media|Crop)Box))/ && $line !~ m/^\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+cm$/) {
          $line =~ s/\s+$//;  # strip off whitespace at end.
          $fuzzy_data .= $line;
	}
      }
 
      if ($line =~ m/^\/([A-Za-z]+)/) {
         $pdf_tags .= $1;
      }

      $got_image=1 if ($line =~ m/\/Image/);
      $encrypted=1 if ($line =~ m/^\/Encrypt/);

      # once we hit the first stream, we stop collecting data for fuzzy md5
      $no_more_fuzzy = 1 if ($line =~ m/stream/);

      # From a v1.3 pdf      
      # [12234] dbg: pdfinfo: line=630 0 0 149 0 0 cm
      # [12234] dbg: pdfinfo: line=/Width 630
      # [12234] dbg: pdfinfo: line=/Height 149
      if ($got_image) {
        if ($line =~ /^(\d+)\s+\d+\s+\d+\s+(\d+)\s+\d+\s+\d+\s+cm$/) {
          $width = $1;
          $height = $2;
        }
        elsif ($line =~ /^\/Width\s(\d+)/) {
          $width = $1;
        }
        elsif ($line =~ /^\/Height\s(\d+)/) {
          $height = $1;
        }
        elsif ($line =~ m/\/Width\s(\d+)\/Height\s(\d+)/) {
          $width = $1;
          $height = $2;
        }
      }

      # did pdf contain image data?
      if ($got_image && $width && $height) {
        $no_more_fuzzy = 1;
        my $area = $width * $height;
        $total_height += $height;
        $total_width += $width;
        $total_area += $area;
        $pms->{pdfinfo}->{dems_pdf}->{"${height}x${width}"} = 1;
        $pms->{'pdfinfo'}->{"count_pdf_images"} ++;
        dbg("pdfinfo: Found image in PDF ".($name ? $name : '')." - $height x $width pixels ($area pixels sq.)");
        $height=0; $width=0;  # reset and check for next image
        $got_image = 0;
      }

      # [5310] dbg: pdfinfo: line=<</Producer(GPL Ghostscript 8.15)
      # [5310] dbg: pdfinfo: line=/CreationDate(D:20070703144220)
      # [5310] dbg: pdfinfo: line=/ModDate(D:20070703144220)
      # [5310] dbg: pdfinfo: line=/Title(Microsoft Word - Document1)
      # [5310] dbg: pdfinfo: line=/Creator(PScript5.dll Version 5.2)
      # [5310] dbg: pdfinfo: line=/Author(colet)>>endobj
      # or all on same line inside xml - v1.6+
      # <</CreationDate(D:20070226165054-06'00')/Creator( Adobe Photoshop CS2 Windows)/Producer(Adobe Photoshop for Windows -- Image Conversion Plug-in)/ModDate(D:20070226165100-06'00')>>
      
      if ($line =~ /\/Producer\(([^\)]+)/) {
        $producer = $1;
      }
      if ($line =~ /\/CreationDate\(D\:(\d+)/) {
        $created = $1;
      }
      if ($line =~ /\/ModDate\(D\:(\d+)/) {
        $modified = $1;
      }
      if ($line =~ /\/Title\(([^\)]+)/) {
        $title = $1;
        # Title=\376\377\000w\000w\000n\000g
        # Title=wwng
        $title =~ s/\\\d{3}//g;
      }
      if ($line =~ /\/Creator\(([^\)]+)/) {
        $creator = $1;
      }
      if ($line =~ /\/Author\(([^\)]+)/) {
        $author = $1;
        # Author=\376\377\000H\000P\000_\000A\000d\000m\000i\000n\000i\000s\000t\000r\000a\000t\000o\000r
        # Author=HP_Administrator
        $author =~ s/\\\d{3}//g;
      }
    }

    # store the file name so we can check pdf_named() or pdf_name_match() later.
    $pms->{pdfinfo}->{names_pdf}->{$name} = 1 if $name;

    # store encrypted flag.
    $pms->{pdfinfo}->{encrypted} = $encrypted;

    # if we had multiple images in the pdf, we need to store the total HxW as well.  
    # If it was a single Image PDF, then this value will already be in the hash.
    $pms->{pdfinfo}->{dems_pdf}->{"${total_height}x${total_width}"} = 1;
    $pms->{pdfinfo}->{pc_pdf} = $total_area;

    dbg("pdfinfo: Filename=$name Total HxW: $total_height x $total_width ($total_area area)") if ($total_area);
    dbg("pdfinfo: Filename=$name Title=$title Author=$author Producer=$producer Created=$created Modified=$modified");

    $md5 = uc(md5_hex($data)) if $data;
    $fuzzy_md5 = uc(md5_hex($fuzzy_data)) if $fuzzy_data;
    my $tags_md5 = uc(md5_hex($pdf_tags)) if $pdf_tags;

    # dbg("pdfinfo: pdftags=$pdf_tags");
    # dbg("pdfinfo: fuzzy=$fuzzy_data");
    dbg("pdfinfo: MD5 results for ".($name ? $name : '')." - md5=$md5 fuzzy1=$fuzzy_md5 fuzzy2=$tags_md5");

    $pms->{pdfinfo}->{details}->{producer} = $producer if $producer;
    $pms->{pdfinfo}->{details}->{created} = $created if $created;
    $pms->{pdfinfo}->{details}->{modified} = $modified if $modified;
    $pms->{pdfinfo}->{details}->{title} = $title if $title;
    $pms->{pdfinfo}->{details}->{creator} = $creator if $creator;
    $pms->{pdfinfo}->{details}->{author} = $author if $author;

    $pms->{pdfinfo}->{md5}->{$md5} = 1;
    $pms->{pdfinfo}->{fuzzy_md5}->{$fuzzy_md5} = 1;
    $pms->{pdfinfo}->{fuzzy_md5}->{$tags_md5} = 1;
  },
  
);

sub _get_images {
  my ($self,$pms) = @_;
  my $result = 0;

  # initialize
  $pms->{'pdfinfo'}->{"pc_pdf"} = 0;
  $pms->{'pdfinfo'}->{"count_pdf"} = 0;
  $pms->{'pdfinfo'}->{"count_pdf_images"} = 0;

  foreach my $p ($pms->{msg}->find_parts(qr@^(image|application)/(pdf|octet\-stream)$@, 1)) {
    my ($type) = $p->{'type'} =~ m@/([\w\-]+)$@;
    my ($name) = $p->{'name'};
    
    my $cte = lc $p->get_header('content-transfer-encoding') || '';
    
    dbg("pdfinfo: found part, type=".($type ? $type : '')." file=".($name ? $name : '')." cte=".($cte ? $cte : '')."");
 
    # make sure its base64 encoded
    next if ($cte !~ /^base64$/);

    # application type must be pdf, or it can be an octet-stream with a .pdf filename
    next unless ($type eq 'pdf' || ($type eq 'octet-stream' && $name =~ /\.pdf$/));

    if ($type eq 'octet-stream' && $p->{'name'} =~ /\.(?:pdf)$/ ) {
      $type='pdf';
    }

    if ($type && exists $get_details{$type}) {
       $get_details{$type}->($pms,$p);
       $pms->{'pdfinfo'}->{"count_$type"} ++;
    }
  }

  foreach my $name ( keys %{$pms->{'pdfinfo'}->{"names_pdf"}} ) {
   dbg("pdfinfo: Found a PDF file - $name");
  }
}

# -----------------------------------------

sub pdf_named {
  my ($self,$pms,$body,$name) = @_;
  return unless (defined $name);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'pdfinfo'}->{"names_pdf"});
  return 1 if (exists $pms->{'pdfinfo'}->{"names_pdf"}->{$name});
  return 0;
}

# -----------------------------------------

sub pdf_name_regex {
  my ($self,$pms,$body,$re) = @_;
  return unless (defined $re);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'pdfinfo'}->{"names_pdf"});

  my $hit = 0;
  foreach my $name (keys %{$pms->{'pdfinfo'}->{"names_pdf"}}) {
    my $eval = 'if (q{'.$name.'} =~  '.$re.') {  $hit = 1; } ';
    eval $eval;
    dbg("pdfinfo: error in regex $re - $@") if $@;
    if ($hit) {
      dbg("pdfinfo: pdf_name_regex hit on $name");
      return 1;
    }
  }
  return 0;

}

# -----------------------------------------

sub pdf_is_encrypted {
  my ($self,$pms,$body) = @_;

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  return  $pms->{'pdfinfo'}->{'encrypted'};
}

# -----------------------------------------

sub pdf_count {
  my ($self,$pms,$body,$min,$max) = @_;
  
  return unless defined $min;

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  # dbg("pdfinfo: count: $min, ".($max ? $max:'').", pdfs=".$pms->{'pdfinfo'}->{"count_pdf"});
  return result_check($min, $max, $pms->{'pdfinfo'}->{"count_pdf"});

}

# -----------------------------------------

sub pdf_image_count {
  my ($self,$pms,$body,$min,$max) = @_;
  
  return unless defined $min;

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  # dbg("pdfinfo: image_count: $min, ".($max ? $max:'').", pdfs=".$pms->{'pdfinfo'}->{"count_pdf_images"});
  return result_check($min, $max, $pms->{'pdfinfo'}->{"count_pdf_images"});

}

# -----------------------------------------

sub pdf_pixel_coverage {
  my ($self,$pms,$body,$min,$max) = @_;

  return unless (defined $min);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }
  
  # dbg("pdfinfo: pc_$type: $min, ".($max ? $max:'').", $type, ".$pms->{'pdfinfo'}->{"pc_pdf"});
  return result_check($min, $max, $pms->{'pdfinfo'}->{"pc_pdf"});
}

# -----------------------------------------

sub pdf_image_to_text_ratio {
  my ($self,$pms,$body,$min,$max) = @_;
  return unless (defined $min && defined $max);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  # depending on how you call this eval (body vs rawbody), 
  # the $textlen will differ.
  my $textlen = length(join('',@$body));

  return 0 unless ( $textlen > 0 && exists $pms->{'pdfinfo'}->{"pc_pdf"} && $pms->{'pdfinfo'}->{"pc_pdf"} > 0);
  
  my $ratio = $textlen / $pms->{'pdfinfo'}->{"pc_pdf"};
  dbg("pdfinfo: image ratio=$ratio, min=$min max=$max");
  return result_check($min, $max, $ratio, 1);
}

# -----------------------------------------

sub pdf_image_size_exact {
  my ($self,$pms,$body,$height,$width) = @_;
  return unless (defined $height && defined $width);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'pdfinfo'}->{"dems_pdf"});
  return 1 if (exists $pms->{'pdfinfo'}->{"dems_pdf"}->{"${height}x${width}"});
  return 0;
}

# -----------------------------------------

sub pdf_image_size_range {
  my ($self,$pms,$body,$minh,$minw,$maxh,$maxw) = @_;
  return unless (defined $minh && defined $minw);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  my $name = 'dems_pdf';
  return unless (exists $pms->{'pdfinfo'}->{$name});

  foreach my $dem ( keys %{$pms->{'pdfinfo'}->{"dems_pdf"}}) {
    my ($h,$w) = split(/x/,$dem);
    next if ($h < $minh);  # height less than min height
    next if ($w < $minw);  # width less than min width
    next if (defined $maxh && $h > $maxh);  # height more than max height
    next if (defined $maxw && $w > $maxw);  # width more than max width

    # if we make it here, we have a match
    return 1;
  }

  return 0;
}

# -----------------------------------------

sub pdf_match_md5 {

  my ($self,$pms,$body,$md5) = @_;
  
  return unless defined $md5;
  my $uc_md5 = uc($md5);  # uppercase matches only

  # make sure we have pdf data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'pdfinfo'}->{"md5"});
  return 1 if (exists $pms->{'pdfinfo'}->{"md5"}->{$uc_md5});
  return 0;
}

# -----------------------------------------

sub pdf_match_fuzzy_md5 {

  my ($self,$pms,$body,$md5) = @_;
  
  return unless defined $md5;
  my $uc_md5 = uc($md5);  # uppercase matches only

  # make sure we have pdf data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'pdfinfo'}->{"fuzzy_md5"});
  return 1 if (exists $pms->{'pdfinfo'}->{"fuzzy_md5"}->{$uc_md5});
  return 0;
}

# -----------------------------------------

sub pdf_match_details {
  my ($self, $pms, $body, $detail, $regex) = @_;
  return unless ($detail && $regex);

  my $check_value = $pms->{pdfinfo}->{details}->{$detail};

  return unless $check_value;
 
  my $hit = 0;
  my $eval = 'if (q{'.$check_value.'} =~ '.$regex.') { $hit = 1; }';
  eval $eval;
  dbg("pdfinfo: error in regex $regex - $@") if $@;
  if ($hit) {
    dbg("pdfinfo: pdf_match_details $detail $regex matches $check_value");
    return 1;
  }
  return 0;
}

# -----------------------------------------

sub result_check {
  my ($min, $max, $value, $nomaxequal) = @_;
  return 0 unless defined $value;
  return 0 if ($value < $min);
  return 0 if (defined $max && $value > $max);
  return 0 if (defined $nomaxequal && $nomaxequal && $value == $max);
  return 1;
}

# -----------------------------------------

1;
