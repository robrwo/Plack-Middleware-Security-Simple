package Plack::Middleware::Security::Common;

# ABSTRACT: A simple security filter for with common rules.

use strict;
use warnings;

use parent qw( Plack::Middleware::Security::Simple Exporter::Tiny );

our @EXPORT = qw(
   archive_extensions
   cgi_bin
   dot_files
   misc_extensions
   non_printable_chars
   null_or_escape
   require_content
   script_extensions
   system_dirs
   unexpected_content
   webdav_methods
   wordpress
);

our $VERSION = 'v0.4.3';

=head1 SYNOPSIS

  use Plack::Builder;

  # import rules
  use Plack::Middleware::Security::Common;

  builder {

    enable "Security::Common",
        rules => [
            archive_extensions, # block .tar, .zip etc
            cgi_bin,            # block /cgi-bin
            script_extensions,  # block .php, .asp etc
            unexpected_content, # block GET with body params
            ...
        ];

   ...

  };

=head1 DESCRIPTION

This is an extension of L<Plack::Middleware::Security::Simple> that
provides common filtering rules.

Most of these rules don't directly improve the security of your web
application: they simply block common exploit scanners from getting
past the PSGI layer.

See L</EXPORTS> for a list of rules.

=cut

=export archive_extensions

This blocks requests with common archive file extensions in the path
or query string.

=cut

sub archive_extensions {
    my $re = qr{\.(?:iso|rar|tar|u?zip|[7g]?z)\b};
    return (
        PATH_INFO    => $re,
        QUERY_STRING => $re,
    );
}

=export cgi_bin

This blocks requests that refer to the C<cgi-bin> directory in the path
or query string, or a C<cgi_wrapper> script.

=cut

sub cgi_bin {
    my $re = qr{/cgi[_\-](bin|wrapper)};
    return (
        PATH_INFO    => $re,
        QUERY_STRING => $re,
    );
}

=export dot_files

This blocks all requests that refer to dot-files or C<..>, except for
the F</.well-known/> path.

=cut

sub dot_files {
    return (
        PATH_INFO    => qr{(?:\.\./|/\.(?!well-known/))},
        QUERY_STRING => qr{\.\./},
    );
}

=export misc_extensions

This blocks requests with miscellenious extensions in the path or
query string.

=cut

sub misc_extensions {
    my $re = qr{[.](?:bak|dat|inc)\b};
    return (
        PATH_INFO    => $re,
        QUERY_STRING => $re,
    )
}

=export non_printable_chars

This blocks requests with non-printable characters in the path.

=cut

sub non_printable_chars {
    return ( PATH_INFO => qr/[^[:print:]]/ )
}

=export null_or_escape

This blocks requests with nulls or escape chatacters in the path or
query string.

=cut

sub null_or_escape {
    my $re = qr{\%(?:00|1b|1B)};
    return (
        REQUEST_URI  => $re,
    )
}

=export require_content

This blocks POST or PUT requests with no content.

This was added in v0.4.1.

=cut

sub require_content {
    return (
        -and => [
             REQUEST_METHOD => qr{^(?:POST|PUT)$},
             CONTENT_LENGTH => sub { !$_[0] },
        ],
    );
}

=export script_extensions

This blocks requests that refer to actual scripts, file file
extension, such as C<.php> or C<.asp>.  It will also block requests
that refer to these scripts in the query string.

=cut

sub script_extensions {
    my $re = qr{[.](?:as[hp]x?|axd|bat|cfm|cgi|jspa?|lua|php5?|p[lm]|ps[dm]?[1h]|sht?|shtml|sql)\b};
    return (
        PATH_INFO    => $re,
        QUERY_STRING => $re,
    )
}

=export system_dirs

This blocks requests that refer to system directories in the path or
query string.

=cut

sub system_dirs {
    my $re = qr{/(?:s?bin|etc|usr|var|srv|opt)/};
    return (
        PATH_INFO    => $re,
        QUERY_STRING => $re,
    );
}

=export unexpected_content

This blocks requests with content bodies using methods that don't
normally have content bodies, such as GET or HEAD.

Note that web sites which do not differentiate between query and body
parameters can be caught out by this. An attacker can hit these
website with GET requests that have parameters that exploit security
holes in the request body.  The request would appear as a normal GET
request in most logs.

=cut

sub unexpected_content {
    return (
        -and => [
             REQUEST_METHOD => qr{^(?:GET|HEAD|CONNECT|OPTIONS|TRACE)$},
             CONTENT_LENGTH => sub { !!$_[0] },
        ],
    );
}

=export webdav_methods

This blocks requests using WebDAV-realted methods.

=cut

sub webdav_methods {
    return ( REQUEST_METHOD =>
          qr{^(COPY|LOCK|MKCOL|MOVE|PROPFIND|PROPPATCH|UNLOCK)$} );
}

=export wordpress

This blocks requests for WordPress-related pages.

=cut

sub wordpress {
    return ( PATH_INFO => qr{\b(?:wp(-\w+)?|wordpress)\b} );
}

=head1 append:BUGS

Suggestions for new rules or improving the existing rules are welcome.

=cut

1;
