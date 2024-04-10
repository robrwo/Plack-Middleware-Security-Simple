package Plack::Middleware::Security::Simple;

# ABSTRACT: A simple security filter for Plack

use v5.14;

use warnings;

use parent qw( Plack::Middleware );

use Hash::Match;
use HTTP::Status qw( HTTP_BAD_REQUEST );
use Ref::Util qw/ is_plain_arrayref is_plain_hashref /;

use Plack::Response;
use Plack::Util::Accessor qw( rules handler status );

# RECOMMEND PREREQ: Ref::Util::XS

our $VERSION = 'v0.12.1';

=head1 SYNOPSIS

  use Plack::Builder;

  builder {

    enable "Security::Simple",
        rules => [
            PATH_INFO       => qr{^/cgi-bin/},
            PATH_INFO       => qr{\.(php|asp)$},
            HTTP_USER_AGENT => qr{BadRobot},
        ];

   ...

  };

=head1 DESCRIPTION

This module provides a simple security filter for PSGI-based
applications, so that you can filter out obvious exploit-seeking
scripts.

Note that as an alternative, you may want to consider using something like
L<modsecurity|https://modsecurity.org/> as a filter in a reverse proxy.

=attr rules

This is a set of rules. It can be a an array-reference or
L<Hash::Match> object containing matches against keys in the Plack
environment.

It can also be a code reference for a subroutine that takes the Plack
environment as an argument and returns a true value if there is a
match.

See L<Plack::Middleware::Security::Common> for a set of common rules.

=attr handler

This is a function that is called when a match is found.

It takes the Plack environment as an argument, and returns a
L<Plack::Response>, or throws an exception for
L<Plack::Middleware::HTTPExceptions>.

The default handler will log a warning to the C<psgix.logger>, and
return a HTTP 400 (Bad Request) response.

The message is of the form

  Plack::Middleware::Security::Simple Blocked $ip $method $path_query HTTP $status

This can be used if you are writing L<fail2ban> filters.

=attr status

This is the HTTP status code that the default L</handler> will return
when a resource is blocked.  It defaults to 400 (Bad Request).

=cut

sub prepare_app {
    my ($self) = @_;

    if (my $rules = $self->rules) {

        if ( is_plain_arrayref($rules) || is_plain_hashref($rules) ) {
            $self->rules( Hash::Match->new( rules => $rules ) );
        }

    }

    unless ( $self->status ) {
        $self->status( HTTP_BAD_REQUEST );
    }

    unless ( $self->handler ) {
        $self->handler(
            sub {
                my ($env) = @_;
                my $status = $self->status;
                if ( my $logger = $env->{'psgix.logger'} ) {
                    $logger->({
                        level   => "warn",
                        message => __PACKAGE__
                          . " Blocked $env->{REMOTE_ADDR} $env->{REQUEST_METHOD} $env->{REQUEST_URI} HTTP $status"
                    });
                }
            my $res = Plack::Response->new($status, [ 'Content-Type' => 'text/plain' ], [ "Bad Request" ] );
                return $res->finalize;

            }
        );
    }

}

sub call {
    my ( $self, $env ) = @_;
    if (my $rules = $self->rules) {
        return $self->handler()->( $env ) if $rules->($env);
    }
    return $self->app->($env);
}

=head1 SUPPORT FOR OLDER PERL VERSIONS

Since v0.9.0, the this module requires Perl v5.14 or later.

Future releases may only support Perl versions released in the last ten years.

If you need this module on Perl v5.10, please use one of the v0.8.x
versions of this module.  Significant bug or security fixes may be
backported to those versions.

=head1 SEE ALSO

L<Hash::Match>

L<Plack>

L<PSGI>

=cut

1;
