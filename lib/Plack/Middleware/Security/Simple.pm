package Plack::Middleware::Security::Simple;

# ABSTRACT: A simple security filter for Plack

use v5.10.0;

use strict;
use warnings;

use parent qw( Plack::Middleware );

use Hash::Match;
use HTTP::Status qw( HTTP_BAD_REQUEST );
use Ref::Util qw/ is_plain_arrayref is_plain_hashref /;

use Plack::Response;
use Plack::Util::Accessor qw( rules handler );

# RECOMMEND PREREQ: Ref::Util::XS

our $VERSION = 'v0.4.0';

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

=attr rules

This is a set of rules. It can be a an array-reference or
L<Hash::Match> object containing matches against keys in the Plack
environment.

It can also be a code reference for a subroutine that takes the Plack
environment as an argument and returns a true value if there is a
match.

=attr handler

This is a function that is called when a match is found.

It takes the Plack environment as an argument, and returns a
L<Plack::Response>, or throws an exception for
L<Plack::Middleware::HTTPExceptions>.

The default handler will log a warning to the C<psgix.logger>, and
return a HTTP 400 (Bad Request) response.

=cut

sub prepare_app {
    my ($self) = @_;

    if (my $rules = $self->rules) {

        if ( is_plain_arrayref($rules) || is_plain_hashref($rules) ) {
            $self->rules( Hash::Match->new( rules => $rules ) );
        }

    }

    unless ( $self->handler ) {
        $self->handler(
            sub {
                my ($env) = @_;
                if ( my $logger = $env->{'psgix.logger'} ) {
                    $logger->({
                        level   => "warn",
                        message => __PACKAGE__
                          . " Blocked $env->{REMOTE_ADDR} $env->{REQUEST_URI}"
                    });
                }
            my $res = Plack::Response->new(HTTP_BAD_REQUEST, [ 'Content-Type' => 'text/plain' ], [ "Bad Request" ] );
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

=head1 SEE ALSO

L<Hash::Match>

L<Plack>

L<PSGI>

=cut

1;
