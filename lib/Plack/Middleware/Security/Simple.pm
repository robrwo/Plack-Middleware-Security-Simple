package Plack::Middleware::Security::Simple;

use strict;
use warnings;

use parent qw( Plack::Middleware );

use Hash::Match;
use HTTP::Exception;
use HTTP::Status qw( HTTP_BAD_REQUEST );
use Ref::Util qw/ is_plain_arrayref is_plain_hashref /;

use Plack::Util;
use Plack::Util::Accessor qw( rules handler );

our $VERSION = 'v0.1.0';

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
                    $logger->(
                        level   => "warn",
                        message => __PACKAGE__
                          . " Blocked $env->{REMOTE_ADDR} $env->{REQUEST_URI}"
                    );
                }
                return HTTP::Exception->throw(HTTP_BAD_REQUEST);
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

1;
