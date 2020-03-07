#!perl

use strict;
use warnings;

use Test::More;

use HTTP::Status qw/ :constants :is /;
use HTTP::Request::Common;
use Plack::Builder;
use Plack::Response;
use Plack::Test;

my $handler = builder {
    enable "HTTPExceptions", rethrow => 1;

    enable "Security::Simple",
        handler => sub {
            my $res = Plack::Response->new(HTTP_NOT_FOUND);
            $res->content_type('text/plain');
            $res->body('Nope');
            return $res->finalize;
        },
        rules => [
            PATH_INFO => qr{\.(php|asp)$},
            -and => {
                PATH_INFO      => qr{^/cgi-bin/},
                REQUEST_METHOD => "POST",
            }
        ];

    sub { return [ HTTP_OK, [], ['Ok'] ] };
};

test_psgi
  app    => $handler,
  client => sub {
    my $cb = shift;

    subtest 'not blocked' => sub {
        my $req = GET "/some/thing.html";
        my $res = $cb->($req);

        ok is_success( $res->code ), join( " ", $req->method, $req->uri );
        is $res->code, HTTP_OK, "HTTP_OK";

    };

    subtest 'blocked' => sub {
        my $req = GET "/some/thing.php";
        my $res = $cb->($req);

        ok is_error( $res->code ), join( " ", $req->method, $req->uri );
        is $res->code, HTTP_NOT_FOUND, "HTTP_NOT_FOUND";

    };

    subtest 'blocked' => sub {
        my $req = GET "/some/thing.php?stuff=1";
        my $res = $cb->($req);

        ok is_error( $res->code ), join( " ", $req->method, $req->uri );
        is $res->code, HTTP_NOT_FOUND, "HTTP_NOT_FOUND";

    };

    subtest 'not blocked' => sub {
        my $req = GET "/cgi-bin/thing.html";
        my $res = $cb->($req);

        ok is_success( $res->code ), join( " ", $req->method, $req->uri );
        is $res->code, HTTP_OK, "HTTP_OK";

    };


    subtest 'blocked' => sub {
        my $req = POST "/cgi-bin/thing?stuff=1";
        my $res = $cb->($req);

        ok is_error( $res->code ), join( " ", $req->method, $req->uri );
        is $res->code, HTTP_NOT_FOUND, "HTTP_NOT_FOUND";

    };

 };

done_testing;