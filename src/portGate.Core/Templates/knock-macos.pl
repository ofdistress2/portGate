use strict;
use warnings;
use Digest::SHA qw(hmac_sha256_hex);
use MIME::Base64 qw(decode_base64);
use IO::Select;
use POSIX qw(strftime);
use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST NI_NUMERICSERV SOCK_DGRAM IPPROTO_UDP);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

my $server = '@@SERVER@@';
my $port = @@PORT@@;
my $server_id = '@@SERVERID@@';
my $client_id = '@@CLIENTID@@';
my $key = decode_base64('@@KEY@@');
my $deadline = clock_gettime(CLOCK_MONOTONIC) + 30;

sub sign_packet {
    my ($body) = @_;
    return $body . '|' . hmac_sha256_hex($body, $key);
}

sub verified_fields {
    my ($packet) = @_;
    return unless $packet =~ /\A([!-~]+)\|([a-f0-9]{64})\z/;
    my ($body, $mac) = ($1, $2);
    my $expected = hmac_sha256_hex($body, $key);
    my $difference = 0;
    $difference |= ord(substr($expected, $_, 1)) ^ ord(substr($mac, $_, 1)) for 0 .. 63;
    return if $difference;
    return split /\|/, $body, -1;
}

sub exchange {
    my ($socket, $body, $type, $nonce, $challenge) = @_;
    my $packet = sign_packet($body);
    my $readable = IO::Select->new($socket);
    for (1 .. 3) {
        my $until = clock_gettime(CLOCK_MONOTONIC) + 2;
        $until = $deadline if $deadline < $until;
        last if $until <= clock_gettime(CLOCK_MONOTONIC);
        defined send($socket, $packet, 0) or last;
        while ((my $remaining = $until - clock_gettime(CLOCK_MONOTONIC)) > 0) {
            last unless $readable->can_read($remaining);
            my $reply;
            last unless defined recv($socket, $reply, 1201, 0);
            next if length($reply) > 1200;
            my @fields = verified_fields($reply);
            next unless @fields == 8 && $fields[0] eq 'KG1' && $fields[1] eq $type
                && $fields[2] eq $server_id && $fields[3] eq $client_id && $fields[4] eq $nonce
                && $fields[5] =~ /\A[a-f0-9]{32}\z/ && $fields[6] =~ /\A[0-9]{1,12}\z/;
            next if defined($challenge) && $fields[5] ne $challenge;
            return @fields;
        }
    }
    return;
}

sub nonce {
    open my $random, '<:raw', '/dev/urandom' or die "KG_RANDOM\n";
    my $bytes;
    read($random, $bytes, 16) == 16 or die "KG_RANDOM\n";
    return unpack 'H*', $bytes;
}

sub authorize {
    # Keep DNS within the same upper bound as the UDP exchange.
    local $SIG{ALRM} = sub { die "KG_DNS\n" };
    alarm 5;
    my ($error, @endpoints) = getaddrinfo($server, "$port", { socktype => SOCK_DGRAM, protocol => IPPROTO_UDP });
    alarm 0;
    die "KG_DNS\n" if $error || !@endpoints;

    my $failure = 'KG_CHALLENGE';
    my $tried = 0;
    for my $endpoint (@endpoints) {
        last if ++$tried > 8 || clock_gettime(CLOCK_MONOTONIC) >= $deadline;
        socket(my $socket, $endpoint->{family}, $endpoint->{socktype}, $endpoint->{protocol}) or next;
        connect($socket, $endpoint->{addr}) or next;
        my $nonce = nonce();
        my $hello = join '|', 'KG1', 'HELLO', $server_id, $client_id, 0, $nonce;
        my @challenge = exchange($socket, $hello, 'CHALLENGE', $nonce, undef);
        next unless @challenge;
        $failure = 'KG_RESULT';
        next if $challenge[6] <= 0;
        my $proof = join '|', 'KG1', 'PROOF', $server_id, $client_id, $nonce, @challenge[5, 6];
        my @result = exchange($socket, $proof, 'RESULT', $nonce, $challenge[5]);
        next unless @result && $result[6] > 0 && $result[7] =~ /\A[0-9]{1,5}\z/
            && $result[7] > 0 && $result[7] <= 65535;
        my $until = strftime('%Y-%m-%d %H:%M:%S', localtime $result[6]);
        my ($address_error, $numeric) = getnameinfo($endpoint->{addr}, NI_NUMERICHOST | NI_NUMERICSERV);
        $numeric = '' if $address_error || !defined $numeric;
        print "KG_OK|$until|$numeric|$result[7]\n";
        return;
    }
    die "$failure\n";
}

my $ok = eval { authorize(); 1 };
if (!$ok) {
    my $error = $@;
    print $error =~ /\A(KG_[A-Z]+)\n\z/ ? "$1\n" : "KG_ERROR\n";
    exit 1;
}
