<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\DNSQuery\Resolver;
use JDWX\DNSQuery\RR\TXT;
use NFSN\APIClient\DNS;
use NFSN\APIClient\Manager;


class NFSNAPIDNSProvider implements DNSProviderInterface {


    private const int DESIRED_TTL = 180;

    private Manager $api;


    public function __construct( #[\SensitiveParameter] string $i_stMemberLogin,
                                 #[\SensitiveParameter] string $i_stApiKey ) {
        $this->api = new Manager( $i_stMemberLogin, $i_stApiKey );
    }


    public function setAuthKey( Target $i_target, string $i_stAuthKey ) : bool {
        $dns = $this->api->newDNS( $i_target->domain() );
        try {
            if ( ! $this->recordExists( $dns, $i_target->acmeName(), $i_stAuthKey ) ) {
                if ( ! $this->recordReplace( $dns, $i_target->acmeName(), $i_stAuthKey ) ) {
                    return false;
                }
            }

            // Verify that the record was set correctly.
            return $this->recordVerify( $i_target->acmeFQDN(), $i_stAuthKey );

        } catch ( \Exception $ex ) {
            echo "Failed to set DNS TXT record for {$i_target->acmeName()} on {$i_target->domain()}: {$ex}\n";
            return false;
        }
    }


    public function setup() : bool {
        return true;
    }


    private function recordExists( DNS $i_dns, string $i_stName, string $i_stAuthKey ) : bool {
        $rRecords = $i_dns->listRRs( $i_stName, 'TXT' );
        if ( ! is_array( $rRecords ) ) {
            return false;
        }
        foreach ( $rRecords as $rr ) {
            if ( $rr[ 'data' ] === $i_stAuthKey ) {
                return true;
            }
        }
        return false;
    }


    /**
     * Atomically replace any existing TXT records with the new one.
     * This is safer than it looks because it operates on the
     * _acme-challenge subdomain which should not have any other
     * records.
     */
    private function recordReplace( DNS $i_dns, string $i_stName, string $i_stAuthKey ) : bool {
        $x = $i_dns->replaceRR(
            $i_stName,
            'TXT',
            $i_stAuthKey,
            self::DESIRED_TTL
        );
        if ( $x === false ) {
            $x = 'Unknown error';
        }
        if ( is_string( $x ) ) {
            echo "Failed to replace record: {$x}\n";
            return false;
        }
        return true;
    }


    private function recordVerify( string $i_stFQDN, string $i_stExpectedValue ) : bool {
        $res = new Resolver( [
            gethostbyname( 'ns.phx1.nearlyfreespeech.net' ),
            gethostbyname( 'ns.phx2.nearlyfreespeech.net' ),
        ] );
        $res->recurse = false;
        echo 'Waiting up to 60 seconds for DNS to propagate...';
        for ( $ii = 0 ; $ii < 60 ; $ii++ ) {
            $v = $res->query( $i_stFQDN, 'TXT' );
            $rr = $v->answer[ 0 ] ?? null;
            if ( $rr instanceof TXT && ( $rr->text[ 0 ] ?? 'Nope' ) === $i_stExpectedValue ) {
                echo "OK!\n";
                return true;
            }
            echo '.';
            sleep( 1 );
        }
        echo "\n";
        echo "Timed out waiting for DNS to propagate.\n";
        return false;
    }


}