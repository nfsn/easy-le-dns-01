<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\DNSQuery\Resolver;
use JDWX\DNSQuery\RR\TXT;
use JDWX\Result\Result;
use NFSN\APIClient\DNSInterface;
use NFSN\APIClient\Manager;
use NFSN\APIClient\ManagerInterface;


class NFSNAPIDNSProvider implements DNSProviderInterface {


    use OutputTrait;


    private const int DESIRED_TTL = 180;


    /** @var list<string> */
    private array $rNameServers = [
        'ns.phx1.nearlyfreespeech.net',
        'ns.phx2.nearlyfreespeech.net',
        'ns.phx3.nearlyfreespeech.net',
        'ns.phx4.nearlyfreespeech.net',
        'ns.phx5.nearlyfreespeech.net',
        'ns.phx6.nearlyfreespeech.net',
        'ns.phx7.nearlyfreespeech.net',
        'ns.phx8.nearlyfreespeech.net',
    ];


    public function __construct( private readonly ManagerInterface $api,
                                 bool                              $i_bVerbose ) {
        $this->bVerbose = $i_bVerbose;
    }


    public static function fromCredentials( #[\SensitiveParameter] string $i_stMemberLogin,
                                            #[\SensitiveParameter] string $i_stApiKey,
                                            bool                          $i_bVerbose ) : self {
        $api = new Manager( $i_stMemberLogin, $i_stApiKey );
        return new self( $api, $i_bVerbose );
    }


    /** @return Result<null> */
    public function removeAuthKey( Target $i_target ) : Result {
        try {
            $dns = $this->dns( $i_target );
            $rRecords = $dns->listRRs( $i_target->acmeName(), 'TXT' );
            if ( ! is_array( $rRecords ) ) {
                return Result::err( 'Could not find TXT record to remove.' );
            }
            foreach ( $rRecords as $rr ) {
                $dns->removeRR( $i_target->acmeName(), 'TXT', $rr[ 'data' ] );
            }
            return Result::ok();
        } catch ( \Exception $ex ) {
            return Result::err(
                "Failed to remove DNS TXT record for {$i_target->acmeName()} on {$i_target->domain()}: {$ex}"
            );
        }
    }


    /** @return Result<null> */
    public function setAuthKey( Target $i_target, string $i_stAuthKey ) : Result {
        $dns = $this->dns( $i_target );
        try {
            if ( ! $this->recordExists( $dns, $i_target->acmeName(), $i_stAuthKey ) ) {
                $res = $this->recordReplace( $dns, $i_target->acmeName(), $i_stAuthKey );
                if ( $res->isError() ) {
                    return $res;
                }
            }

            // Verify that the record was set correctly.
            return $this->recordVerify( $i_target->acmeFQDN(), $i_stAuthKey );

        } catch ( \Exception $ex ) {
            return Result::err(
                "Failed to set DNS TXT record for {$i_target->acmeName()} on {$i_target->domain()}: {$ex}"
            );
        }
    }


    /** @return Result<null> */
    public function setup() : Result {
        return Result::ok();
    }


    private function dns( Target $i_target ) : DNSInterface {
        return $this->api->newDNS( $i_target->domain() );
    }


    private function recordExists( DNSInterface $i_dns, string $i_stName, string $i_stAuthKey ) : bool {
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
     * @return Result<null>
     *
     * Atomically replace any existing TXT records with the new one.
     * This is safer than it looks because it operates on the
     * _acme-challenge subdomain which should not have any other
     * records.
     */
    private function recordReplace( DNSInterface $i_dns, string $i_stName, string $i_stAuthKey ) : Result {
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
            return Result::err( "Failed to replace record: {$x}" );
        }
        return Result::ok();
    }


    /** @return Result<null> */
    private function recordVerify( string $i_stFQDN, string $i_stExpectedValue ) : Result {
        $this->verbose( 'Waiting for DNS to propagate...' );
        foreach ( $this->rNameServers as $stNS ) {
            $ip = gethostbyname( $stNS );
            $res = new Resolver( [ $ip ] );
            $res->recurse = false;
            for ( $ii = 0 ; $ii < 60 ; $ii++ ) {
                try {
                    $v = $res->query( $i_stFQDN, 'TXT' );
                } catch ( \Exception ) {
                    $v = null;
                }
                $rr = $v->answer[ 0 ] ?? null;
                if ( $rr instanceof TXT && ( $rr->text[ 0 ] ?? 'Nope' ) === $i_stExpectedValue ) {
                    $this->verbose( '👍' );
                    continue 2;
                }
                $this->verbose( '.' );
                sleep( 1 );
            }
            $this->verbose( "\n" );
            return Result::err( 'Timed out waiting for DNS to propagate.' );
        }
        if ( $this->bVerbose ) {
            $this->verbose( "OK!\n" );
        }
        $this->verbose( "Waiting an extra 10 seconds just to be sure...\n" );
        sleep( 10 );
        return Result::ok();
    }


}