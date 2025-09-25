<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\App\InteractiveTrait;
use JDWX\Json\Json;
use JDWX\Result\Result;


class ManualDNSProvider implements DNSProviderInterface {


    use InteractiveTrait;

    use OutputTrait;


    public function __construct( bool $i_bVerbose = false ) {
        $this->bVerbose = $i_bVerbose;
    }


    /** @param array<string, mixed> $context */
    public function error( \Stringable|string $message, array $context = [] ) : void {
        $this->output( 'Error: ', $message, "\n" );
        $this->verbose( Json::encode( $context, JSON_PRETTY_PRINT ), "\n" );
    }


    /** @return Result<null> */
    public function removeAuthKey( Target $i_target ) : Result {
        $this->output( 'It is now safe to remove the DNS TXT record.' );
        return Result::ok();
    }


    /** @return Result<null> */
    public function setAuthKey( Target $i_target, string $i_stAuthKey ) : Result {
        $this->output( "Please create the following DNS TXT record:\n\n" );
        $this->output( "\$ORIGIN {$i_target->domain()}.\n" );
        $this->output( "{$i_target->acmeName()} IN TXT \"{$i_stAuthKey}\"\n\n" );
        if ( ! $this->askYN( 'Do you want to continue? ' ) ) {
            return Result::err( 'Manual creation of DNS records aborted.' );
        }
        return Result::ok();
    }


    /** @return Result<null> */
    public function setup() : Result {
        return Result::ok();
    }


    /** @param array<string, mixed> $context */
    public function warning( \Stringable|string $message, array $context = [] ) : void {
        $this->output( 'Warning: ', $message, "\n" );
        $this->verbose( Json::encode( $context, JSON_PRETTY_PRINT ), "\n" );
    }


}
