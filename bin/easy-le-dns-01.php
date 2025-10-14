#!/usr/bin/env php
<?php


declare( strict_types = 1 );


require_once __DIR__ . '/../vendor/autoload.php';


use JDWX\Args\Option;
use JDWX\Result\Result;
use NFSN\DNS01\Application;
use NFSN\DNS01\DNSProviderInterface;
use NFSN\DNS01\ManualDNSProvider;
use NFSN\DNS01\NFSNAPIDNSProvider;
use NFSN\DNS01\Target;


( new class( $argv ) extends Application {


    private const string CONFIG_FILE_PATH     = __DIR__ . '/../data/lets-encrypt.json';

    private const string DEFAULT_DNS_PROVIDER = 'nfsn';


    private string $stProvider;


    protected function getTarget() : Target {
        $stFQDN = $this->args()->shiftStringEx( 'FQDN is required.' );
        $stDomain = $this->args()->shiftString();
        $this->args()->end();
        return new Target( $stFQDN, $stDomain );
    }


    public function setup() : void {
        parent::setup();
        $this->stProvider = Option::simpleString( 'provider', $this->args() ) ?? self::DEFAULT_DNS_PROVIDER;
    }


    protected function getConfigFilePath() : string {
        return self::CONFIG_FILE_PATH;
    }


    /** @return Result<DNSProviderInterface> */
    protected function getDNSProvider() : Result {
        return match ( $this->stProvider ) {
            'nfsn' => $this->getNFSNDNSProvider(),
            'manual' => $this->getManualDNSProvider(),
            default => Result::err( "Unknown DNS provider: {$this->stProvider}" ),
        };
    }


    protected function listFlags() : array {
        return array_merge( parent::listFlags(), [
            'provider=xxxx' => 'DNS provider to use ("nfsn", "manual"). [default: ' . self::DEFAULT_DNS_PROVIDER . ']',
        ] );
    }


    /** @return Result<DNSProviderInterface> */
    private function getNFSNDNSProvider() : Result {

        $resLogin = $this->getMemberLogin();
        if ( $resLogin->isError() ) {
            return $resLogin->withValue( null );
        }
        $resAPIKey = $this->getAPIKey();
        if ( $resAPIKey->isError() ) {
            return $resAPIKey->withValue( null );
        }
        return Result::ok(
            i_xValue: NFSNAPIDNSProvider::fromCredentials( $resLogin->unwrapEx(), $resAPIKey->unwrapEx(), $this->bVerbose )
        );
    }


    /** @return Result<DNSProviderInterface> */
    private function getManualDNSProvider() : Result {
        return Result::ok( i_xValue: new ManualDNSProvider( $this->bVerbose ) );
    }


    /** @return Result<string> */
    private function getMemberLogin() : Result {
        if ( ! empty( $_ENV[ 'NFSN_API_USERNAME' ] ) ) {
            return Result::ok( i_xValue: $_ENV[ 'NFSN_API_USERNAME' ] );
        }
        if ( is_string( $st = $this->cfg->getApiValue( 'nfsn_member_login' ) ) ) {
            return Result::ok( i_xValue: $st );
        }

        $st = $this->readLine( 'Enter your NFSN Member Login: ' );
        if ( empty( $st ) ) {
            return Result::err( 'NFSN Member Login is required.' );
        }
        $this->cfg->setApiValue( 'nfsn_member_login', $st );
        return Result::ok( i_xValue: $st );
    }


    /** @return Result<string> */
    private function getAPIKey() : Result {
        if ( ! empty( $_ENV[ 'NFSN_API_KEY' ] ) ) {
            return Result::ok( i_xValue: $_ENV[ 'NFSN_API_KEY' ] );
        }
        if ( is_string( $st = $this->cfg->getApiValue( 'nfsn_api_key' ) ) ) {
            return Result::ok( i_xValue: $st );
        }
        $st = $this->readLine( 'Enter your NFSN API Key: ' );
        if ( empty( $st ) ) {
            return Result::err( 'NFSN API Key is required.' );
        }
        if ( $this->askYN( 'Save API Key to configuration file? ', false ) ) {
            $this->cfg->setApiValue( 'nfsn_api_key', $st );
        }
        return Result::ok( i_xValue: $st );
    }


} )();

