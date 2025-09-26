<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\Config\ConfigDB;


class Config {


    private ConfigDB $cfg;


    public function __construct( private readonly string $stConfigFile ) {
        if ( file_exists( $this->stConfigFile ) ) {
            $this->cfg = ConfigDB::fromFile( $this->stConfigFile );
        } else {
            $this->cfg = ConfigDB::fromJsonString( '{}' );
        }
    }


    public function getAcmeAccountUrl() : ?string {
        return $this->cfg->testGet( 'acme', 'account_url' )?->asString();
    }


    public function getAcmeAgreedTerms() : bool {
        return $this->cfg->testGet( 'acme', 'agreed_terms' )?->asBool() ?? false;
    }


    public function getAcmeContact() : ?string {
        return $this->cfg->testGet( 'acme', 'contact' )?->asEmailAddress();
    }


    public function getAcmeContactEx() : string {
        $stContact = $this->getAcmeContact();
        if ( is_string( $stContact ) ) {
            return $stContact;
        }
        throw new \RuntimeException( 'ACME contact not configured.' );
    }


    public function getApiValue( string $i_stKey ) : ?string {
        return $this->cfg->testGet( 'api', $i_stKey )?->asString();
    }


    public function getApiValueEx( string $i_stKey ) : string {
        $stValue = $this->getApiValue( $i_stKey );
        if ( is_string( $stValue ) ) {
            return $stValue;
        }
        throw new \RuntimeException( "API value '$i_stKey' not configured." );
    }


    public function hasAcmeContact() : bool {
        return ! empty( $this->getAcmeContact() );
    }


    public function setAcmeAccountUrl( string $i_stUrl ) : void {
        $this->cfg->set( 'acme', 'account_url', $i_stUrl );
        $this->save();
    }


    public function setAcmeAgreedTerms( bool $bAgreed ) : void {
        $this->cfg->set( 'acme', 'agreed_terms', $bAgreed );
        $this->save();
    }


    public function setAcmeContact( string $i_stContact ) : void {
        $this->cfg->set( 'acme', 'contact', $i_stContact );
        $this->save();
    }


    public function setApiValue( string $i_stKey, string $i_stValue ) : void {
        $this->cfg->set( 'api', $i_stKey, $i_stValue );
        $this->save();
    }


    private function save() : void {
        $this->cfg->serializeToFile( $this->stConfigFile );
        chmod( $this->stConfigFile, 0600 );
    }


}
