<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\ACME\ACMEv2;
use JDWX\ACME\Certificate;
use JDWX\ACME\Client;
use JDWX\ACME\JWT;
use JDWX\App\InteractiveApplication;
use JDWX\Param\Validate;
use OpenSSLAsymmetricKey;


abstract class Application extends InteractiveApplication {


    protected Config $cfg;

    private Client $client;

    private DNSProviderInterface $dns;

    private Target $target;


    abstract protected function getConfigFilePath() : string;


    abstract protected function getDNSProvider() : ?DNSProviderInterface;


    abstract protected function getTarget() : Target;


    protected function main() : int {
        $this->cfg = new Config( $this->getConfigFilePath() );

        $jwk = JWT::getOrCreateKey( __DIR__ . '/../data/le-account.key' );
        $acme = new ACMEv2( ACMEv2::LE_PRODUCTION_URL );
        $this->client = new Client( $jwk, $acme );

        if ( ! $this->agreeToLetsEncryptTerms() ) {
            echo "No worries. (Exiting.)\n";
            return 0;
        }

        if ( ! $this->setContactEmailAddress() ) {
            echo "No worries. (Exiting.)\n";
            return 1;
        }

        $this->loadAcmeAccount();

        $this->target = $this->getTarget();

        echo $this->target, "\n";


        if ( ( $dns = $this->getDNSProvider() ) === null ) {
            echo "No DNS provider configured. (Exiting.)\n";
            return 1;
        }
        $this->dns = $dns;
        if ( ! $this->dns->setup() ) {
            echo "Failed to set up DNS provider. (Exiting.)\n";
            return 1;
        }

        $this->dns->setAuthKey( $this->target, 'example-key' );

        return 0;
    }


    private function agreeToLetsEncryptTerms() : bool {
        if ( $this->cfg->getAcmeAgreedTerms() ) {
            return true;
        }
        $stURL = $this->client->directory()[ 'meta' ][ 'termsOfService' ];
        echo "The Let's Encrypt Terms of Service can be found at:\n";
        echo "  {$stURL}\n";
        $stPrompt = "Do you agree to the Let's Encrypt Terms of Service [y/n]? ";
        if ( ! $this->askYN( $stPrompt ) ) {
            return false;
        }
        $this->cfg->setAcmeAgreedTerms( true );
        return true;
    }


    private function getOrCreateAcmeAccount() : string {
        $stAccount = $this->cfg->getAcmeAccountUrl();
        if ( is_string( $stAccount ) ) {
            echo "Using existing account: {$stAccount}\n";
            return $stAccount;
        }
        $stAccount = $this->client->newAccount( $this->cfg->getAcmeContactEx() );
        $this->cfg->setAcmeAccountUrl( $stAccount );
        echo "New account created: {$stAccount}\n";
        return $stAccount;
    }


    private function getOrCreateTLSPrivateKey( string $i_stName ) : OpenSSLAsymmetricKey {
        $stKeyPath = "{$i_stName}.key";
        if ( file_exists( $stKeyPath ) ) {
            echo "Using existing private key in {$stKeyPath}\n";
            return Certificate::readKeyPrivate( $stKeyPath );
        }
        echo "Generating new private key in {$stKeyPath}\n";
        $key = Certificate::makeKey();
        Certificate::writeKeyPrivate( $stKeyPath, $key );
        return $key;
    }


    private function loadAcmeAccount() : void {
        $stAccount = $this->getOrCreateAcmeAccount();
        $this->client->account( $stAccount );
    }


    private function setContactEmailAddress() : bool {
        if ( $this->cfg->hasAcmeContact() ) {
            return true;
        }
        echo "Let's Encrypt requires a contact email address to send updates about\n",
        "expiration and suchlike.\n";
        while ( true ) {
            $bst = $this->readLine( 'What email address should they use? ' );
            if ( empty( $bst ) ) {
                return false;
            }
            if ( Validate::emailAddress( $bst ) ) {
                break;
            }
            echo "That doesn't look like a valid email address.\n";
        }

        $this->cfg->setAcmeContact( $bst );
        return true;
    }


}
