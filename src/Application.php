<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\ACME\ACMEv2;
use JDWX\ACME\Certificate;
use JDWX\ACME\Client;
use JDWX\ACME\JWT;
use JDWX\ACME\Order;
use JDWX\App\InteractiveApplication;
use JDWX\Param\Validate;
use JDWX\Result\Result;
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

        if ( ! $this->initialize() ) {
            echo "(Exiting.)\n";
            return 1;
        }

        $order = new Order( $this->client->newOrder( $this->target->fqdn() ), $this->target->fqdn() );
        $stOrderUrl = $order->locationEx();
        $res = $this->client->waitOnOrder( $order );
        if ( $res->isError() ) {
            echo 'Failed to create order: ', $res->message(), "\n";
            return 1;
        }
        $order = $res->unwrapEx();
        if ( $order->hasCertificate() ) {
            echo "Order already has a certificate.\n";
        } else {

            $order = $this->doChallenge( $order );
            if ( ! $order instanceof Order ) {
                echo "Failed to complete challenge. (Exiting.)\n";
                return 1;
            }

            $res = $this->waitForValidation( $order );
            if ( $res->isError() ) {
                echo 'Order did not become ready: ', $res->message(), "\n";
                /** @noinspection ForgottenDebugOutputInspection */
                var_dump( $res->xValue );
                return 1;
            }

            $order = $this->client->order( $stOrderUrl );
            $res = $this->doFinalize( $order );
            if ( $res->isError() ) {
                echo 'Failed to finalize order: ', $res->message(), "\n";
                /** @noinspection ForgottenDebugOutputInspection */
                var_dump( $res->xValue );
                return 1;
            }
            $order = $res->unwrapEx();
        }

        $res = $this->saveCertificate( $order );
        if ( $res->isError() ) {
            echo 'Failed to save certificate: ', $res->message(), "\n";
            /** @noinspection ForgottenDebugOutputInspection */
            var_dump( $res->xValue );
            return 1;
        }

        echo "All set!\n";
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


    private function doChallenge( Order $order ) : ?Order {
        echo "Starting challenge...\n";
        $rChallenge = $this->client->getChallenge( $order, $this->target->fqdn(), 'dns-01' );
        $stAuthKey = $this->client->keyAuthorizationHashed( $rChallenge[ 'token' ] );

        if ( ! $this->dns->setAuthKey( $this->target, $stAuthKey ) ) {
            return null;
        }

        echo "Validating challenge...\n";
        $this->client->validate( $order, $this->target->fqdn(), 'dns-01' );

        $res = $this->client->waitOnOrder( $order );
        if ( $res->isError() ) {
            echo 'Validate failed: ', $res->message(), "\n";
            echo "This information may help for debugging:\n";
            /** @noinspection ForgottenDebugOutputInspection */
            var_dump( $order );
            return null;
        }
        return $res->unwrapEx();
    }


    /** @return Result<Order> */
    private function doFinalize( Order $order ) : Result {
        echo "Finalizing order...\n";
        $privateKey = $this->getOrCreateTLSPrivateKey( $this->target->fqdn() );
        $stCSR = Certificate::makeCSR( $privateKey, [ $this->target->fqdn() ] );
        if ( ! $order->hasFinalize() ) {
            return Result::err( 'Order does not have a finalize URL.', $order );
        }
        if ( ! $order->isReady() ) {
            return Result::err( 'Order is not ready to finalize.', $order );
        }
        $order = $this->client->finalize( $order, $stCSR );
        return $this->client->waitOnOrder( $order );
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
        $stKeyPath = __DIR__ . "/../data/{$i_stName}.key";
        if ( file_exists( $stKeyPath ) ) {
            return Certificate::readKeyPrivate( $stKeyPath );
        }
        echo "Generating new private key in {$stKeyPath}\n";
        $key = Certificate::makeKey();
        Certificate::writeKeyPrivate( $stKeyPath, $key );
        return $key;
    }


    private function initialize() : bool {
        $this->cfg = new Config( $this->getConfigFilePath() );

        $jwk = JWT::getOrCreateKey( __DIR__ . '/../data/le-account.key' );
        $acme = new ACMEv2( ACMEv2::LE_PRODUCTION_URL );
        $this->client = new Client( $jwk, $acme );

        if ( ! $this->agreeToLetsEncryptTerms() ) {
            echo "No worries.\n";
            return false;
        }

        if ( ! $this->setContactEmailAddress() ) {
            echo "No worries.\n";
            return false;
        }

        $this->loadAcmeAccount();

        $this->target = $this->getTarget();
        echo $this->target, "\n";

        if ( ( $dns = $this->getDNSProvider() ) === null ) {
            echo "No DNS provider configured.\n";
            return false;
        }
        $this->dns = $dns;
        if ( ! $this->dns->setup() ) {
            echo "Failed to set up DNS provider. (Exiting.)\n";
            return false;
        }

        return true;
    }


    private function loadAcmeAccount() : void {
        $stAccount = $this->getOrCreateAcmeAccount();
        $this->client->account( $stAccount );
    }


    /** @return Result<Order> */
    private function saveCertificate( Order $i_order ) : Result {
        if ( $i_order->getStatus() !== 'valid' ) {
            return Result::err( 'Order status is not valid.', $i_order );
        }
        if ( ! $i_order->hasCertificate() ) {
            return Result::err( 'Order does not have a certificate URL.', $i_order );
        }
        $stCertificate = $this->client->certificate( $i_order );
        $stKey = Certificate::keyToString( $this->getOrCreateTLSPrivateKey( $this->target->fqdn() ) );
        $stPEMPath = __DIR__ . "/../data/{$this->target->fqdn()}.pem";
        if ( file_exists( $stPEMPath ) ) {
            rename( $stPEMPath, "{$stPEMPath}.old" );
        }
        file_put_contents( $stPEMPath, $stKey . "\n" . $stCertificate );
        echo "Wrote PEM file {$stPEMPath}\n";
        return Result::ok( i_xValue: $i_order );
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


    /**
     * @return Result<mixed[]>
     * @suppress PhanPossiblyUndeclaredVariable
     */
    private function waitForValidation( Order $i_order ) : Result {
        echo 'Waiting for validation...';
        for ( $ii = 0 ; $ii < 60 ; $ii++ ) {
            $rCheck = $this->client->checkChallenge( $i_order, $this->target->fqdn(), 'dns-01' );
            $stStatus = $rCheck[ 'status' ] ?? 'unknown';
            if ( $stStatus === 'valid' ) {
                echo "done!\n";
                return Result::ok( i_xValue: $rCheck );
            }
            if ( $stStatus !== 'pending' ) {
                echo "failed!\n";
                return Result::err( "Challenge status is {$stStatus} not valid.", $rCheck );
            }
            echo '.';
            sleep( 1 );
        }
        echo "giving up!\n";
        return Result::err( 'Timed out waiting for validation.', $rCheck );
    }


}
