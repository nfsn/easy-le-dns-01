<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\ACME\ACMEv2;
use JDWX\ACME\Certificate;
use JDWX\ACME\Client;
use JDWX\ACME\JWT;
use JDWX\ACME\KeyType;
use JDWX\ACME\Order;
use JDWX\App\InteractiveApplication;
use JDWX\Args\Option;
use JDWX\Param\Validate;
use JDWX\Result\Result;
use OpenSSLAsymmetricKey;


abstract class Application extends InteractiveApplication {


    use OutputTrait;


    /** @var list<string> */
    private const array ALLOWED_KEY_TYPES = [ 'rsa', 'ec' ];


    protected Config $cfg;

    protected string $stKeyType;

    private Client $client;

    private DNSProviderInterface $dns;

    private Target $target;

    private bool $bHelp;

    private bool $bSplit = true;


    public function setup() : void {
        parent::setup();
        $this->bVerbose = Option::simpleBool( 'verbose', $this->args() );
        $this->bHelp = Option::simpleBool( 'help', $this->args() );
        $this->bSplit = Option::simpleBool( 'split', $this->args() );
        $this->stKeyType = strtolower( trim( Option::simpleString( 'type', $this->args() ) ?? 'ec' ) );
    }


    abstract protected function getConfigFilePath() : string;


    /** @return Result<DNSProviderInterface> */
    abstract protected function getDNSProvider() : Result;


    protected function getTLSPrivateKeyPath() : string {
        $stKeyPath = __DIR__ . "/../data/{$this->target->fqdn()}-{$this->stKeyType}.key";
        return str_replace( '*', '_', $stKeyPath );
    }


    abstract protected function getTarget() : Target;


    /** @return array<string, string> */
    protected function listFlags() : array {
        return [
            'help' => 'Show this information',
            'split' => 'Write certificate, chain, and key files instead of a single PEM file',
            'type' => 'Type of key to create ("rsa" or "ec") [default: ec]',
            'verbose' => 'Enable verbose output',
        ];
    }


    protected function main() : int {

        if ( $this->bHelp ) {
            return $this->usage();
        }

        if ( ! in_array( $this->stKeyType, self::ALLOWED_KEY_TYPES, true ) ) {
            $this->output( "Invalid key type: {$this->stKeyType}\n" );
            exit( 1 );
        }

        $res = $this->initialize();
        if ( $res->isError() ) {
            $this->failure( 'Initialization failed', $res );
        }

        $order = new Order( $this->client->newOrder( $this->target->fqdn() ), $this->target->fqdn() );
        $stOrderUrl = $order->locationEx();
        $res = $this->client->waitOnOrder( $order );
        if ( $res->isError() ) {
            $this->failure( 'Order creation failed', $res );
            return 1;
        }
        $order = $res->unwrapEx();
        if ( $order->hasCertificate() ) {
            $this->verbose( "Order already has a certificate.\n" );
        } else {

            $res = $this->doChallenge( $order );
            if ( $res->isError() ) {
                $this->failure( 'Challenge failed', $res );
                return 1;
            }
            $order = $res->unwrapEx();

            $res = $this->waitForValidation( $order );
            if ( $res->isError() ) {
                $this->failure( 'Validation failed', $res );
                return 1;
            }

            # Have to reload the order to get the updated status.
            $order = $this->client->order( $stOrderUrl );
            $res = $this->doFinalize( $order );
            if ( $res->isError() ) {
                $this->failure( 'Finalize failed', $res );
                return 1;
            }
            $order = $res->unwrapEx();
        }

        $res = $this->saveCertificate( $order );
        if ( $res->isError() ) {
            $this->failure( 'Save certificate failed', $res );
            return 1;
        }

        $this->dns->removeAuthKey( $this->target );

        $this->output( "All set!\n" );
        return 0;
    }


    private function agreeToLetsEncryptTerms() : bool {
        if ( $this->cfg->getAcmeAgreedTerms() ) {
            return true;
        }
        $stURL = $this->client->directory()[ 'meta' ][ 'termsOfService' ];
        $this->output(
            "The Let's Encrypt Terms of Service can be found at:\n",
            "  {$stURL}\n"
        );
        $stPrompt = "Do you agree to the Let's Encrypt Terms of Service [y/n]? ";
        if ( ! $this->askYN( $stPrompt ) ) {
            return false;
        }
        $this->cfg->setAcmeAgreedTerms( true );
        return true;
    }


    /** @return Result<Order> */
    private function doChallenge( Order $order ) : Result {
        $this->verbose( "Starting challenge...\n" );
        $rChallenge = $this->client->getChallenge( $order, $this->target->fqdn(), 'dns-01' );
        $stAuthKey = $this->client->keyAuthorizationHashed( $rChallenge[ 'token' ] );

        $res = $this->dns->setAuthKey( $this->target, $stAuthKey );
        if ( $res->isError() ) {
            return $res;
        }

        $this->verbose( "Validating challenge...\n" );
        $this->client->validate( $order, $this->target->fqdn(), 'dns-01' );

        return $this->client->waitOnOrder( $order );
    }


    /** @return Result<Order> */
    private function doFinalize( Order $order ) : Result {
        $this->verbose( "Finalizing order...\n" );
        $privateKey = $this->getOrCreateTLSPrivateKey();
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


    private function getAccountKeyPath() : string {
        return __DIR__ . '/../data/le-account.key';
    }


    private function getOrCreateAcmeAccount() : string {
        $stAccount = $this->cfg->getAcmeAccountUrl();
        if ( is_string( $stAccount ) ) {
            $this->verbose( "Using existing account: {$stAccount}\n" );
            return $stAccount;
        }
        $stAccount = $this->client->newAccount( $this->cfg->getAcmeContactEx() );
        $this->cfg->setAcmeAccountUrl( $stAccount );
        $this->verbose( "New account created: {$stAccount}\n" );
        return $stAccount;
    }


    private function getOrCreateTLSPrivateKey() : OpenSSLAsymmetricKey {
        if ( strtolower( $this->stKeyType ) === 'rsa' ) {
            $key = Certificate::makeKey( KeyType::RSA );
        } elseif ( strtolower( $this->stKeyType ) === 'ec' ) {
            $key = Certificate::makeKey();
        } else {
            $this->output( "Unknown key type: {$this->stKeyType}" );
            exit( 1 );
        }
        $stKeyPath = $this->getTLSPrivateKeyPath();
        if ( file_exists( $stKeyPath ) ) {
            return Certificate::readKeyPrivate( $stKeyPath );
        }
        $this->verbose( "Generating new private key in {$stKeyPath}\n" );
        Certificate::writeKeyPrivate( $stKeyPath, $key );
        chmod( $stKeyPath, 0600 );
        return $key;
    }


    /** @return Result<null> */
    private function initialize() : Result {
        $this->cfg = new Config( $this->getConfigFilePath() );

        $stKeyPath = $this->getAccountKeyPath();
        $jwk = JWT::getOrCreateKey( $stKeyPath );
        $acme = new ACMEv2( ACMEv2::LE_PRODUCTION_URL );
        $this->client = new Client( $jwk, $acme );

        if ( ! $this->agreeToLetsEncryptTerms() ) {
            return Result::err( "Let's Encrypt requires agreement to their terms of use." );
        }

        if ( ! $this->setContactEmailAddress() ) {
            return Result::err( 'A contact email address is required.' );
        }

        $this->loadAcmeAccount();

        $this->target = $this->getTarget();
        $this->verbose( $this->target, "\n" );

        $res = $this->getDNSProvider();
        if ( $res->isError() ) {
            return $res->withValue( null );
        }
        $this->dns = $res->unwrapEx();

        $res = $this->dns->setup();
        if ( $res->isError() ) {
            return $res->withValue( null );
        }

        return Result::ok();
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
        $stKey = Certificate::keyToString( $this->getOrCreateTLSPrivateKey() );
        $stFQDN = $this->target->fqdn();
        $stFQDN = str_replace( '*', '_', $stFQDN );

        if ( ! $this->bSplit ) {
            $stPEMPath = __DIR__ . "/../data/{$stFQDN}.pem";
            $this->writeFileSavingOld( $stPEMPath, $stKey . "\n" . $stCertificate );
            $this->verbose( "Wrote PEM file {$stPEMPath}\n" );

            # Because the PEM contains the private key, we lock down the permissions.
            chmod( $stPEMPath, 0600 );

            # Now that we have written the certificate, get rid of the key file.
            $stKeyPath = $this->getTLSPrivateKeyPath();
            if ( file_exists( $stKeyPath ) ) {
                unlink( $stKeyPath );
            }

            return Result::ok( i_xValue: $i_order );
        }

        $stCertOnly = Certificate::parseChain( $stCertificate, $this->target->fqdn() )[ 0 ];
        $stCertOnly = Certificate::toString( $stCertOnly );
        $stChainOnly = str_replace( $stCertOnly, '', $stCertificate );

        $stCertPath = __DIR__ . "/../data/{$stFQDN}.crt";
        $this->writeFileSavingOld( $stCertPath, $stCertOnly );
        $this->verbose( "Wrote certificate file {$stCertPath}\n" );

        $stChainPath = __DIR__ . "/../data/{$stFQDN}.chn";
        $this->writeFileSavingOld( $stChainPath, $stChainOnly );
        $this->verbose( "Wrote chain file {$stChainPath}\n" );

        return Result::ok( i_xValue: $i_order );
    }


    private function setContactEmailAddress() : bool {
        if ( $this->cfg->hasAcmeContact() ) {
            return true;
        }
        $this->output(
            "Let's Encrypt requires a contact email address to send updates about\n",
            "expiration and suchlike.\n"
        );
        while ( true ) {
            $bst = $this->readLine( 'What email address should they use? ' );
            if ( empty( $bst ) ) {
                return false;
            }
            if ( Validate::emailAddress( $bst ) ) {
                break;
            }
            $this->output( "That doesn't look like a valid email address.\n" );
        }

        $this->cfg->setAcmeContact( $bst );
        return true;
    }


    private function usage() : int {
        echo "\nYourPrompt\$ {$this->stCommand} [options] <fqdn> [domain-name]\n\n";
        echo "Arguments:\n\n";
        echo "  <fqdn>         Fully qualified domain name to get a certificate for.\n\n";
        echo "  [domain-name]  Domain name to use with the DNS provider. Will be\n";
        echo "                 derived from the FQDN if not provided.\n\n";
        echo "Options:\n\n";
        foreach ( $this->listFlags() as $stFlag => $stDesc ) {
            echo "  --{$stFlag}\n      {$stDesc}\n\n";
        }
        return 0;
    }


    /**
     * @return Result<mixed[]>
     * @suppress PhanPossiblyUndeclaredVariable
     */
    private function waitForValidation( Order $i_order ) : Result {
        $this->verbose( 'Waiting for validation...' );
        for ( $ii = 0 ; $ii < 60 ; $ii++ ) {
            $rCheck = $this->client->checkChallenge( $i_order, $this->target->fqdn(), 'dns-01' );
            $stStatus = $rCheck[ 'status' ] ?? 'unknown';
            if ( $stStatus === 'valid' ) {
                $this->verbose( "done!\n" );
                return Result::ok( i_xValue: $rCheck );
            }
            if ( $stStatus !== 'pending' ) {
                $this->verbose( "failed! ({$stStatus})\n" );
                return Result::err( "Challenge status is {$stStatus} not valid.", $rCheck );
            }
            $this->verbose( '.' );
            sleep( 1 );
        }
        $this->verbose( "giving up!\n" );
        return Result::err( 'Timed out waiting for validation.', $rCheck );
    }


    private function writeFileSavingOld( string $i_stPath, string $i_stData ) : void {
        if ( file_exists( $i_stPath ) ) {
            rename( $i_stPath, "{$i_stPath}.old" );
        }
        file_put_contents( $i_stPath, $i_stData );
    }


}
