<?php


declare( strict_types = 1 );


require_once __DIR__ . '/../vendor/autoload.php';


use JDWX\Strict\TypeIs;
use NFSN\DNS01\Application;
use NFSN\DNS01\DNSProviderInterface;
use NFSN\DNS01\NFSNAPIDNSProvider;
use NFSN\DNS01\Target;


( new class( $argv ) extends Application {


    private const string CONFIG_FILE_PATH = 'lets-encrypt.json';


    protected function getTarget() : Target {
        $stFQDN = $this->args()->shiftStringEx( 'FQDN is required.' );
        $stDomain = $this->args()->shiftString();
        $this->args()->end();
        return new Target( $stFQDN, $stDomain );
    }


    protected function getConfigFilePath() : string {
        return self::CONFIG_FILE_PATH;
    }


    protected function getDNSProvider() : ?DNSProviderInterface {

        if ( empty( $stMemberLogin = $this->getMemberLogin() ) ) {
            return null;
        }
        if ( empty( $stAPIKey = $this->getAPIKey() ) ) {
            return null;
        }
        return new NFSNAPIDNSProvider( TypeIs::string( $stMemberLogin ), TypeIs::string( $stAPIKey ) );
    }


    private function getMemberLogin() : ?string {
        if ( is_string( $st = $this->cfg->getApiValue( 'nfsn_member_login' ) ) ) {
            return $st;
        }

        $st = $this->readLine( 'Enter your NFSN Member Login: ' );
        if ( empty( $st ) ) {
            return null;
        }
        $this->cfg->setApiValue( 'nfsn_member_login', $st );
        return $st;
    }


    private function getAPIKey() : ?string {
        if ( is_string( $st = $this->cfg->getApiValue( 'nfsn_api_key' ) ) ) {
            return $st;
        }
        $st = $this->readLine( 'Enter your NFSN API Key: ' );
        if ( empty( $st ) ) {
            return null;
        }
        $this->cfg->setApiValue( 'nfsn_api_key', $st );
        return $st;
    }


    /*
    protected function oldMain() : int {

        $order = new Order( $this->client->newOrder( $stFQDN ) );
        if ( ! $order->hasCertificate() ) {
            if ( ! $this->doChallenge( $order, $stDomain, $stFQDN ) ) {
                echo "Failed to complete challenge. (Exiting.)\n";
                return 1;
            }
            if ( ! $order->isReady() ) {
                $order = $this->waitOutPending( $order );
                if ( ! $order || ! $order->isReady() ) {
                    echo "Order is not ready. (Exiting.)\n";
                    return 1;
                }
            }
            $order = $this->doFinalize( $order, $stFQDN );
            if ( ! $order ) {
                echo "Failed to finalize order. (Exiting.)\n";
                return 1;
            }
        } else {
            echo "Order is already ready already.\n";
        }

        $stCertificate = $this->client->certificate( $order );

        $this->savePEM( $stFQDN, Certificate::keyToString( $this->getPrivateKey( $stFQDN ) ), $stCertificate );


        return 0;
    }


    private function waitOutPending( Order $order ) : ?Order {
        echo 'Waiting for order to be ready...';
        for ( $ii = 0 ; $ii < 60 ; $ii++ ) {
            $stStatus = $order->getStatus();
            if ( $stStatus !== 'pending' ) {
                echo "OK! ({$stStatus})\n";
                return $order;
            }
            echo '.';
            sleep( 1 );
            $order = $this->client->order( $order );
        }
        echo "\n";
        echo "Timed out waiting for order to be ready.\n";
        return null;
    }


    private function savePEM( string $i_stFQDN, string $i_stKey, string $i_stCertificate ) : void {
        $stPEMPath = "{$i_stFQDN}.pem";
        if ( file_exists( $stPEMPath ) ) {
            rename( $stPEMPath, "{$stPEMPath}.old" );
        }
        $stPEM = $i_stKey . "\n" . $i_stCertificate;
        file_put_contents( $stPEMPath, $stPEM );
        echo "Wrote PEM file {$stPEMPath}\n";
    }


    private function doFinalize( Order $order, string $i_stName ) : ?Order {
        $privateKey = $this->getPrivateKey( $i_stName );
        $stCSR = Certificate::makeCSR( $privateKey, [ $i_stName ] );
        $this->client->finalize( $order, $stCSR );

        echo 'Waiting for order to finalize...';
        for ( $ii = 0 ; $ii < 60 ; $ii++ ) {
            $nstLocation = $order->location();
            if ( ! is_string( $nstLocation ) ) {
                echo "OK!\n";
                return $order;
            }
            echo '.';
            $order = $this->client->order( $order );
            sleep( 1 );
        }

        echo "Timed out waiting for order to finalize.\n";
        return null;
    }


    private function doChallenge( Order $order, string $i_stDomain, string $i_stFQDN ) : bool {
        $rChallenge = $this->client->getChallenge( $order, $i_stFQDN, 'dns-01' );
        $stAuthKey = $this->client->keyAuthorizationHashed( $rChallenge[ 'token' ] );

        $stName = substr( $i_stFQDN, 0, -strlen( $i_stDomain ) - 1 );
        $stAcmeName = '_acme-challenge' . ( empty( $stName ) ? '' : '.' . $stName );

        $api = new Manager( $_ENV[ 'NFSN_API_USER' ], $_ENV[ 'NFSN_API_KEY' ] );
        $dns = $api->newDNS( $i_stDomain );
        $dns->replaceRR( $stAcmeName, 'TXT', $stAuthKey, 180 );

        if ( ! $this->waitForDNS( '_acme-challenge.' . $i_stFQDN, $stAuthKey, 60 ) ) {
            echo "Giving up on DNS update. Seek help on our forum?\n";
            return false;
        }

        $this->client->validate( $order, $i_stFQDN, 'dns-01' );

        $r = $this->waitForChallenge( $order, $i_stFQDN, 60 );
        if ( ! is_array( $r ) ) {
            echo "Giving up on challenge. Seek help on our forum?\n";
            return false;
        }

        if ( ( $r[ 'status' ] ?? 'Nope' ) !== 'valid' ) {
            echo "Challenge did not validate. Seek help on our forum? This info may help:\n";
            echo Json::encodePretty( $r ), "\n";
            return false;
        }

        echo "Challenge validated!\n";
        return true;
    }


    private function waitForChallenge( Order $order, string $i_stName, int $i_nTimeoutSeconds ) : ?array {
        echo 'Waiting for challenge to finish...';
        for ( $ii = 0 ; $ii < $i_nTimeoutSeconds ; $ii++ ) {
            $r = $this->client->checkChallenge( $order, $i_stName, 'dns-01' );
            if ( ! empty( $r[ 'status' ] && $r[ 'status' ] !== 'pending' ) ) {
                echo "done!\n";
                return $r;
            }
            echo '.';
            sleep( 1 );
        }
        echo "\n";
        echo "Timed out waiting for challenge to be marked valid.\n";
        return null;
    }

    */


} )();

