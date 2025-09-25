<?php


declare( strict_types = 1 );


require_once __DIR__ . '/../vendor/autoload.php';


use JDWX\Strict\TypeIs;
use NFSN\DNS01\Application;
use NFSN\DNS01\DNSProviderInterface;
use NFSN\DNS01\NFSNAPIDNSProvider;
use NFSN\DNS01\Target;


( new class( $argv ) extends Application {


    private const string CONFIG_FILE_PATH = __DIR__ . '/../data/lets-encrypt.json';


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

