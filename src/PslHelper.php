<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\Strict\OK;
use Pdp\Domain;
use Pdp\Rules;


final class PslHelper {


    public const string PSL_URL        = 'https://publicsuffix.org/list/public_suffix_list.dat';

    public const string PSL_CACHE_FILE = __DIR__ . '/../data/public_suffix_list.dat';

    private static Rules $psl;


    public static function clearCacheFile() : void {
        if ( file_exists( self::PSL_CACHE_FILE ) ) {
            unlink( self::PSL_CACHE_FILE );
        }
    }


    public static function getPSLData() : string {
        if ( ! file_exists( self::PSL_CACHE_FILE ) || ( time() - filemtime( self::PSL_CACHE_FILE ) ) > 86400 ) {
            $data = OK::file_get_contents( self::PSL_URL );
            OK::file_put_contents( self::PSL_CACHE_FILE, $data );
            return $data;
        }
        return OK::file_get_contents( self::PSL_CACHE_FILE );
    }


    public static function getRules() : Rules {
        if ( ! isset( self::$psl ) ) {
            self::$psl = Rules::fromString( self::getPSLData() );
        }
        return self::$psl;
    }


    public static function inferDomainFromFQDN( string $i_stFQDN ) : string {
        $psl = self::getRules();
        $domain = Domain::fromIDNA2008( $i_stFQDN );
        $result = $psl->resolve( $domain );
        return $result->registrableDomain()->toString();
    }


}
