<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\Param\Validate;


readonly class Target implements \Stringable {


    private string $stDomain;

    private string $stName;


    public function __construct( private string $stFQDN, ?string $i_nstDomain = null ) {

        $bWild = false;
        if ( str_starts_with( $stFQDN, '*.' ) ) {
            $bWild = true;
            $stFQDN = substr( $stFQDN, 2 );
        }
        if ( ! Validate::hostname( $stFQDN ) ) {
            throw new \RuntimeException( "FQDN \"{$stFQDN}\" is not a valid hostname." );
        }
        if ( $bWild ) {
            $stFQDN = '*.' . $stFQDN;
        }

        if ( is_string( $i_nstDomain ) ) {
            if ( str_starts_with( $i_nstDomain, '.' ) ) {
                $i_nstDomain = substr( $i_nstDomain, 1 );
            }
            if ( ! Validate::hostname( $i_nstDomain ) ) {
                throw new \RuntimeException( "Domain \"{$i_nstDomain}\" is not a valid hostname." );
            }
        }

        if ( empty( $i_nstDomain ) ) {
            $i_nstDomain = PslTools::inferDomainFromFQDN( $stFQDN );
        }
        $this->stDomain = $i_nstDomain;

        if ( $stFQDN !== $i_nstDomain && ! str_ends_with( $stFQDN, '.' . $i_nstDomain ) ) {
            throw new \RuntimeException( "FQDN \"{$stFQDN}\" is not within the domain \"{$i_nstDomain}\"." );
        }

        if ( $this->stFQDN === $this->stDomain ) {
            $this->stName = '';
        } else {
            $this->stName = substr( $this->stFQDN, 0, -( strlen( $this->stDomain ) + 1 ) );
        }

    }


    public function __toString() : string {
        return
            "FQDN: {$this->fqdn()}\n" .
            "Domain: {$this->domain()}\n" .
            "Name: {$this->name()}\n" .
            "ACME Name: {$this->acmeName()}\n" .
            "ACME FQDN: {$this->acmeFQDN()}\n";
    }


    public function acmeFQDN() : string {
        return $this->acmeName() . '.' . $this->stDomain;
    }


    public function acmeName() : string {
        if ( $this->stName === '' || $this->stName === '*' ) {
            return '_acme-challenge';
        }
        if ( str_starts_with( $this->stName, '*.' ) ) {
            return '_acme-challenge.' . substr( $this->stName, 2 );
        }
        return '_acme-challenge' . ( empty( $this->stName ) ? '' : '.' . $this->stName );
    }


    public function domain() : string {
        return $this->stDomain;
    }


    public function fqdn() : string {
        return $this->stFQDN;
    }


    public function name() : string {
        return $this->stName;
    }


}
