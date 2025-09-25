<?php


declare( strict_types = 1 );


namespace NFSN\DNS01\Tests;


use NFSN\DNS01\Target;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( Target::class )]
final class TargetTest extends TestCase {


    public function testAcmeFQDN() : void {
        $target = new Target( 'example.com' );
        self::assertSame( '_acme-challenge.example.com', $target->acmeFQDN() );

        $target = new Target( 'www.example.com' );
        self::assertSame( '_acme-challenge.www.example.com', $target->acmeFQDN() );

        $target = new Target( 'www.sub.example.com' );
        self::assertSame( '_acme-challenge.www.sub.example.com', $target->acmeFQDN() );

        $target = new Target( '*.example.com' );
        self::assertSame( '_acme-challenge.example.com', $target->acmeFQDN() );

        $target = new Target( '*.sub.example.com' );
        self::assertSame( '_acme-challenge.sub.example.com', $target->acmeFQDN() );

        $target = new Target( 'www.sub.example.com', 'sub.example.com' );
        self::assertSame( '_acme-challenge.www.sub.example.com', $target->acmeFQDN() );
    }


    public function testAcmeName() : void {
        $target = new Target( 'example.com' );
        self::assertSame( '_acme-challenge', $target->acmeName() );

        $target = new Target( 'www.example.com' );
        self::assertSame( '_acme-challenge.www', $target->acmeName() );

        $target = new Target( 'www.sub.example.com' );
        self::assertSame( '_acme-challenge.www.sub', $target->acmeName() );

        $target = new Target( '*.example.com' );
        self::assertSame( '_acme-challenge', $target->acmeName() );

        $target = new Target( '*.sub.example.com' );
        self::assertSame( '_acme-challenge.sub', $target->acmeName() );

        $target = new Target( 'www.sub.example.com', 'sub.example.com' );
        self::assertSame( '_acme-challenge.www', $target->acmeName() );
    }


    public function testConstructForEmptyFqdn() : void {
        $this->expectException( \InvalidArgumentException::class );
        $x = new Target( '' );
        unset( $x );
    }


    public function testConstructForFqdnNotInDomain() : void {
        $this->expectException( \InvalidArgumentException::class );
        $this->expectExceptionMessage( 'not within the domain' );
        $x = new Target( 'www.example.com', 'example.org' );
        unset( $x );
    }


    public function testConstructForInvalidDomain() : void {
        $this->expectException( \InvalidArgumentException::class );
        $this->expectExceptionMessage( 'not a valid domain' );
        $x = new Target( 'www.example.com', 'invalid_domain' );
        unset( $x );
    }


    public function testConstructForInvalidHostname() : void {
        $this->expectException( \InvalidArgumentException::class );
        $this->expectExceptionMessage( 'not a valid hostname' );
        $x = new Target( 'invalid_host_name' );
        unset( $x );
    }


    public function testConstructForLeadingDotDomain() : void {
        $target = new Target( 'www.example.com', '.example.com' );
        self::assertSame( 'example.com', $target->domain() );
        self::assertSame( 'www', $target->name() );
    }


    public function testDomain() : void {
        $target = new Target( 'example.com' );
        self::assertSame( 'example.com', $target->domain() );

        $target = new Target( 'www.example.com' );
        self::assertSame( 'example.com', $target->domain() );

        $target = new Target( 'www.sub.example.com' );
        self::assertSame( 'example.com', $target->domain() );

        $target = new Target( '*.example.com' );
        self::assertSame( 'example.com', $target->domain() );

        $target = new Target( '*.sub.example.com' );
        self::assertSame( 'example.com', $target->domain() );

        $target = new Target( 'www.sub.example.com', 'sub.example.com' );
        self::assertSame( 'sub.example.com', $target->domain() );
    }


    public function testFqdn() : void {
        $target = new Target( 'example.com' );
        self::assertSame( 'example.com', $target->fqdn() );

        $target = new Target( 'www.example.com' );
        self::assertSame( 'www.example.com', $target->fqdn() );

        $target = new Target( 'www.sub.example.com' );
        self::assertSame( 'www.sub.example.com', $target->fqdn() );

        $target = new Target( '*.example.com' );
        self::assertSame( '*.example.com', $target->fqdn() );

        $target = new Target( '*.sub.example.com' );
        self::assertSame( '*.sub.example.com', $target->fqdn() );

        $target = new Target( 'www.sub.example.com', 'sub.example.com' );
        self::assertSame( 'www.sub.example.com', $target->fqdn() );
    }


    public function testName() : void {
        $target = new Target( 'example.com' );
        self::assertSame( '', $target->name() );

        $target = new Target( 'www.example.com' );
        self::assertSame( 'www', $target->name() );

        $target = new Target( 'www.sub.example.com' );
        self::assertSame( 'www.sub', $target->name() );

        $target = new Target( '*.example.com' );
        self::assertSame( '*', $target->name() );

        $target = new Target( '*.sub.example.com' );
        self::assertSame( '*.sub', $target->name() );

        $target = new Target( 'www.sub.example.com', 'sub.example.com' );
        self::assertSame( 'www', $target->name() );
    }


    public function testToString() : void {
        $target = new Target( 'www.sub.example.com' );
        $stTarget = strval( $target );
        self::assertStringContainsString( 'FQDN: www.sub.example.com', $stTarget );
        self::assertStringContainsString( 'Domain: example.com', $stTarget );
        self::assertStringContainsString( 'Name: www.sub', $stTarget );
        self::assertStringContainsString( 'ACME Name: _acme-challenge.www.sub', $stTarget );
        self::assertStringContainsString( 'ACME FQDN: _acme-challenge.www.sub.example.com', $stTarget );
    }


}
