<?php
namespace ghopunk\Validate;

use ghopunk\Helpers\Encryption;
use ghopunk\Helpers\Servers\Is;
use ghopunk\Helpers\Cookie;

class Login {
	private $domainCode 	= 'bgp';
	
	public $lastLogin 		= false;
	public $error 			= false;
	protected $users 		= array();
	private $userName 		= false;
	private $isLogin 		= false;
	public $expiredCookie;
	
	public function __construct( $uniqueCode = false, $path = false, $expired = false ){
		if( !empty( $uniqueCode ) ){
			$this->setDomainCode( $uniqueCode );
		}
		if( empty($expired) ) {
			$expired = time() + ( 3600 * 24 * 30 * 1 ); //1 x 30 day
		}
		$this->cookie = new Cookie( $path, $expired );
		$this->setExpiredCookie( $expired );
		
		$c_login = $this->cookie->get( $this->getCookieKey( 'ulogin' ) );
		if ( !empty( $c_login ) ){
			$lastLogin = $c_login;
		} else {
			$lastLogin = time();
		}
		$this->lastLogin = $lastLogin;
	}
	
	public function checkLogin( $userName, $password ) {
		$userName 	= stripslashes( $userName );
		$password 	= stripslashes( $password );
		if( !empty( $this->users ) && is_array( $this->users ) ){
			foreach ( $this->users as $user => $pass ) {
				if ( $userName == $user && $password == $pass ) {
					$this->userName = $userName;
					$this->setCookie( $userName, $password );
					return TRUE;
				}
			}
		}
		return FALSE;
	}
	
	public function setExpiredCookie( $time ) {
		$this->expiredCookie = $time;
	}
	public function getExpiredCookie() {
		return $this->expiredCookie;
	}
	public function setCookie( $userName, $password = false ) {
		$this->setUserName( $userName );
		$_uid	= $this->encode( $userName );
		$_cid	= $this->encode( $_uid );
		$this->cookie->set( $this->getCookieKey( 'uid' ), 		$_uid, 				$this->getExpiredCookie() );
		$this->cookie->set( $this->getCookieKey( 'cid' ), 		$_cid, 				$this->getExpiredCookie() );
		$this->cookie->set( $this->getCookieKey( 'uname' ),		$this->userName, 	$this->getExpiredCookie() );
		$this->cookie->set( $this->getCookieKey( 'ulogin' ), 	$this->lastLogin, 	$this->getExpiredCookie() );
		if( !empty( $password ) ){
			$_pid	= $this->encode( $password );
			$this->cookie->set( $this->getCookieKey( 'pid' ), 	$_pid, 				$this->getExpiredCookie() );
		}
	}
	public function getCookieKey( $type ){
		return $this->getDomainCode() . '_' . $type;
	}
	public function removeCookie() {
		if(isset( $_COOKIE ) && !empty( $_COOKIE ) ){
			foreach( $_COOKIE as $k => $v ){
				$this->cookie->remove( $k );
			}
		}
	}
	
	public function setDomainCode( $code ){
		$this->domainCode = $code;
	}
	public function getDomainCode(){
		if( !empty( $this->getUniquecode() ) ){
			$this->domainCode = substr( $this->getUniquecode(), 1, 3 ) . substr( $this->getUniquecode(), -2, 2 );
		}
		return $this->domainCode;
	}
	
	public function setUsers( array $users ) {
		$this->users = $users;
	}
	public function getUsers() {
		return $this->users;
	}
	public function setUserName( $userName ) {
		$this->userName = $userName;
	}
	public function getUserName() {
		return $this->userName;
	}
	
	public function setEncryption( $g_encryption ){
		$this->g_encryption = $g_encryption;
	}
	public function getEncryption(){
		if( empty( $this->g_encryption ) && class_exists( 'Encryption' ) ) {
			$g_encryption = new Encryption;
			$this->setEncryption( $g_encryption );
		}
		return $this->g_encryption;
	}
	public function setUniquecode( $uniqueCode ){
		if( method_exists( $this->getEncryption(), 'setUniquecode' ) ){
			$this->getEncryption()->setUniquecode( $uniqueCode );
		} else {
			$this->setDomainCode( $uniqueCode );
		}
	}
	public function getUniquecode(){
		if( method_exists( $this->getEncryption(), 'getUniquecode' ) ){
			return  $this->getEncryption()->getUniquecode();
		}
		return false;
	}
	public function encode( $value ) {
		if( method_exists( $this->getEncryption(), 'encode' ) ){
			$value = $this->getEncryption()->encode( $value );
		}
		return $value;
	}
	public function decode( $value ) {
		if( method_exists( $this->getEncryption(), 'decode' ) ){
			$value = $this->getEncryption()->decode( $value );
		}
		return $value;
	}
	
	public function setIsLogin( $isLogin ){
		$this->isLogin = $isLogin;
	}
	public function getIsLogin(){
		return $this->isLogin;
	}
	
	public function verifyLogin() {
		$_uid 	= $this->cleanse_input( $this->cookie->get( $this->getCookieKey( 'uid' ) ) );
		$_cid 	= $this->cleanse_input( $this->cookie->get( $this->getCookieKey( 'cid' ) ) );
		$_uname = $this->cleanse_input( $this->cookie->get( $this->getCookieKey( 'uname' ) ) );
		if ( !empty( $_uid ) && $_uname == $this->decode( $_uid ) && !empty( $_cid ) && $_uid == $this->decode( $_cid ) ) {
			if( !empty( $this->users ) && is_array( $this->users ) && array_key_exists( $_uname,$this->users ) ){
				$_pid = $this->cookie->get( $this->getCookieKey( 'pid' ) );
				if( !empty( $_pid ) ){
					$_pid = $this->decode( $_pid );
					if( $_pid == $this->users[$_uname] ){
						$this->setUserName( $_uname );
						return TRUE;
					}
				}
			}
		}
		return FALSE;
	}
	public function checkUserLogin( $userName ) {
		$_uname = $this->cookie->get( $this->getCookieKey( 'uname' ) );
		if( $userName == $_uname ){
			$this->setUserName( $_uname );
			return TRUE;
		}
		return FALSE;
	}
	public function getCookieLogin() {
		if ( 	!empty( $this->cookie->get( $this->getCookieKey( 'uid' ) ) )
				&& !empty( $this->cookie->get( $this->getCookieKey( 'cid' ) ) ) 
				&& !empty( $this->cookie->get( $this->getCookieKey( 'uname' ) ) ) 
		) {
				return TRUE;
		}
		return FALSE;
	}
	public function errorLogin() {
		if ( !empty( $this->getError() ) ) {
			echo '<div class="error-notice" style="text-align:center;">' . $this->getError() . '</div>';	
		} else {
			echo '<div class="error-notice" style="text-align:center; visibility: hidden;">You have logged out.</div>';	
		}
	}
	public function cleanse_input( $input ) {
		$input = trim( $input );
		$input = htmlentities( $input );
		return $input;
	}
	public function setError( $message ) {
		$this->error = $message;
	}
	public function getError() {
		return $this->error;
	}
}

?>