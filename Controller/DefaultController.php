
<?php

/*
 * This file is part of the Artseld\OpeninviterBundle package.
 *
 * (c) Dmitry Kozlovich <artseld@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Artseld\OpeninviterBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Artseld\OpeninviterBundle\Form\Type\LoginFormType;
use Artseld\OpeninviterBundle\Form\Type\InviteFormType;

use Artseld\OpeninviterBundle\ArtseldOpeninviter\ArtseldOpeninviter;

use Symfony\Component\Security\Core\SecurityContext;
use JMS\SecurityExtraBundle\Annotation\Secure;
use Qubeey\ApiBundle\Entity\Entitycategory;
use Qubeey\ApiBundle\Model\Member as ModelMember;

use Qubeey\ApiBundle\Document\MemberProfile;
use Qubeey\ApiBundle\Entity\Member;
use Qubeey\ApiBundle\Document\MemberInviter;
use Qubeey\ApiBundle\Utility\Facebook;
use TwitterOAuth\Api;
use Qubeey\ApiBundle\Utility\LinkedIn;
//use Artseld\OpeninviterBundle\Utility\YahooOAuth\OAuth\Globals;
use Qubeey\ApiBundle\Utility\YahooOAuth\OAuth\Globals;


class DefaultController extends Controller
{
    // Steps
    const STEP_LOGIN    = 'login';
    const STEP_INVITE   = 'invite';
    const STEP_DONE     = 'done';

    // Session variables
    const SVAR_STEP         = 'step';
    const SVAR_SESSID       = 'sessid';
    const SVAR_PROVIDER     = 'provider';
    const SVAR_EMAIL        = 'email';
    const SVAR_CONTACTS     = 'contacts';

    // Flash types
    const FLASH_SUCCESS     = 'success';
    const FLASH_ERROR       = 'error';

    protected $openinviter;
    protected $oiPlugins;

    protected $errorcontent;

    
    //****************************************************************************************//
    
    /**
     * Gmail action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function gmailAction(Request $request)
    {
    	return $this->get('templating')->renderResponse('ArtseldOpeninviterBundle:Default:gmail.html.twig');
    } 
    
    //****************************************************************************************//
    
    /**
     * Yahoo action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function yahooAction(Request $request, $ycb=false)
    {
    	$this->_init();
    
    	$user = $this->get('security.context')->getToken()->getUser();
    	//$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    
    	//////////////////////////////////////////////////////////////////////////////////////
    
    	$response = new Response();
    	$session = $request->getSession();
    
    	$mt = microtime();
    	$rand = mt_rand();
    	
    	$oauth_consumer_key = rawurlencode($this->container->getParameter('YAHOO_API_KEY'));
    	$oauth_secret_key = $this->container->getParameter('YAHOO_API_SECRET');
    	 	
		$oauthcallback = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_yahoo')."LST";
    	
    	$yahooapi = new Globals();
    	//print_r($yahooapi);    	
    	//die();

    	//////////////////////////////////////////////////////////////////////////////
    	if(isset($ycb) && $ycb == 'LST'){
    		
    		$getaccesstoken = $yahooapi->get_access_token($oauth_consumer_key, $oauth_secret_key, $_SESSION['oauth_requesttoken'], $_SESSION['oauth_requesttoken_secret'], $_GET['oauth_verifier'], false, true, true);
    		
    		if (! empty($getaccesstoken)) {
	    		list($info2, $headers2, $body2, $body_parsed2) = $getaccesstoken;

	    		if ($info2['http_code'] == 200 && !empty($body2)) {

	    			$_SESSION['oauth_accesstoken'] = $body_parsed2['oauth_token'];
	    			$_SESSION['oauth_accesstoken_secret'] = $body_parsed2['oauth_token_secret'];
	    
	    			$_SESSION['oauth_session_handle'] = $body_parsed2['oauth_session_handle'];
	    			$_SESSION['xoauth_yahoo_guid'] = $body_parsed2['xoauth_yahoo_guid'];
	    
	    			//print_r($_SESSION);	    
	    			//die();
	    			
	    			/*
	    			//$querynum = 1 (Show my profile)
    				//$querynum = 2 (Find my friends)
    				//$querynum = 3 (Find my contacts)
	    			$querynum = 3;
	    			$callyql = $yahooapi->call_yql($oauth_consumer_key, $oauth_secret_key, $querynum, rawurldecode($_SESSION['oauth_accesstoken']), rawurldecode($_SESSION['oauth_accesstoken_secret']), false, true, $oauth_callback);
	    			print_r($callyql);
	    			die();
					*/
	    			$callcontacts =  $yahooapi->callcontact($oauth_consumer_key, $oauth_secret_key, $_SESSION['xoauth_yahoo_guid'], rawurldecode($body_parsed2['oauth_token']), rawurldecode($body_parsed2['oauth_token_secret']), false, true);
	    			
	    			list($info3, $headers3, $body3) = $callcontacts;
	    			$callcontact = json_decode($body3, true);
	    			print_r($callcontact);
	    			
	    			foreach($callcontact['contacts']['contact'] as $key=>$val){
	    				//echo $key."".$val."<br/>";
	    				foreach($val as $key2=>$val2){
	    					//echo $key2." ".$val2."<br/>";
	    					//capture id and parse fields
	    					if($key2 == 'id'){
	    						//echo $key2." ".$val2."<br/>";
	    					}
	    					
	    					if($key2 == 'fields'){
	    						foreach($val2 as $key3=>$val3){
	    							//echo $key3." ".$val3."<br/>";
	    							foreach($val3 as $key4=>$val4){
	    								echo $key4." ".$val4."<br/>";
	    							}
	    						}
	    					}
	    				}
	    				echo "<br/>";
	    			}
	    			//$callcontact = json_decode($callcontacts, true);
	    			//print_r($_SESSION);    
	    			//print_r($callcontact);
	    			die();
	    			
 			
	    	  }    
    	  }
    
    }
    
    //////////////////////////////////////////////////////////////////////////////
    
    
    
    $getrequesttoken = $yahooapi->get_request_token($oauth_consumer_key, $oauth_secret_key, $oauthcallback, false, true, true);
    
    //print_r($getrequesttoken);
    
    //die();
    
    
    if (! empty($getrequesttoken)) {
    	list($info, $headers, $body, $body_parsed) = $getrequesttoken;
    	
	    if ($info['http_code'] == 200 && !empty($body)) {
	    $_SESSION['oauth_requesttoken'] = $body_parsed['oauth_token'];
	    			$_SESSION['oauth_requesttoken_secret'] = $body_parsed['oauth_token_secret'];
	    
	    			//echo $body_parsed['oauth_token'];
	    			//die();
	    			$params = array(
	    					'oauth_token' => $body_parsed['oauth_token'],
	    					'oauth_token_secret' => $body_parsed['oauth_token_secret'],
	    			);
	    
	    			// Authentication request
	    			$url2 = 'https://api.login.yahoo.com/oauth/v2/request_auth?' . http_build_query($params);
	    			// Redirect user to authenticate
	    			header("Location: $url2");
	    			die();
	    			
	    			/*
	    			//$url = 'https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token='.$body_parsed['oauth_token'];
	    			$url = $this->rfc3986_decode($body_parsed['xoauth_request_auth_url']);  //same as above.
	    			//echo $url;
	    			header("Location: $url");
	    			die();
	    			*/
	    
	    }
    }
    
    
    die();   
    
    return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
    
    }
    
    
    
    
    //****************************************************************************************//
    
    /**
     * Live action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function liveAction(Request $request, $lcb=false)
    {
    	$this->_init();
    
    	$user = $this->get('security.context')->getToken()->getUser();
    	//$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    
    	//////////////////////////////////////////////////////////////////////////////////////
    
    	$response = new Response();
    	//echo "response: ";
    	//print_r($response);
    	//echo "<br/><br/>";
    	

    	$CLIENT_ID = $this->container->getParameter('LIVE_API_KEY');
    	$CLIENT_SECRET = $this->container->getParameter('LIVE_API_SECRET');
    	$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";
    	
    	$scope='wl.singin,wl.basic,wl.emails,wl.contacts_emails';
    	//$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";
    	$u_agent = $_SERVER['HTTP_USER_AGENT'];
    	
    	if(isset($lcb) && $lcb == 'LSTT'){
    		print_r($_REQUEST);
    		die();
    	}
    	
        	if(isset($lcb) && $lcb == 'LST'){
    		$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";
    		echo "live";
    		//echo "<br/><br/>";
    		//echo "response: ";
    		//print_r($response);
    		//print_r($_GET);
    		//print_r($_REQUEST);
    		//print_r($_POST);
    		echo "<br/><br/>";
    		// echo "query: ".$_SERVER['QUERY_STRING'];
    		//echo "<br/><br/>";
    		//echo $_GET[access_token];
    		echo  $request->get('access_token')."<br/><br/>";
    		echo  $request->get('authentication_token')."<br/><br/>";
    		echo  $request->get('token_type')."<br/><br/>";
		
//////////////////////////////////////////////////////////////////////////////
			if($_GET['code']){
				
				
				$fields_string = "client_id=".$CLIENT_ID."&redirect_uri=".$REDIRECT_URL."&client_secret=".$CLIENT_SECRET."&code=".$_GET['code']."&grant_type=authorization_code";
				$ch = curl_init('https://login.live.com/oauth20_token.srf');
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_HTTPHEADER, array(' Content-Type:application/x-www.form-urlencoded ', 'charset: UTF-8', 'Content-Length: '. strlen($fields_string)));
				//curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www.form-urlencoded')); 
				curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
				curl_setopt( $ch, CURLOPT_USERAGENT, $u_agent );
				curl_setopt($ch, CURLOPT_HEADER, 0);
				curl_setopt($ch, CURLOPT_VERBOSE,0);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, TRUE);
				$output1 = curl_exec($ch);
				
				echo $curl_errno = curl_errno($ch);
				echo $curl_error = curl_error($ch);
				curl_close($ch);
				$reqst = json_decode($output1, true);
				//print_r($reqst);
				
				//echo $reqst['access_token'];
				
				
				// ******************************************** //
				$url = 'https://apis.live.net/v5.0/me/contacts?access_token='.$reqst['access_token'];
				$ch = curl_init($url);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				$output = curl_exec($ch);
				$output = json_decode($output,true);
				echo $curl_errno = curl_errno($ch);
				echo $curl_error = curl_error($ch);
				curl_close($ch);
				//print_r($output);
				
				$contacts=array();				
				foreach($output['data'] as $key=>$val){
					//echo $key." = ".$val."<br/>";
					foreach($val as $key2=>$val2){
						
						//echo $val['name']."<br/>";
						
						echo $key2." = ".$val2."<br/>";
						if($key2=='email_hashes'){
							foreach($val2 as $ekey=>$eval){
								echo "test: ".$ekey." = ".$eval."<br/>";
							}
						}
						
						if($key2=='emails'){
							foreach($val2 as $ekey2=>$eval2){
								if($ekey2 == 'preferred'){
									echo "test: ".$ekey2." = ".$eval2."<br/>";
									$contacts[trim($eval2)] = $val['name'];
								 }
								//$contacts[trim($eval2)] = $val['name'];
							}
						}
				
					}   echo "<br/>";
				}
				// ******************************************** //
				//print_r($contacts); die();
				
				$this->_setSessionVar(array(
						self::SVAR_STEP     => self::STEP_INVITE,
						self::SVAR_SESSID   => '33765123', //$this->openinviter->plugin->getSessionID(),
						self::SVAR_PROVIDER => 'hotmail', //$values['provider'],
						self::SVAR_EMAIL    => '', //$values['email'],
						self::SVAR_CONTACTS => $contacts,
				));
				
				
				return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
				
				
				die();			
			}

    		
///////////////////////////////////////////////////////////////////////////// 
   		
    		// echo $uri = $_SERVER['REQUEST_URI'];
    		//echo   $currentUrl = $this->getRequest()->getUri();
    		// echo $lcb;
    	// ******************************************** //    
    		$url = 'https://apis.live.net/v5.0/me/contacts?access_token='.$request->get('access_token');
    		$ch = curl_init($url);
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		$output = curl_exec($ch);
    		$output = json_decode($output,true);
    		echo $curl_errno = curl_errno($ch);
    		echo $curl_error = curl_error($ch);
    		curl_close($ch);
    		//print_r($output);
    		
    		foreach($output['data'] as $key=>$val){
    			//echo $key." = ".$val."<br/>";
    			foreach($val as $key2=>$val2){
	    			echo $key2." = ".$val2."<br/>";
	    			if($key2=='email_hashes'){
		    			foreach($val2 as $ekey=>$eval){
			    		echo "test: ".$ekey." = ".$eval."<br/>";
			    		}
		    		}
	    
	    		}   echo "<br/>";
    		}

    		die();
    }
    		
			$url = "https://login.live.com/oauth20_authorize.srf?client_id=".$CLIENT_ID."&client_secret=".$CLIENT_SECRET."&scope=wl.signin,wl.basic,wl.emails,wl.contacts_emails&response_type=code&redirect_uri=".$REDIRECT_URL;
    		$url = str_replace( "&amp;", "&", urldecode(trim($url)) );
    		//dpm($url);
    		
    		$ch = curl_init($url);
    		
    		//curl_setopt($ch, CURLOPT_POST, 1);
    		//curl_setopt( $ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1" );
    		curl_setopt($ch, CURLOPT_HEADER, 0);
    		curl_setopt($ch, CURLOPT_VERBOSE,0);
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, TRUE);
    		$out = curl_exec($ch);
////////////////////////////////////////////////////

////////////////////////////////////////////////////    		
    		curl_close($ch);
    		//$out = json_decode($out, true);
    		print_r($out);
    		die();
    		//return $out;
    		//$todo = explode("\n",$out);
    		    		
    		
    		die();
    		
    		return $this->get('templating')->renderResponse(
    				'ArtseldOpeninviterBundle:Default:live.html.twig', array(
    						'fbl' => '',
    				));
    		
    		//return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
    
    

    }
    //***************************************************************************************//
    
    
    //****************************************************************************************//
    
    /**
     * LinkedIn action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function linkedinAction(Request $request, $lcb=false)
    {
    	$this->_init();
    
    	$user = $this->get('security.context')->getToken()->getUser();
    	//$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    	//////////////////////////////////////////////////////////////////////////////////////
    	//http://developer.linkedin.com/forum/post-httpapilinkedincomv1peoplemailbox-error
    	//limit to 10 per day ?????? https://developer.linkedin.com/documents/throttle-limits
    
    	$response = new Response();
    
    	if(isset($lcb) && $lcb == 'LST'){
    		//	echo "START 0</br/>";  die();
    	}
    
    	//**//
    	$request = $this->getRequest();
    	$REDIRECT_URI =  $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath();
    	$url = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_linkedincb', array('lcb'=>'LST'));
    
    	$API_KEY    = $this->container->getParameter('LINKEDIN_API_KEY');
    	$API_SECRET = $this->container->getParameter('LINKEDIN_API_SECRET');
    
    	$SCOPE      = 'w_messages r_fullprofile r_emailaddress rw_nus r_network';
    
    
    	// You'll probably use a database
    	session_name('linkedin');
    
    	// OAuth 2 Control Flow
    	if (isset($_GET['error'])) {
    		// LinkedIn returned an error
    		print $_GET['error'] . ': ' . $_GET['error_description'];
    		exit;
    	} elseif (isset($_GET['code'])) {
    		// User authorized your application
    		if ($_SESSION['state'] == $_GET['state']) {
    			// Get token so you can make API calls
    			//echo "access token"; die();
    			$this->getAccessToken($API_KEY, $API_SECRET, $url);
    		} else {
    			// CSRF attack? Or did you mix up your states?
    			exit;
    		}
    	} else {
    		if ((empty($_SESSION['expires_at'])) || (time() > $_SESSION['expires_at'])) {
    			// Token has expired, clear the state
    			$_SESSION = array();
    		}
    		if (empty($_SESSION['access_token'])) {
    			// Start authorization process
    			// echo "Auth"; die();
    			$this->getAuthorizationCode($API_KEY, $SCOPE, $url);
    		}
    	}
    
    	// Congratulations! You have a valid token. Now fetch your profile
    	//http://api.linkedin.com/v1/people/~/connections
    	// $user = $this->fetch('GET', '/v1/people/~:(firstName,lastName)');
    	$user2 = $this->fetch('GET', '/v1/people/~:(id,firstName,lastName)');
    	//print_r($user2->{'id'});
    	// print "Hello $user2->firstName $user2->lastName.";
    
    	// $user = $this->fetch('GET', '/v1/people/~/connections:(first-name,last-name,main-address)');
    	$user = $this->fetch('GET', '/v1/people/~/connections');
    
    	//print_r($user); die();
    	// print_r($user->{'values'}); die();
    	if($user->{'_total'} > 0){
    
    		$contacts=array();
    		foreach($user->{'values'} as $key=>$val){
    			//echo $key."=>".$val;
    			//print_r($key);
    			//foreach($val as $lkey=>$lval){
    			//echo $lkey."=>".$lval;
    			//}
    
    			//////////////////////////////////////// SEND LINKEDIN MESSAGE ////////////////////////////////////////////////
    			$subject= "Hello come join me at qubeey.com!";
    			$body= "Hello ".$val->{'firstName'}." ".$val->{'lastName'}."!  Join me at http://www.qubeey.com";
    			//$postrespose =  $this->sendMessageById($val->{'id'}, $ccUser=true, $subject, $body);
    
    
    			//$postrespose = $this->fetch('POST', '/v1/people/~/mailbox', $data2);
    			//echo "the result of a post messages: ";	print_r($postrespose); echo "<br/><br/>";
    			////////////////////////////////////////////////////////////////////////////////////////////////////////////
    			//print_r($val);
    			/*
    			echo "<br/><br/>";
    			echo "id: ".$val->{'id'}."<br/>";
    			echo "firstName: ".$val->{'firstName'}."<br/>";
    			echo "lastName: ".$val->{'lastName'}."<br/>";
    			echo "headline: ".$val->{'headline'};
    			echo "<br/><br/>";
    			*/
    			$contacts[trim($val->{'id'})] = $val->{'firstName'}." ".$val->{'lastName'};
    
    }
    
    }
    
    // print_r($contacts);
    // die();
    
    $this->_setSessionVar(array(
    		self::SVAR_STEP     => self::STEP_INVITE,
    		self::SVAR_SESSID   => $user2->{'id'}, //$this->openinviter->plugin->getSessionID(),
    		self::SVAR_PROVIDER => 'linkedin', //$values['provider'],
    		self::SVAR_EMAIL    => '', //$values['email'],
    		self::SVAR_CONTACTS => $contacts,
    		));
    
    		return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
    
    			//**//
    
    			///////////////////////////////////////////////////////////////////////////////
    }
    
    function sendMessageById($id, $ccUser=FALSE, $subject='', $message='') {
    //$messageUrl   =   "http://api.linkedin.com/v1/people/~/mailbox";
    $messageUrl   =   "/v1/people/~/mailbox";
    
    $subject      =   htmlspecialchars($subject, ENT_NOQUOTES, "UTF-8") ;
    $message      =   htmlspecialchars($message, ENT_NOQUOTES, "UTF-8") ;
    
    if ($ccUser){
    $CCToUser   =   "<recipient>
    <person path='/people/~'></person>
    </recipient>";
    			}
    			else{
    			$CCToUser   =   '';
    			}
    
    			$xml = '<?xml version="1.0" encoding="UTF-8" ?>';
    			$xml .= "<mailbox-item>
    			<recipients>
    			$CCToUser
    			<recipient>
    			<person path='/people/$id' ></person>
    			</recipient>
    			</recipients>
    			<subject>$subject</subject>
    			<body>$message</body>
    			</mailbox-item>";
    
    			//echo $xml . "\n";
    
    			$fields_string = "oauth2_access_token=".$_SESSION['access_token'];
    			$ch = curl_init();
    			curl_setopt($ch, CURLOPT_URL, 'https://api.linkedin.com'.$messageUrl. '?' .$fields_string );
    			curl_setopt($ch, CURLOPT_POST, 1);
    			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: text/xml', 'Content-Length: '. strlen($xml)));
    			curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
    			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    			//curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    			$postrespose = curl_exec($ch);
    			//curl_close($ch);
    
    			$curl_errno = curl_errno($ch);
    			$curl_error = curl_error($ch);
    			curl_close($ch);
    
    			//print_r($curl_errno);
    			//print_r($curl_error);
    			//print_r($postrespose); die();
    
    			return $postrespose;
    }
    	//////////////////// LinkedIn Methods///////////////////////////////////////////////////////////////////////
    	function getAuthorizationCode($API_KEY, $SCOPE, $url) {
    	$params = array('response_type' => 'code',
    	'client_id' => $API_KEY,
    	'scope' => $SCOPE,
    	'state' => uniqid('', true), // unique long string
    	'redirect_uri' => $url,
    	);
    
    	// Authentication request
    	$url2 = 'https://www.linkedin.com/uas/oauth2/authorization?' . http_build_query($params);
    
    	// Needed to identify request when it returns to us
    	$_SESSION['state'] = $params['state'];
    
    	// Redirect user to authenticate
    	header("Location: $url2");
    	exit;
    	}
    
    	function getAccessToken($API_KEY, $API_SECRET, $url) {
    	$params = array('grant_type' => 'authorization_code',
    			'client_id' => $API_KEY,
    			'client_secret' => $API_SECRET,
    			'code' => $_GET['code'],
    			'redirect_uri' => $url,
    	);
    
    	// Access Token request
    	//$url2 = 'https://www.linkedin.com/uas/oauth2/accessToken?' . http_build_query($params);
    	$url2 = 'https://www.linkedin.com/uas/oauth2/accessToken';
    
    	// Tell streams to make a POST request
    	$context = stream_context_create(
    	array('http' =>
    			array('method' => 'POST',
    			'header'  => 'Content-type:txt/html',
    	)
    	)
    	);
    
    	// Retrieve access token information
    	//$response = file_get_contents($url2, false, $context)
    
    
    	//******//
    	$fields_string = "grant_type=authorization_code&client_id=".$API_KEY."&client_secret=".$API_SECRET."&code=".$_GET['code']."&redirect_uri=".$url;
    	$ch = curl_init();
    	curl_setopt($ch, CURLOPT_URL, $url2);
    	curl_setopt($ch, CURLOPT_POST, 1);
    	curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
    	// curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    	$response = curl_exec ($ch);
    	curl_close ($ch);
    	//print_r($response);
    	//die();
    	//******//
    	// Native PHP object, please
    	$token = json_decode($response);
    
    	// Store access token and expiration time
    	$_SESSION['access_token'] = $token->access_token; // guard this!
    		$_SESSION['expires_in']   = $token->expires_in; // relative time (in seconds)
    		$_SESSION['expires_at']   = time() + $_SESSION['expires_in']; // absolute time
    
    		return true;
    	}
    
    	function fetch($method, $resource, $body = '') {
    		$params = array('oauth2_access_token' => $_SESSION['access_token'],
    		'format' => 'json',
    		);
    
    		// Need to use HTTPS
    		$url = 'https://api.linkedin.com' . $resource . '?' . http_build_query($params);
    		// Tell streams to make a (GET, POST, PUT, or DELETE) request
    				$context = stream_context_create(
    				array('http' =>
    						array('method' => $method,
    						)
    						)
    						);
    
    						$fields_string = "oauth2_access_token=".$_SESSION['access_token']."&format=json";
    		$ch = curl_init();
    		curl_setopt($ch, CURLOPT_URL, 'https://api.linkedin.com'.$resource. '?' .$fields_string );
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    		$response = curl_exec($ch);
    		curl_close($ch);
    		// print_r($response);
    // die();
    
    // Hocus Pocus
    //$response = file_get_contents($url, false, $context);
    //print_r($response);
    
    // Native PHP object, please
    return json_decode($response);
    }
    
    //////////////////////////////////////// END LinkedIn Methods//////////////////////////////////////////
    
    //****************************************************************************************//

    /**
     * Twitter action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function twitterAction(Request $request, $twt=false)
    {
    	$this->_init();
    
    	$user = $this->get('security.context')->getToken()->getUser();
    	//$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    
    	//////////////////////////////////////////////////////////////////////////////////////
    
    	$response = new Response();
    	//echo "response: ";
    	//print_r($response);
    	//echo "<br/><br/>";
    	if(isset($twt) && $twt == 'LST'){

			//////////////////////////////////////////////////////////////////////////////////////
    			$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'), $_SESSION['oauth_token'], $_SESSION['oauth_token_secret']);
    			$access_token = $connection->getAccessToken($_REQUEST['oauth_verifier']);
    			/* Save the access tokens. Normally these would be saved in a database for future use.  DO IT IN SYMFONY */
    			$_SESSION['access_token'] = $access_token;
    			
    			/* Remove no longer needed request tokens */
    			//unset($_SESSION['oauth_token']);
    			//unset($_SESSION['oauth_token_secret']);
    			
    			/* If HTTP response is 200 continue otherwise send to connect page to retry */
    			if (200 == $connection->http_code) {
    				/* The user has been verified and the access tokens can be saved for future use.  DO IT IN SYMFONY*/
    				$_SESSION['status'] = 'verified';
    				//header('Location: ./index.php');
    				/* Create a TwitterOauth object with consumer/user tokens. */
    				$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'), $access_token['oauth_token'], $access_token['oauth_token_secret']);
   			
    				/* If method is set change API call made. Test is called by default. */
    				$content = $connection->get('account/verify_credentials');
    				//print_r($content);
    				//var_dump($content);
    				//var_dump($content->{'name'});
                    //echo "<br/><br/>";
                    
                    $connection->host = 'https://api.twitter.com/1.1/'; // By default library uses API version 1.  
                    //$friendsJson = $connection->get('/followers/list.json?cursor=-1&screen_name='.$content->{'screen_name'}.'&skip_status=true&include_user_entities=false');
                    $friendsJson = $connection->get('/friends/list.json?cursor=-1&screen_name='.$content->{'screen_name'}.'&skip_status=true&include_user_entities=false');

                    //echo "followers: "; print_r($friendsJson); die();
                    //echo count($friendsJson);
                    //echo $friendsJson->{'name'};
                    //print_r($friendsJson->{'users'});

                    $contacts=array();

	                $k = 1;
	                for($i=0; $i < count($friendsJson->{'users'}); $i++){
		                //echo "\r\n";
			               // echo "<div style='display:inline-block;padding:15px; vertical-align:middle;text-align:center'>";
			                //echo $friendsJson->{'users'}[$i]->{'id'}."<br/>";
			                //echo $friendsJson->{'users'}[$i]->{'name'}."<br/>";
			              //  echo "<img src=".$friendsJson->{'users'}[$i]->{'profile_image_url'}." /><br/><input type='checkbox' checked name='contactid' id='contactid' value='".$friendsJson->{'users'}[$i]->{'id'}."'>";
			               // echo $friendsJson->{'users'}[$i]->{'screen_name'}."</div>";		
		                //echo "\r\n";

		                //if($friendsJson->{'users'}[$i]->{'id_str'} == 1564400612){
		                if($friendsJson->{'users'}[$i]->{'screen_name'} == 'PanDeTrigo1'){

		                //if($friendsJson->{'users'}[$i]->{'id_str'} == 1205773753){
		                //if($friendsJson->{'users'}[$i]->{'screen_name'} == 'PanDorado2000'){

			                //////////////////////////////////////////////////////////////////////////////////////
                            //$mess = urlencode("Join me at http://qubeey.com everything you care about can find you. Social,Buisness,Personal,Fun Qubeey connects it all.");
                            $mess = "Join me at http://qubeey.com everything you care about can find you. Social,Buisness,Personal,Fun Qubeey connects it all.";
                            $parameters = array('user_id' => $friendsJson->{'users'}[$i]->{'id'}, 'text' => $mess);
                            $method = 'direct_messages/new';
                           // $postfriends = $connection->post($method, $parameters);
                        }

                        $img1 = "<img src=".$friendsJson->{'users'}[$i]->{'profile_image_url'}.">";
		               // $contacts[$friendsJson->{'users'}[$i]->{'id'}] = $img1 ."<br/>". $friendsJson->{'users'}[$i]->{'screen_name'}; //."\r\n";
                        $contacts[trim($friendsJson->{'users'}[$i]->{'id'})] = trim($friendsJson->{'users'}[$i]->{'screen_name'});
	                }
//print_r($contacts);
//die();
                $this->_setSessionVar(array(
		                self::SVAR_STEP     => self::STEP_INVITE,
		                self::SVAR_SESSID   => $content->{'id'}, //$this->openinviter->plugin->getSessionID(),
		                self::SVAR_PROVIDER => 'twitter', //$values['provider'],
		                self::SVAR_EMAIL    => '', //$values['email'],
		                self::SVAR_CONTACTS => $contacts,
                ));

 //die();
                return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));

	

    				//// ************* ////
    		die();
    				$profile = new MemberProfile();
    				$form = $this->createForm(new \Qubeey\WebBundle\Form\Member($profile), $member, array('validation_groups' => array('registration', 'Default')));
    				return array(
    				'member' => $member,
    				'profile' => $profile,
    				'form'   => $form->createView(),
    						'tw_firstname' => $twname[0],
    						'appId'  => $this->container->getParameter('FACEBOOK_APP_ID'),
    								'memberaccount' => $access_token['oauth_token']."~:~".$access_token['oauth_token_secret']."~:~".$content->{'screen_name'},
    								);
    			
    				} else {
    				/* Save HTTP status for error dialog on connnect page. REDIRECT TO /oi/ */
                    $url = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_login');
    				header('Location: '.$url);
    			}
    						//***//
    						exit(); return  $this->render('QubeeyWebBundle:Page:dummy.html.twig');
    						    			
			//////////////////////////////////////////////////////////////////////////////////////
    	}
    	
    	
    	$request = $this->getRequest();
        $connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'));
        $url = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_twtp', array('twt'=>'LST'));
       // $logger = $this->get('logger');
       // $logger->info($url);
        
        $request_token = $connection->getRequestToken($url);

        
       //echo $url."<br/><br/>";
       //print_r($request_token);
       
       //die();
        /* Save temporary credentials to session. DO IT IN SYMFONY */
        $_SESSION['oauth_token'] = $token = $request_token['oauth_token'];
        $_SESSION['oauth_token_secret'] = $request_token['oauth_token_secret'];
         
        /* If last connection failed don't display authorization link. */
        switch ($connection->http_code) {
          case 200:
            /* Build authorize URL and redirect user to Twitter. */
            $url = $connection->getAuthorizeURL($token);
            header('Location: ' . $url); // DO IT IN SYMFONY
            break;
          default:
            /* Show notification if something went wrong. */
            $this->errorcontent = 'Could not connect to Twitter. Refresh the page or try again later.';
        }
        //***//
                return  $this->render('QubeeyWebBundle:Page:dummy.html.twig', array('returnerror' => $this->errorcontent));
    }    
    //***************************************************************************************//
    	
   
//****************************************************************************************//
    /**
     * Facebook action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function facebookAction(Request $request)
    {
    	$this->_init();
    
    	$user = $this->get('security.context')->getToken()->getUser();
    	//$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    
    	//////////////////////////////////////////////////////////////////////////////////////
    
    	$response = new Response();
    	//echo "response: ";
    	//print_r($response);
    	//echo "<br/><br/>";
    
    	$request = $this->getRequest();
    
    	$facebook = new Facebook(array(
    			'appId'  => $this->container->getParameter('FACEBOOK_APP_ID'),
    			'secret' => $this->container->getParameter('FACEBOOK_SECRET'),
    			'cookie' => true
    	));
    
    	// Get User ID
    	$fbuser = $facebook->getUser();
    	$access_token = $facebook->getAccessToken();
    
    	if(isset($access_token)){
    		// echo "current token: "; print_r($access_token);
    		// echo "<br/><br/><br/>";
    
    		$ch = curl_init();
    		//curl_setopt($ch, CURLOPT_URL, "https://graph.facebook.com/100006247597448?fields=name,email,friends.fields%28email,name%29&access_token=".$access_token);
    		// curl_setopt($ch, CURLOPT_URL, "https://graph.facebook.com/".$user."?fields=email,friends.fields%28username,email,name%29&access_token=".$access_token);
    		//Above is the returned access token for the authirized user.
    		
    		//Below is the app's accesstoken 
    		curl_setopt($ch, CURLOPT_URL, "https://graph.facebook.com/".$fbuser."?fields=email,friends.fields%28username,email,name%29&access_token=292135030842967|da195cc276228e148c88080f58e406d3");
    
    
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		$output = curl_exec($ch);
    		curl_close($ch);
    		$emailscont = json_decode($output,true);
    		// echo count($emailscont['friends']['data']);
    
    		//if (in_array("friends", $emailscont['friends']['data'])) {
    			//print_r($emailscont); //die();
    		//}
    		//print_r($emailscont);
    		$contacts=array();
    		//print_r($emailscont['friends']['data']);
    		if(isset($emailscont['friends']['data'])){
    		foreach($emailscont['friends']['data'] as $indx=>$arrcont){
    
    		// print_r($arrcont);
    
    				if(array_key_exists('email', $arrcont)){
    			//echo $arrcont['name']."--".$arrcont['username']."--".$arrcont['email']."--".$arrcont['id']."<br/>";
    			$contacts[$arrcont['email']]=$arrcont['name'];
    		}else{
    		$contacts[$arrcont['username']."@facebook.com"]=$arrcont['name'];
    		}
    		/*
    		echo"<br/>"; echo"<br/>"; echo"<br/>";
    		foreach($arrcont as $name=>$val){
    		echo "print friend: ".$name."=>".$val."<br/>";
    
    }
    		echo"<br/>";
    		*/
    }
    
    		print_r($contacts);
    }
    }
    
    		//// ******************************************************* ////
    		// Login or logout url will be needed depending on current user state.
    		if ($fbuser) {
    		//echo "loged";
    		$logoutUrl = $facebook->getLogoutUrl();
    		// echo "logout: <a href=".$logoutUrl.">LOGOUT</a><br/><br/>";
    
    		// *****************************************//
    		//MANNUAL LOGOUT
    		$facebook -> destroySession();
    		//setcookie("fbsr_YOUR_APP_ID",'',time()-10);
    			// *****************************************//
    		} else {
    		//REQUEST FOLLOWING PERMISIONS WHEN LOGININ;
    		//'email, publish_actions, publish_stream, read_stream, friends_likes, read_friendlists'
    		$params = array(
    				'scope' => 'email, publish_actions, publish_stream, read_friendlists',
    				'redirect_uri' => $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath()."/app_dev.php/oi/facebook/",
    				);
    				//print_r($params);
    
    		$loginUrl = $facebook->getLoginUrl($params);
    		
    	//insert a twig view  and pass the array('fbl'=>$loginUrl) login url   
    	//replacing the code below to a cutom look 	
    		return $this->get('templating')->renderResponse(
    				'ArtseldOpeninviterBundle:Default:facebook.html.twig', array(
    						'fbl' => $loginUrl,
    				));
    		
    		
    		//echo "login: <a href=".$loginUrl.">LOGIN</a><br/><br/>";
    		die();
    		//$loginUrl = $facebook->getLoginUrl();
    }
    
    //$currentuser = $facebook->api('/me/friends.fields(email)');
    
    		//echo "currentuser"; print_r($currentuser);
   
     
    $this->_setSessionVar(array(
    		self::SVAR_STEP     => self::STEP_INVITE,
    		self::SVAR_SESSID   => '765123', //$this->openinviter->plugin->getSessionID(),
    		self::SVAR_PROVIDER => 'facebook', //$values['provider'],
    		self::SVAR_EMAIL    => '', //$values['email'],
    		self::SVAR_CONTACTS => $contacts,
    ));
    
    
    return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
    
    
    		die();
    
    		//////////////////////////////////////////////////////////////////////////////////////
    		// if($user){
    		 defined( $user->getMemberQid())? $id = $user->getMemberQid():'';
    		$id = $user->getMemberQid();
    		$username = $user->getUsername();
    
    
    		//$ts = new \DateTime("now"); $new_time = date("Y-m-d H:m:s", strtotime('+1 hours', NOW())); print_r($new_time); die();
    		if ($this->_getSessionVar(self::SVAR_STEP) != self::STEP_LOGIN) {
    		$this->_clearSessionVar();
    		$this->_setSessionVar(self::SVAR_STEP, self::STEP_LOGIN);
    		}
    		$form = $this->get('form.factory')->create(new LoginFormType( $this->openinviter ));
    		if ($request->getMethod() == 'POST') {
    			$form->bindRequest($request);
    
	    		if ($form->isValid()) {
		    		$values = $form->getData();
		    		$this->openinviter->startPlugin($values['provider']);
		    		$internal = $this->openinviter->getInternalError();
		    		if ($internal) {
		    		$form->addError(new \Symfony\Component\Form\FormError( $this->_trans($internal) ));
		    		} elseif (!$this->openinviter->login( $values['email'], $values['password'] )) {
		    		$internal = $this->openinviter->getInternalError();
		    		$form->addError(new \Symfony\Component\Form\FormError( $this->_trans(
		    				// $internal ? $internal : $values["email"]." ".$values["password"].' - artseld_openinviter.notification.error.incorrect_login'
		    				$internal ? $internal : 'artseld_openinviter.notification.error.incorrect_login'
		    				)));
		    		} elseif (false === $contacts = $this->openinviter->getMyContacts()) {
		    		$form->addError(new \Symfony\Component\Form\FormError(
		    				$this->_trans('artseld_openinviter.notification.error.cannot_get_contacts')
		    		));
		    		} else {
		    		$this->_setSessionVar(array(
		    				self::SVAR_STEP     => self::STEP_INVITE,
		    				self::SVAR_SESSID   => $this->openinviter->plugin->getSessionID(),
		    				self::SVAR_PROVIDER => $values['provider'],
		    				self::SVAR_EMAIL    => $values['email'],
		    				self::SVAR_CONTACTS => $contacts,
		    				));
		    				return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
				    }
			    }
		    }
		    
    				return $this->get('templating')->renderResponse(
				    'ArtseldOpeninviterBundle:Default:login.html.twig', array(
				    'login_form' => $form->createView(),
				    ));
    
    //}else {
    //return $this->redirect($this->generateUrl('page_homepage'));
    //}
    }
    
    //====================================================  Vimeo Action ==================================================//
    /**
     * Vimeo action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function vimeoAction(Request $request, $user)
    {
    	$this->_init();
    
    	$member = $this->get('security.context')->getToken()->getUser();
    	$id = $member->getMemberQid();  //var_dump($id); die;
    
    	//////////////////////////////////////////////////////////////////////////////////////
    
    	$response = new Response();
    
    	$request = $this->getRequest();
    	$redirect_url =  $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath();
    	//$url = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath() . $this->generateUrl('artseld_openinviter_login');
    	$url = $request->getScheme().'://'.$request->getHttpHost().$request->getBasePath().$this->generateUrl('artseld_openinviter_vimeo', array('user'=>'olechka'));
    
    	//$_consumer_key    = '70418d113d90a73b7fe63fbd18f46985c2c4f6e7';  // Client ID (Also known as Consumer Key or API Key)
    	//$_consumer_secret = '5a7aff371bed7ca71b3a30a9ea4a1da0d1a9f38f';  // Client Secret (Also known as Consumer Secret or API Secret)
    	//$_token           = '318d1b37e3fbb2e2abce499876054d01';          // Access token
    	//$_token_secret    = 'f835c4de75ad41d8e85e9bec54673fd3d8c8cbc7';  // Access token secret     // guard this!
    	$_consumer_key    = $this->container->getParameter('VIMEO_CONSUMER_KEY');
    	$_consumer_secret = $this->container->getParameter('VIMEO_CONSUMER_SECRET');
    	$_token           = $this->container->getParameter('VIMEO_ACCESS_TOKEN');    //echo "<br />AccessToken: " . $_token;
    	$_token_secret    = $this->container->getParameter('VIMEO_TOKEN_SECRET');
    
    	//echo "<br />TOKEN: " . $this->container->getParameter('VIMEO_ACCESS_TOKEN');
    
    	$API_REST_URL          = 'http://vimeo.com/api/rest/v2';
    	$API_AUTH_URL          = 'http://vimeo.com/oauth/authorize';      // Authorize URL
    	$API_ACCESS_TOKEN_URL  = 'http://vimeo.com/oauth/access_token';   // Access Token URL
    	$API_REQUEST_TOKEN_URL = 'http://vimeo.com/oauth/request_token';  // Request Token URL
    
    	// echo  $this->get('kernel')->getRootDir(); echo "<br/>";
    	// echo  $this->get('kernel')->getRootDir(). '/cache/dev/inviter' . $request->getBasePath();  //home2/olga/serverWeb/app/../web/dev
    	// die();
    	$path= $this->get('kernel')->getRootDir(). '/cache/dev/inviter' . $this->getRequest()->getBasePath();
    
    	$this->_cache_dir = $path;     //echo "<br /><br />Path from class: " . getcwd();
    	//$files = scandir($this->_cache_dir);
    
    	$filename = $this->get('kernel')->getRootDir(). '/cache/dev/inviter' . $this->getRequest()->getBasePath(); // . $this->getRequest()->getBasePath();
    
    	if (file_exists($filename)) {
    		echo "<br /><br />The file $filename exists";
    } else {
    	echo "<br /><br />The file $filename does not exist";
    }
    //die();
    		//====================================================== simple api interface ====================================================================//
    
    		$vim = new \Qubeey\ApiBundle\Utility\Vimeo($_consumer_key, $_consumer_secret, $_token, $_token_secret);   print_r($vim);
    
    		$params = array(1);//vimeo.contacts.getAll
    		//
    		$vim->setToken($_token, $_token_secret);
    		$token = $vim->getRequestToken();  echo "<br /><br />I am here: <br />" . print_r($token);
    //$vim->getAccessToken('olechka');
    $vim->getAuthorizeUrl($_consumer_key);
    $vim->auth('read', 'http://nginx1.qubedev.com:7031/app_dev.php/oi/invite');
    echo $vim->call('vimeo.contacts.getAll', $params);
    //echo md5(uniqid(microtime()));
    
    //================================================================================================================================================//
    
    
    // Create the object and enable caching
    //$vimeo = new \Qubeey\ApiBundle\Utility\Vimeo($_consumer_key, $_consumer_secret, $_token, $_token_secret);
    ///$vimeo = new \Qubeey\ApiBundle\Utility\Vimeo($this->container->getParameter('VIMEO_CONSUMER_KEY'), $this->container->getParameter('VIMEO_CONSUMER_SECRET'),$_token, $_token_secret);
    //$vimeo->enableCache(\Qubeey\ApiBundle\Utility\Vimeo::CACHE_FILE, $path, 300);
    //$vimeo->enableCache(phpVimeo::CACHE_FILE, './cache', 300);
    //echo "<br /><br />Vimeo: ";
    //print_r($vimeo); die();
    
    	/* Save the access tokens. Normally these would be saved in a database for future use.  DO IT IN SYMFONY */
    // Set up variables
    //$state = 'start';
    
    //$state = $_SESSION['vimeo_state'];                   //echo "<br />Vimeo State: " . $_SESSION['vimeo_state'];
    $request_token = $_SESSION['oauth_request_token'];   //echo "<br />Vimeo oauth_request_token: " . $_SESSION['oauth_request_token'];
    $access_token = $_SESSION['oauth_access_token'];     //echo "<br />Vimeo oauth_access_token: " . $_SESSION['oauth_access_token'];
    
    echo "<br /><br />Vimeo: ";
    print_r($vimeo); //die();
    echo "<br /><br />Oauth Token: " . $_REQUEST['oauth_token'];
    /************************************************************************************************************************************************/
    /*
    // Coming back
    if ($_REQUEST['oauth_token'] != NULL && $_SESSION['vimeo_state'] === 'start') {
    $_SESSION['vimeo_state'] = $state = 'returned';
    }
    
    // If we have an access token, set it
    if (isset($_SESSION['oauth_access_token']) && ($_SESSION['oauth_access_token'] != null)) {
    $vimeo->setToken($_SESSION['oauth_access_token'], $_SESSION['oauth_access_token_secret']);  echo "access token: " . $_SESSION['oauth_access_token'];
    }
    
    switch ($_SESSION['vimeo_state']) {
    default:
    
    // Get a new request token
    $token = $vimeo->getRequestToken();  echo "<br /><br />I am here: " . print_r($token);
    
    // Store it in the session
    $_SESSION['oauth_request_token'] = $token['oauth_token'];
    $_SESSION['oauth_request_token_secret'] = $token['oauth_token_secret'];
    $_SESSION['vimeo_state'] = 'start';
    
    // Build authorize link
    $authorize_link = $vimeo->getAuthorizeUrl($token['oauth_token'], 'write');
    
    break;
    
    case 'returned':
    
    // Store it
    if ($_SESSION['oauth_access_token'] === NULL && $_SESSION['oauth_access_token_secret'] === NULL) {
    // Exchange for an access token
    $vimeo->setToken($_SESSION['oauth_request_token'], $_SESSION['oauth_request_token_secret']);
    $token = $vimeo->getAccessTokenVim($_REQUEST['oauth_verifier']);
    
    // Store
    $_SESSION['oauth_access_token'] = $token['oauth_token'];
    $_SESSION['oauth_access_token_secret'] = $token['oauth_token_secret'];
    $_SESSION['vimeo_state'] = 'done';
    
    // Set the token
    $vimeo->setToken($_SESSION['oauth_access_token'], $_SESSION['oauth_access_token_secret']);
    }
    
    // Do an authenticated call
    try {
    $videos = $vimeo->call('vimeo.videos.getUploaded');
    }
    catch (VimeoAPIException $e) {
    echo "Encountered an API error -- code {$e->getCode()} - {$e->getMessage()}";
    }
    
    break;
    
    }
    //*********************************************************************************************************************/
    
    // Change this to your username to load in your videos
    // $vimeo_user_name = ($_GET['user']) ? $_GET['user'] : 'olechka';
    $vimeo_user_name = $user ? $user : 'olechka';
    
    // API endpoint
    $api_endpoint = 'http://vimeo.com/api/v2/' . $vimeo_user_name;
    
    // Curl helper function
    function curl_get($url) {
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_TIMEOUT, 30);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
    $return = curl_exec($curl);
    curl_close($curl);
    return $return;
    }
    
    // Load the user info and clips
    $user = simplexml_load_string(curl_get($api_endpoint . '/info.xml'));
    $videos = simplexml_load_string(curl_get($api_endpoint . '/videos.xml'));
    
    $output = '';
    $output .= '<h1>Vimeo API PHP Example</h1>';
    $output .= '<div id="stats">';
    $output .= '<img id="portrait" src="'. $user->user->portrait_small .'" />';
    $output .= '<h2>'. $user->user->display_name.'\'s Videos</h2>';
    $output .= '</div>';
    $output .= '<p id="bio">'. $user->user->bio .'</p>';
    $output .= '<div id="thumbs">';
    $output .= '<ul>';
    foreach ($videos->video as $video) {
    $output .= '<li>';
    $output .= '<a href="'. $video->url .'"><img src="'. $video->thumbnail_medium .'" /></a>';
    $output .= '</li>';
    }
    $output .= '</ul>';
    $output .= '</div>';
    //========================================================================================
    /*
    $output .= '<h1>Vimeo Advanced API OAuth Example</h1>';
    $output .= '<p>This is a basic example of Vimeo\'s new OAuth authentication method.
    Everything is saved in session vars, so <a href="?clear=all">click here if you want to start over</a>.</p>';
    
    if ($_SESSION['vimeo_state'] == 'start') {
    $output .= '<p>Click the link to go to Vimeo to authorize your account.</p>';
    $output .= '<p><a href="'.$authorize_link.'">'.$authorize_link.'</a></p>';
    }
    
    if ($ticket) {
    $output .= '<pre>'. print_r($ticket) .'</pre>';
    }
    
    if ($videos) {
    $output .= '<pre>'. print_r($videos) .'</pre>';
    }
    */
    //=======================================================================================
    
    
    echo $output;
    //die();
    return $this->get('templating')->renderResponse(
    'ArtseldOpeninviterBundle:Default:done.html.twig', array('output'=> $output
    ));
    
    }
    
    
    
    //==================================================== End Vimeo Action =============================================//    
//***************************************************************************************//
    /**
     * Login action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function loginAction(Request $request)
    {
        $this->_init();
        
        $user = $this->get('security.context')->getToken()->getUser();
        //$id = $user->getMemberQid();  //var_dump($id); die;
        //print_r($user);
        
       // if($user){
	       // defined( $user->getMemberQid())? $id = $user->getMemberQid():'';
        	$id = $user->getMemberQid();
	        $username = $user->getUsername();
	        
	        
	        //$ts = new \DateTime("now"); $new_time = date("Y-m-d H:m:s", strtotime('+1 hours', NOW())); print_r($new_time); die();
	        if ($this->_getSessionVar(self::SVAR_STEP) != self::STEP_LOGIN) {
	            $this->_clearSessionVar();
	            $this->_setSessionVar(self::SVAR_STEP, self::STEP_LOGIN);
	        }
	        $form = $this->get('form.factory')->create(new LoginFormType( $this->openinviter ));
	        if ($request->getMethod() == 'POST') {
	            $form->bindRequest($request);
	
	            if ($form->isValid()) {
	                $values = $form->getData();
	                $this->openinviter->startPlugin($values['provider']);
	                $internal = $this->openinviter->getInternalError();
	                if ($internal) {
	                    $form->addError(new \Symfony\Component\Form\FormError( $this->_trans($internal) ));
	                } elseif (!$this->openinviter->login( $values['email'], $values['password'] )) {
	                    $internal = $this->openinviter->getInternalError();
	                    $form->addError(new \Symfony\Component\Form\FormError( $this->_trans(
	                       // $internal ? $internal : $values["email"]." ".$values["password"].' - artseld_openinviter.notification.error.incorrect_login'
	                    $internal ? $internal : 'artseld_openinviter.notification.error.incorrect_login'
	                    )));
	                } elseif (false === $contacts = $this->openinviter->getMyContacts()) {
	                    $form->addError(new \Symfony\Component\Form\FormError(
	                        $this->_trans('artseld_openinviter.notification.error.cannot_get_contacts')
	                    ));
	                } else {
	                    $this->_setSessionVar(array(
	                        self::SVAR_STEP     => self::STEP_INVITE,
	                        self::SVAR_SESSID   => $this->openinviter->plugin->getSessionID(),
	                        self::SVAR_PROVIDER => $values['provider'],
	                        self::SVAR_EMAIL    => $values['email'],
	                        self::SVAR_CONTACTS => $contacts,
	                    ));
	                    return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
	                }
	            }
	        }
	
	        return $this->get('templating')->renderResponse(
	            'ArtseldOpeninviterBundle:Default:login.html.twig', array(
	                'login_form' => $form->createView(),
	            ));
        
    	//}else {
    		//return $this->redirect($this->generateUrl('page_homepage'));
    	//}
    }

    
    /**
     * Invite action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function inviteAction(Request $request)
    {
        $this->_init();
        
        $member = new Member();
        $dm = $this->get('doctrine.odm.mongodb.document_manager');
        $em = $this->getDoctrine()->getEntityManager();
        $session = $request->getSession();
        $user = $this->get('security.context')->getToken()->getUser();
        
        
        if ($this->_getSessionVar(self::SVAR_STEP) != self::STEP_INVITE) {
            return new RedirectResponse($this->generateUrl('artseld_openinviter_login'));
        }
		//print_r($this->_getSessionVar(self::SVAR_CONTACTS));
		//print_r($_SESSION); 
		//die();
        $form = $this->get('form.factory')->create(new InviteFormType( $this->_getSessionVar(self::SVAR_CONTACTS) ));
        if ($request->getMethod() == 'POST') {
            $form->bindRequest($request);

            if ($form->isValid()) {
                $values = $form->getData();
                $this->openinviter->startPlugin( $this->_getSessionVar(self::SVAR_PROVIDER) );
                $internal = $this->openinviter->getInternalError();
                if ($internal) {
                    $form->addError(new \Symfony\Component\Form\FormError( $this->_trans($internal) ));
                } else {
                    if (empty($values['email'])) {
                        $form->addError(new \Symfony\Component\Form\FormError(
                            $this->_trans('artseld_openinviter.notification.error.email_not_set')
                        ));
                    }
                    
                    $sessid = $this->_getSessionVar(self::SVAR_SESSID);
                    //echo "session :". $sessid;
                    if (empty($sessid)) {
                        $form->addError(new \Symfony\Component\Form\FormError(
                            $this->_trans('artseld_openinviter.notification.error.no_active_session')
                        ));
                    }
                    
                    /*
                     //remove custom message. 
                    if (empty($values['message'])) {
                        $form->addError(new \Symfony\Component\Form\FormError(
                            $this->_trans('artseld_openinviter.notification.error.message_missing')
                        ));
                    } else {
                        $values['message'] = strip_tags($values['message']);
                    }
                    */
                    
                    
                    // ********************************************** //
                    // print_r($values); die();
                   
                    //$session = $request->getSession();
                    //$user = $this->get('security.context')->getToken()->getUser();
                   // print_r($user);
                    $id = $user->getMemberQid();
                    $username = $user->getUsername();
                    //$sess = $this->get('session')->get('email');
                    //echo "User Id: ".$username." ".$id; //." ".$session->get(SecurityContext::LAST_USERNAME);
                    //echo "<br/><br/>"; echo "sess ".$sess; echo "<br/><br/>"; 
                    //print_r($session);
                    $id=1457007;
                    $categories = $this->getDoctrine()->getRepository('QubeeyApiBundle:Entitycategory')->findBy(array('entityQid' => 1457007));
                    if(count($categories)>0) {
                    	$x=0;
                    	foreach ($categories AS $category) {
                    		$arrCategories[$x]['id']=$category->getEntitycategoryQid();
                    		$arrCategories[$x]['name']=$category->getCategory()->getName();
                    		//$arrCategories[$x]['catid']=$category->getCategory()->getCategoryId()
                    		//echo category ID:sourceid:Name 
                    		
                    		$source = $arrCategories[$x]['name'];
                    		//echo($arrCategories[$x]['id']. " : ".$category->getCategory()->getCategoryId()." : ".$arrCategories[$x]['name']);
                    		$x++;
                    	}
                    }
                    
     
                   // print_r($arrCategories); echo "<br/><br/>";
                   // print_r($categories->entitycategoryQid);  echo "<br/><br/>";                  
                    //print_r($categories->getEntitycategoryQid()); echo "<br/><br/>";
                    // ********************************************** //
                   
                    $message = array(
                        'subject'       => $this->_trans('artseld_openinviter.text.message_subject',
                           // array('%link%' => $this->generateUrl('_welcome', array(), true))),
                           array('%link%' => $this->generateUrl('channels_lp', array('custlp'=>$arrCategories[0]['name']), true))),
                        'body'          => $this->_trans('artseld_openinviter.text.message_body',
                            array('%username%' => $this->_getSessionVar(self::SVAR_EMAIL),
                                //'%link%' => $this->generateUrl('_welcome', array(), true))) . "\n\r" . $values['message'],
                            	'%link%' => $this->generateUrl('channels_lp', array('custlp'=>$arrCategories[0]['name']), true))) . "\n\r",
                        'attachment'    => '',
                    );

                    // ********************************************** //
	                    //echo $this->generateUrl('channels_lp', array('custlp'=>$arrCategories[0]['name']), true);
	                   	// echo "<br/><br/>";
	                   	// echo "<br/>".$this->generateUrl('channels_lp', array('custlp'=>$arrCategories[0]['name']), true) . "\n\r" . $values['message']."<br/>";
	                   	// print_r($values); //die(); 
	                  	//echo "<br/><br/>";
	                  	//echo "message: ";  print_r($message); //die();
                 	 // ********************************************** //
                    $selectedContacts = array();
                    if ($this->openinviter->showContacts())
                    {
                        $i = 0;
                        foreach ($this->_getSessionVar(self::SVAR_CONTACTS) as $email => $name) {
                            if (in_array($i, $values['email'])) $selectedContacts[$email] = $name;
                            $i++;
                        }
                        if (count($selectedContacts) == 0) {
                            $form->addError(new \Symfony\Component\Form\FormError(
                                $this->_trans('artseld_openinviter.notification.error.contacts_not_selected')
                            ));
                        }
                    }  
                }
              //  print_r($this->_getSessionVar(self::SVAR_PROVIDER)); echo "<br/>can you: ";  die();
                // ********************************************** //
                if (count($form->getErrors()) == 0) {
                    $sendMessage = $this->openinviter->sendMessage(
                        $this->_getSessionVar(self::SVAR_SESSID), $message, $selectedContacts);
                    $this->openinviter->logout(); 
                    
                    /////////////////// ******** PROVIDERS ********* ///////////////////
                    
                    ////////////////////////////// faceBook //////////////////////////////////
                    if($this->_getSessionVar(self::SVAR_PROVIDER) == 'facebook'){ $sendMessage = -1; }                    
                    
                    ////////////////////////////// Twitter //////////////////////////////////                    
                    if($this->_getSessionVar(self::SVAR_PROVIDER) == 'twitter'){
                    	$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'), $_SESSION['access_token']['oauth_token'], $_SESSION['access_token']['oauth_token_secret']);
                    	$content = $connection->get('account/verify_credentials');   
                    	$connection->host = 'https://api.twitter.com/1.1/'; // By default library uses API version 1.

                    	//Message must be less than 140 characters
                        foreach($selectedContacts as $emailid=>$username){
                            $mess = "Join me at http://qubeey.com everything you care about can find you. Social,Buisness,Personal,Fun Qubeey connects it all.";
                            $method = 'direct_messages/new'; 
                            $parameters = array('user_id' => $emailid, 'text' => $mess);
                            print_r($parameters); echo "<br/><br/>";
                           // $postfriends = $connection->post($method, $parameters);
                        }
						$this->_setFlash(self::FLASH_SUCCESS, 'Qubeey sent your invitaions successfully.');
                    	//die();
                   }
                  ////////////////////////////// Linkedin ////////////////////////////////// 
                   if($this->_getSessionVar(self::SVAR_PROVIDER) == 'linkedin'){
	                 	$user = $this->fetch('GET', '/v1/people/~/connections');                  
	                  	//print_r($user); die();                  		
	                  	foreach($selectedContacts as $emailid=>$username){        		
		        		//////////////////////////////////// SEND LINKEDIN MESSAGE ///////////////////////////////////////        	
		        		$subject= "Hello come join me at qubeey.com!";
		        		$body= "Hello ".$username."!  Join me at http://www.qubeey.com/".$source;        		
		        		//$postrespose =  $this->sendMessageById($emailid, $ccUser=false, $subject, $body); 
		        		echo 'Subject: '.$subject.' <br/> Body: '.$body.'<br/><br/>';      		
		        		/////////////////////////////////////////////////////////////////////////////////////////////////
	        			} die();
	                  	$this->_setFlash(self::FLASH_SUCCESS, 'Qubeey sent your invitaions successfully.');              			
               		}
                  //////////////////////////////////////////////////////////////////////  

               		
               		
                    	//echo "almost: "; print_r($sendMessage); die();
                    	if ($sendMessage === -1) {

               // ********************************************** //
                        
//******************************************************************************************************************************//
                        $member = $em->getRepository('QubeeyApiBundle:Member')->findOneBy(array('email' => $username));
                       // print_r($member->getMemberQid());
                        //die();
                    	if ($member) {


		    					$modelMember = new ModelMember($em, $this->get('doctrine.odm.mongodb.document_manager'), $member);
		    					$restpass = $modelMember->addInvitation('Inviter', $category->getCategory()->getCategoryId(), json_encode($selectedContacts));
   
	    			 }
//******************************************************************************************************************************//
	    			   //$this->_setFlash(self::FLASH_SUCCESS, 'artseld_openinviter.notification.success.invitations_sent');
                        // ********************************************** //                        
                        $this->_setFlash(self::FLASH_SUCCESS, 'Qubeey sent your invitaions successfully.');
                       
                    } elseif ($sendMessage === false) {
                        $internal = $this->openinviter->getInternalError();
                        $this->_setFlash(self::FLASH_ERROR, $internal ? $internal
                            : 'artseld_openinviter.notification.error.invitations_with_errors'
                        );
                    } else {
                        $this->_setFlash(self::FLASH_SUCCESS, 'artseld_openinviter.notification.success.invitations_sent');
                    }
                    return new RedirectResponse($this->generateUrl('artseld_openinviter_done'));
                } echo "cant: ";  die();
///////////////////////////////////////////////////////////////////////////////////////////////////////                
            }
        }

        return $this->get('templating')->renderResponse(
            'ArtseldOpeninviterBundle:Default:invite.html.twig', array(
                'invite_form' => $form->createView(),
            ));
    }

    /**
     * Done action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function doneAction()
    {
        $this->_init();

        $this->_clearSessionVar();

        return $this->get('templating')->renderResponse(
            'ArtseldOpeninviterBundle:Default:done.html.twig', array(
            ));
    }

    /**
     * Create Openinviter instance and load plugins
     */
    protected function _init()
    {
        $this->openinviter = new ArtseldOpeninviter( $this->container );
        $this->oiPlugins = $this->openinviter->getPlugins();
    }

    /**
     * Set session variable
     * @param $name
     * @param $value
     * @return DefaultController
     */
    protected function _setSessionVar($name, $value = null)
    {
        $this->_checkSessionVar($name);
        if (is_array($name) && null === $value) {
            foreach ($name as $k => $v) {
                $this->get('session')->set('artseld_openinviter.session.' . $k, $v);
            }
        } else {
            $this->get('session')->set('artseld_openinviter.session.' . $name, $value);
        }

        return $this;
    }

    protected function _getSessionVar($name) {
        $this->_checkSessionVar($name);
        return $this->get('session')->get('artseld_openinviter.session.' . $name);
    }

    /**
     * Clear session variable
     * @param $name
     * @return DefaultController
     */
    protected function _clearSessionVar($name = null)
    {
        if (null !== $name) {
            $this->_checkSessionVar($name);
            if (is_array($name)) {
                foreach ($name as $item) {
                    $this->_setSessionVar($item, null);
                }
            } else {
                $this->_setSessionVar($name, null);
            }
        } else {
            foreach ($this->_getAvailableSessionVars() as $sessionVar) {
                $this->_setSessionVar($sessionVar, null);
            }
        }

        return $this;
    }

    /**
     * Check if valid session variable name called
     * @param $name
     * @return bool
     * @throws \RuntimeException
     */
    protected function _checkSessionVar($name)
    {
        $checked = true;
        if (is_array($name)) {
            foreach ($name as $k => $v) {
                if (is_numeric($k)) {
                    $item = $v;
                } else {
                    $item = $k;
                }
                if (!in_array($item, $this->_getAvailableSessionVars())) {
                    $checked = false;
                }
            }
        } else {
            if (!in_array($name, $this->_getAvailableSessionVars())) {
                $checked = false;
            }
        }
        if (!$checked) {
            throw new \RuntimeException('Incorrect session variable called', 500);
        }

        return $checked;
    }

    /**
     * Get all available session variables as array list
     * @return array
     */
    protected function _getAvailableSessionVars()
    {
        $reflection = new \ReflectionClass($this);
        $sessionVars = array();

        foreach ($reflection->getConstants() as $k => $v) {
            if (substr($k, 0, 5) === 'SVAR_') $sessionVars[$k] = $v;
        }

        return $sessionVars;
    }

    /**
     * Set flash message
     * @param $type
     * @param $message
     * @return DefaultController
     */
    protected function _setFlash( $type, $message )
    {
        if (!in_array($type, array(self::FLASH_SUCCESS, self::FLASH_ERROR))) {
            $type = self::FLASH_ERROR;
        }
        $this->get('session')->setFlash('artseld_openinviter.notification.' . $type, $message);

        return $this;
    }

    /**
     * Translate message
     * @param $message
     * @return mixed
     */
    protected function _trans( $message, $params = array() )
    {
        return $this->get('translator')->trans($message, $params);
    }

}