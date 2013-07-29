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
    	$url = "https://api.login.yahoo.com/oauth/v2/get_request_token?";
    	$oauth_consumer_key = rawurlencode('dj0yJmk9czE4SDBUTmk0em5kJmQ9WVdrOVZIcGFOR00zTXpnbWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD1hMA--');
    	$oauth_secret_key = 'fa414608a6389da9e93e2e14a9ba21d03510a659';
    	
    	
		$oauthcallback = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_yahoo')."LST";
    	$oauth_callback = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_yahoo')."LSTC";
    	//$oauth_callback = str_replace( "&amp;", "&", urldecode(trim($oauth_callback)) );
    	$u_agent = $_SERVER['HTTP_USER_AGENT'];
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

	    			/*
	    			//$querynum = 1 (Show my profile)
    				//$querynum = 2 (Find my friends)
    				//$querynum = 3 (Find my contacts)
	    			$querynum = 3;
	    			$callyql = $yahooapi->call_yql($oauth_consumer_key, $oauth_secret_key, $querynum, rawurldecode($_SESSION['oauth_accesstoken']), rawurldecode($_SESSION['oauth_accesstoken_secret']), false, true, $oauth_callback);
	    			print_r($callyql);
	    			die();
					*/
	    			
	    			//$callcontacts =  $yahooapi->callcontact($oauth_consumer_key, $oauth_secret_key, $_SESSION['xoauth_yahoo_guid'], $_SESSION['oauth_accesstoken'], $_SESSION['oauth_accesstoken_secret'], false, true);
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
    
    			//die();
    			/*
    			//$querynum = 1 (Show my profile)
    			//$querynum = 2 (Find my friends)
    			//$querynum = 3 (Find my contacts)
    			$querynum = 3;    
    			$callyql = $yahooapi->call_yql($oauth_consumer_key, $oauth_secret_key, $querynum, $body_parsed2['oauth_accesstoken'], $body_parsed2['oauth_accesstoken_secret'], false, true,$oauth_callback);
    			print_r($callyql);
    			die();
    			*/
    
    
    
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
	    			//'oauth_callback_confirmed' => $body_parsed['oauth_callback_confirmed'],
	    			//'oauth_callback' => $oauthcallback,
	    			);
	    
	    			// Authentication request
	    			$url2 = 'https://api.login.yahoo.com/oauth/v2/request_auth?' . http_build_query($params);
	    			//echo $url2;
	    			//echo "<br/><br/>";
	    			//die();
	    
	    			// Redirect user to authenticate
	    			header("Location: $url2");
	    			die();
	    
	    			//$url = 'https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token='.$body_parsed['oauth_token'];
	    			$url = $this->rfc3986_decode($body_parsed['xoauth_request_auth_url']);  //same as above.
	    			//echo $url;
	    			header("Location: $url");
	    			die();
	    
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
    	
    	$CLIENT_ID = '00000000480FD1C6';
    	$CLIENT_SECRET = '5hwwDBF8OHU68RHxsE-ehvkUorbu9hRa';
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
		// ******************************************** //
    		/*
    		$url = "https://login.live.com/oauth20_token.srf?client_id=".$CLIENT_ID."&redirect_uri=".$REDIRECT_URL."&client_secret=".$CLIENT_SECRET."&code=".$_GET['code']."&grant_type=authorization_code";
    		//$url = str_replace( "&amp;", "&", urldecode(trim($url)) );
    		$ch = curl_init($url);
    		curl_setopt($ch, CURLOPT_POST, 1);
    		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www.form-urlencoded'));
    		curl_setopt( $ch, CURLOPT_USERAGENT, $u_agent );
    		curl_setopt($ch, CURLOPT_HEADER, 0);
    		curl_setopt($ch, CURLOPT_VERBOSE,0);
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, TRUE);
    		$output = curl_exec($ch);
    
    		echo $curl_errno = curl_errno($ch);
    		echo $curl_error = curl_error($ch);
    		curl_close($ch);
    		print_r($output);
    		*/
    		die();
    }
    		

    		
    		/*
    		$client_id='00000000480FD1C6';
    		$clientsecret = '5hwwDBF8OHU68RHxsE-ehvkUorbu9hRa';
    		
    		$scope='wl.singin%20wl.basic%20wl,emails';
    		$response_type='token';
    		
    		$redirect_uri=$request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live', array('lcb'=>'LST'));
    		//$redirect_uri='https://login.live.com/oauth20_desktop.srf';
    		$fields_string = "client_id=".$client_id."&scope=".$scope."&response_type=".$response_type."&redirect_uri=".$redirect_uri;
    		echo $redirect_uri."<br/><br/>";
    		echo $fields_string."<br/><br/>";
 
    		$ch = curl_init();
    		//curl_setopt($ch, CURLOPT_URL, 'https://login.live.com/oauth20_authorize.srf?' .$fields_string );
    		curl_setopt($ch, CURLOPT_URL, 'https://login.live.com/oauth20_authorize.srf');
    		//curl_setopt($ch, CURLOPT_POST, 1);
    		//curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: text/html', 'Content-Length: '. strlen($xml)));
    		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www.form-urlencoded'));
    		
    		curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
    		$postrespose = curl_exec($ch);
    		//curl_close($ch);
    		
    		echo $curl_errno = curl_errno($ch);
    		echo $curl_error = curl_error($ch);
    		curl_close($ch);
    		
    		print_r($postrespose);
    		echo "<br/><br/>LIVE1";
    		*/
    		
    		$CLIENT_ID = '00000000480FD1C6';
    		$clientsecret = '5hwwDBF8OHU68RHxsE-ehvkUorbu9hRa';
    		$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";
    		//print_r($REDIRECT_URL);
    		//die();
    		//$url = "https://oauth.live.com/authorize?client_id=$CLIENT_ID&scope=wl.signin&response_type=code&redirect_uri=$REDIRECT_URL";
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
    		
    		
//echo "hope";
    		
    		/*
    		$postFields = array(
    				'client_id' => $CLIENT_ID,
    				'client_secret' => $clientsecret,
    				'code' => 'token',
    				'redirect_uri' => $REDIRECT_URL,
    				//'grant_type' => 'authorization_code'
    		);
    		$bodyData = http_build_query($postFields);
    		
    		$headers = array(
    				'Content-Type: application/x-www-form-urlencoded'
    		);
    		

    		$ch = curl_init("https://login.live.com/oauth20_authorize.srf");
    		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    		//curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    		curl_setopt($ch, CURLOPT_POST, 1);
    		curl_setopt($ch, CURLOPT_POSTFIELDS, $bodyData);
    		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    		
    		if (!$response = curl_exec($ch)) {
    			throw new \Exception('cURL request failed');
    		} else if (curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200) {
    			throw new \Exception('Live API returned an error response code: '.curl_getinfo($ch, CURLINFO_HTTP_CODE));
    		} else if (!$responseObj = json_decode($response)) {
    			throw new \Exception('Cannot decode API response as JSON; data: '.$response);
    		} else if (!isset($responseObj->access_token)) {
    			throw new \Exception('Live API did not return an access token; error: '.$responseObj->error_description);
    		}
    		
    		print_r($responseObj);
    		*/
    		
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
