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
use Qubeey\ApiBundle\Utility\YahooOAuth\OAuth\Globals;
use Qubeey\ApiBundle\Utility\Linkedinapi;
use Qubeey\ApiBundle\Utility\Liveapi;


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
    	$this->_init();
    	$response = new Response();
    	$request = $this->getRequest();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    		$user = "anon.";
    	}
    	
    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    	//////////////////////////////////////////////////////////////////////////////////////
    	
    	
    	
    	
    	
    	
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
    	
    	$response = new Response();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    			$user = "anon.";
    	}
    	
    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    	//////////////////////////////////////////////////////////////////////////////////////
    	$mt = microtime();
    	$rand = mt_rand();
    	
    	$oauth_consumer_key = rawurlencode($this->container->getParameter('YAHOO_API_KEY'));
    	$oauth_secret_key = $this->container->getParameter('YAHOO_API_SECRET');
    	 	
		$oauthcallback = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_yahoo')."LST";
		$oauth_callback = '';
    	$yahooapi = new Globals();
    	//print_r($yahooapi);    	
    	//die();
    	//////////////////////////////////////////////////////////////////////////////
    	
    	if(isset($ycb) && $ycb == 'LST'){
    		
    		$getaccesstoken = $yahooapi->get_access_token($oauth_consumer_key, $oauth_secret_key, $_SESSION['oauth_requesttoken'], $_SESSION['oauth_requesttoken_secret'], $_GET['oauth_verifier'], false, true, true);
    		
    		if (! empty($getaccesstoken)) {
	    		list($info2, $headers2, $body2, $body_parsed2) = $getaccesstoken;

	    		if ($info2['http_code'] == 200 && !empty($body2)) {
	    			
	    			$session->set('oauth_accesstoken', $body_parsed2['oauth_token']);	    			
	    			$session->set('oauth_accesstoken_secret', $body_parsed2['oauth_token_secret']);
	    			$session->set('oauth_session_handle', $body_parsed2['oauth_session_handle']);
	    			$session->set('xoauth_yahoo_guid', $body_parsed2['xoauth_yahoo_guid']);
	    			
	    			//print_r($session);	    			    
	    			//die();
	    			
	    			/*
	    			//$querynum = 1 (Show my profile)
    				//$querynum = 2 (Find my friends)
    				//$querynum = 3 (Find my contacts)
	    			$querynum = 3;
	    			$callyql = $yahooapi->call_yql($oauth_consumer_key, $oauth_secret_key, $querynum, rawurldecode($session->get('oauth_accesstoken')), rawurldecode($session->get('oauth_accesstoken_secret')), false, true, $oauth_callback);
	    			print_r($callyql);
	    			die();
					*/
	    			
	    			$callcontacts =  $yahooapi->callcontact($oauth_consumer_key, $oauth_secret_key, $session->get('xoauth_yahoo_guid'), rawurldecode($body_parsed2['oauth_token']), rawurldecode($body_parsed2['oauth_token_secret']), false, true);
	    			//print_r($callcontacts); die();
	    			list($info3, $headers3, $body3) = $callcontacts;
	    			$callcontact = json_decode($body3, true);
	    			//print_r($callcontact);echo "<br/><br/><br/>";
	    			
	    			$contacts=array();
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
	    							if($val3['type'] == 'email'){
	    								
	    								//echo $val3['value']."<br>";
	    								$contacts[trim($val3['value'])] = $val3['value'];
	    								
	    								foreach($val3 as $key4=>$val4){
	    									//echo $key4." ".$val4."<br/>";
	    									//$contacts[trim($val4)] = $val4;
	    								}	    								
	    							}else {
	    								continue;
	    							}

	    						}
	    					}
	    				}
	    				echo "<br/>";
	    			}
	    			
	    			//$callcontact = json_decode($callcontacts, true);
	    			//print_r($_SESSION);    
	    			//print_r($contacts);
	    			//die();
	    			
	    			
	    			$this->_setSessionVar(array(
	    					self::SVAR_STEP     => self::STEP_INVITE,
	    					self::SVAR_SESSID   => mt_rand(), //'33765123', //$this->openinviter->plugin->getSessionID(),
	    					self::SVAR_PROVIDER => 'yahoo', //$values['provider'],
	    					self::SVAR_EMAIL    => '', //$values['email'],
	    					self::SVAR_CONTACTS => $contacts,
	    			));
	    			
	    			
	    			return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
	    			
	    			
	    			die();	    			
 			
	    	  }    
    	  }
    
    }
    
    //////////////////////////////////////////////////////////////////////////////

    $getrequesttoken = $yahooapi->get_request_token($oauth_consumer_key, $oauth_secret_key, $oauthcallback, false, true, true);
    
    //print_r($getrequesttoken);  //die();
    
    
    if (! empty($getrequesttoken)) {
    	list($info, $headers, $body, $body_parsed) = $getrequesttoken;
    	
	    if ($info['http_code'] == 200 && !empty($body)) {
	    			$_SESSION['oauth_requesttoken'] = $body_parsed['oauth_token'];
	    			$_SESSION['oauth_requesttoken_secret'] = $body_parsed['oauth_token_secret'];
	    
	    			//echo $body_parsed['oauth_token']; //die();
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
    
    	$response = new Response();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    		$user = "anon.";
    	}
    	
    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);

    	$liveapi = new Liveapi();
    	//////////////////////////////////////////////////////////////////////////////////////

    	$CLIENT_ID = $this->container->getParameter('LIVE_API_KEY');
    	$CLIENT_SECRET = $this->container->getParameter('LIVE_API_SECRET');
    	$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";
    	
    	$scope='wl.singin,wl.basic,wl.emails,wl.contacts_emails';
    	//$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";
    	$u_agent = $_SERVER['HTTP_USER_AGENT'];
    	    	
    	
        	if(isset($lcb) && $lcb == 'LST'){
    		$REDIRECT_URL = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_live')."LST";

//////////////////////////////////////////////////////////////////////////////
			if($_GET['code']){
				
				$getequestutorizationcode = $liveapi->getRequestAutorizationCode($CLIENT_ID, $CLIENT_SECRET, $REDIRECT_URL,$_GET['code']);

				//$url = 'https://apis.live.net/v5.0/me/contacts?access_token='.$reqst['access_token'];
				$url = 'https://apis.live.net/v5.0/me/contacts?access_token='.$getequestutorizationcode['access_token'];
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
						self::SVAR_SESSID   => mt_rand(), //'33765123', //$this->openinviter->plugin->getSessionID(),
						self::SVAR_PROVIDER => 'hotmail', //$values['provider'],
						self::SVAR_EMAIL    => '', //$values['email'],
						self::SVAR_CONTACTS => $contacts,
				));
				
				
				return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
				
				
				die();			
			}

    		
///////////////////////////////////////////////////////////////////////////// 

    }
    		
    
    		$code = $liveapi->getRequestCode($CLIENT_ID, $CLIENT_SECRET, $REDIRECT_URL);
    
    		print_r($code);
    		// echo ($CLIENT_ID."<br/>". $CLIENT_SECRET."<br/>". $REDIRECT_URL); 
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
    	
    	$response = new Response();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    		$user = "anon.";
    	}    	

    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);

    	$linkedinapi = new Linkedinapi();
    	
    	//////////////////////////////////////////////////////////////////////////////////////
    	//http://developer.linkedin.com/forum/post-httpapilinkedincomv1peoplemailbox-error
    	//limit to 10 per day ?????? https://developer.linkedin.com/documents/throttle-limits
    
    	$response = new Response();

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
    		if ($_SESSION['link_state'] == $_GET['state']) {
    			// Get token so you can make API calls
    			//echo "access token"; die();
    			$linkedinapi->getAccessToken($API_KEY, $API_SECRET, $url);
    		} else {
    			// CSRF attack? Or did you mix up your states?
    			exit;
    		}
    	} else {
    		if ((empty($_SESSION['link_expires_at'])) || (time() > $_SESSION['link_expires_at'])) {
    			// Token has expired, clear the state
    			//$_SESSION = array();
    		}
    		if (empty($_SESSION['link_access_token'])) {
    			// Start authorization process
    			// echo "Auth"; die();
    			$linkedinapi->getAuthorizationCode($API_KEY, $SCOPE, $url);
    		}
    	}
    
    	// Congratulations! You have a valid token. Now fetch your profile
    	//http://api.linkedin.com/v1/people/~/connections
    	// $user = $this->fetch('GET', '/v1/people/~:(firstName,lastName)');
    	$user2 = $linkedinapi->fetch('GET', '/v1/people/~:(id,firstName,lastName)');
		$session->set('link_name', $user2->{'firstName'}. " ". $user2->{'lastName'});  //echo $session->get('link_name'); die();
    	
    	// $user = $this->fetch('GET', '/v1/people/~/connections:(first-name,last-name,main-address)');
    	$user = $linkedinapi->fetch('GET', '/v1/people/~/connections');
		//print_r($user); die();
    	if($user->{'_total'} > 0){    
    		$contacts=array();
    		foreach($user->{'values'} as $key=>$val){
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

    
    //****************************************************************************************//
    
    /**
     * Twitter action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function twitterAction(Request $request, $twt=false)
    {
    	$this->_init();

    	$response = new Response();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    		$user = "anon.";
    	}    

    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);    	
    	//////////////////////////////////////////////////////////////////////////////////////
    
    	if(isset($twt) && $twt == 'LST')
    	{    
    		//////////////////////////////////////////////////////////////////////////////////////
    		$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'), $session->get('oauth_token'), $session->get('oauth_token_secret'));
    		$access_token = $connection->getAccessToken($_REQUEST['oauth_verifier']);
    		
    		/* Save the access tokens. Normally these would be saved in a database for future use.  DO IT IN SYMFONY */
    		$_SESSION['access_token'] = $access_token;
    		
    		/* Remove no longer needed request tokens */
    		//unset($_SESSION['oauth_token']);
    		//unset($_SESSION['oauth_token_secret']);
    
    		/* If HTTP response is 200 continue otherwise send to connect page to retry */
    		if (200 == $connection->http_code) {
    			/* The user has been verified and the access tokens can be saved for future use.  DO IT IN SYMFONY*/
    			$session->set('status', '');
    			$session->set('status', 'verified');
    			//header('Location: ./index.php');
    			/* Create a TwitterOauth object with consumer/user tokens. */
    			$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'), $access_token['oauth_token'], $access_token['oauth_token_secret']);
    
    			/* If method is set change API call made. Test is called by default. */
    			$content = $connection->get('account/verify_credentials');
    			$_SESSION['twt_screenname'] = $content->{'screen_name'};
    			$_SESSION['twt_name'] = $content->{'name'};

    			$connection->host = 'https://api.twitter.com/1.1/'; // By default library uses API version 1.
    			
    			//GET Followers
    			$friendsJson = $connection->get('/followers/list.json?cursor=-1&screen_name='.$content->{'screen_name'}.'&skip_status=true&include_user_entities=false');
    			//print_r($friendsJson); die();
    			//GET Friends
    			//$friendsJson = $connection->get('/friends/list.json?cursor=-1&screen_name='.$content->{'screen_name'}.'&skip_status=true&include_user_entities=false');
    			    
    			$contacts=array();
    
    			$k = 1;
    			for($i=0; $i < count($friendsJson->{'users'}); $i++){    
    				$img1 = "<img src=".$friendsJson->{'users'}[$i]->{'profile_image_url'}.">";
    					// $contacts[$friendsJson->{'users'}[$i]->{'id'}] = $img1 ."<br/>". $friendsJson->{'users'}[$i]->{'screen_name'}; //."\r\n";
    					$contacts[trim($friendsJson->{'users'}[$i]->{'id'})] = trim($friendsJson->{'users'}[$i]->{'screen_name'});
    			}
	    		//print_r($contacts); die();
	    		$this->_setSessionVar(array(
	    		self::SVAR_STEP     => self::STEP_INVITE,
	    		self::SVAR_SESSID   => $content->{'id'}, //$this->openinviter->plugin->getSessionID(),
	    		self::SVAR_PROVIDER => 'twitter', //$values['provider'],
	    		self::SVAR_EMAIL    => '', //$values['email'],
	    		self::SVAR_CONTACTS => $contacts,
	    		));
	    
    			//die();
    			return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
    		}
    	}
    
    	
    	//// *************************************************************************************************************************** ////
    		$request = $this->getRequest();
    		$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'));
    		$url = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath().$this->generateUrl('artseld_openinviter_twtp', array('twt'=>'LST'));
    		$request_token = $connection->getRequestToken($url);

    		/* Save temporary credentials to session. DO IT IN SYMFONY */
    		$session->set('oauth_token', '');
    		$session->set('oauth_token_secret', '');
    		
    		$session->set('oauth_token', $request_token['oauth_token']);
    		$session->set('oauth_token_secret', $request_token['oauth_token_secret']);    		
    		
    		/* If last connection failed don't display authorization link. */
    		switch ($connection->http_code) {
    		case 200:
    		/* Build authorize URL and redirect user to Twitter. */
    		$url = $connection->getAuthorizeURL($session->get('oauth_token'));
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
    
        $response = new Response();
        $request = $this->getRequest();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    		$user = "anon.";
    	}
    	
    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
    
    	//////////////////////////////////////////////////////////////////////////////////////
     
    	
    
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
	    		// curl_setopt($ch, CURLOPT_URL, "https://graph.facebook.com/".$user."?fields=email,friends.fields%28username,email,name%29&access_token=".$access_token);
	    		//Above is the returned access token for the authirized user.
	    		$apptoken = $this->container->getParameter('FACEBOOK_APP_ID')."|".$this->container->getParameter('FACEBOOK_SECRET');
	  
	    		//Below is the app's accesstoken 
	    		curl_setopt($ch, CURLOPT_URL, "https://graph.facebook.com/".$fbuser."?fields=email,friends.fields%28username,email,name%29&access_token=".$apptoken);
	    
	    
	    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	    		$output = curl_exec($ch);
	    		curl_close($ch);
	    		$emailscont = json_decode($output,true);
	    		// echo count($emailscont['friends']['data']);
	    
	    		//if (in_array("friends", $emailscont['friends']['data'])) {
	    			print_r($emailscont); die();
	    		//}
	    		//print_r($emailscont);
	    		$contacts=array();
	    		//print_r($emailscont['friends']['data']);
	    		if(isset($emailscont['friends']['data'])){    			
		    		foreach($emailscont['friends']['data'] as $indx=>$arrcont){	    
			    		if(array_key_exists('email', $arrcont)){
			    			//echo $arrcont['name']."--".$arrcont['username']."--".$arrcont['email']."--".$arrcont['id']."<br/>";
			    			$contacts[$arrcont['email']]=$arrcont['name'];
			    		}else{
			    			$contacts[$arrcont['username']."@facebook.com"]=$arrcont['name'];
			    		}
		    		}
		    
		    		//print_r($contacts); die();
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
	    		header("Location: $loginUrl");
	    		
	    		
	    		//insert a twig view  and pass the array('fbl'=>$loginUrl) login url   
	    		//replacing the code below to a cutom look 	
	    		return $this->get('templating')->renderResponse(
	    				'ArtseldOpeninviterBundle:Default:facebook.html.twig', array(
	    						'fbl' => $loginUrl,
	    				));
	    		die();
    		}
    
		    //$currentuser = $facebook->api('/me/friends.fields(email)');
		    //echo "currentuser"; print_r($currentuser);
		     
		    $this->_setSessionVar(array(
		    		self::SVAR_STEP     => self::STEP_INVITE,
		    		self::SVAR_SESSID   => mt_rand(), //'765123', //$this->openinviter->plugin->getSessionID(),
		    		self::SVAR_PROVIDER => 'facebook', //$values['provider'],
		    		self::SVAR_EMAIL    => '', //$values['email'],
		    		self::SVAR_CONTACTS => $contacts,
		    ));
		    
		    if ($fbuser) {
		    	// *****************************************//
		    	//MANNUAL LOGOUT
		    	//$facebook -> destroySession();
		    	//setcookie("fbsr_YOUR_APP_ID",'',time()-10);
		    	// *****************************************//
		    }
		    
		    return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));    
    		die();
    
    }
    
//====================================================  Vimeo Action ==================================================//
    /**
     * Vimeo action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function vimeoAction(Request $request, $vmo=false)
    {
        $this->_init();
   
        $response = new Response();
    	$session = $request->getSession();
    	$em = $this->getDoctrine()->getEntityManager();
    	
    	$seswithtoken = $session->get('seswithtoken');
    	$sessource = $session->get('sessource');
    	
    	if($seswithtoken != '' && $sessource != ''){
    		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
    		$user = $clientSession->getMember();  //die();
    	}else {
    		$user = "anon.";
    	}    	

    	$id = $user->getMemberQid();  //var_dump($id); die;
    	//print_r($user);
             
        //////////////////////////////////////////////////////////////////////////////////////
       
        if(isset($vmo) && $vmo == 'VMO'){
        		echo "START 0</br/>";  die();
        }
        
        $request = $this->getRequest();
        $redirect_url =  $request->getScheme().'://'.$request->getHttpHost().$request->getBasePath().$this->generateUrl('artseld_openinviter_login').'invite';             ///echo "RedirectURL: " .$redirect_url ."<br />";
        $url = $request->getScheme().'://'.$request->getHttpHost().$request->getBasePath().$this->generateUrl('artseld_openinviter_vimeovm', array('vmo'=>'VMO'));         ///echo "URL: " . $url ."<br />";
 
	    $_consumer_key    = $this->container->getParameter('VIMEO_CONSUMER_KEY');     // Client ID (Also known as Consumer Key or API Key)
    	$_consumer_secret = $this->container->getParameter('VIMEO_CONSUMER_SECRET');  // Client Secret (Also known as Consumer Secret or API Secret)
    	$_token           = $this->container->getParameter('VIMEO_ACCESS_TOKEN');     // Access token
    	$_token_secret    = $this->container->getParameter('VIMEO_TOKEN_SECRET');     // Access token secret     // guard this!
                 
        $API_REST_URL          = 'http://vimeo.com/api/rest/v2';
        $API_AUTH_URL          = 'http://vimeo.com/oauth/authorize';      // Authorize URL
        $API_ACCESS_TOKEN_URL  = 'http://vimeo.com/oauth/access_token';   // Access Token URL
        $API_REQUEST_TOKEN_URL = 'http://vimeo.com/oauth/request_token';  // Request Token URL

        $path = $this->get('kernel')->getRootDir(). '/cache/dev/inviter' . $this->getRequest()->getBasePath();       
        $this->_cache_dir = $path;     

        //====================================================== simple api interface ====================================================================//
        $params = array(1); 
       
        // Create the object and enable caching
        // 1. Get a request token
        $vimeo = new \Qubeey\ApiBundle\Utility\Vimeo($_consumer_key, $_consumer_secret, $_token, $_token_secret);
        $vimeo->enableCache(\Qubeey\ApiBundle\Utility\Vimeo::CACHE_FILE, $path, 300);
        $token = $vimeo->getRequestToken();  echo "<br /><br />";    //print_r($token); 
        //Store in session, or wherever you like-- these are temporary, so doesn't matter.
        $_SESSION['oauth_request_token'] = $token['oauth_token'];               echo "<br />OAUTH TOKEN: " . $token['oauth_token'];
        $_SESSION['oauth_request_token_secret'] = $token['oauth_token_secret']; echo "<br />OAUTH SECRET TOKEN: " . $token['oauth_token_secret'];
        
        // 2. Request authorization
        $authorize_link = $vimeo->getAuthorizeUrl($_SESSION['oauth_request_token'], 'write');          echo "<br /><b>AutorizeURL:</b> " .$authorize_link;
        $callback_url = $vimeo->auth('read', 'http://nginx1.qubedev.com:7031/app_dev.php/oi/invite');  echo "<br /><b>CallbackURL:</b> " .$callback_url;
       
        die(); 
        //================================================================================================================================================//
        /*
        // Create the object and enable caching
        $vimeo = new \Qubeey\ApiBundle\Utility\Vimeo($_consumer_key, $_consumer_secret, $_token, $_token_secret);
        $vimeo->enableCache(\Qubeey\ApiBundle\Utility\Vimeo::CACHE_FILE, $path, 300);
        $vimeo->setToken($_token, $_token_secret);
        $token = $vimeo->getRequestToken();  echo "<br /><br />";  print_r($token);
 
         
        // Store it in the session
        $_SESSION['oauth_request_token'] = $token['oauth_token'];
        $_SESSION['oauth_request_token_secret'] = $token['oauth_token_secret'];
        $_SESSION['vimeo_state'] = 'start';

        switch ($_SESSION['vimeo_state']) {
            default:
       
            // Get a new request token
            // $token = $vimeo->getRequestToken();
       
            // Store it in the session
            $_SESSION['oauth_request_token'] = $token['oauth_token'];
            $_SESSION['oauth_request_token_secret'] = $token['oauth_token_secret'];
            $_SESSION['vimeo_state'] = 'start';
       
            // Build authorize link
            $authorize_link = $vimeo->getAuthorizeUrl($token['oauth_token'], 'read');  echo "<br />AutorizeURL: " .$authorize_link;
       
            break;
       
            case 'returned':
                echo "<br />Vimeo State1: " . $_SESSION['vimeo_state'];
                // Store it
                if ($_SESSION['oauth_access_token'] === NULL && $_SESSION['oauth_access_token_secret'] === NULL) {
                    // Exchange for an access token
                    $vimeo->setToken($_SESSION['oauth_request_token'], $_SESSION['oauth_request_token_secret']);
                    $token = $vimeo->getAccessToken($_REQUEST['oauth_verifier']);
       
                    // Store
                    $_SESSION['oauth_access_token'] = $token['oauth_token'];   echo "SESSION access token: " . $_SESSION['oauth_access_token'];
                    $_SESSION['oauth_access_token_secret'] = $token['oauth_token_secret'];
                    $_SESSION['vimeo_state'] = 'done';
       
                    // Set the token
                    $vimeo->setToken($_SESSION['oauth_access_token'], $_SESSION['oauth_access_token_secret']); 
                    echo "Tokens: " . $vimeo->setToken($_SESSION['oauth_access_token'], $_SESSION['oauth_access_token_secret']);
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
       */
       
        // Coming back
        //if ($token['oauth_token'] != NULL && $_SESSION['vimeo_state'] === 'start') {
        //    $_SESSION['vimeo_state'] = $state = 'returned';
        //}
        //echo "<br />Vimeo State: " . $_SESSION['vimeo_state'];
               
        // If we have an access token, set it
        /*if (isset($_SESSION['oauth_access_token']) && ($_SESSION['oauth_access_token'] != null)) {
            $vimeo->setToken($_SESSION['oauth_access_token'], $_SESSION['oauth_access_token_secret']);  echo "IF access token: " . $_SESSION['oauth_access_token'];
        }       
        else{
            echo "ELSE access token: " . $_SESSION['oauth_access_token'];
        }
        die();
        /* Save the access tokens. Normally these would be saved in a database for future use.  DO IT IN SYMFONY */
        // Set up variables       
        /*$token = $vimeo->getRequestToken();
        $vimeo->getAuthorizeUrl($_consumer_key);
        $vimeo->auth('read', 'http://nginx1.qubedev.com:7031/app_dev.php/oi/invite');
        //$state = $_SESSION['vimeo_state'];                   //echo "<br />Vimeo State: " . $_SESSION['vimeo_state'];
        //$request_token = $_SESSION['oauth_request_token'];     //echo "<br />Vimeo oauth_request_token: " . $_SESSION['oauth_request_token'];
        //$access_token = $_SESSION['oauth_access_token'];       //echo "<br />Vimeo oauth_access_token: " . $_SESSION['oauth_access_token'];
       
        echo "<br /><br />Vimeo State: " .  $_SESSION['vimeo_state'];
        print_r($vimeo); die(); */
      
    /************************************************************************************************************************************************/

    //echo $output;
    //die();
    // return $this->get('templating')->renderResponse('ArtseldOpeninviterBundle:Default:done.html.twig', array('output'=> $output));
     return new RedirectResponse($this->generateUrl('artseld_openinviter_invite'));
    }
   
   
 
    //==================================================== End Vimeo Action =============================================//  

    
    
//***************************************************************************************//
    /**
     * Login action
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function loginAction(Request $request, $withtoken = null)
    {
        $this->_init();
        
        $request = $this->getRequest();
        $session = $request->getSession();  
        $source =  $request->query->get('source');
        $em = $this->getDoctrine()->getEntityManager();
        
        if(isset($withtoken) && $source != ''){       	
       		//echo $withtoken."<br/> ".$request->query->get('source');
        	$session->set('sessource', $source);
        	$session->set('seswithtoken', $withtoken);
       	 	$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($withtoken);
       	 	
       	 	/*
       	 	echo "<br/><br/>";
       	 	echo $clientSession->getClientsessionQguid();
       		 echo "<br/><br/>";       	 
       	 	//print_r($clientSession->getMember());
       		 echo $clientSession->getMember()->getMemberQid();
       	 	 echo "<br/><br/>";     	
       		 echo $clientSession->getMember()->getEmail();
       		 echo "<br/><br/>";
       		// print_r($clientSession);
       		 //$id = $clientSession->getMember()->getMemberQid();
       		 */
       	 	
       		 $user = $clientSession->getMember();
       	 //die();
        }else{
        	
        	$seswithtoken = $session->get('seswithtoken');
        	$sessource = $session->get('sessource');
        	
        	if(isset($seswithtoken) && isset($sessource)){
        		
        		$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
        		$user = $clientSession->getMember();
        	}else {
        	$user = "anon.";
        	}
        }
        
        
        if ($user != "anon.") {
         
         $id = $user->getMemberQid();  //var_dump($id); die();         
         
	        
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
	                    $internal ? $internal : 'Incorrect login. Please check E-mail and password and try again.'
	                    )));
	                } elseif (false === $contacts = $this->openinviter->getMyContacts()) {
	                    $form->addError(new \Symfony\Component\Form\FormError(
	                        $this->_trans('Cannot get contacts!')
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
	            	'with_token' =>  $session->get('seswithtoken')
	            ));
        
    	}else {
    		
    		return $this->redirect($this->generateUrl('_login'));
    	}
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
        //$user = $this->get('security.context')->getToken()->getUser();
        $seswithtoken = $session->get('seswithtoken');
        $sessource = $session->get('sessource');
        
        if($seswithtoken != '' && $sessource != ''){
        	$clientSession = $em->getRepository('QubeeyApiBundle:Clientsession')->findOneByToken($seswithtoken);
        	$user = $clientSession->getMember();  //die();
        }else {
        	$user = "anon.";
        }
        
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
                            $this->_trans('Sender E-mail is not set!')
                        ));
                    }
                    
                    $sessid = $this->_getSessionVar(self::SVAR_SESSID);
                    //echo "session :". $sessid;
                    if (empty($sessid)) {
                        $form->addError(new \Symfony\Component\Form\FormError(
                            $this->_trans('Session is not active!')
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
                   
                   // print_r($user);
                    $id = $user->getMemberQid();
                    $username = $user->getUsername();
                    
                    $categories = $em->getRepository('QubeeyApiBundle:Category')->findOneByCategoryId($sessource);
                   // print_r( $source = $categories->getName()); die();
                    $source = $categories->getName();
     
                    // ********************************************** //
                   
                    $message = array(
                        'subject'       => $this->_trans('artseld_openinviter.text.message_subject',
                           // array('%link%' => $this->generateUrl('_welcome', array(), true))),
                           array('%link%' => $this->generateUrl('channels_lp', array('custlp'=> ''), true))),
                        'body'          => $this->_trans('artseld_openinviter.text.message_body',
                            array('%username%' => $this->_getSessionVar(self::SVAR_EMAIL),
                                //'%link%' => $this->generateUrl('_welcome', array(), true))) . "\n\r" . $values['message'],
                            	'%link%' => $this->generateUrl('channels_lp', array('custlp'=> ''), true))) . "\n\r",
                        'attachment'    => '',
                    );

                    // ********************************************** //

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
                                $this->_trans('You did not choose any contacts for inviting!')
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
                   // echo $this->_getSessionVar(self::SVAR_PROVIDER); die();
                   
                    switch ($this->_getSessionVar(self::SVAR_PROVIDER))
                    {
                    	case "yahoo":
                    		$sendMessage = -1;
                    		break;
                    	case "hotmail":
                    		$sendMessage = -1;
                    		break;
                    	case "facebook":
                    		$sendMessage = -1;
                    		break;
                    	case "twitter":
                    		$connection = new Api($this->container->getParameter('CONSUMERTWITKEY'), $this->container->getParameter('CONSUMERTWITSECRET'), $_SESSION['access_token']['oauth_token'], $_SESSION['access_token']['oauth_token_secret']);
                    		$content = $connection->get('account/verify_credentials');
                    		$connection->host = 'https://api.twitter.com/1.1/'; // By default library uses API version 1.
                    		
                    		foreach($selectedContacts as $emailid=>$tusername){                    			
                    			// Using the senders name can cause problem do to message length restrictions (Not recommended)
                    			//echo "Screen Name: ".$_SESSION['twt_screenname']." Name: ". $_SESSION['twt_name'];
                    			
                    			//Message must be less than 140 characters
                    			//$mess = "Hey there!\n\rConnect with me in I2G Touch – a fun way to manage all your social media you already use in one super-easy-to-use place.\n\rIt’s one tool to rule them all!\n\r\n\rJoin me here (replicating website)";
                    			//$mess = "Hey there! Connect with me in I2G Touch – a fun way to manage all your social media you already use in one super-easy-to-use place. It’s one tool to rule them all! Join me here (replicating website)";
                    			//echo "<br/>".strlen($mess);
                    			
                    			//$mess = "Join me at http://qubeey.com everything you care about can find you. Social, Buisness, Personal, Fun Qubeey connects it all.";
                    			$method = 'direct_messages/new';
                    			$parameters = array('user_id' => $emailid, 'text' => $mess);
                    			print_r($parameters); echo "<br/><br/>"; echo "Senders Screen Name: ".$_SESSION['twt_screenname']." Name: ". $_SESSION['twt_name'];
                    			
                    			//$postfriends = $connection->post($method, $parameters);
                    		} die();
                    		$this->_setFlash(self::FLASH_SUCCESS, 'Qubeey sent your Twitter invitaions successfully.');
                    		break;
                    	case "linkedin":
                    		$linkedinapi = new Linkedinapi();
                    		$user = $linkedinapi->fetch('GET', '/v1/people/~/connections');
                    		//print_r($user); die();
                    		foreach($selectedContacts as $emailid=>$lusername){
                    			//******************************** SEND LINKEDIN MESSAGE ****************************************//
                    			$subject= "Hello come join ".$session->get('link_name')." at qubeey.com!";
                    			$body= "Hello ".$lusername."!  Join me at http://www.qubeey.com/".$source;
                    			echo 'Subject: '.$subject.' <br/> Body: '.$body.'<br/><br/>';
                    			//$postrespose =  $linkedin->sendMessageById($emailid, $ccUser=false, $subject, $body);
                    
                    			/////////////////////////////////////////////////////////////////////////////////////////////////
                    		} die();
                    		$this->_setFlash(self::FLASH_SUCCESS, 'Qubeey sent your Linkedin invitaions successfully.');
                    		break;
                    	default:
                    		echo "You must collect your contacts to send a message!";
                    }
                    
               		
                  //////////////////////////////////////////////////////////////////////  

                    	if ($sendMessage === -1) {

               // ********************************************** //
                        
//******************************************************************************************************************************//
                        $member = $em->getRepository('QubeeyApiBundle:Member')->findOneBy(array('email' => $username));
                       // print_r($member->getMemberQid());
                        //die();
                    	if ($member) {


		    					$modelMember = new ModelMember($em, $this->get('doctrine.odm.mongodb.document_manager'), $member);
		    					$restpass = $modelMember->addInvitation('Inviter', $source, json_encode($selectedContacts));
   
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
                        $this->_setFlash(self::FLASH_SUCCESS, 'Qubeey sent your invitaions successfully.');
                    }
                    return new RedirectResponse($this->generateUrl('artseld_openinviter_done'));
                } //echo "cant: ";  die();
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