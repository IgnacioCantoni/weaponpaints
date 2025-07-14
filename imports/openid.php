<?php

if(!function_exists("Path")) {
    return;
}

/**
 * This class provides a simple interface for OpenID 1.1/2.0 authentication.
 * 
 * It requires PHP >= 5.1.2 with cURL or HTTP/HTTPS stream wrappers enabled.
 *
 * @version     v1.3.1 (2016-03-04)
 * @link        https://code.google.com/p/lightopenid/          Project URL
 * @link        https://github.com/iignatov/LightOpenID         GitHub Repo
 * @author      Mewp <mewp151 at gmail dot com>
 * @copyright   Copyright (c) 2013 Mewp
 * @license     http://opensource.org/licenses/mit-license.php  MIT License
 */
class LightOpenID
{
    public $returnUrl
         , $required = array()
         , $optional = array()
         , $verify_peer = null
         , $capath = null
         , $cainfo = null
         , $cnmatch = null
         , $data
         , $oauth = array()
         , $curl_time_out = 30          // in seconds
         , $curl_connect_time_out = 30; // in seconds
    private $identity, $claimed_id;
    protected $server, $version, $trustRoot, $aliases, $identifier_select = false
            , $ax = false, $sreg = false, $setup_url = null, $headers = array()
            , $proxy = null, $user_agent = 'LightOpenID'
            , $xrds_override_pattern = null, $xrds_override_replacement = null;
    static protected $ax_to_sreg = array(
        'namePerson/friendly'     => 'nickname',
        'contact/email'           => 'email',
        'namePerson'              => 'fullname',
        'birthDate'               => 'dob',
        'person/gender'           => 'gender',
        'contact/postalCode/home' => 'postcode',
        'contact/country/home'    => 'country',
        'pref/language'           => 'language',
        'pref/timezone'           => 'timezone',
        );

    function __construct($host, $proxy = null)
    {
        $this->set_realm($host);
        $this->set_proxy($proxy);

        $uri = rtrim(preg_replace('#((?<=\?)|&)openid\.[^&]+#', '', $_SERVER['REQUEST_URI']), '?');
        $this->returnUrl = $this->trustRoot . $uri;

        $this->data = ($_SERVER['REQUEST_METHOD'] === 'POST') ? $_POST : $_GET;

        if(!function_exists('curl_init') && !in_array('https', stream_get_wrappers())) {
            throw new ErrorException('You must have either https wrappers or curl enabled.');
        }
    }
    
    function __isset($name)
    {
        return in_array($name, array('identity', 'trustRoot', 'realm', 'xrdsOverride', 'mode'));
    }

    function __set($name, $value)
    {
        switch ($name) {
        case 'identity':
            if (strlen($value = trim((String) $value))) {
                if (preg_match('#^xri:/*#i', $value, $m)) {
                    $value = substr($value, strlen($m[0]));
                } elseif (!preg_match('/^(?:[=@+\$!\(]|https?:)/i', $value)) {
                    $value = "http://$value";
                }
                if (preg_match('#^https?://[^/]+$#i', $value, $m)) {
                    $value .= '/';
                }
            }
            $this->$name = $this->claimed_id = $value;
            break;
        case 'trustRoot':
        case 'realm':
            $this->trustRoot = trim($value);
            break;
        case 'xrdsOverride':
            if (is_array($value)) {
                list($pattern, $replacement) = $value;
                $this->xrds_override_pattern = $pattern;
                $this->xrds_override_replacement = $replacement;
            } else {
                trigger_error('Invalid value specified for "xrdsOverride".', E_USER_ERROR);
            }
            break;
        }
    }

    function __get($name)
    {
        switch ($name) {
        case 'identity':
            # We return claimed_id instead of identity,
            # because the developer should see the claimed identifier,
            # i.e. what he set as identity, not the op-local identifier (which is what we verify)
            return $this->claimed_id;
        case 'trustRoot':
        case 'realm':
            return $this->trustRoot;
        case 'mode':
            return empty($this->data['openid_mode']) ? null : $this->data['openid_mode'];
        }
    }
    
    function set_proxy($proxy)
    {
        if (!empty($proxy)) {
            // When the proxy is a string - try to parse it.
            if (!is_array($proxy)) {
                $proxy = parse_url($proxy);
            }
            
            // Check if $proxy is valid after the parsing.
            if ($proxy && !empty($proxy['host'])) {
                // Make sure that a valid port number is specified.
                if (array_key_exists('port', $proxy)) {
                    if (!is_int($proxy['port'])) {
                        $proxy['port'] = is_numeric($proxy['port']) ? intval($proxy['port']) : 0;
                    }
                    
                    if ($proxy['port'] <= 0) {
                        throw new ErrorException('The specified proxy port number is invalid.');
                    }
                }
                
                $this->proxy = $proxy;
            }
        }
    }

    /**
     * Checks if the server specified in the url exists.
     *
     * @param $url url to check
     * @return true, if the server exists; false otherwise
     */
    function hostExists($url)
    {
        if (strpos($url, '/') === false) {
            $server = $url;
        } else {
            $server = @parse_url($url, PHP_URL_HOST);
        }

        if (!$server) {
            return false;
        }

        return !!gethostbynamel($server);
    }
    
    protected function set_realm($uri)
    {
        $realm = '';
        
        # Set a protocol, if not specified.
        $realm .= (($offset = strpos($uri, '://')) === false) ? $this->get_realm_protocol() : '';
        
        # Set the offset properly.
        $offset = (($offset !== false) ? $offset + 3 : 0);
        
        # Get only the root, without the path.
        $realm .= (($end = strpos($uri, '/', $offset)) === false) ? $uri : substr($uri, 0, $end);
        
        $this->trustRoot = $realm;
    }
    
    protected function get_realm_protocol()
    {
        if (!empty($_SERVER['HTTPS'])) {
            $use_secure_protocol = ($_SERVER['HTTPS'] != 'off');
        } else if (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            $use_secure_protocol = ($_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https');
        } else if (isset($_SERVER['HTTP__WSSC'])) {
            $use_secure_protocol = ($_SERVER['HTTP__WSSC'] == 'https');
        } else {
                $use_secure_protocol = false;
        }
        
        return $use_secure_protocol ? 'https://' : 'http://';
    }

    
protected function request_curl($url, $update_claimed_id, $params = array(), $method = 'GET') {
    if (!is_array($params)) {
        throw new Exception('Parámetro inválido: se esperaba un array en http_build_query, se recibió ' . gettype($params));
    }

    $params = http_build_query($params, '', '&');
    $curl = curl_init($url . ($method == 'GET' && $params ? '?' . $params : ''));
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_USERAGENT, $this->user_agent);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

    if ($method == 'POST') {
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-type: application/x-www-form-urlencoded'));
    } else {
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Accept: application/xrds+xml, */*'));
    }

    curl_setopt($curl, CURLOPT_TIMEOUT, $this->curl_time_out);
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT , $this->curl_connect_time_out);

    if (!empty($this->proxy)) {
        curl_setopt($curl, CURLOPT_PROXY, $this->proxy['host']);

        if (!empty($this->proxy['port'])) {
            curl_setopt($curl, CURLOPT_PROXYPORT, $this->proxy['port']);
        }

        if (!empty($this->proxy['user'])) {
            curl_setopt($curl, CURLOPT_PROXYUSERPWD, $this->proxy['user'] . ':' . $this->proxy['pass']);
        }
    }

    $response = curl_exec($curl);

    if ($response === false) {
        throw new Exception('cURL error: ' . curl_error($curl));
    }

    curl_close($curl);
    return $response;
}
