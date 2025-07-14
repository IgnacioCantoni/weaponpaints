<?php
class LightOpenID
{
    public $identity;
    public $claimed_id;
    public $returnUrl;
    public $trustRoot;
    public $data = array();
    public $setup_url;
    public $mode;
    public $server;
    public $version;
    public $ax;
    public $sreg;
    public $required = array();
    public $optional = array();
    public $aliases = array();
    public $headers = array();
    public $user_agent = 'LightOpenID PHP Library';
    public $curl_time_out = 30;
    public $curl_connect_time_out = 5;
    public $proxy = array();
    public $verify_peer = true;
    public $capath = null;
    public $cainfo = null;
    public $cnmatch = null;
    public $oauth = array();
    public $identifier_select = false;

    protected static $ax_to_sreg = array(
        'contact/email'    => 'email',
        'namePerson/friendly' => 'nickname',
        'namePerson'       => 'fullname',
        'birthDate'        => 'dob',
        'person/gender'    => 'gender',
        'contact/postalCode/home' => 'postcode',
        'contact/country/home' => 'country',
        'contact/city/home' => 'city',
        'contact/state/home' => 'state',
        'contact/phone/default' => 'phone',
    );

    public function __construct($host = null)
    {
        if (!$host) {
            if (isset($_SERVER['HTTP_HOST'])) {
                $host = $_SERVER['HTTP_HOST'];
            } else {
                throw new Exception('No host specified.');
            }
        }
        $this->returnUrl = 'http://' . $host . $_SERVER['REQUEST_URI'];
        $this->trustRoot = 'http://' . $host;
    }

    public function __get($name)
    {
        return isset($this->data[$name]) ? $this->data[$name] : null;
    }

    public function __set($name, $value)
    {
        $this->data[$name] = $value;
    }

    protected function hostExists($url)
    {
        $url_parts = parse_url($url);
        if (!$url_parts || !isset($url_parts['host'])) {
            return false;
        }
        $host = $url_parts['host'];
        return checkdnsrr($host, 'A') || checkdnsrr($host, 'AAAA');
    }

    protected function request_curl($url, $method = 'GET', $params = array(), $update_claimed_id = false)
    {
        $curl = curl_init($url);

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
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $this->curl_connect_time_out);

        if (!empty($this->proxy)) {
            curl_setopt($curl, CURLOPT_PROXY, $this->proxy['host']);
            if (!empty($this->proxy['port'])) {
                curl_setopt($curl, CURLOPT_PROXYPORT, $this->proxy['port']);
            }
            if (!empty($this->proxy['user'])) {
                curl_setopt($curl, CURLOPT_PROXYUSERPWD, $this->proxy['user'] . ':' . $this->proxy['pass']);
            }
        }

        if ($this->verify_peer !== null) {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $this->verify_peer);
            if ($this->capath) {
                curl_setopt($curl, CURLOPT_CAPATH, $this->capath);
            }
            if ($this->cainfo) {
                curl_setopt($curl, CURLOPT_CAINFO, $this->cainfo);
            }
        }

        if ($method == 'POST') {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
        } elseif ($method == 'HEAD') {
            curl_setopt($curl, CURLOPT_HEADER, true);
            curl_setopt($curl, CURLOPT_NOBODY, true);
        } else {
            curl_setopt($curl, CURLOPT_HEADER, true);
            curl_setopt($curl, CURLOPT_HTTPGET, true);
        }

        $response = curl_exec($curl);

        if ($method == 'HEAD' && curl_getinfo($curl, CURLINFO_HTTP_CODE) == 405) {
            curl_setopt($curl, CURLOPT_HTTPGET, true);
            $response = curl_exec($curl);
            $response = substr($response, 0, strpos($response, "\r\n\r\n"));
        }

        if ($method == 'HEAD' || $method == 'GET') {
            $header_response = $response;
            if ($method == 'GET') {
                $header_response = substr($response, 0, strpos($response, "\r\n\r\n"));
            }
            $headers = array();
            foreach (explode("\n", $header_response) as $header) {
                $pos = strpos($header, ':');
                if ($pos !== false) {
                    $name = strtolower(trim(substr($header, 0, $pos)));
                    $headers[$name] = trim(substr($header, $pos + 1));
                }
            }
            if ($update_claimed_id) {
                $effective_url = curl_getinfo($curl, CURLINFO_EFFECTIVE_URL);
                if (strtok($effective_url, '#') != strtok($url, '#')) {
                    $this->identity = $this->claimed_id = $effective_url;
                }
            }
            if ($method == 'HEAD') {
                curl_close($curl);
                return $headers;
            } else {
                $this->headers = $headers;
            }
        }

        if (curl_errno($curl)) {
            throw new ErrorException(curl_error($curl), curl_errno($curl));
        }

        curl_close($curl);

        return $response;
    }

    protected function parse_header_array($array, $update_claimed_id)
    {
        $headers = array();
        foreach ($array as $header) {
            $pos = strpos($header, ':');
            if ($pos !== false) {
                $name = strtolower(trim(substr($header, 0, $pos)));
                $headers[$name] = trim(substr($header, $pos + 1));
                if ($name == 'location' && $update_claimed_id) {
                    if (strpos($headers[$name], 'http') === 0) {
                        $this->identity = $this->claimed_id = $headers[$name];
                    } elseif ($headers[$name][0] == '/') {
                        $parsed_url = parse_url($this->claimed_id);
                        $this->identity = $this->claimed_id = $parsed_url['scheme'] . '://' . $parsed_url['host'] . $headers[$name];
                    }
                }
            }
        }
        return $headers;
    }

    protected function request_streams($url, $method = 'GET', $params = array(), $update_claimed_id = false)
    {
        if (!$this->hostExists($url)) {
            throw new ErrorException("Could not connect to $url.", 404);
        }

        if (empty($this->cnmatch)) {
            $this->cnmatch = parse_url($url, PHP_URL_HOST);
        }

        $params = http_build_query($params, '', '&');

        switch ($method) {
            case 'GET':
                $opts = array(
                    'http' => array(
                        'method' => 'GET',
                        'header' => 'Accept: application/xrds+xml, */*',
                        'user_agent' => $this->user_agent,
                        'ignore_errors' => true,
                    ),
                    'ssl' => array(
                        'CN_match' => $this->cnmatch
                    )
                );
                $url = $url . ($params ? '?' . $params : '');
                if (!empty($this->proxy)) {
                    $opts['http']['proxy'] = $this->proxy_url();
                }
                break;
            case 'POST':
                $opts = array(
                    'http' => array(
                        'method' => 'POST',
                        'header' => 'Content-type: application/x-www-form-urlencoded',
                        'user_agent' => $this->user_agent,
                        'content' => $params,
                        'ignore_errors' => true,
                    ),
                    'ssl' => array(
                        'CN_match' => $this->cnmatch
                    )
                );
                if (!empty($this->proxy)) {
                    $opts['http']['proxy'] = $this->proxy_url();
                }
                break;
            case 'HEAD':
                $default = stream_context_get_options(stream_context_get_default());
                $default += array('http' => array(), 'ssl' => array());
                $default['http'] += array(
                    'method' => 'GET',
                    'header' => '',
                    'user_agent' => '',
                    'ignore_errors' => false
                );
                $default['ssl'] += array('CN_match' => '');

                $opts = array(
                    'http' => array(
                        'method' => 'HEAD',
                        'header' => 'Accept: application/xrds+xml, */*',
                        'user_agent' => $this->user_agent,
                        'ignore_errors' => true,
                    ),
                    'ssl' => array(
                        'CN_match' => $this->cnmatch
                    )
                );

                if ($this->verify_peer) {
                    $default['ssl'] += array(
                        'verify_peer' => false,
                        'capath' => '',
                        'cafile' => ''
                    );
                    $opts['ssl'] += array(
                        'verify_peer' => true,
                        'capath' => $this->capath,
                        'cafile' => $this->cainfo
                    );
                }

                stream_context_get_default($opts);
                $headers = get_headers($url . ($params ? '?' . $params : ''));

                stream_context_get_default($default);

                if (!empty($headers)) {
                    if (intval(substr($headers[0], strlen('HTTP/1.1 '))) == 405) {
                        $args = func_get_args();
                        $args[1] = 'GET';
                        call_user_func_array(array($this, 'request_streams'), $args);
                        $headers = $this->headers;
                    } else {
                        $headers = $this->parse_header_array($headers, $update_claimed_id);
                    }
                } else {
                    $headers = array();
                }
                return $headers;
            default:
                throw new Exception("Unsupported method: $method");
        }

        if ($this->verify_peer) {
            $opts['ssl'] += array(
                'verify_peer' => true,
                'capath' => $this->capath,
                'cafile' => $this->cainfo
            );
        }

        $context = stream_context_create($opts);
        $data = file_get_contents($url, false, $context);

        if (isset($http_response_header)) {
            $this->headers = $this->parse_header_array($http_response_header, $update_claimed_id);
        }

        return $data;
    }

    protected function request($url, $method = 'GET', $params = array(), $update_claimed_id = false)
    {
        $use_curl = false;

        if (function_exists('curl_init')) {
            if (!$use_curl) {
                $use_curl = !ini_get('allow_url_fopen');
            }
            if (!$use_curl) {
                $use_curl = !in_array('https', stream_get_wrappers());
            }
            if (!$use_curl) {
                $use_curl = !(ini_get('safe_mode') || ini_get('open_basedir'));
            }
        }

        return
            $use_curl
                ? $this->request_curl($url, $method, $params, $update_claimed_id)
                : $this->request_streams($url, $method, $params, $update_claimed_id);
    }

    protected function proxy_url()
    {
        $result = '';
        if (!empty($this->proxy)) {
            $result = $this->proxy['host'];
            if (!empty($this->proxy['port'])) {
                $result .= ':' . $this->proxy['port'];
            }
            if (!empty($this->proxy['user'])) {
                $result = $this->proxy['user'] . ':' . $this->proxy['pass'] . '@' . $result;
            }
            $result = 'http://' . $result;
        }
        return $result;
    }

    protected function build_url($url, $parts)
    {
        if (isset($url['query'], $parts['query'])) {
            $parts['query'] = $url['query'] . '&' . $parts['query'];
        }

        $url = $parts + $url;
        $url = $url['scheme'] . '://'
            . (empty($url['username']) ? '' : $url['username'] . (empty($url['password']) ? '' : ':' . $url['password']) . '@')
            . $url['host']
            . (empty($url['port']) ? '' : ':' . $url['port'])
            . (empty($url['path']) ? '/' : $url['path'])
            . (empty($url['query']) ? '' : '?' . $url['query'])
            . (empty($url['fragment']) ? '' : '#' . $url['fragment']);

        return $url;
    }

    protected function htmlTag($content, $tag, $attr, $value, $return = 'href')
    {
        $matches = array();
        preg_match_all('#<' . $tag . '\s+[^>]*' . $attr . '=[\'"]' . preg_quote($value, '#') . '[\'"][^>]*>#i', $content, $matches, PREG_OFFSET_CAPTURE);
        if (!empty($matches[0])) {
            $pos = $matches[0][0][1];
            $length = strlen($matches[0][0][0]);
            $close = strpos($content, '>', $pos) - $pos;
            preg_match('#' . $return . '=[\'"](.*?)[\'"]#i', substr($content, $pos, $close + 1), $m);
            if (!empty($m[1])) {
                return $m[1];
            }
        }
        return false;
    }

    protected function discover($url)
    {
        $originalUrl = $url;
        $iterationCount = 0;
        $next = false;

        while ($iterationCount < 10) {
            $iterationCount++;
            if (!$this->hostExists($url)) {
                throw new ErrorException("Host does not exist: $url", 404);
            }

            $this->headers = $this->request($url, 'HEAD', array(), true);

            if (isset($this->headers['x-xrds-location'])) {
                $url = $this->build_url(parse_url($url), parse_url(trim($this->headers['x-xrds-location'])));
                continue;
            }

            $location = $this->htmlTag($this->request($url, 'GET', array(), true), 'meta', 'http-equiv', 'X-XRDS-Location', 'content');
            if ($location) {
                $url = $this->build_url(parse_url($url), parse_url($location));
                continue;
            }

            $content = $this->request($url, 'GET');
            $server = $this->htmlTag($content, 'link', 'rel', 'openid2.provider', 'href');
            $delegate = $this->htmlTag($content, 'link', 'rel', 'openid2.local_id', 'href');
            $this->version = 2;

            if (!$server) {
                $server = $this->htmlTag($content, 'link', 'rel', 'openid.server', 'href');
                $delegate = $this->htmlTag($content, 'link', 'rel', 'openid.delegate', 'href');
                $this->version = 1;
            }

            if ($server) {
                if ($delegate) {
                    $this->identity = $delegate;
                }
                $this->server = $server;
                return $server;
            }

            throw new ErrorException("No OpenID Server found at $url", 404);
        }
        throw new ErrorException('Endless redirection!', 500);
    }

    protected function is_allowed_type($content_type)
    {
        $allowed_types = array('application/xrds+xml', 'text/xml');

        if ($this->get_provider_name($this->claimed_id) == 'yahoo') {
            $allowed_types[] = 'text/html';
        }

        foreach ($allowed_types as $type) {
            if (strpos($content_type, $type) !== false) {
                return true;
            }
        }

        return false;
    }

    protected function get_provider_name($provider_url)
    {
        $result = '';

        if (!empty($provider_url)) {
            $tokens = array_reverse(
                explode('.', parse_url($provider_url, PHP_URL_HOST))
            );
            $result = strtolower(
                (count($tokens) > 1 && strlen($tokens[1]) > 3)
                    ? $tokens[1]
                    : (count($tokens) > 2 ? $tokens[2] : '')
            );
        }

        return $result;
    }

    protected function sregParams()
    {
        $params = array();
        $params['openid.ns.sreg'] = 'http://openid.net/extensions/sreg/1.1';

        if ($this->required) {
            $params['openid.sreg.required'] = array();
            foreach ($this->required as $required) {
                if (!isset(self::$ax_to_sreg[$required])) continue;
                $params['openid.sreg.required'][] = self::$ax_to_sreg[$required];
            }
            $params['openid.sreg.required'] = implode(',', $params['openid.sreg.required']);
        }

        if ($this->optional) {
            $params['openid.sreg.optional'] = array();
            foreach ($this->optional as $optional) {
                if (!isset(self::$ax_to_sreg[$optional])) continue;
                $params['openid.sreg.optional'][] = self::$ax_to_sreg[$optional];
            }
            $params['openid.sreg.optional'] = implode(',', $params['openid.sreg.optional']);
        }
        return $params;
    }

    protected function axParams()
    {
        $params = array();
        if ($this->required || $this->optional) {
            $params['openid.ns.ax'] = 'http://openid.net/srv/ax/1.0';
            $params['openid.ax.mode'] = 'fetch_request';
            $this->aliases = array();
            $counts = array();
            $required = array();
            $optional = array();
            foreach (array('required', 'optional') as $type) {
                foreach ($this->$type as $alias => $field) {
                    if (is_int($alias)) $alias = strtr($field, '/', '_');
                    $this->aliases[$alias] = 'http://axschema.org/' . $field;
                    if (empty($counts[$alias])) $counts[$alias] = 0;
                    $counts[$alias] += 1;
                    ${$type}[] = $alias;
                }
            }
            foreach ($this->aliases as $alias => $ns) {
                $params['openid.ax.type.' . $alias] = $ns;
            }
            foreach ($counts as $alias => $count) {
                if ($count == 1) continue;
                $params['openid.ax.count.' . $alias] = $count;
            }

            if ($required) {
                $params['openid.ax.required'] = implode(',', $required);
            }
            if ($optional) {
                $params['openid.ax.if_available'] = implode(',', $optional);
            }
        }
        return $params;
    }

    protected function authUrl_v1($immediate)
    {
        $returnUrl = $this->returnUrl;
        if ($this->identity != $this->claimed_id) {
            $returnUrl .= (strpos($returnUrl, '?') ? '&' : '?') . 'openid.claimed_id=' . $this->claimed_id;
        }

        $params = array(
            'openid.return_to' => $returnUrl,
            'openid.mode' => $immediate ? 'checkid_immediate' : 'checkid_setup',
            'openid.identity' => $this->identity,
            'openid.trust_root' => $this->trustRoot,
        ) + $this->sregParams();

        return $this->build_url(parse_url($this->server), array('query' => http_build_query($params, '', '&')));
    }

    protected function authUrl_v2($immediate)
    {
        $params = array(
            'openid.ns' => 'http://specs.openid.net/auth/2.0',
            'openid.mode' => $immediate ? 'checkid_immediate' : 'checkid_setup',
            'openid.return_to' => $this->returnUrl,
            'openid.realm' => $this->trustRoot,
        );

        if ($this->ax) {
            $params += $this->axParams();
        }

        if ($this->sreg) {
            $params += $this->sregParams();
        }

        if (!$this->ax && !$this->sreg) {
            $params += $this->axParams() + $this->sregParams();
        }

        if (!empty($this->oauth) && is_array($this->oauth)) {
            $params['openid.ns.oauth'] = 'http://specs.openid.net/extensions/oauth/1.0';
            $params['openid.oauth.consumer'] = str_replace(array('http://', 'https://'), '', $this->trustRoot);
            $params['openid.oauth.scope'] = implode(' ', $this->oauth);
        }

        if ($this->identifier_select) {
            $params['openid.identity'] = $params['openid.claimed_id'] = 'http://specs.openid.net/auth/2.0/identifier_select';
        } else {
            $params['openid.identity'] = $this->identity;
            $params['openid.claimed_id'] = $this->claimed_id;
        }

        return $this->build_url(parse_url($this->server), array('query' => http_build_query($params, '', '&')));
    }

    public function authUrl($immediate = false)
    {
        if ($this->setup_url && !$immediate) return $this->setup_url;
        if (!$this->server) $this->discover($this->identity);

        if ($this->version == 2) {
            return $this->authUrl_v2($immediate);
        }
        return $this->authUrl_v1($immediate);
    }

    public function validate()
    {
        if (isset($this->data['openid_user_setup_url'])) {
            $this->setup_url = $this->data['openid_user_setup_url'];
            return false;
        }
        if ($this->mode != 'id_res') {
            return false;
        }

        $this->claimed_id = isset($this->data['openid_claimed_id']) ? $this->data['openid_claimed_id'] : $this->data['openid_identity'];

        $params = array(
            'openid.assoc_handle' => $this->data['openid_assoc_handle'],
            'openid.signed' => $this->data['openid_signed'],
            'openid.sig' => $this->data['openid_sig'],
        );

        if (isset($this->data['openid_ns'])) {
            $params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
        } elseif (isset($this->data['openid_claimed_id']) && $this->data['openid_claimed_id'] != $this->data['openid_identity']) {
            $this->returnUrl .= (strpos($this->returnUrl, '?') ? '&' : '?') . 'openid.claimed_id=' . $this->claimed_id;
        }

        if ($this->data['openid_return_to'] != $this->returnUrl) {
            return false;
        }

        $server = $this->discover($this->claimed_id);

        foreach (explode(',', $this->data['openid_signed']) as $item) {
            $value = $this->data['openid_' . str_replace('.', '_', $item)];
            if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
                $value = stripslashes($value);
            }
            $params['openid.' . $item] = $value;
        }

        $params['openid.mode'] = 'check_authentication';

        $response = $this->request($server, 'POST', $params);

        return preg_match('/is_valid\s*:\s*true/i', $response);
    }

    protected function getAxAttributes()
    {
        $result = array();

        if ($alias = $this->getNamespaceAlias('http://openid.net/srv/ax/1.0', 'ax')) {
            $prefix = 'openid_' . $alias;
            $length = strlen('http://axschema.org/');

            foreach (explode(',', $this->data['openid_signed']) as $key) {
                $keyMatch = $alias . '.type.';

                if (strncmp($key, $keyMatch, strlen($keyMatch)) !== 0) {
                    continue;
                }

                $key = substr($key, strlen($keyMatch));
                $idv = $prefix . '_value_' . $key;
                $idc = $prefix . '_count_' . $key;
                $key = substr($this->getItem($prefix . '_type_' . $key), $length);

                if (!empty($key)) {
                    if (($count = intval($this->getItem($idc))) > 0) {
                        $value = array();

                        for ($i = 1; $i <= $count; $i++) {
                            $value[] = $this->getItem($idv . '_' . $i);
                        }

                        $value = ($count == 1) ? reset($value) : $value;
                    } else {
                        $value = $this->getItem($idv);
                    }

                    if (!is_null($value)) {
                        $result[$key] = $value;
                    }
                }
            }
        }
        return $result;
    }

    protected function getSregAttributes()
    {
        $attributes = array();
        $sreg_to_ax = array_flip(self::$ax_to_sreg);
        foreach (explode(',', $this->data['openid_signed']) as $key) {
            $keyMatch = 'sreg.';
            if (strncmp($key, $keyMatch, strlen($keyMatch)) !== 0) {
                continue;
            }
            $key = substr($key, strlen($keyMatch));
            if (!isset($sreg_to_ax[$key])) {
                continue;
            }
            $attributes[$sreg_to_ax[$key]] = $this->data['openid_sreg_' . $key];
        }
        return $attributes;
    }

    public function getAttributes()
    {
        if (isset($this->data['openid_ns']) && $this->data['openid_ns'] == 'http://specs.openid.net/auth/2.0') {
            return $this->getAxAttributes() + $this->getSregAttributes();
        }
        return $this->getSregAttributes();
    }

    public function getOAuthRequestToken()
    {
        $alias = $this->getNamespaceAlias('http://specs.openid.net/extensions/oauth/1.0');
        return !empty($alias) ? $this->data['openid_' . $alias . '_request_token'] : false;
    }

    private function getNamespaceAlias($namespace, $hint = null)
    {
        $result = null;

        if (empty($hint) || $this->getItem('openid_ns_' . $hint) != $namespace) {
            $prefix = 'openid_ns_';
            $length = strlen($prefix);

            foreach ($this->data as $key => $val) {
                if (strncmp($key, $prefix, $length) === 0 && $val === $namespace) {
                    $result = trim(substr($key, $length));
                    break;
                }
            }
        } else {
            $result = $hint;
        }

        return $result;
    }

    private function getItem($id)
    {
        return isset($this->data[$id]) ? $this->data[$id] : null;
    }
}
