<?php

class LightOpenID
{
    public string $returnUrl;
    public string $trustRoot;
    public ?string $identity = null;
    public ?string $claimed_id = null;
    public ?string $server = null;
    public ?string $setup_url = null;
    public ?string $version = null;
    public ?string $ax = null;
    public ?string $sreg = null;
    public bool $identifier_select = false;
    public array $data = [];
    public array $required = [];
    public array $optional = [];
    public array $headers = [];
    public ?array $proxy = null;
    public string $user_agent = 'PHP OpenID';
    public int $curl_time_out = 30;
    public int $curl_connect_time_out = 30;
    public ?bool $verify_peer = null;
    public ?string $capath = null;
    public ?string $cainfo = null;
    public ?string $cnmatch = null;
    public ?array $oauth = null;
    public ?string $xrds_override_pattern = null;
    public ?string $xrds_override_replacement = null;
    public bool $identifier_select_supported = false;

    public static array $ax_to_sreg = [
        'namePerson/friendly' => 'nickname',
        'contact/email'       => 'email',
        'namePerson'          => 'fullname',
        'birthDate'           => 'dob',
        'person/gender'       => 'gender',
        'contact/postalCode/home' => 'postcode',
        'contact/country/home' => 'country',
        'pref/language'       => 'language',
        'pref/timezone'       => 'timezone',
    ];

    public function __construct(string $host)
    {
        $this->trustRoot = $this->returnUrl = $host;
    }

    protected function hostExists(string $url): bool
    {
        $urlParts = parse_url($url);
        if (!isset($urlParts['host'])) {
            return false;
        }

        $host = $urlParts['host'];
        return checkdnsrr($host, 'A') || checkdnsrr($host, 'AAAA');
    }

    protected function request(string $url, string $method = 'GET', array $params = [], bool $update_claimed_id = false): string|array
    {
        $use_curl = function_exists('curl_init') &&
            (
                !ini_get('allow_url_fopen') ||
                !in_array('https', stream_get_wrappers()) ||
                ini_get('open_basedir')
            );

        return $use_curl
            ? $this->request_curl($url, $method, $params, $update_claimed_id)
            : $this->request_streams($url, $method, $params, $update_claimed_id);
    }

    protected function request_curl(string $url, string $method, array $params, bool $update_claimed_id): string|array
    {
        $curl = curl_init();

        $method = strtoupper($method);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_USERAGENT, $this->user_agent);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

            if ($method === 'POST') {
            curl_setopt($curl, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        } else {
            curl_setopt($curl, CURLOPT_HTTPHEADER, ['Accept: application/xrds+xml, */*']);
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

        if ($method === 'POST') {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params, '', '&'));
        } elseif ($method === 'HEAD') {
            curl_setopt($curl, CURLOPT_HEADER, true);
            curl_setopt($curl, CURLOPT_NOBODY, true);
        } else {
            curl_setopt($curl, CURLOPT_HEADER, true);
            curl_setopt($curl, CURLOPT_HTTPGET, true);
        }

        $response = curl_exec($curl);
        if ($method === 'HEAD' && curl_getinfo($curl, CURLINFO_HTTP_CODE) === 405) {
            curl_setopt($curl, CURLOPT_HTTPGET, true);
            $response = curl_exec($curl);
            $response = substr($response, 0, strpos($response, "\r\n\r\n"));
        }

        if ($method === 'HEAD' || $method === 'GET') {
            $header_response = $response;
            if ($method === 'GET') {
                $header_response = substr($response, 0, strpos($response, "\r\n\r\n"));
            }

            $headers = [];
            foreach (explode("\n", $header_response) as $header) {
                $pos = strpos($header, ':');
                if ($pos !== false) {
                    $name = strtolower(trim(substr($header, 0, $pos)));
                    $headers[$name] = trim(substr($header, $pos + 1));
                }
            }

            if ($update_claimed_id) {
                $effective_url = curl_getinfo($curl, CURLINFO_EFFECTIVE_URL);
                if (strtok($effective_url, '#') !== strtok($url, '#')) {
                    $this->identity = $this->claimed_id = $effective_url;
                }
            }

            if ($method === 'HEAD') {
                return $headers;
            } else {
                $this->headers = $headers;
            }
        }

        if (curl_errno($curl)) {
            throw new ErrorException(curl_error($curl), curl_errno($curl));
        }

        return $response;
    }
    protected function parse_header_array($array, $update_claimed_id)
    {
        $headers = [];
        foreach ($array as $header) {
            $pos = strpos($header, ':');
            if ($pos !== false) {
                $name = strtolower(trim(substr($header, 0, $pos)));
                $headers[$name] = trim(substr($header, $pos + 1));

                if ($name === 'location' && $update_claimed_id) {
                    if (strpos($headers[$name], 'http') === 0) {
                        $this->identity = $this->claimed_id = $headers[$name];
                    } elseif ($headers[$name][0] === '/') {
                        $parsed_url = parse_url($this->claimed_id);
                        $this->identity =
                        $this->claimed_id = $parsed_url['scheme'] . '://' . $parsed_url['host'] . $headers[$name];
                    }
                }
            }
        }
        return $headers;
    }

    protected function request_streams($url, $method = 'GET', $params = [], $update_claimed_id)
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
                $opts = [
                    'http' => [
                        'method' => 'GET',
                        'header' => 'Accept: application/xrds+xml, */*',
                        'user_agent' => $this->user_agent,
                        'ignore_errors' => true,
                    ],
                    'ssl' => [
                        'CN_match' => $this->cnmatch
                    ]
                ];
                $url .= $params ? '?' . $params : '';
                if (!empty($this->proxy)) {
                    $opts['http']['proxy'] = $this->proxy_url();
                }
                break;
            case 'POST':
                $opts = [
                    'http' => [
                        'method'  => 'POST',
                        'header'  => 'Content-type: application/x-www-form-urlencoded',
                        'user_agent' => $this->user_agent,
                        'content' => $params,
                        'ignore_errors' => true,
                    ],
                    'ssl' => [
                        'CN_match' => $this->cnmatch
                    ]
                ];
                if (!empty($this->proxy)) {
                    $opts['http']['proxy'] = $this->proxy_url();
                }
                break;

            case 'HEAD':
                $default = stream_context_get_options(stream_context_get_default());
                $default += ['http' => [], 'ssl' => []];

                $default['http'] += [
                    'method' => 'GET',
                    'header' => '',
                    'user_agent' => '',
                    'ignore_errors' => false
                ];
                $default['ssl'] += ['CN_match' => ''];

                $opts = [
                    'http' => [
                        'method' => 'HEAD',
                        'header' => 'Accept: application/xrds+xml, */*',
                        'user_agent' => $this->user_agent,
                        'ignore_errors' => true,
                    ],
                    'ssl' => [
                        'CN_match' => $this->cnmatch
                    ]
                ];

                if ($this->verify_peer) {
                    $default['ssl'] += [
                        'verify_peer' => false,
                        'capath' => '',
                        'cafile' => ''
                    ];
                    $opts['ssl'] += [
                        'verify_peer' => true,
                        'capath' => $this->capath,
                        'cafile' => $this->cainfo
                    ];
                }

                stream_context_get_default($opts);
                $headers = @get_headers($url . ($params ? '?' . $params : ''));

                stream_context_get_default($default);

                if (!empty($headers)) {
                    if (intval(substr($headers[0], strlen('HTTP/1.1 '))) === 405) {
                        $args = func_get_args();
                        $args[1] = 'GET';
                        call_user_func_array([$this, 'request_streams'], $args);
                        $headers = $this->headers;
                    } else {
                        $headers = $this->parse_header_array($headers, $update_claimed_id);
                    }
                } else {
                    $headers = [];
                }

                return $headers;
        }

        if ($this->verify_peer) {
            $opts['ssl'] += [
                'verify_peer' => true,
                'capath'      => $this->capath,
                'cafile'      => $this->cainfo
            ];
        }

        $context = stream_context_create($opts);
        $data = @file_get_contents($url, false, $context);

        if (isset($http_response_header)) {
            $this->headers = $this->parse_header_array($http_response_header, $update_claimed_id);
        }

        return $data;
    }
    protected function request($url, $method = 'GET', $params = [], $update_claimed_id = false)
    {
        $use_curl = false;

        if (function_exists('curl_init')) {
            // Prefer cURL if allow_url_fopen is off
            if (!$use_curl) {
                $use_curl = !ini_get('allow_url_fopen');
            }

            // Use cURL if https wrapper is not available
            if (!$use_curl) {
                $use_curl = !in_array('https', stream_get_wrappers());
            }

            // Use cURL if safe_mode or open_basedir is set (stream can't follow redirects)
            if (!$use_curl) {
                $use_curl = (ini_get('safe_mode') || ini_get('open_basedir'));
            }
        }

        return $use_curl
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

        return $url['scheme'] . '://'
            . (empty($url['user']) ? '' : (empty($url['pass']) ? "{$url['user']}@" : "{$url['user']}:{$url['pass']}@"))
            . $url['host']
            . (empty($url['port']) ? '' : ":{$url['port']}")
            . (empty($url['path']) ? '' : $url['path'])
            . (empty($url['query']) ? '' : "?{$url['query']}")
            . (empty($url['fragment']) ? '' : "#{$url['fragment']}");
    }
    /**
     * Helper function used to scan for <meta>/<link> tags and extract information from them
     */
    protected function htmlTag($content, $tag, $attrName, $attrValue, $valueName)
    {
        preg_match_all(
            "#<{$tag}[^>]*$attrName=['\"]([^'\"]*{$attrValue}[^'\"]*)['\"][^>]*$valueName=['\"](.+?)['\"][^>]*/?>#i",
            $content,
            $matches1
        );

        preg_match_all(
            "#<{$tag}[^>]*$valueName=['\"](.+?)['\"][^>]*$attrName=['\"]([^'\"]*{$attrValue}[^'\"]*)['\"][^>]*/?>#i",
            $content,
            $matches2
        );

        $result = array_merge($matches1[2] ?? [], $matches2[1] ?? []);

        return empty($result) ? false : $result[0];
    }

    /**
     * Performs Yadis and HTML discovery. Normally not used.
     * @param string $url Identity URL.
     * @return string OP Endpoint (i.e. OpenID provider address).
     * @throws ErrorException
     */
    function discover($url)
    {
        if (!$url) {
            throw new ErrorException('No identity supplied.');
        }

        // Use xri.net proxy to resolve i-name identities
        if (!preg_match('#^https?:#i', $url)) {
            $url = "https://xri.net/$url";
        }

        // Save the original url in case of Yadis discovery failure.
        $originalUrl = $url;

        $yadis = true;

        // Optional regex replacement of the URL (e.g. Google Apps workaround)
        if (!is_null($this->xrds_override_pattern) && !is_null($this->xrds_override_replacement)) {
            $url = preg_replace($this->xrds_override_pattern, $this->xrds_override_replacement, $url);
        }

        // Max 5 redirects to avoid endless loops
        for ($i = 0; $i < 5; $i++) {
            if ($yadis) {
                $headers = $this->request($url, 'HEAD', [], true);

                $next = false;
                if (isset($headers['x-xrds-location'])) {
                    $xrdsLocation = trim($headers['x-xrds-location']);
                    $url = $this->build_url(parse_url($url), parse_url($xrdsLocation));
                    $next = true;
                }

                if (isset($headers['content-type']) && $this->is_allowed_type($headers['content-type'])) {
                    // Found XRDS document, find server and delegate
                    $content = $this->request($url, 'GET');

                    preg_match_all('#<Service.*?>(.*?)</Service>#s', $content, $services);
                    foreach ($services[1] as $serviceContent) {
                        $serviceContent = ' ' . $serviceContent;

                        // OpenID 2.0
                        $ns = preg_quote('http://specs.openid.net/auth/2.0/', '#');
                        if (preg_match('#<Type>\s*' . $ns . '(server|signon)\s*</Type>#s', $serviceContent, $typeMatch)) {
                            if ($typeMatch[1] == 'server') {
                                $this->identifier_select = true;
                            }

                            preg_match('#<URI.*?>(.*)</URI>#', $serviceContent, $serverMatch);
                            preg_match('#<(Local|Canonical)ID>(.*)</\1ID>#', $serviceContent, $delegateMatch);
                            if (empty($serverMatch)) {
                                return false;
                            }

                            $this->ax   = (strpos($serviceContent, '<Type>http://openid.net/srv/ax/1.0</Type>') !== false);
                            $this->sreg = (strpos($serviceContent, '<Type>http://openid.net/sreg/1.0</Type>') !== false)
                                       || (strpos($serviceContent, '<Type>http://openid.net/extensions/sreg/1.1</Type>') !== false);

                            $server = $serverMatch[1];
                            if (isset($delegateMatch[2])) {
                                $this->identity = trim($delegateMatch[2]);
                            }
                            $this->version = 2;

                            $this->server = $server;
                            return $server;
                        }

                        // OpenID 1.1
                        $ns = preg_quote('http://openid.net/signon/1.1', '#');
                        if (preg_match('#<Type>\s*' . $ns . '\s*</Type>#s', $serviceContent)) {

                            preg_match('#<URI.*?>(.*)</URI>#', $serviceContent, $serverMatch);
                            preg_match('#<.*?Delegate>(.*)</.*?Delegate>#', $serviceContent, $delegateMatch);
                            if (empty($serverMatch)) {
                                return false;
                            }

                            $this->sreg = (strpos($serviceContent, '<Type>http://openid.net/sreg/1.0</Type>') !== false)
                                       || (strpos($serviceContent, '<Type>http://openid.net/extensions/sreg/1.1</Type>') !== false);

                            $server = $serverMatch[1];
                            if (isset($delegateMatch[1])) {
                                $this->identity = $delegateMatch[1];
                            }
                            $this->version = 1;

                            $this->server = $server;
                            return $server;
                        }
                    }

                    $next = true;
                    $yadis = false;
                    $url = $originalUrl;
                    $content = null;
                    break;
                }
                if ($next) {
                    continue;
                }

                // No info in headers, search body
                $content = $this->request($url, 'GET', [], true);

                if (isset($this->headers['x-xrds-location'])) {
                    $xrdsLocation = trim($this->headers['x-xrds-location']);
                    $url = $this->build_url(parse_url($url), parse_url($xrdsLocation));
                    continue;
                }

                $location = $this->htmlTag($content, 'meta', 'http-equiv', 'X-XRDS-Location', 'content');
                if ($location) {
                    $url = $this->build_url(parse_url($url), parse_url($location));
                    continue;
                }
            }

            if (!$content) {
                $content = $this->request($url, 'GET');
            }

            // YADIS discovery failed, fallback to HTML discovery OpenID 2.0
            $server = $this->htmlTag($content, 'link', 'rel', 'openid2.provider', 'href');
            $delegate = $this->htmlTag($content, 'link', 'rel', 'openid2.local_id', 'href');
            $this->version = 2;

            if (!$server) {
                // Fallback OpenID 1.1
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
    protected function build_url($url, $parts)
    {
        if (isset($url['query'], $parts['query'])) {
            $parts['query'] = $url['query'] . '&' . $parts['query'];
        }

        $url = $parts + $url;

        $userpass = '';
        if (!empty($url['username'])) {
            $userpass = $url['username'];
            if (!empty($url['password'])) {
                $userpass .= ':' . $url['password'];
            }
            $userpass .= '@';
        }

        $result = $url['scheme'] . '://' 
                . $userpass
                . $url['host']
                . (!empty($url['port']) ? ':' . $url['port'] : '')
                . (!empty($url['path']) ? $url['path'] : '')
                . (!empty($url['query']) ? '?' . $url['query'] : '')
                . (!empty($url['fragment']) ? '#' . $url['fragment'] : '');

        return $result;
    }

    protected function sregParams()
    {
        $params = array();
        $params['openid.ns.sreg'] = 'http://openid.net/extensions/sreg/1.1';

        if (!empty($this->required)) {
            $params['openid.sreg.required'] = array();
            foreach ($this->required as $required) {
                if (!isset(self::$ax_to_sreg[$required])) continue;
                $params['openid.sreg.required'][] = self::$ax_to_sreg[$required];
            }
            $params['openid.sreg.required'] = implode(',', $params['openid.sreg.required']);
        }

        if (!empty($this->optional)) {
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

        if (!empty($this->required) || !empty($this->optional)) {
            $params['openid.ns.ax'] = 'http://openid.net/srv/ax/1.0';
            $params['openid.ax.mode'] = 'fetch_request';
            $this->aliases  = array();
            $counts   = array();
            $required = array();
            $optional = array();

            foreach (array('required', 'optional') as $type) {
                if (empty($this->$type)) continue;
                foreach ($this->$type as $alias => $field) {
                    if (is_int($alias)) {
                        $alias = strtr($field, '/', '_');
                    }
                    $this->aliases[$alias] = 'http://axschema.org/' . $field;
                    if (empty($counts[$alias])) {
                        $counts[$alias] = 0;
                    }
                    $counts[$alias]++;
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

            if (!empty($required)) {
                $params['openid.ax.required'] = implode(',', $required);
            }
            if (!empty($optional)) {
                $params['openid.ax.if_available'] = implode(',', $optional);
            }
        }

        return $params;
    }

    protected function authUrl_v1($immediate)
    {
        $returnUrl = $this->returnUrl;

        if ($this->identity != $this->claimed_id) {
            $returnUrl .= (strpos($returnUrl, '?') ? '&' : '?') . 'openid.claimed_id=' . urlencode($this->claimed_id);
        }

        $params = array(
            'openid.return_to'  => $returnUrl,
            'openid.mode'       => $immediate ? 'checkid_immediate' : 'checkid_setup',
            'openid.identity'   => $this->identity,
            'openid.trust_root' => $this->trustRoot,
        ) + $this->sregParams();

        return $this->build_url(parse_url($this->server), array('query' => http_build_query($params, '', '&')));
    }

    protected function authUrl_v2($immediate)
    {
        $params = array(
            'openid.ns'          => 'http://specs.openid.net/auth/2.0',
            'openid.mode'        => $immediate ? 'checkid_immediate' : 'checkid_setup',
            'openid.return_to'   => $this->returnUrl,
            'openid.realm'       => $this->trustRoot,
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
    /**
     * Returns authentication url. Usually, you want to redirect your user to it.
     * @param bool $immediate Whether to request immediate authentication.
     * @return string The authentication URL.
     * @throws ErrorException
     */
    function authUrl($immediate = false)
    {
        if ($this->setup_url && !$immediate) {
            return $this->setup_url;
        }

        if (!$this->server) {
            $this->discover($this->identity);
        }

        if ($this->version == 2) {
            return $this->authUrl_v2($immediate);
        }

        return $this->authUrl_v1($immediate);
    }

    /**
     * Performs OpenID verification with the OP.
     * @return bool Whether the verification was successful.
     * @throws ErrorException
     */
    function validate()
    {
        if (isset($this->data['openid_user_setup_url'])) {
            $this->setup_url = $this->data['openid_user_setup_url'];
            return false;
        }

        if ($this->mode !== 'id_res') {
            return false;
        }

        $this->claimed_id = $this->data['openid_claimed_id'] ?? $this->data['openid_identity'];

        $params = [
            'openid.assoc_handle' => $this->data['openid_assoc_handle'] ?? '',
            'openid.signed'       => $this->data['openid_signed'] ?? '',
            'openid.sig'          => $this->data['openid_sig'] ?? '',
        ];

        if (isset($this->data['openid_ns'])) {
            $params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
        } elseif (!empty($this->data['openid_claimed_id']) &&
                  $this->data['openid_claimed_id'] != $this->data['openid_identity']) {
            $this->returnUrl .= (strpos($this->returnUrl, '?') ? '&' : '?')
                             . 'openid.claimed_id=' . urlencode($this->claimed_id);
        }

        if (($this->data['openid_return_to'] ?? '') !== $this->returnUrl) {
            return false;
        }

        $server = $this->discover($this->claimed_id);

        foreach (explode(',', $this->data['openid_signed'] ?? '') as $item) {
            $key = 'openid_' . str_replace('.', '_', $item);
            $value = $this->data[$key] ?? null;

            if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc() && $value !== null) {
                $value = stripslashes($value);
            }

            $params['openid.' . $item] = $value;
        }

        $params['openid.mode'] = 'check_authentication';

        $response = $this->request($server, 'POST', $params);

        return (bool) preg_match('/is_valid\s*:\s*true/i', $response);
    }

    protected function getAxAttributes()
    {
        $result = [];

        $alias = $this->getNamespaceAlias('http://openid.net/srv/ax/1.0', 'ax');

        if ($alias !== null) {
            $prefix = 'openid_' . $alias;
            $length = strlen('http://axschema.org/');

            foreach (explode(',', $this->data['openid_signed'] ?? '') as $key) {
                $keyMatch = $alias . '.type.';

                if (strncmp($key, $keyMatch, strlen($keyMatch)) !== 0) {
                    continue;
                }

                $field = substr($key, strlen($keyMatch));
                $idv = $prefix . '_value_' . $field;
                $idc = $prefix . '_count_' . $field;

                $keyUri = $this->getItem($prefix . '_type_' . $field);
                $keyUri = substr($keyUri, $length);

                if (!empty($keyUri)) {
                    $count = intval($this->getItem($idc));
                    if ($count > 0) {
                        $values = [];
                        for ($i = 1; $i <= $count; $i++) {
                            $values[] = $this->getItem($idv . '_' . $i);
                        }
                        $value = ($count === 1) ? reset($values) : $values;
                    } else {
                        $value = $this->getItem($idv);
                    }

                    if ($value !== null) {
                        $result[$keyUri] = $value;
                    }
                }
            }
        }

        return $result;
    }

    protected function getSregAttributes()
    {
        $attributes = [];
        $sreg_to_ax = array_flip(self::$ax_to_sreg);

        foreach (explode(',', $this->data['openid_signed'] ?? '') as $key) {
            $keyMatch = 'sreg.';
            if (strncmp($key, $keyMatch, strlen($keyMatch)) !== 0) {
                continue;
            }
            $field = substr($key, strlen($keyMatch));
            if (!isset($sreg_to_ax[$field])) {
                continue;
            }
            $attributes[$sreg_to_ax[$field]] = $this->data['openid_sreg_' . $field] ?? null;
        }

        return $attributes;
    }

    /**
     * Gets AX/SREG attributes provided by OP. Use only after successful validation.
     * Returns attributes with keys as AX schema names (e.g., 'contact/email').
     * @return array
     */
    function getAttributes()
    {
        if (($this->data['openid_ns'] ?? '') === 'http://specs.openid.net/auth/2.0') {
            return $this->getAxAttributes() + $this->getSregAttributes();
        }
        return $this->getSregAttributes();
    }

    /**
     * Gets an OAuth request token if OpenID+OAuth hybrid protocol was used.
     * @return string|bool OAuth request token or false if none provided.
     */
    function getOAuthRequestToken()
    {
        $alias = $this->getNamespaceAlias('http://specs.openid.net/extensions/oauth/1.0');

        return !empty($alias) ? ($this->data['openid_' . $alias . '_request_token'] ?? false) : false;
    }

    /**
     * Gets the alias for a specified namespace if present.
     * @param string $namespace
     * @param string|null $hint
     * @return string|null
     */
    private function getNamespaceAlias($namespace, $hint = null)
    {
        if (empty($hint) || ($this->getItem('openid_ns_' . $hint) !== $namespace)) {
            $prefix = 'openid_ns_';
            $length = strlen($prefix);

            foreach ($this->data as $key => $val) {
                if (strncmp($key, $prefix, $length) === 0 && $val === $namespace) {
                    return trim(substr($key, $length));
                }
            }

            return null;
        }
        return $hint;
    }

    /**
     * Gets an item from the $data array by specified id.
     * @param string $id
     * @return string|null
     */
    private function getItem($id)
    {
        return $this->data[$id] ?? null;
    }
/**
 * Gets an OAuth request token if the OpenID+OAuth hybrid protocol has been used.
 *
 * In order to use the OpenID+OAuth hybrid protocol, you need to add at least one
 * scope to the $openid->oauth array before you get the call to getAuthUrl(), e.g.:
 * $openid->oauth[] = 'https://www.googleapis.com/auth/plus.me';
 * 
 * Furthermore the registered consumer name must fit the OpenID realm. 
 * To register an OpenID consumer at Google use: https://www.google.com/accounts/ManageDomains
 * 
 * @return string|false OAuth request token on success, FALSE if no token was provided.
 */
function getOAuthRequestToken()
{
    $alias = $this->getNamespaceAlias('http://specs.openid.net/extensions/oauth/1.0');
    
    return !empty($alias) && isset($this->data['openid_' . $alias . '_request_token'])
        ? $this->data['openid_' . $alias . '_request_token']
        : false;
}

/**
 * Gets the alias for the specified namespace, if it's present.
 *
 * @param string $namespace The namespace for which an alias is needed.
 * @param string|null $hint Common alias of this namespace, used for optimization.
 * @return string|null The namespace alias if found, otherwise NULL.
 */
private function getNamespaceAlias(string $namespace, ?string $hint = null): ?string
{
    if (empty($hint) || ($this->getItem('openid_ns_' . $hint) !== $namespace)) {
        $prefix = 'openid_ns_';
        $length = strlen($prefix);
        foreach ($this->data as $key => $val) {
            if (str_starts_with($key, $prefix) && $val === $namespace) {
                return substr($key, $length);
            }
        }
        return null;
    }
    return $hint;
}

/**
 * Gets an item from the $data array by the specified id.
 *
 * @param string $id The id of the desired item.
 * @return string|null The item if found, otherwise NULL.
 */
private function getItem(string $id): ?string
{
    return $this->data[$id] ?? null;
}
