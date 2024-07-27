<?php
// Copyright (c) 2024 RAMPAGE Interactive
// Written with <3 by vq9o.

class RobloxOAuthSDK {
    private $clientId;
    private $clientSecret;
    private $redirectUri;
    private $discoveryUrl;
    private $tokenSet;
    private $home_page;

    public function __construct($home_page, $clientId, $clientSecret, $redirectUri, $discoveryUrl) {
        $this->home_page = $home_page;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->discoveryUrl = $discoveryUrl;
        session_start();
    }

    private function discoverOAuthConfig() {
        $response = file_get_contents($this->discoveryUrl);
        return json_decode($response, true);
    }

    public function getAuthUrl() {
        $oauthConfig = $this->discoverOAuthConfig();
        $authUrl = $oauthConfig['authorization_endpoint'];
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth2state'] = $state;

        $authUrl .= '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid profile',
            'state' => $state,
        ]);

        return $authUrl;
    }

    public function handleOAuthCallback() {
        $oauthConfig = $this->discoverOAuthConfig();
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $_GET['code'],
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $options = [
            'http' => [
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($params),
            ],
        ];

        $context = stream_context_create($options);
        $response = file_get_contents($oauthConfig['token_endpoint'], false, $context);

        $this->tokenSet = json_decode($response, true);
        $_SESSION['tokenSet'] = $this->tokenSet;

        header("Location: $this->home_page");
        exit();
    }

    public function checkLoggedIn() {
        return isset($_SESSION['tokenSet']);
    }

    public function getTokenSet() {
        return $this->tokenSet ?? $_SESSION['tokenSet'];
    }

    public function getClaims() {
        $tokenSet = $this->getTokenSet();
        return json_decode(base64_decode(explode('.', $tokenSet['id_token'])[1]), true);
    }
}
