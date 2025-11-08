<?php
// Copyright (c) 2025 Meta Games, LLC. All rights reserved.
// Written with <3 by vq9o.
/**
 * 
 * @author vq9o
 * @version 1.0.0
 * @requires PHP 7.4+
 * @requires cURL extension
 * @requires JSON extension
 * 
 * RobloxOAuthSDK - A PHP SDK for Roblox OAuth 2.0 authentication
 * 
 * This class provides a simple interface for implementing Roblox OAuth 2.0 authentication
 * in your PHP applications. It handles the OAuth flow, token management, and user data retrieval.
 * 
 * @example Basic Usage:
 * ```php
 * // Initialize the SDK
 * $oauth = new RobloxOAuthSDK(
 *     'https://yoursite.com/dashboard',  // Home page redirect after login
 *     'your_client_id',                  // Roblox OAuth Client ID
 *     'your_client_secret',              // Roblox OAuth Client Secret
 *     'https://yoursite.com/callback',   // OAuth callback URL
 *     'https://apis.roblox.com/oauth/.well-known/openid-configuration'
 * );
 * 
 * // Step 1: Generate login URL and redirect user
 * if (!$oauth->checkLoggedIn()) {
 *     $authUrl = $oauth->getAuthUrl();
 *     header("Location: $authUrl");
 *     exit();
 * }
 * 
 * // Step 2: Handle callback (in your callback endpoint)
 * if (isset($_GET['code'])) {
 *     $oauth->handleOAuthCallback();
 * }
 * 
 * // Step 3: Use authenticated user data
 * if ($oauth->checkLoggedIn()) {
 *     $claims = $oauth->getClaims();
 *     $userGroups = $oauth->getUserGroups();
 *     $groupRank = $oauth->getGroupRank($userGroups['data'], 123456);
 *     
 *     echo "Welcome, " . $claims['preferred_username'];
 *     echo "Your rank in group 123456 is: " . $groupRank;
 * }
 * ```
 * 
 * @example Group Rank Checking:
 * ```php
 * // Check if user has minimum rank in a specific group
 * $userGroups = $oauth->getUserGroups();
 * $requiredGroupId = 123456;
 * $minimumRank = 100;
 * 
 * $userRank = $oauth->getGroupRank($userGroups['data'], $requiredGroupId);
 * if ($userRank >= $minimumRank) {
 *     echo "Access granted! User has rank $userRank";
 * } else {
 *     echo "Access denied. Minimum rank required: $minimumRank";
 * }
 * ```
 */

class RobloxOAuthSDK
{
    private $clientId;
    private $clientSecret;
    private $redirectUri;
    private $discoveryUrl; // Roblox discovery URL is; https://apis.roblox.com/oauth/.well-known/openid-configuration
    private $tokenSet;
    private $home_page;

    public function __construct($home_page, $clientId, $clientSecret, $redirectUri, $discoveryUrl)
    {
        $this->home_page = $home_page;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->discoveryUrl = $discoveryUrl;
        session_start();
    }

    private function httpRequest($url, $method = 'GET', $data = null, $headers = [])
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($data) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        }

        if (!empty($headers)) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($ch);

        if (curl_error($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception("HTTP Request error: " . $error);
        }

        curl_close($ch);
        return $response;
    }

    private function discoverOAuthConfig()
    {
        $response = $this->httpRequest($this->discoveryUrl);
        return json_decode($response, true);
    }

    public function getAuthUrl()
    {
        $oauthConfig = $this->discoverOAuthConfig();
        $authUrl = $oauthConfig['authorization_endpoint'];
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth2state'] = $state;

        $authUrl .= '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid profile group:read', // user.advanced:read user.social:read',
            'state' => $state,
        ]);

        return $authUrl;
    }

    public function handleOAuthCallback()
    {
        $oauthConfig = $this->discoverOAuthConfig();
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $_GET['code'],
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $response = $this->httpRequest(
            $oauthConfig['token_endpoint'], 
            'POST', 
            http_build_query($params), 
            ['Content-Type: application/x-www-form-urlencoded']
        );

        $this->tokenSet = json_decode($response, true);
        $_SESSION['tokenSet'] = $this->tokenSet;

        header("Location: $this->home_page");
        exit();
    }

    public function checkLoggedIn()
    {
        return isset($_SESSION['tokenSet']);
    }

    public function getTokenSet()
    {
        return $this->tokenSet ?? $_SESSION['tokenSet'];
    }

    public function getClaims()
    {
        $tokenSet = $this->getTokenSet();
        return json_decode(base64_decode(explode('.', $tokenSet['id_token'])[1]), true);
    }

    public function getGroupRank($groupsJson, $groupId): int
    {
        if (!is_array($groupsJson))
            throw new InvalidArgumentException("Invalid groups data provided.");

        foreach ($groupsJson as $groupData) {
            if (!isset($groupData['group']['id'], $groupData['role']['rank']))
                continue;

            if ((int) $groupData['group']['id'] === (int) $groupId) return (int) $groupData['role']['rank']; // Return the rank directly 
        }

        return 0;
    }

    public function getUserGroups()
    {
        $tokenSet = $this->getTokenSet();
        if (!$tokenSet || !isset($tokenSet['access_token']))
            throw new Exception("No valid token set found. User may not be logged in.");

        $claims = $this->getClaims();
        if (!isset($claims['sub']))
            throw new Exception("Cannot find user ID in ID token claims.");

        $userId = $claims['sub'];
        $groupsUrl = "https://groups.roblox.com/v1/users/{$userId}/groups/roles";

        $headers = [
            "Authorization: Bearer {$tokenSet['access_token']}",
            "Accept: application/json"
        ];

        $response = $this->httpRequest($groupsUrl, 'GET', null, $headers);

        if ($response === false)
            throw new Exception("Failed to fetch user groups.");
        return json_decode($response, true);
    }
}
