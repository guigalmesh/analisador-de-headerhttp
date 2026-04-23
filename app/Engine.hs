{-# LANGUAGE OverloadedStrings #-}

module Engine
    ( evaluateHeader
    , securityHeaders
    ) where

import Types
import Data.Text(Text, isInfixOf, toLower)

securityHeaders :: [Text]
securityHeaders =
    [ "strict-transport-security"
    , "content-security-policy"
    , "x-frame-options"
    , "x-xss-protection"
    , "x-content-type-options"
    , "referrer-policy"
    , "set-cookie"
    , "access-control-allow-origin"
    , "access-control-allow-credentials"
    , "cross-origin-opener-policy"
    , "cross-origin-embedder-policy"
    , "cross-origin-resource-policy"
    , "permissions-policy"
    , "server"
    , "x-powered-by"
    , "x-aspnet-version"
    , "x-aspnetmvc-version"
    ]

evaluateHeader :: Text -> Maybe Text -> HeaderAnalysis
evaluateHeader name mValue = case name of

    "strict-transport-security" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Enforces secure (HTTP over SSL/TLS) connections to the server."
        , vulnerability = "Man-in-the-Middle (MitM) attacks and protocol downgrade."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | "max-age=0" `isInfixOf` toLower val -> Vulnerable
                | otherwise                           -> Secure
        }

    "content-security-policy" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Restricts the resources (such as JavaScript, CSS) that the browser is allowed to load."
        , vulnerability = "Cross-Site Scripting (XSS) and Data Injection attacks."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | "unsafe-inline" `isInfixOf` toLower val -> Vulnerable
                | "unsafe-eval"   `isInfixOf` toLower val -> Vulnerable
                | "*"             `isInfixOf` val         -> Vulnerable
                | otherwise                               -> Secure
        }

    "x-frame-options" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Protects visitors against clickjacking attacks by restricting iframe rendering."
        , vulnerability = "Clickjacking (UI redressing)."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | toLower val == "deny"       -> Secure
                | toLower val == "sameorigin" -> Secure
                | otherwise                   -> Vulnerable
        }

    "x-xss-protection" -> HeaderAnalysis
        { headerName = name
        , severity = Other
        , description = "Legacy header used to configure the built-in reflected XSS filter of older browsers."
        , vulnerability = "Cross-Site Scripting (XSS). Largely obsolete; modern defense relies entirely on CSP."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | "0" `isInfixOf`val -> Secure
                | otherwise          -> Vulnerable
        }

    "x-content-type-options" -> HeaderAnalysis
        { headerName = name
        , severity = Recommended
        , description = "Prevents the browser from MIME-sniffing a response away from the declared content-type."
        , vulnerability = "MIME-sniffing attacks (which can lead to Cross-Site Scripting)."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | toLower val == "nosniff" -> Secure
                | otherwise                -> Vulnerable
        }

    "referrer-policy" -> HeaderAnalysis
        { headerName = name
        , severity = Recommended
        , description = "Controls how much referrer information (the URL of the current page) is included with requests."
        , vulnerability = "Information leakage (exposing sensitive URLs or session tokens to third parties)."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | "unsafe-url" `isInfixOf` toLower val -> Vulnerable
                | otherwise                            -> Secure
        }

    "set-cookie" -> HeaderAnalysis
        { headerName = name
        , severity = Recommended
        , description = "Manages session state and cookies. Missing security flags expose session tokens to theft or unauthorized cross-site usage."
        , vulnerability = "Session hijacking (via XSS), Cross-Site Request Forgery (CSRF), Credential Interception (MitM)."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | hasHttpOnly && hasSecure && hasSameSite -> Secure
                | otherwise                               -> Vulnerable
                where
                    lowerVal = toLower val
                    hasHttpOnly = "httponly" `isInfixOf` lowerVal
                    hasSecure = "secure" `isInfixOf` lowerVal
                    hasSameSite = "samesite" `isInfixOf` lowerVal
        }

    "access-control-allow-origin" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Restricts which external domains can read the server's HTTP responses. A wildcard (*) or 'null' origin allows malicious websites to steal data via the victim's browser. If it is missing the site is protected by default"
        , vulnerability = "Unauthorized cross-origin data reading and sensitive information leakage."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                |val == "*"     -> Vulnerable
                | val == "null" -> Vulnerable
                | otherwise     -> Secure
        }

    "access-control-allow-credentials" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Authenticated cross-origin data theft. If paired with a permissive Origin, attackers can steal data acting as the logged-in victim."
        , vulnerability = "Permits the browser to include credentials (cookies, authorization headers, TLS certificates) in cross-origin requests."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | toLower val == "true" -> Secure
                | otherwise             -> Vulnerable
        }

    "cross-origin-opener-policy" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Ensures the application runs in an isolated browsing context, preventing other documents from sharing its rendering process."
        , vulnerability = "Side-channel attacks (like Spectre) and cross-window state leaks."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | toLower val == "same-origin" -> Secure
                | otherwise                    -> Vulnerable
        }

    "cross-origin-embedder-policy" -> HeaderAnalysis
        { headerName = name
        , severity = Critical
        , description = "Prevents a document from loading any cross-origin resources that don't explicitly grant the document permission."
        , vulnerability = "Cross-origin information leaks and side-channel attacks when embedding third-party resources."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | toLower val == "require-corp" -> Secure
                | otherwise                     -> Vulnerable
        }

    "cross-origin-resource-policy" -> HeaderAnalysis
        { headerName = name
        , severity = Recommended
        , description = "Defines a policy that lets web sites opt in to protection against certain requests from other origins."
        , vulnerability = "Cross-site leaks and side-channel attacks (like Spectre) against static resources."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just val
                | toLower val == "same-origin" -> Secure
                | toLower val == "same-site"   -> Secure
                | otherwise                    -> Vulnerable
        }

    "permissions-policy" -> HeaderAnalysis
        { headerName = name
        , severity = Recommended
        , description = "Allows a site to control which browser features and APIs (e.g., camera, microphone, geolocation) can be used."
        , vulnerability = "Unauthorized use of powerful browser features by malicious third-party scripts or embedded iframes."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just _  -> Secure
        }

    "server" -> HeaderAnalysis
        { headerName = name
        , severity = Other
        , description = "Contains information about the software used by the origin server (e.g., Apache, Nginx)."
        , vulnerability = "Information Disclosure. Facilitates targeted exploitation by revealing server software and exact versions."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Secure
            Just _  -> Vulnerable
        }

    "x-powered-by" -> HeaderAnalysis
        { headerName = name
        , severity = Other
        , description = "May contain information about the server-side technologies (e.g., PHP, Express) supporting the application."
        , vulnerability = "Information Disclosure. Aids attackers in fingerprinting the backend stack to search for CVEs."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Secure
            Just _  -> Vulnerable
        }

    "x-aspnet-version" -> HeaderAnalysis
        { headerName = name
        , severity = Other
        , description = "Reveals the specific version of ASP.NET running on the server."
        , vulnerability = "Information Disclosure. Exposes the Microsoft technology stack version."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Secure
            Just _  -> Vulnerable
        }

    "x-aspnetmvc-version" -> HeaderAnalysis
        { headerName = name
        , severity = Other
        , description = "Reveals the specific version of ASP.NET MVC running on the server."
        , vulnerability = "Information Disclosure. Exposes the Microsoft MVC framework version."
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Secure
            Just _  -> Vulnerable
        }

    _ -> HeaderAnalysis
        { headerName = name
        , severity = Other
        , description = "Security header pending detailed rule mapping."
        , vulnerability = "Unknown"
        , foundValue = mValue
        , status = case mValue of
            Nothing -> Missing
            Just _  -> Secure
        }
