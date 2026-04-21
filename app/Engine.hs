{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}

module Engine
    ( evaluateHeader
    , securityHeaders
    ) where

import Types
import Data.Text(Text, isInfixOf, toLower)

-- lista com todos os headers que eu achei usar depois para aumentar a complexidade
--securityHeaders :: [Text]
--securityHeaders = ["x-frame-options", "x-xss-protection", "x-content-type-options", "referrer-policy", "content-type",
--    "cache-control", "set-cookie", "strict-transport-security", "expect-ct", "content-security-policy",
--    "access-control-allow-origin", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
--    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-robots-tag", "permissions-policy",
--    "x-dns-prefetch-control", "public-key-pins", "access-control-allow-credentials", "access-control-allow-methods", "www-authenticate"]


securityHeaders :: [Text]
securityHeaders =
    [ "strict-transport-security"
    , "content-security-policy"
    , "x-frame-options"
    , "x-xss-protection"
    , "x-content-type-options"
    , "referrer-policy"
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


