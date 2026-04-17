{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

import Web.Scotty(scotty, post, jsonData, json)
import Data.Text (Text, unpack, toLower)
import Data.Text.Encoding(decodeUtf8)
import Data.CaseInsensitive(original)
import Data.Aeson
import GHC.Generics
import Network.HTTP.Simple(parseRequest, httpNoBody, setRequestMethod, getResponseHeaders)
import Network.HTTP.Types.Header(HeaderName)
import Control.Monad.IO.Class(liftIO)
import Data.ByteString(ByteString)
import Data.Bifunctor

newtype TargetURL = 
    TargetURL {url :: Text} 
    deriving (Show, Generic)

instance FromJSON TargetURL

-- acho que essa lista pode ser melhorada com mais opções
securityHeaders :: [Text]
securityHeaders = ["x-frame-options", "x-xss-protection", "x-content-type-options", "referrer-policy", "content-type", 
    "cache-control", "set-cookie", "strict-transport-security", "expect-ct", "content-security-policy", 
    "access-control-allow-origin", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-robots-tag", "permissions-policy", 
    "x-dns-prefetch-control", "public-key-pins", "access-control-allow-credentials", "access-control-allow-methods", "www-authenticate"]

translateHeaderByteStringToText :: [(HeaderName, ByteString)] -> [(Text, Text)]
translateHeaderByteStringToText = map processTuple
    where
        processTuple = bimap (toLower . decodeUtf8 . original) decodeUtf8

securityHeadersPresentInSite :: [(Text, Text)] -> [(Text, Text)]
securityHeadersPresentInSite = filter (\(h, _) ->  h `elem` securityHeaders)

main :: IO ()
main = scotty 3000 $ do

    post "/analisador" $ do
        receivedData <- jsonData

        let linkString = unpack $ url receivedData

        requestRaw <- parseRequest linkString

        let request = setRequestMethod "HEAD" requestRaw

        response <- liftIO $ httpNoBody request

        let siteSecurityHeaders = securityHeadersPresentInSite $ translateHeaderByteStringToText $ getResponseHeaders response

        json siteSecurityHeaders