{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

import Web.Scotty(scotty, post, jsonData, json, ActionM, status)
import Data.Text (Text, unpack, toLower, pack)
import Data.Text.Encoding(decodeUtf8)
import Data.CaseInsensitive(original)
import Data.Aeson
import Data.List((\\))
import GHC.Generics
import Network.HTTP.Simple(parseRequest, httpNoBody, setRequestMethod, getResponseHeaders, Response)
import Network.HTTP.Types.Header(HeaderName)
import Control.Monad.IO.Class(liftIO)
import Data.ByteString(ByteString)
import Data.Bifunctor
import qualified Data.Map as Map
import Control.Exception(try, SomeException)
import Network.HTTP.Types.Status(status500)
import Network.Wai.Middleware.Cors(simpleCors)

newtype TargetURL = 
    TargetURL {url :: Text} 
    deriving (Show, Generic)

instance FromJSON TargetURL

data SecurityReport = SecurityReport 
    { present :: Map.Map Text Text
    , missing :: [Text]
    } deriving (Show, Generic)

instance ToJSON SecurityReport

data ErrorReport = ErrorReport
    { erro :: Text
    , detalhes :: Text
    } deriving(Show, Generic)

instance ToJSON ErrorReport

securityHeaders :: [Text]
securityHeaders = ["x-frame-options", "x-xss-protection", "x-content-type-options", "referrer-policy", "content-type", 
    "cache-control", "set-cookie", "strict-transport-security", "expect-ct", "content-security-policy", 
    "access-control-allow-origin", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-robots-tag", "permissions-policy", 
    "x-dns-prefetch-control", "public-key-pins", "access-control-allow-credentials", "access-control-allow-methods", "www-authenticate"]

translateHeaderByteStringToText :: [(HeaderName, ByteString)] -> [(Text, Text)]
translateHeaderByteStringToText = map (bimap (toLower . decodeUtf8 . original) decodeUtf8)

filterSecurityHeadersPresent:: [(Text, Text)] -> [(Text, Text)]
filterSecurityHeadersPresent = filter (\(h, _) ->  h `elem` securityHeaders)

main :: IO ()
main = scotty 3000 $ do

    post "/analisador" $ do
        receivedData <- jsonData

        let linkString = unpack $ url receivedData

        requestRaw <- parseRequest linkString

        let request = setRequestMethod "HEAD" requestRaw

        result <- liftIO $ try (httpNoBody request) :: ActionM (Either SomeException (Response ()))

        case result of
            Left exception -> do
                status status500
                let errorMessage = ErrorReport "Failure at communicating with target" (pack $ show exception)
                json errorMessage

            Right response -> do
                let securityHeadersList = filterSecurityHeadersPresent $ translateHeaderByteStringToText $ getResponseHeaders response
                let dictionaryJSON = Map.fromList securityHeadersList
                let missingKeys = securityHeaders \\ Map.keys dictionaryJSON

                let finalReport = SecurityReport dictionaryJSON missingKeys
                json finalReport