{-# LANGUAGE OverloadedStrings #-}

import Web.Scotty(scotty, post, jsonData, json, ActionM, middleware)
import qualified Web.Scotty as Scotty
import Data.Text (Text, unpack, toLower, pack)
import Data.Text.Encoding(decodeUtf8)
import Data.CaseInsensitive(original)
import Network.HTTP.Simple(parseRequest, httpNoBody, setRequestMethod, getResponseHeaders, Response)
import Network.HTTP.Types.Header(HeaderName)
import Control.Monad.IO.Class(liftIO)
import Data.ByteString(ByteString)
import Data.Bifunctor
import Control.Exception(try, SomeException)
import Network.HTTP.Types.Status(status500)
import Network.Wai.Middleware.Cors(cors, simpleCorsResourcePolicy, corsRequestHeaders)
import Network.Wai (Middleware)
import Types
import Engine

translateHeaderByteStringToText :: [(HeaderName, ByteString)] -> [(Text, Text)]
translateHeaderByteStringToText = map (bimap (toLower . decodeUtf8 . original) decodeUtf8)

corsPolicy :: Middleware
corsPolicy = cors (const $ Just policy)
    where
        policy = simpleCorsResourcePolicy
            { corsRequestHeaders = ["Content-Type"] }

main :: IO ()
main = scotty 3000 $ do
    middleware corsPolicy

    post "/analisador" $ do
        receivedData <- jsonData

        let linkString = unpack $ url receivedData

        requestRaw <- parseRequest linkString

        let request = setRequestMethod "HEAD" requestRaw

        result <- liftIO $ try (httpNoBody request) :: ActionM (Either SomeException (Response ()))

        case result of
            Left exception -> do
                Scotty.status status500
                let errorMessage = ErrorReport "Failure at communicating with target" (pack $ show exception)
                json errorMessage

            Right response -> do
                let allHeaders = translateHeaderByteStringToText $ getResponseHeaders response
                let analyzeHeaders = map (\header -> let value = lookup header allHeaders in evaluateHeader header value) securityHeaders
                let finalReport = SecurityReport { results = analyzeHeaders}

                json finalReport
