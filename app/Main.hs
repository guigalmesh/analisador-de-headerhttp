{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

import Web.Scotty(scotty, post, jsonData, json)
import Data.Text (Text, unpack )
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

translateHeaderByteStringToText :: [(HeaderName, ByteString)] -> [(Text, Text)]
translateHeaderByteStringToText = map processTuple
    where
        processTuple = bimap (decodeUtf8 . original) decodeUtf8

main :: IO ()
main = scotty 3000 $ do

    post "/analisador" $ do
        receivedData <- jsonData

        let linkString = unpack $ url receivedData

        requestRaw <- parseRequest linkString

        let request = setRequestMethod "HEAD" requestRaw

        response <- liftIO $ httpNoBody request

        let siteHeaders = translateHeaderByteStringToText $ getResponseHeaders response

        json siteHeaders