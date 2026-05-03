{-# LANGUAGE OverloadedStrings #-}

module Main
    ( translateHeaderByteStringToText
    , corsPolicy
    , main
    ) where

import DBHelper (initDB, saveToHistory, getHistory, getRanking)
import System.Environment (lookupEnv)
import Web.Scotty(scotty, post, jsonData, json, ActionM, middleware, text, get)
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
import Network.Wai.Middleware.Cors(cors, simpleCorsResourcePolicy, corsRequestHeaders, corsOrigins)
import Network.Wai (Middleware)
import Types
    ( ErrorReport(ErrorReport),
      SecurityReport(SecurityReport, results),
      TargetURL(url),
      HistoryPayload(scannedURL, grade, summary) )
import Engine

translateHeaderByteStringToText :: [(HeaderName, ByteString)] -> [(Text, Text)]
translateHeaderByteStringToText = map (bimap (toLower . decodeUtf8 . original) decodeUtf8)

corsPolicy :: Middleware
corsPolicy = cors (const $ Just policy)
    where
        policy = simpleCorsResourcePolicy
            { corsOrigins = Just (["https://headerreport.onrender.com"], True)
            , corsRequestHeaders = ["Content-Type"] }

main :: IO ()
main = do
    initDB

    portStr <- lookupEnv "PORT"

    let porta = case portStr of
            Just p -> read p
            Nothing -> 3000

    scotty porta $ do

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

        post "/api/history" $ do
            payload <- jsonData :: ActionM HistoryPayload

            let target = scannedURL payload
            let gradeData = grade payload
            let summaryData = summary payload

            liftIO $ saveToHistory target gradeData summaryData
            text "Saved successfully"

        get "/api/history" $ do
            historyList <- liftIO getHistory
            json historyList

        get "/api/ranking" $ do
            rows <- liftIO getRanking
            json rows
