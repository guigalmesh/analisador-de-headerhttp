{-# LANGUAGE OverloadedStrings #-}


import Database.SQLite.Simple
import Data.Time.Clock (getCurrentTime)
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
import Network.Wai.Middleware.Cors(cors, simpleCorsResourcePolicy, corsRequestHeaders)
import Network.Wai (Middleware)
import Types
    ( ErrorReport(ErrorReport),
      SecurityReport(SecurityReport, results),
      TargetURL(url),
      HistoryPayload(scannedURL, grade, summary) )
import Engine

initDB :: IO ()
initDB = do
    conn <- open "history.db"
    execute_ conn "CREATE TABLE IF NOT EXISTS history (targetUrl TEXT PRIMARY KEY, scan_date TEXT, grade TEXT, summary TEXT)"
    close conn

saveToHistory :: String -> String -> String -> IO ()
saveToHistory targetUrl gradeVal summaryVal = do
    conn <- open "history.db"
    currentTime <- show <$> getCurrentTime
    execute conn "INSERT OR REPLACE INTO history (targetUrl, scan_date, grade, summary) VALUES (?, ?, ?, ?)"
        (targetUrl, currentTime, gradeVal, summaryVal)
    close conn

getHistory :: IO [(String, String, String, String)]
getHistory = do
    conn <- open "history.db"
    rows <- query_ conn "SELECT targetUrl, scan_date, grade, summary FROM history ORDER BY scan_date DESC" :: IO [(String, String, String, String)]
    close conn
    return rows

translateHeaderByteStringToText :: [(HeaderName, ByteString)] -> [(Text, Text)]
translateHeaderByteStringToText = map (bimap (toLower . decodeUtf8 . original) decodeUtf8)

corsPolicy :: Middleware
corsPolicy = cors (const $ Just policy)
    where
        policy = simpleCorsResourcePolicy
            { corsRequestHeaders = ["Content-Type"] }

main :: IO ()
main = do
    initDB

    scotty 3000 $ do

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
