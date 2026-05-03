{-# LANGUAGE OverloadedStrings #-}

module DBHelper
    ( initDB
    , saveToHistory
    , getHistory
    , getRanking
    ) where

import Database.SQLite.Simple
import Data.Time.Clock (getCurrentTime)

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

getRanking :: IO [(String, String, String)]
getRanking = do
    conn <- open "history.db"
    rows <- query_ conn "SELECT targetUrl, grade, scan_date FROM history GROUP BY targetUrl ORDER BY grade ASC, scan_date DESC"
    close conn
    return rows
