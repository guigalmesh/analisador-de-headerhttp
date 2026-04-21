{-# LANGUAGE DeriveGeneric #-}

module Types
    ( TargetURL(..)
    , Severity(..)
    , SecurityStatus(..)
    , HeaderAnalysis(..)
    , SecurityReport(..)
    , ErrorReport(..)
    ) where

import Data.Text (Text)
import Data.Aeson (ToJSON, FromJSON)
import GHC.Generics (Generic)

newtype TargetURL =
    TargetURL {url :: Text}
    deriving (Show, Generic)
instance FromJSON TargetURL

data Severity = Critical | Recommended | Other
    deriving (Show, Generic, Eq)
instance ToJSON Severity

data SecurityStatus = Secure | Vulnerable | Missing
    deriving (Show, Generic, Eq)
instance ToJSON SecurityStatus

data HeaderAnalysis = HeaderAnalysis
    { headerName      :: Text
    , status          :: SecurityStatus
    , severity        :: Severity
    , foundValue      :: Maybe Text
    , description     :: Text
    , vulnerability   :: Text
    } deriving (Show, Generic)
instance ToJSON HeaderAnalysis

newtype SecurityReport = SecurityReport
    { results :: [HeaderAnalysis]
    } deriving (Show, Generic)
instance ToJSON SecurityReport

data ErrorReport = ErrorReport
    { error :: Text
    , details :: Text
    } deriving (Show, Generic)
instance ToJSON ErrorReport
