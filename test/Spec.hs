{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Test.HUnit
import qualified Data.Text as T
import Engine (evaluateHeader, securityHeaders)
import Types (SecurityStatus(..), HeaderAnalysis(..))
import qualified DBHelper as DBHelper
import System.IO.Temp (withSystemTempDirectory)
import System.Directory (setCurrentDirectory, getCurrentDirectory)
import System.Exit (exitFailure)


test_x_content_type_nosniff :: Test
test_x_content_type_nosniff = TestCase $
	assertEqual "x-content-type-options nosniff should be Secure"
		Secure
		(status (evaluateHeader "x-content-type-options" (Just "nosniff")))

test_csp_unsafe_inline :: Test
test_csp_unsafe_inline = TestCase $
	assertEqual "CSP with unsafe-inline should be Vulnerable"
		Vulnerable
		(status (evaluateHeader "content-security-policy" (Just "default-src 'self'; script-src 'unsafe-inline'")))

test_security_headers_list :: Test
test_security_headers_list = TestCase $
	assertBool "securityHeaders should contain strict-transport-security" ("strict-transport-security" `elem` securityHeaders)

test_main_db :: Test
test_main_db = TestCase $ withSystemTempDirectory "histTest" $ \dir -> do
	oldCwd <- getCurrentDirectory
	setCurrentDirectory dir
	DBHelper.initDB
	DBHelper.saveToHistory "http://example.test" "A" "summary"
	rows <- DBHelper.getHistory
	setCurrentDirectory oldCwd
	assertBool "history should contain at least one row" (not (null rows))

tests :: Test
tests = TestList
	[ TestLabel "X-Content-Type Options" test_x_content_type_nosniff
	, TestLabel "CSP Unsafe Inline" test_csp_unsafe_inline
	, TestLabel "Security Headers List" test_security_headers_list
	, TestLabel "Main DB Integration" test_main_db
	]


main :: IO ()
main = do
	counts <- runTestTT tests
	if errors counts + failures counts > 0
		then exitFailure
		else return ()
