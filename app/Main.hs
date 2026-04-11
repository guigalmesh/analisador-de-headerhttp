import Web.Scotty(get, text, scotty)

main :: IO ()
main = scotty 3000 $ do

    get "/analisador" $ do
        text "Teste do analisador"
