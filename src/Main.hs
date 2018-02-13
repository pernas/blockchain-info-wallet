{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Lens
import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error
import           Crypto.KDF.PBKDF2
import qualified Data.Aeson                 as Aeson
import           Data.Aeson.Encode.Pretty
import           Data.Aeson.Lens
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as ByteString
import qualified Data.ByteString.Base64     as Base64
import qualified Data.ByteString.Char8      as Char8
import qualified Data.ByteString.Lazy       as Lazy
import qualified Data.ByteString.Lazy.Char8 as LazyChar8
import           Data.Either
import           Data.Text                  (Text)
import qualified Data.Text.Encoding         as Encoding
import           Foundation
import           Foundation.Monad
import           Network.Wreq
import           System.Console.Haskeline

url = "https://blockchain.info/"

stretchPassword :: Int -> ByteString -> LString -> ByteString
stretchPassword iterations salt password =
    fastPBKDF2_SHA1 (Parameters iterations 32) (Char8.pack password) salt

decodeB64 :: Text -> Maybe ByteString
decodeB64 base64String = either
    (const Nothing)
    return
    (Base64.decode $ Encoding.encodeUtf8 base64String)

decrypt :: Int -> LString -> Text -> Maybe Aeson.Value
decrypt iterations password payload64 = do
    payloadWithSalt <- decodeB64 payload64
    let (salt, payload) = ByteString.splitAt 16 payloadWithSalt
    let key             = stretchPassword iterations salt password
    iv  <- makeIV salt
    aes <- case cipherInit key of
        CryptoPassed a -> return (a :: AES256)
        CryptoFailed e -> Nothing
    let decrypted = cbcDecrypt aes iv payload
    let len       = ByteString.length decrypted
    let pad       = fromIntegral (ByteString.last decrypted)
    let chomped   = ByteString.take (len - pad) decrypted
    Aeson.decode (Lazy.fromStrict chomped)

decryptWrapper :: AsValue s => LString -> s -> Maybe Aeson.Value
decryptWrapper password wrapper = do
    version    <- wrapper ^? key "version" . _Integer -- TODO: Handle versions
    payload    <- wrapper ^? key "payload" . _String
    iterations <- fromIntegral <$> wrapper ^? key "pbkdf2_iterations" . _Integer
    decrypt iterations password payload

fetchWallet :: LString -> LString -> IO (Response LazyChar8.ByteString)
fetchWallet guid skey = post
    (url <> "wallet")
    [ "method" := ("wallet.aes.json" :: LString)
    , "format" := ("json" :: LString)
    , "sharedKey" := skey
    , "guid" := guid
    ]

readArguments :: IO (LString, LString, LString)
readArguments = do
    args <- getArgs
    guid <- case args of
        [guid] -> return $ toList guid
        _      -> error "No GUID provided"
    skeyM <- runInputT defaultSettings (getPassword (Just '*') "SKey: ")
    skey  <- case skeyM of
        Nothing -> error "No SKey provided"
        Just s  -> return s
    passM <- runInputT defaultSettings (getPassword (Just '*') "Password: ")
    pass  <- case passM of
        Nothing -> error "No password provided"
        Just p  -> return p
    return (guid, skey, pass)

main = do
    (guid, skey, pass) <- readArguments
    response           <- fetchWallet guid skey
    let valM = do
            wrapper <- response ^? responseBody . key "payload" . _String
            decryptWrapper pass wrapper
    case valM of
        Nothing  -> error ":: Wallet Fetch Failed ::"
        Just val -> LazyChar8.putStrLn (encodePretty val)
