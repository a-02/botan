import           Test.Tasty.Bench

import           Prelude

import           Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

import qualified Botan.Low.Bcrypt as Botan
import qualified Botan.Low.RNG as Botan

import qualified Botan.Low.PubKey as Botan
-- import qualified Botan.Low.PubKey.Decrypt as Botan
import qualified Botan.Low.PubKey.Encrypt as Botan

import qualified Crypto.Hash as Crypton
import qualified Crypto.KDF.BCrypt as Crypton

password :: ByteString
password = "Fee fi fo fum!"

cryptonBcrypt :: Int -> IO ByteString
cryptonBcrypt factor = Crypton.hashPassword factor password

botanBcrypt :: Int -> IO ByteString
botanBcrypt factor = do
    rng <- Botan.rngInit "system"
    Botan.bcryptGenerate password rng factor

botanEncrypt :: Int -> IO ByteString
botanEncrypt n = do
    rng <- Botan.rngInit "system"
    privKey <- Botan.privKeyCreate Botan.RSA "2048" rng
    pubKey <- Botan.privKeyExportPubKey privKey
    enc <- Botan.encryptCreate pubKey Botan.EME_PKCS1_v1_5
    Botan.encrypt enc rng (ByteString.replicate n 1)

botanEncryptTrim :: Int -> IO ByteString
botanEncryptTrim n = do
    rng <- Botan.rngInit "system"
    privKey <- Botan.privKeyCreate Botan.RSA "2048" rng
    pubKey <- Botan.privKeyExportPubKey privKey
    enc <- Botan.encryptCreate pubKey Botan.EME_PKCS1_v1_5
    Botan.encryptTrim enc rng (ByteString.replicate n 1)

plaintext :: ByteString
plaintext = "Fee fi fo fum! I smell the blood of an Englishman! Be he alive or be he dead, I'll grind his bones to make my bread!"

longtext :: ByteString
longtext = ByteString.concat $ replicate 10000 plaintext

cryptonHash :: ByteString -> Crypton.Digest Crypton.SHA3_512
cryptonHash = Crypton.hash

-- TODO: hashWithName is not exposed from Botan.Low.Hash. See issue #34.
{- botanHash :: ByteString -> IO Botan.HashDigest
   botanHash = Botan.hashWithName "SHA-3(512)"
-}

main :: IO ()
main = defaultMain
    [ bgroup "Bcrypt work factor"
        [ bgroup "Crypton"
            [ bench "twelve"    $ nfIO $ cryptonBcrypt 12
            , bench "fourteen"  $ nfIO $ cryptonBcrypt 14
            , bench "sixteen"   $ nfIO $ cryptonBcrypt 16
            ]
        , bgroup "Botan"
            [ bench "twelve"    $ nfIO $ botanBcrypt 12
            , bench "fourteen"  $ nfIO $ botanBcrypt 14
            , bench "sixteen"   $ nfIO $ botanBcrypt 16
            ]
        ]
    , bgroup "Hash"
        [ bgroup "Crypton"
            [ bench "password"  $ nf cryptonHash password
            , bench "plaintext" $ nf cryptonHash plaintext
            , bench "longtext" $ nf cryptonHash longtext
            ]
        ]
    , bgroup "Encrypt"
        [ bgroup "createUpToN"
            [ bench "1"  $ nfIO $ botanEncrypt 1
            , bench "10"  $ nfIO $ botanEncrypt 10
            , bench "100"  $ nfIO $ botanEncrypt 100
            ]
        , bgroup "createAndTrim"
            [ bench "1"  $ nfIO $ botanEncryptTrim 1
            , bench "10"  $ nfIO $ botanEncryptTrim 10
            , bench "100"  $ nfIO $ botanEncryptTrim 100
            ]
        -- TODO: hashWithName is not exposed from Botan.Low.Hash. See issue #34.
        {- , bgroup "Botan"
            [ bench "password"  $ nfIO $ botanHash password
            , bench "plaintext" $ nfIO $ botanHash plaintext
            , bench "longtext" $ nfIO $ botanHash longtext
            ]
        -}
        ]
    ]

