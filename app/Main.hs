{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Main where

import Crypto.Random.Types qualified as Crypto
import Data.ByteString (ByteString)
import Data.Functor.Rep (tabulate)
import Data.Maybe (fromMaybe)
import Data.OpenApi (NamedSchema (..), ToSchema (..))
import Data.Yaml (FromJSON)
import Data.Yaml.Aeson (decodeFileThrow)
import GHC.Generics
import GHC.TypeNats (KnownNat, type (+), type (^))
import Options.Applicative
import System.IO.Unsafe
import ZkFold.Algebra.Class
import ZkFold.Data.Binary (fromByteString)
import ZkFold.Protocol.NonInteractiveProof (TrustedSetup)
import ZkFold.Protocol.NonInteractiveProof.TrustedSetup (powersOfTauSubset)
import ZkFold.Protocol.Plonkup.Prover.Secret (PlonkupProverSecret (..))
import ZkFold.Prover.API.Server
import ZkFold.Prover.API.Types.ProveAlgorithm (ProveAlgorithm (proveAlgorithm))
import ZkFold.Symbolic.Ledger.Circuit.Compile (
  ByteStringFromHex,
  LedgerCircuitGates,
  LedgerContractInput,
  ZKF (..),
  ZKProofBytes,
  ledgerCircuit,
  ledgerProof,
  mkProof,
 )
import ZkFold.Symbolic.Ledger.Types (SignatureState, SignatureTransactionBatch)
import Prelude hiding (Bool, (==))

configPathParser ∷ Parser FilePath
configPathParser =
  option
    str
    ( long "config"
        <> help "Path to server configuration yaml file"
        <> showDefault
        <> value "./rollup-prover-config.yaml"
        <> metavar "PATH"
    )

deriving newtype instance ToSchema ZKF

-- instance ∀ bi bo ud a i o t c. (SignatureState bi bo ud a c, SignatureTransactionBatch ud i o a t c, KnownNat ud) => ToSchema (LedgerContractInput bi bo ud a i o t c)

instance ToSchema ByteStringFromHex where
  declareNamedSchema _ = do
    pure $ NamedSchema (Just "Byte string in hex encoding") mempty

instance ToSchema ZKProofBytes

ts ∷ TrustedSetup (LedgerCircuitGates + 6)
{-# NOINLINE ts #-}
ts = unsafePerformIO powersOfTauSubset

instance ∀ bi bo ud a i o t c. ProveAlgorithm (LedgerContractInput bi bo ud a i o t c) ZKProofBytes where
  proveAlgorithm zkProofInput = proofBytes
   where
    randomFieldElement = fromMaybe zero . fromByteString <$> Crypto.getRandomBytes 32
    proverSecret = PlonkupProverSecret <$> sequence (tabulate $ const randomFieldElement)
    !proofBytes = mkProof $ ledgerProof @ByteString ts (unsafePerformIO proverSecret) ledgerCircuit zkProofInput

deriving instance Generic ServerConfig

instance FromJSON ServerConfig

main ∷ ∀ bi bo ud a i o t c. IO ()
main = do
  serverConfigPath ← execParser opts
  print serverConfigPath
  serverConfig ← decodeFileThrow serverConfigPath
  print @String ("Started with " <> show serverConfig)
  runServer @(LedgerContractInput bi bo ud a i o t c) @ZKProofBytes serverConfig
 where
  opts =
    info
      (configPathParser <**> helper)
      ( fullDesc
          <> progDesc "Rollup prover"
          <> header "zkFold's Rollup prover server"
      )
