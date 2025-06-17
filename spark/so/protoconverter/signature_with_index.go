package protoconverter

import (
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
)

func SparkSignatureWithIndexFromTokenProto(sig *tokenpb.SignatureWithIndex) *sparkpb.SignatureWithIndex {
	if sig == nil {
		return nil
	}
	return &sparkpb.SignatureWithIndex{
		Signature:  sig.Signature,
		InputIndex: sig.InputIndex,
	}
}
