// Code generated by pg-bindings generator. DO NOT EDIT.
package schema

import (
	"github.com/stackrox/rox/generated/storage"
)

// ConvertTestGrandparentFromProto converts a `*storage.TestGrandparent` to Gorm model
func ConvertTestGrandparentFromProto(obj *storage.TestGrandparent) (*TestGrandparents, error) {
	serialized, err := obj.Marshal()
	if err != nil {
		return nil, err
	}
	model := &TestGrandparents{
		Id:         obj.GetId(),
		Val:        obj.GetVal(),
		Priority:   obj.GetPriority(),
		RiskScore:  obj.GetRiskScore(),
		Serialized: serialized,
	}
	return model, nil
}

// ConvertTestGrandparent_EmbeddedFromProto converts a `*storage.TestGrandparent_Embedded` to Gorm model
func ConvertTestGrandparent_EmbeddedFromProto(obj *storage.TestGrandparent_Embedded, idx int, test_grandparents_Id string) (*TestGrandparentsEmbeddeds, error) {
	model := &TestGrandparentsEmbeddeds{
		TestGrandparentsId: test_grandparents_Id,
		Idx:                idx,
		Val:                obj.GetVal(),
	}
	return model, nil
}

// ConvertTestGrandparent_Embedded_Embedded2FromProto converts a `*storage.TestGrandparent_Embedded_Embedded2` to Gorm model
func ConvertTestGrandparent_Embedded_Embedded2FromProto(obj *storage.TestGrandparent_Embedded_Embedded2, idx int, test_grandparents_Id string, test_grandparents_embeddeds_idx int) (*TestGrandparentsEmbeddedsEmbedded2, error) {
	model := &TestGrandparentsEmbeddedsEmbedded2{
		TestGrandparentsId:           test_grandparents_Id,
		TestGrandparentsEmbeddedsIdx: test_grandparents_embeddeds_idx,
		Idx:                          idx,
		Val:                          obj.GetVal(),
	}
	return model, nil
}

// ConvertTestGrandparentToProto converts Gorm model `TestGrandparents` to its protobuf type object
func ConvertTestGrandparentToProto(m *TestGrandparents) (*storage.TestGrandparent, error) {
	var msg storage.TestGrandparent
	if err := msg.Unmarshal(m.Serialized); err != nil {
		return nil, err
	}
	return &msg, nil
}
