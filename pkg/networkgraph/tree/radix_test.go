package tree

import (
	"net"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	pkgNet "github.com/stackrox/rox/pkg/net"
	"github.com/stackrox/rox/pkg/networkgraph"
	"github.com/stackrox/rox/pkg/networkgraph/testutils"
	"github.com/stackrox/rox/pkg/protoassert"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stretchr/testify/assert"
)

func TestNRadixTreeIPv4(t *testing.T) {
	e1 := testutils.GetExtSrcNetworkEntityInfo("1", "1", "35.187.144.0/20", true, false)
	e2 := testutils.GetExtSrcNetworkEntityInfo("2", "2", "35.187.144.0/16", false, false)
	e3 := testutils.GetExtSrcNetworkEntityInfo("3", "3", "35.187.144.0/8", false, false)
	e4 := testutils.GetExtSrcNetworkEntityInfo("4", "4", "35.187.144.0/23", false, false)
	e5 := testutils.GetExtSrcNetworkEntityInfo("5", "5", "35.188.144.0/16", true, false)
	e6 := testutils.GetExtSrcNetworkEntityInfo("6", "6", "36.188.144.0/30", false, false)
	e7 := testutils.GetExtSrcNetworkEntityInfo("7", "7", "36.188.144.0/16", true, false)
	e8 := testutils.GetExtSrcNetworkEntityInfo("8", "8", "36.188.144.0/32", true, false)

	tree, err := NewNRadixTree(pkgNet.IPv4, []*storage.NetworkEntityInfo{e1, e2, e3, e4, e5, e6, e7, e8})
	assert.NoError(t, err)
	assert.NotNil(t, tree)

	protoassert.Equal(t, e1, tree.Get("1"))
	protoassert.Equal(t, e2, tree.Get("2"))
	protoassert.Equal(t, e3, tree.Get("3"))
	protoassert.Equal(t, e4, tree.Get("4"))
	protoassert.Equal(t, e5, tree.Get("5"))
	protoassert.Equal(t, e6, tree.Get("6"))
	protoassert.Equal(t, e7, tree.Get("7"))
	protoassert.Equal(t, e8, tree.Get("8"))

	assert.Error(t, tree.Insert(testutils.GetExtSrcNetworkEntityInfo("60", "60", "36.188.144.0/16", true, false)))

	protoassert.Equal(t, e2, tree.GetSupernet(e1.GetId()))
	protoassert.Equal(t, e1, tree.GetSupernet(e4.GetId()))
	protoassert.Equal(t, e7, tree.GetSupernet(e6.GetId()))

	protoassert.Equal(t, e2, tree.GetMatchingSupernet(e4.GetId(), func(e *storage.NetworkEntityInfo) bool {
		return !e.GetExternalSource().GetDefault()
	}))

	protoassert.Equal(t, e1, tree.GetMatchingSupernet(e4.GetId(), func(e *storage.NetworkEntityInfo) bool {
		return e.GetExternalSource().GetDefault()
	}))

	assert.Nil(t, tree.GetSupernetForCIDR("0.0.0.0/0"))
	protoassert.Equal(t, e2, tree.GetSupernetForCIDR("35.187.144.0/20"))
	protoassert.Equal(t, e2, tree.GetSupernetForCIDR("35.187.144.0/18"))

	protoassert.Equal(t, e3, tree.GetMatchingSupernetForCIDR("35.187.144.0/18", func(e *storage.NetworkEntityInfo) bool {
		return e.GetId() != e2.GetId()
	}))

	protoassert.Equal(t, e2, tree.GetMatchingSupernetForCIDR("35.187.144.0/18", nil))

	protoassert.ElementsMatch(t, []*storage.NetworkEntityInfo{e2, e5}, tree.GetSubnets(e3.GetId()))

	tree.Remove(e3.GetId())
	assert.Nil(t, tree.Get(e3.GetId()))

	protoassert.ElementsMatch(t, []*storage.NetworkEntityInfo{e2, e5}, tree.GetSubnetsForCIDR(e3.GetExternalSource().GetCidr()))
	protoassert.ElementsMatch(t, []*storage.NetworkEntityInfo{e2, e5, e7}, tree.GetSubnetsForCIDR("0.0.0.0/0"))
}

func getIds(entityInfos []*storage.NetworkEntityInfo) set.StringSet {
	ids := set.NewStringSet()

	for _, entityInfo := range entityInfos {
		ids.Add(entityInfo.GetId())
	}

	return ids
}

func TestNRadixTreeIPv4Remove(t *testing.T) {
	e1 := testutils.GetExtSrcNetworkEntityInfo("1", "1", "35.187.144.0/32", false, true)
	e2 := testutils.GetExtSrcNetworkEntityInfo("2", "2", "35.187.144.4/32", false, true)
	e3 := testutils.GetExtSrcNetworkEntityInfo("3", "3", "17.187.144.4/32", false, true)
	e4 := testutils.GetExtSrcNetworkEntityInfo("4", "4", "17.187.144.0/24", false, true)

	cases := map[string]struct {
		externalEntityInfos []*storage.NetworkEntityInfo
		toBeDeleted         []*storage.NetworkEntityInfo
	}{
		"Similar IPs": {
			externalEntityInfos: []*storage.NetworkEntityInfo{e1, e2},
			toBeDeleted:         []*storage.NetworkEntityInfo{e2},
		},
		"Disimilar IPs": {
			externalEntityInfos: []*storage.NetworkEntityInfo{e1, e3},
			toBeDeleted:         []*storage.NetworkEntityInfo{e3},
		},
		"Delete multiple": {
			externalEntityInfos: []*storage.NetworkEntityInfo{e1, e2, e3},
			toBeDeleted:         []*storage.NetworkEntityInfo{e2, e3},
		},
		"Delete all": {
			externalEntityInfos: []*storage.NetworkEntityInfo{e1, e2},
			toBeDeleted:         []*storage.NetworkEntityInfo{e1, e2},
		},
		"Delete supernet": {
			externalEntityInfos: []*storage.NetworkEntityInfo{e3, e4},
			toBeDeleted:         []*storage.NetworkEntityInfo{e4},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tree, err := NewNRadixTree(pkgNet.IPv4, c.externalEntityInfos)
			assert.NoError(t, err)
			assert.NotNil(t, tree)

			for _, entityInfo := range c.toBeDeleted {
				log.Infof("Deleting %+v", entityInfo)
				assert.NotNil(t, tree.Get(entityInfo.GetId()))
				tree.Remove(entityInfo.GetId())
				assert.Nil(t, tree.Get(entityInfo.GetId()))
			}

			externalEntityIds := getIds(c.externalEntityInfos)
			deletedIds := getIds(c.toBeDeleted)

			remainingIds := externalEntityIds.Difference(deletedIds)

			for id := range remainingIds {
				assert.NotNil(t, tree.Get(id))
			}

			assert.True(t, tree.ValidateNetworkTree())
		})
	}
}

func TestNRadixTreeFindCIDR(t *testing.T) {
	e1 := testutils.GetExtSrcNetworkEntityInfo("1", "1", "35.187.144.0/32", false, true)
	e2 := testutils.GetExtSrcNetworkEntityInfo("2", "2", "35.187.144.4/32", false, true)
	e3 := testutils.GetExtSrcNetworkEntityInfo("3", "3", "17.187.144.4/32", false, true)
	e4 := testutils.GetExtSrcNetworkEntityInfo("4", "4", "17.187.144.0/24", false, true)

	internetEntity := networkgraph.InternetProtoWithDesc(pkgNet.IPv4)
	cidr := "255.0.0.0/32"
	_, ipNet, err := net.ParseCIDR(cidr)
	assert.NoError(t, err)

	tree := newDefaultNRadixTree(pkgNet.IPv4)
	err = tree.build([]*storage.NetworkEntityInfo{e1, e2, e3, e4})
	assert.NoError(t, err)

	supernet, err := tree.findCIDRNoLock(ipNet)
	assert.NoError(t, err)
	protoassert.Equal(t, supernet.value, internetEntity)
}

func TestNRadixTreeFindCIDR_Depth31(t *testing.T) {
	e := testutils.GetExtSrcNetworkEntityInfo("1", "1", "255.0.0.0/31", false, true)

	cidr := "255.0.0.0/32"
	_, ipNet, err := net.ParseCIDR(cidr)
	assert.NoError(t, err)

	tree := newDefaultNRadixTree(pkgNet.IPv4)
	err = tree.build([]*storage.NetworkEntityInfo{e})
	assert.NoError(t, err)

	supernet, err := tree.findCIDRNoLock(ipNet)
	assert.NoError(t, err)
	protoassert.Equal(t, supernet.value, e)
}

func TestNRadixTreeIPv6(t *testing.T) {
	e1 := testutils.GetExtSrcNetworkEntityInfo("1", "1", "2001:db8:3333:4444:5555:6666:7777:8888/63", true, false)
	e2 := testutils.GetExtSrcNetworkEntityInfo("2", "2", "2001:db8:3333:4444:5555:6666:7777:8888/64", false, false)
	e3 := testutils.GetExtSrcNetworkEntityInfo("3", "3", "2001:db8:3333:4444:5555:6666:7777:8888/100", false, false)
	e4 := testutils.GetExtSrcNetworkEntityInfo("4", "4", "2001:db8:3333:4444:5555:6666:7777:8888/128", false, false)
	e5 := testutils.GetExtSrcNetworkEntityInfo("5", "5", "2001:db8:2222:4444:5555:6666:7777:8888/70", true, false)
	e6 := testutils.GetExtSrcNetworkEntityInfo("6", "6", "2001:db8:2222:4444:5555:6666:7777:8888/80", false, false)

	tree, err := NewNRadixTree(pkgNet.IPv6, []*storage.NetworkEntityInfo{e1, e2, e3, e4, e5, e6})
	assert.NoError(t, err)
	assert.NotNil(t, tree)

	protoassert.Equal(t, e1, tree.Get("1"))
	protoassert.Equal(t, e2, tree.Get("2"))
	protoassert.Equal(t, e3, tree.Get("3"))
	protoassert.Equal(t, e4, tree.Get("4"))
	protoassert.Equal(t, e5, tree.Get("5"))
	protoassert.Equal(t, e6, tree.Get("6"))

	assert.Error(t, tree.Insert(testutils.GetExtSrcNetworkEntityInfo("60", "60", "2001:db8:2222:4444:5555:6666:7777:8888/80", true, false)))

	protoassert.Equal(t, e1, tree.GetSupernet(e2.GetId()))
	protoassert.Equal(t, networkgraph.InternetEntity().ToProto(), tree.GetSupernet(e1.GetId()))
	protoassert.Equal(t, e5, tree.GetSupernet(e6.GetId()))

	protoassert.Equal(t, e3, tree.GetMatchingSupernet(e4.GetId(), func(e *storage.NetworkEntityInfo) bool {
		return !e.GetExternalSource().GetDefault()
	}))

	protoassert.Equal(t, e1, tree.GetMatchingSupernet(e4.GetId(), func(e *storage.NetworkEntityInfo) bool {
		return e.GetExternalSource().GetDefault()
	}))

	assert.Nil(t, tree.GetSupernetForCIDR("::ffff:0:0/0"))
	protoassert.Equal(t, e2, tree.GetSupernetForCIDR("2001:db8:3333:4444:5555:6666:7777:8888/100"))
	protoassert.Equal(t, e2, tree.GetSupernetForCIDR("2001:db8:3333:4444:5555:6666:7777:8888/90"))

	protoassert.Equal(t, e1, tree.GetMatchingSupernetForCIDR("2001:db8:3333:4444:5555:6666:7777:8888/90", func(e *storage.NetworkEntityInfo) bool {
		return e.GetId() != e2.GetId()
	}))

	protoassert.Equal(t, e2, tree.GetMatchingSupernetForCIDR("2001:db8:3333:4444:5555:6666:7777:8888/90", nil))

	protoassert.ElementsMatch(t, []*storage.NetworkEntityInfo{e4}, tree.GetSubnets(e3.GetId()))

	tree.Remove(e3.GetId())
	assert.Nil(t, tree.Get(e3.GetId()))

	protoassert.ElementsMatch(t, []*storage.NetworkEntityInfo{e4}, tree.GetSubnetsForCIDR(e3.GetExternalSource().GetCidr()))
	protoassert.ElementsMatch(t, []*storage.NetworkEntityInfo{e1, e5}, tree.GetSubnetsForCIDR("::ffff:0:0/0"))
}
