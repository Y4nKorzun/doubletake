package airplay

import (
	"bytes"
	"encoding/binary"
	"testing"

	"howett.net/plist"
)

func TestUnmarshalNetworkPlistReceiverMetadata(t *testing.T) {
	want := map[string]interface{}{
		"name":     "Mac mini",
		"pk":       bytes.Repeat([]byte{0xa5}, 32),
		"features": uint64(0x1122334455667788),
		"displays": []interface{}{map[string]interface{}{"width": uint64(1920), "height": uint64(1080)}},
	}
	data, err := plist.Marshal(want, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	format, err := unmarshalNetworkPlist(data, &got)
	if err != nil || format != plist.BinaryFormat {
		t.Fatalf("decode metadata: format=%d, err=%v", format, err)
	}
	if got["name"] != want["name"] || got["features"] != want["features"] || !bytes.Equal(got["pk"].([]byte), want["pk"].([]byte)) {
		t.Fatalf("metadata changed: %#v", got)
	}
}

func TestUnmarshalNetworkPlistRejectsMalformedReceiverData(t *testing.T) {
	oversizedObjects := networkPlistFixture([][]byte{{0x08}}, 0, 1)
	binary.BigEndian.PutUint64(oversizedObjects[len(oversizedObjects)-24:], maxNetworkPlistObjects+1)
	badOffset := networkPlistFixture([][]byte{{0x08}}, 0, 1)
	binary.BigEndian.PutUint32(badOffset[9:13], 0xffffffff)
	badLengthTag := networkPlistFixture([][]byte{{0x5f, 0x2f}}, 0, 1)
	zeroRefWidth := networkPlistFixture([][]byte{networkPlistLengthObject(0xa0, 1<<30)}, 0, 0)
	for name, data := range map[string][]byte{
		"not binary":             []byte("<?xml version=\"1.0\"?><plist><dict/></plist>"),
		"short":                  []byte("bplist00"),
		"oversized input":        make([]byte, maxNetworkPlistBytes+1),
		"oversized object count": oversizedObjects,
		"offset out of bounds":   badOffset,
		"array count overflow":   networkPlistFixture([][]byte{networkPlistLengthObject(0xa0, 1<<63)}, 0, 2),
		"dictionary overflow":    networkPlistFixture([][]byte{networkPlistLengthObject(0xd0, 1<<63)}, 0, 1),
		"UTF16 count overflow":   networkPlistFixture([][]byte{networkPlistLengthObject(0x60, 1<<63)}, 0, 1),
		"zero reference width":   zeroRefWidth,
		"length tag is not int":  badLengthTag,
		"scalar exceeds section": networkPlistFixture([][]byte{{0x23}}, 0, 1),
		"reference out of range": networkPlistFixture([][]byte{{0xa1, 1}}, 0, 1),
		"direct cycle":           networkPlistFixture([][]byte{{0xa1, 0}}, 0, 1),
		"indirect cycle":         networkPlistFixture([][]byte{{0xa1, 1}, {0xa1, 0}}, 0, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var got interface{}
			if _, err := unmarshalNetworkPlist(data, &got); err == nil {
				t.Fatal("accepted malformed receiver data")
			}
		})
	}
}

func TestUnmarshalNetworkPlistBoundsGraphExpansion(t *testing.T) {
	makeGraph := func(depth int, duplicate bool) []byte {
		objects := make([][]byte, depth)
		for i := 0; i < depth-1; i++ {
			objects[i] = []byte{0xa1, byte(i + 1)}
			if duplicate {
				objects[i] = []byte{0xa2, byte(i + 1), byte(i + 1)}
			}
		}
		objects[depth-1] = []byte{0x51, 'x'}
		return networkPlistFixture(objects, 0, 1)
	}
	for name, data := range map[string][]byte{
		"deep chain":         makeGraph(maxNetworkPlistDepth+1, false),
		"shared exponential": makeGraph(20, true),
	} {
		t.Run(name, func(t *testing.T) {
			var got interface{}
			if _, err := unmarshalNetworkPlist(data, &got); err == nil {
				t.Fatal("accepted excessive graph expansion")
			}
		})
	}
	for _, data := range [][]byte{makeGraph(maxNetworkPlistDepth, false), makeGraph(8, true)} {
		var got interface{}
		if _, err := unmarshalNetworkPlist(data, &got); err != nil {
			t.Fatalf("rejected bounded graph: %v", err)
		}
	}
}

func TestUnmarshalNetworkPlistBoundsExpandedScalarBytes(t *testing.T) {
	dataObject := append(networkPlistLengthObject(0x40, 1<<20), make([]byte, 1<<20)...)
	refs := []byte{0xaf, 0x10, 17}
	refs = append(refs, bytes.Repeat([]byte{1}, 17)...)
	data := networkPlistFixture([][]byte{refs, dataObject}, 0, 1)
	var got interface{}
	if _, err := unmarshalNetworkPlist(data, &got); err == nil {
		t.Fatal("accepted a small reference table expanding to excessive scalar data")
	}
}

func TestUnmarshalNetworkPlistChecksDepthOfAlreadyVisitedGraph(t *testing.T) {
	objects := [][]byte{{0x51, 'x'}}
	for i := 1; i <= maxNetworkPlistDepth; i++ {
		objects = append(objects, []byte{0xa1, byte(i - 1)})
	}
	var got interface{}
	if _, err := unmarshalNetworkPlist(networkPlistFixture(objects, uint64(len(objects)-1), 1), &got); err == nil {
		t.Fatal("accepted excessive depth through cached graph nodes")
	}
}

func TestUnmarshalNetworkPlistBoundsTotalObjectReferences(t *testing.T) {
	array := append(networkPlistLengthObject(0xa0, maxNetworkPlistReferences/2+1), bytes.Repeat([]byte{2}, maxNetworkPlistReferences/2+1)...)
	data := networkPlistFixture([][]byte{array, array, {0x08}}, 0, 1)
	var got interface{}
	if _, err := unmarshalNetworkPlist(data, &got); err == nil {
		t.Fatal("accepted excessive references across individually bounded objects")
	}
}

func TestUnmarshalNetworkPlistContainsUpstreamPanic(t *testing.T) {
	data, err := plist.Marshal("valid", plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalNetworkPlist(data, nil); err == nil {
		t.Fatal("upstream panic was not converted into an error")
	}
}

func networkPlistLengthObject(tag byte, count uint64) []byte {
	data := make([]byte, 10)
	data[0], data[1] = tag|15, 0x13
	binary.BigEndian.PutUint64(data[2:], count)
	return data
}

func networkPlistFixture(objects [][]byte, root uint64, refWidth byte) []byte {
	data := []byte("bplist00")
	offsets := make([]uint32, len(objects))
	for i, object := range objects {
		offsets[i] = uint32(len(data))
		data = append(data, object...)
	}
	table := uint64(len(data))
	for _, offset := range offsets {
		data = binary.BigEndian.AppendUint32(data, offset)
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 4, refWidth
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:], root)
	binary.BigEndian.PutUint64(trailer[24:], table)
	return append(data, trailer...)
}
