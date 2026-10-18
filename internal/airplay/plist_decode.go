package airplay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"howett.net/plist"
)

const (
	maxNetworkPlistBytes        = 8 << 20
	maxNetworkPlistObjects      = 16 << 10
	maxNetworkPlistReferences   = 64 << 10
	maxNetworkPlistDepth        = 64
	maxNetworkPlistExpandedSize = 16 << 20
)

// The upstream decoder trusts binary object counts and recursively expands
// shared collections. Validate both the serialized graph and its expanded size
// before letting it allocate or recurse on a receiver's input.
func unmarshalNetworkPlist(data []byte, out interface{}) (format int, err error) {
	format = plist.InvalidFormat
	if err = validateNetworkPlist(data); err != nil {
		return format, err
	}
	defer func() {
		if recover() != nil {
			format = plist.InvalidFormat
			err = errors.New("decode network plist: parser panic")
		}
	}()
	return plist.Unmarshal(data, out)
}

type networkPlistObject struct {
	refs  []uint64
	bytes uint64
}

type networkPlistExpansion struct {
	nodes uint64
	bytes uint64
	depth int
}

func validateNetworkPlist(data []byte) error {
	if len(data) < 41 || len(data) > maxNetworkPlistBytes {
		return errors.New("invalid network plist size")
	}
	if !bytes.Equal(data[:8], []byte("bplist00")) && !bytes.Equal(data[:8], []byte("bplist01")) {
		return errors.New("network plist must use the binary format")
	}
	trailer := data[len(data)-32:]
	offsetWidth, refWidth := int(trailer[6]), int(trailer[7])
	validWidth := func(width int) bool { return width == 1 || width == 2 || width == 4 || width == 8 }
	if !validWidth(offsetWidth) || !validWidth(refWidth) {
		return errors.New("invalid network plist integer width")
	}
	count := binary.BigEndian.Uint64(trailer[8:16])
	root := binary.BigEndian.Uint64(trailer[16:24])
	table := binary.BigEndian.Uint64(trailer[24:32])
	trailerStart := uint64(len(data) - 32)
	if count == 0 || count > maxNetworkPlistObjects || root >= count || table < 9 || table >= trailerStart {
		return errors.New("invalid network plist object table")
	}
	if count != (trailerStart-table)/uint64(offsetWidth) || (trailerStart-table)%uint64(offsetWidth) != 0 {
		return errors.New("invalid network plist offset table size")
	}
	if refWidth < 8 && count > uint64(1)<<(8*refWidth) {
		return errors.New("network plist object reference is too narrow")
	}
	objects := make([]networkPlistObject, int(count))
	var totalRefs uint64
	for i := range objects {
		start := table + uint64(i*offsetWidth)
		offset := networkPlistUint(data[start : start+uint64(offsetWidth)])
		if offset < 8 || offset >= table {
			return errors.New("network plist object offset is out of bounds")
		}
		object, err := inspectNetworkPlistObject(data[:table], offset, refWidth, count)
		if err != nil {
			return err
		}
		totalRefs += uint64(len(object.refs))
		if totalRefs > maxNetworkPlistReferences {
			return errors.New("too many network plist references")
		}
		objects[i] = object
	}
	state := make([]byte, len(objects))
	expanded := make([]networkPlistExpansion, len(objects))
	var visit func(uint64, int) (networkPlistExpansion, error)
	visit = func(index uint64, depth int) (networkPlistExpansion, error) {
		if depth > maxNetworkPlistDepth {
			return networkPlistExpansion{}, errors.New("network plist is nested too deeply")
		}
		if state[index] == 1 {
			return networkPlistExpansion{}, errors.New("network plist contains a reference cycle")
		}
		if state[index] == 2 {
			if depth+expanded[index].depth-1 > maxNetworkPlistDepth {
				return networkPlistExpansion{}, errors.New("network plist is nested too deeply")
			}
			return expanded[index], nil
		}
		state[index] = 1
		object := objects[index]
		size := networkPlistExpansion{nodes: 1, bytes: object.bytes + 128, depth: 1}
		for _, ref := range object.refs {
			child, err := visit(ref, depth+1)
			if err != nil {
				return networkPlistExpansion{}, err
			}
			size.nodes += child.nodes
			size.bytes += child.bytes
			if child.depth+1 > size.depth {
				size.depth = child.depth + 1
			}
			if size.nodes > maxNetworkPlistReferences || size.bytes > maxNetworkPlistExpandedSize {
				return networkPlistExpansion{}, errors.New("network plist expansion exceeds the limit")
			}
		}
		if size.bytes > maxNetworkPlistExpandedSize {
			return networkPlistExpansion{}, errors.New("network plist expansion exceeds the limit")
		}
		state[index] = 2
		expanded[index] = size
		return size, nil
	}
	for i := range objects {
		if _, err := visit(uint64(i), 1); err != nil {
			return err
		}
	}
	return nil
}

func inspectNetworkPlistObject(data []byte, offset uint64, refWidth int, objectCount uint64) (networkPlistObject, error) {
	tag := data[offset]
	position := offset + 1
	count := uint64(tag & 15)
	width := uint64(1)
	object := networkPlistObject{}
	ensure := func(length uint64) error {
		if length > uint64(len(data))-position {
			return errors.New("network plist object exceeds its data section")
		}
		return nil
	}
	switch tag & 0xf0 {
	case 0x00:
		if tag != 0x08 && tag != 0x09 {
			return object, errors.New("unsupported network plist scalar")
		}
		count = 0
	case 0x10:
		if count > 4 {
			return object, errors.New("invalid network plist integer size")
		}
		count = uint64(1) << count
	case 0x20:
		if count != 2 && count != 3 {
			return object, errors.New("invalid network plist real size")
		}
		count = uint64(1) << count
	case 0x30:
		if tag != 0x33 {
			return object, errors.New("invalid network plist date size")
		}
		count = 8
	case 0x80:
		count++
		if count > 8 && count != 16 {
			return object, errors.New("unsupported network plist UID size")
		}
	case 0x40, 0x50, 0x60, 0xa0, 0xd0:
		if count == 15 {
			if err := ensure(1); err != nil {
				return object, err
			}
			sizeTag := data[position]
			position++
			if sizeTag&0xf0 != 0x10 || sizeTag&15 > 3 {
				return object, errors.New("invalid network plist length encoding")
			}
			sizeWidth := uint64(1) << (sizeTag & 15)
			if err := ensure(sizeWidth); err != nil {
				return object, err
			}
			count = networkPlistUint(data[position : position+sizeWidth])
			position += sizeWidth
		}
		if tag&0xf0 == 0x60 {
			width = 2
		}
		if tag&0xf0 == 0xa0 || tag&0xf0 == 0xd0 {
			width = uint64(refWidth)
			if tag&0xf0 == 0xd0 {
				if count > maxNetworkPlistReferences/2 {
					return object, errors.New("too many network plist dictionary entries")
				}
				count *= 2
			}
			if count > maxNetworkPlistReferences {
				return object, errors.New("too many network plist collection entries")
			}
			if count > (uint64(len(data))-position)/width {
				return object, errors.New("network plist references exceed the data section")
			}
			object.refs = make([]uint64, int(count))
			for i := range object.refs {
				ref := networkPlistUint(data[position : position+width])
				if ref >= objectCount {
					return object, errors.New("network plist object reference is out of bounds")
				}
				object.refs[i] = ref
				position += width
			}
			object.bytes = count * 16
			return object, nil
		}
	default:
		return object, fmt.Errorf("unsupported network plist tag 0x%02x", tag)
	}
	if count > (uint64(len(data))-position)/width {
		return object, errors.New("network plist scalar exceeds the data section")
	}
	object.bytes = count * width
	if tag&0xf0 == 0x60 {
		object.bytes *= 2
	}
	return object, nil
}

func networkPlistUint(data []byte) uint64 {
	var value uint64
	for _, b := range data {
		value = value<<8 | uint64(b)
	}
	return value
}
