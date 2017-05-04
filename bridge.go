package netlink

import (
	"bytes"
	"encoding/binary"
	"github.com/vishvananda/netlink/nl"
	"syscall"
)

const (
	IFLA_BRIDGE_FLAGS = iota
	IFLA_BRIDGE_MODE
	IFLA_BRIDGE_VLAN_INFO
	IFLA_BRIDGE_VLAN_TUNNEL_INFO
	IFLA_BRIDGE_MAX
)

const (
	BRIDGE_VLAN_INFO_MASTER      = 0x1
	BRIDGE_VLAN_INFO_PVID        = 0x2
	BRIDGE_VLAN_INFO_UNTAGGED    = 0x4
	BRIDGE_VLAN_INFO_RANGE_BEGIN = 0x8
	BRIDGE_VLAN_INFO_RANGE_END   = 0x10
	BRIDGE_VLAN_INFO_BRENTRY     = 0x20
)

const (
	RTEXT_FILTER_BRVLAN = 2
)

type BridgeInfo struct {
	Index int
	Vlans []*VlanInfo
}

type VlanInfo struct {
	Vid                                                   uint16
	Master, Pvid, Untagged, RangeBegin, RangeEnd, Brentry bool
}

func GetBridgeInfo() ([]*BridgeInfo, error) {
	return pkgHandle.GetBridgeInfo()
}

func (h *Handle) GetBridgeInfo() ([]*BridgeInfo, error) {

	req := h.newNetlinkRequest(
		syscall.RTM_GETLINK,
		syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST,
	)

	nra := &syscall.RtAttr{
		Len:  8,
		Type: nl.IFLA_EXT_MASK,
	}
	var ext_filter_mask uint32 = RTEXT_FILTER_BRVLAN

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, nra.Len)
	binary.Write(buf, binary.LittleEndian, nra.Type)
	binary.Write(buf, binary.LittleEndian, ext_filter_mask)

	msg := nl.NewIfInfomsg(syscall.AF_BRIDGE)
	req.AddData(msg)
	req.AddRawData(buf.Bytes())

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	var result []*BridgeInfo
	for _, m := range msgs {
		b, err := BridgeDeserialize(nil, m)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}

	return result, nil
}

func BridgeDeserialize(hdr *syscall.NlMsghdr, m []byte) (*BridgeInfo, error) {

	msg := nl.DeserializeIfInfomsg(m)
	attrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}
	if msg.Family != syscall.AF_BRIDGE {
		return nil, nil
	}

	bi := &BridgeInfo{Index: int(msg.Index)}

	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.IFLA_AF_SPEC:
			infos, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				switch info.Attr.Type {
				case IFLA_BRIDGE_VLAN_INFO:
					vl := &VlanInfo{}
					r := bytes.NewReader(info.Value)
					var flags uint16
					binary.Read(r, binary.LittleEndian, &flags)
					binary.Read(r, binary.LittleEndian, &vl.Vid)

					vl.Master = flags&BRIDGE_VLAN_INFO_MASTER != 0
					vl.Pvid = flags&BRIDGE_VLAN_INFO_PVID != 0
					vl.Untagged = flags&BRIDGE_VLAN_INFO_UNTAGGED != 0
					vl.RangeBegin = flags&BRIDGE_VLAN_INFO_RANGE_BEGIN != 0
					vl.RangeEnd = flags&BRIDGE_VLAN_INFO_RANGE_END != 0
					vl.Brentry = flags&BRIDGE_VLAN_INFO_BRENTRY != 0
					bi.Vlans = append(bi.Vlans, vl)
				}
			}
		}
	}
	return bi, nil
}
